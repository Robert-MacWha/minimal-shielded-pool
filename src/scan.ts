/**
 * Receiving notes: a wallet finds its notes, and their spends, in the pool's finalized logs from
 * its seed and its owner set's root. src/notes.ts defines the notes and the secrets that seal
 * them. This module reads the pool's logs from a node, from where the last scan stopped to the
 * finalized head, by eth_getLogs or, where the node leaves logs out, from block receipts. It
 * groups them into one event per shield or settlement, matches each note's tag against the
 * secrets the wallet watches, and turns what it found into the contents of the wallet's state
 * file, from which a later scan resumes. src/cli/notes.ts reads and writes that file under a
 * lock.
 */
import * as crypto from "node:crypto";

import {
  compareBigint,
  compareKeys,
  fromHex,
  hex32,
  hexPadded,
  maxBigint,
  parseAddress,
  parseDec,
  parseHex,
  toBigint,
  toHex,
} from "./bytes.ts";
import { NotesError } from "./errors.ts";
import { KEM_CIPHERTEXT_BYTES, NOTE_BYTES, SHIELD_NOTE_BYTES, SPEND_NOTES_BYTES } from "./gas.ts";
import { asList, asObject, isObject } from "./json.ts";
import {
  GAP,
  LOOKAHEAD,
  SECRET_BYTES,
  TAG_BYTES,
  noteRho,
  noteTag,
  openNote,
  type WalletKeys,
} from "./notes.ts";
import * as protocol from "./protocol.ts";
import { LEAF_APPENDED, NOTES, NOTE_SPENT, TREE_CAPACITY } from "./protocol.ts";
import { ChainError, TOO_LARGE, type RpcChain } from "./rpc.ts";

const STATE_VERSION = 3;
const POOL_TOPICS: readonly string[] = [LEAF_APPENDED, NOTE_SPENT, NOTES];
const EMPTY: Uint8Array = new Uint8Array();

// ---- the scanner ----

export type Leaf = { cm: bigint; epoch: bigint; index: bigint };

/** What one shield or settlement published; (block, tx, call) orders events on chain. */
export interface PoolEvent {
  block: bigint;
  tx: bigint; // the transaction's index in its block
  call: number; // which shield or settlement of that transaction
  notes: Uint8Array;
  leaves: Leaf[];
  spent: bigint[]; // nullifiers
}

type Kind = "self" | "direct" | "kem";

/** A secret this wallet watches; `number` is a direct secret's number, -1 otherwise. */
type Incoming = { secret: Uint8Array; kind: Kind; nextIndex: bigint; number: bigint };

/** A note this wallet owns. The state file writes `kind` under the key "secret". */
interface NoteRecord extends Leaf {
  value: bigint;
  rho: bigint;
  nullifier: bigint;
  spent: boolean;
  kind: Kind;
}

export type ScannerOptions = { gap?: number };

// The 48-byte notes of an event's body after any ciphertext, and their tags as Map keys.
const notesOf = (body: Uint8Array) =>
  Array.from({ length: body.length / NOTE_BYTES }, (_, i) =>
    body.subarray(i * NOTE_BYTES, (i + 1) * NOTE_BYTES),
  );
const tagOf = (note: Uint8Array) => toHex(note.subarray(0, TAG_BYTES));
const placeOf = (leaf: Leaf) => `${leaf.epoch},${leaf.index}`;

/**
 * When a leaf in `epoch` would begin a later epoch than the latest one in `tree`, the number of
 * leaves seen in the epoch before it, 0 if that epoch was never seen; otherwise null.
 */
function closedLeaves(tree: ReadonlyMap<bigint, bigint>, epoch: bigint): bigint | null {
  const latest = [...tree.keys()].reduce(maxBigint, -1n);
  if (latest < 0n || epoch <= latest) return null;
  return epoch === latest + 1n ? tree.get(latest)! : 0n;
}

/** The first epoch before the latest in `tree` shown with fewer than TREE_CAPACITY leaves. */
function shortClosedEpoch(tree: ReadonlyMap<bigint, bigint>): bigint | null {
  const latest = [...tree.keys()].reduce(maxBigint, -1n);
  for (let epoch = 0n; epoch < latest; epoch++) {
    if ((tree.get(epoch) ?? 0n) < TREE_CAPACITY) return epoch;
  }
  return null;
}

/**
 * Finds a wallet's notes and their spends in the pool's finalized events, from its keys. Each
 * epoch's leaves must arrive without gaps, and the next epoch may begin only with a call whose
 * leaves did not fit, so a node that left a payment's logs out stops the scan instead of hiding
 * the payment. The exception is a payment in an epoch's last leaf when a two-leaf call begins the
 * next epoch, since such a call also begins one after an epoch one leaf short of full;
 * scanToFinalized reads receipts there.
 */
export class Scanner {
  readonly keys: WalletKeys;
  readonly chainId: bigint;
  readonly pool: bigint;
  readonly incoming: Incoming[] = [];
  readonly notes = new Map<string, NoteRecord>(); // by placeOf, in the order found
  directHighest = -1n; // the highest direct number paid
  directIssued = -1n; // the highest direct number handed out
  scannedBlock = -1n;
  leafBlock = -1n; // the block of the last leaf seen
  rescanReason: string | null = null; // why fromJson sent the scan back to the deployment block
  readonly #gap: bigint;
  readonly #tags = new Map<string, [Incoming, bigint]>(); // tag hex -> secret, note index
  readonly #tree = new Map<bigint, bigint>(); // epoch -> next leaf index
  readonly #nullifiers = new Map<bigint, string>(); // nullifier -> placeOf its note

  constructor(keys: WalletKeys, chainId: bigint, pool: bigint, options: ScannerOptions = {}) {
    this.keys = keys;
    this.chainId = chainId;
    this.pool = pool;
    this.#gap = BigInt(options.gap ?? GAP);
    // Every pool starts at epoch 0, so a node that serves nothing of it stops the scan instead
    // of letting it begin at a later epoch and miss that epoch's notes.
    this.#tree.set(0n, 0n);
    this.#add(keys.selfSecret, "self");
    for (let n = 0n; n < this.#gap; n++) this.#add(keys.directSecret(n), "direct", 0n, n);
  }

  #add(secret: Uint8Array, kind: Kind, nextIndex = 0n, number = -1n): void {
    const incoming = { secret, kind, nextIndex, number };
    this.incoming.push(incoming);
    this.#watch(incoming);
  }

  // From index 0: a payment with an earlier index can land after a later one, including after
  // the state was saved and loaded again. Tags stay watched, so a window that moves on derives
  // only the indices it newly covers.
  #watch(incoming: Incoming, from = 0n): void {
    for (let index = from; index < incoming.nextIndex + BigInt(LOOKAHEAD); index++) {
      this.#tags.set(tagOf(noteTag(incoming.secret, index)), [incoming, index]);
    }
  }

  /**
   * Whether this event's leaves skip some that were never seen, or may. The pool begins a new
   * epoch only when a call's leaves do not fit, so an epoch closes full, or one leaf short before
   * a two-leaf call. An epoch seen one leaf short may instead have lost its last leaf, so only one
   * seen full rules a skip out.
   */
  skipsLeaves(event: PoolEvent): boolean {
    const expected = new Map(this.#tree);
    for (const { epoch, index } of event.leaves) {
      const closed = closedLeaves(expected, epoch);
      if (index !== (expected.get(epoch) ?? 0n) || (closed !== null && closed < TREE_CAPACITY)) {
        return true;
      }
      expected.set(epoch, index + 1n);
    }
    return false;
  }

  /** Whether this event's leaves are already in the tree. */
  applied(event: PoolEvent): boolean {
    const first = event.leaves[0];
    return first !== undefined && first.index < (this.#tree.get(first.epoch) ?? 0n);
  }

  /**
   * Applies one event and returns the notes it paid to this wallet. inOrder=false applies a
   * call whose logs the node left out, rebuilt from receipts once a later leaf showed the gap.
   */
  scan(event: PoolEvent, inOrder = true): NoteRecord[] {
    if (inOrder && event.block < this.scannedBlock) {
      throw new NotesError("events must arrive in chain order");
    }
    for (const { epoch, index } of event.leaves) {
      const expected = this.#tree.get(epoch) ?? 0n;
      if (index !== expected) {
        throw new NotesError(
          `leaf ${index} of epoch ${epoch} arrived where ${expected} was expected; this node ` +
            "is missing pool logs, so notes may be hidden",
        );
      }
      const closed = closedLeaves(this.#tree, epoch);
      if (closed !== null && closed + BigInt(event.leaves.length) <= TREE_CAPACITY) {
        throw new NotesError(
          `leaf ${index} of epoch ${epoch} arrived after ${closed} leaves of epoch ${epoch - 1n}, ` +
            "which had room for its call; this node is missing pool logs, so notes may be hidden",
        );
      }
      this.#tree.set(epoch, index + 1n);
      this.leafBlock = maxBigint(this.leafBlock, event.block);
    }
    for (const nf of event.spent) {
      const place = this.#nullifiers.get(nf);
      if (place !== undefined) this.notes.get(place)!.spent = true;
    }
    let body = event.notes;
    if ([NOTE_BYTES, 2 * NOTE_BYTES].includes(body.length - KEM_CIPHERTEXT_BYTES)) {
      const secret = this.keys.decapsulate(body.subarray(0, KEM_CIPHERTEXT_BYTES));
      body = body.subarray(KEM_CIPHERTEXT_BYTES);
      // A foreign ciphertext decapsulates to a pseudorandom key, so a secret is adopted only if
      // a note carries a tag at an index a fresh channel would watch. A watched secret's first
      // tag is always in #tags, so one lookup tells whether the secret is already watched.
      const window = new Set<string>();
      for (let i = 0n; i < BigInt(LOOKAHEAD); i++) window.add(tagOf(noteTag(secret, i)));
      const [first] = window;
      const watched = this.#tags.get(first!);
      const known = watched !== undefined && crypto.timingSafeEqual(watched[0].secret, secret);
      if (!known && notesOf(body).some((note) => window.has(tagOf(note)))) this.#add(secret, "kem");
    } else if (![0, NOTE_BYTES, 2 * NOTE_BYTES].includes(body.length)) {
      throw new NotesError(`an event published ${body.length} note bytes`);
    }
    const found: NoteRecord[] = [];
    for (const note of notesOf(body)) {
      const match = this.#tags.get(tagOf(note));
      const record = match && this.#take(match, note, event.leaves);
      if (record) found.push(record);
    }
    if (inOrder) this.scannedBlock = maxBigint(this.scannedBlock, event.block);
    return found;
  }

  #take([incoming, noteIndex]: [Incoming, bigint], note: Uint8Array, leaves: Leaf[]) {
    const value = openNote(incoming.secret, noteIndex, note);
    if (value === null) return null;
    const rho = noteRho(incoming.secret, noteIndex);
    const cm = protocol.commitment(this.keys.ownerPk, rho, value);
    const leaf = leaves.find((l) => l.cm === cm);
    // A note naming no output of its own event pays nobody, and none is counted twice.
    if (leaf === undefined || this.notes.has(placeOf(leaf))) return null;
    const { epoch, index } = leaf;
    const domain = protocol.domainScalar(this.chainId, this.pool, epoch);
    const nullifier = protocol.nullifier(domain, this.keys.nk, cm, index);
    const { kind } = incoming;
    const record = this.#record({ cm, epoch, index, value, rho, nullifier, spent: false, kind });
    if (noteIndex + 1n > incoming.nextIndex) {
      const watched = incoming.nextIndex + BigInt(LOOKAHEAD);
      incoming.nextIndex = noteIndex + 1n;
      this.#watch(incoming, watched);
    }
    if (kind === "direct" && incoming.number > this.directHighest) {
      for (let n = this.directHighest + this.#gap + 1n; n <= incoming.number + this.#gap; n++) {
        this.#add(this.keys.directSecret(n), "direct", 0n, n);
      }
      this.directHighest = incoming.number;
    }
    return record;
  }

  #record(record: NoteRecord): NoteRecord {
    this.notes.set(placeOf(record), record);
    this.#nullifiers.set(record.nullifier, placeOf(record));
    return record;
  }

  /**
   * The next direct secret's number, recorded so that it goes to one sender. A scan from the
   * seed watches numbers up to GAP past the highest one paid, so none is issued beyond that.
   */
  issueDirect(): bigint {
    const number = maxBigint(this.directIssued, this.directHighest) + 1n;
    if (number > this.directHighest + this.#gap) {
      throw new NotesError(
        `${this.#gap} direct secrets are waiting for a first payment, and a scan from the seed ` +
          "would not look further: wait until one of them is paid",
      );
    }
    this.directIssued = number;
    return number;
  }

  unspent(): NoteRecord[] {
    return [...this.notes.values()].filter((note) => !note.spent);
  }

  /** The state file's contents, format version 3. */
  toJson() {
    const tree = [...this.#tree].sort(([a], [b]) => compareBigint(a, b));
    const notes = [...this.notes.values()].sort((a, b) =>
      compareKeys([a.epoch, a.index], [b.epoch, b.index]),
    );
    return {
      version: STATE_VERSION,
      chain_id: this.chainId,
      pool: hexPadded(this.pool, 40),
      account: this.keys.account,
      owner_pk: hex32(this.keys.ownerPk),
      scanned_block: this.scannedBlock,
      leaf_block: this.leafBlock,
      direct_highest: this.directHighest,
      direct_issued: this.directIssued,
      tree: Object.fromEntries(tree.map(([epoch, next]) => [String(epoch), next])),
      incoming: this.incoming.map(({ secret, kind, nextIndex, number }) => {
        return { secret: toHex(secret), kind, next_index: nextIndex, number };
      }),
      notes: notes.map((n) => ({
        cm: hex32(n.cm),
        epoch: n.epoch,
        index: n.index,
        value: n.value,
        rho: hex32(n.rho),
        nullifier: hex32(n.nullifier),
        spent: n.spent,
        secret: n.kind,
      })),
    };
  }

  /** A scanner restored from its state file, refused unless it is this wallet's and account's. */
  static fromJson(keys: WalletKeys, data: unknown): Scanner {
    const state = isObject(data) ? data : {};
    const { account } = state;
    if (
      (state.version !== 2 && state.version !== STATE_VERSION) ||
      (Number.isSafeInteger(account) ? BigInt(account as number) : account) !== keys.account ||
      state.owner_pk !== hex32(keys.ownerPk)
    ) {
      throw new NotesError("the state file belongs to another wallet, account or format");
    }
    const chainId = parseDec(state.chain_id, "the state's chain_id");
    const pool = parseAddress(state.pool, "the state's pool");
    const scanner = new Scanner(keys, chainId, pool);
    // The file lists every watched secret, the self and direct ones included.
    scanner.incoming.length = 0;
    scanner.#tags.clear();
    // Each note found raises its secret's next_index by at most LOOKAHEAD, and every note found
    // is kept, so the indices sum to at most LOOKAHEAD per note. A larger sum is a corrupt file,
    // whose tags would take without end to derive.
    const notes = asList(state.notes, "notes");
    let indices = BigInt(LOOKAHEAD) * BigInt(notes.length);
    for (const item of asList(state.incoming, "incoming")) {
      const i = asObject(item, "an incoming secret");
      // 32 bytes, as scan() compares secrets with timingSafeEqual, which throws on other lengths.
      const secret = fromHex(i.secret, "an incoming secret", SECRET_BYTES);
      const nextIndex = parseDec(i.next_index, "an incoming next_index");
      indices -= nextIndex;
      if (indices < 0n) throw new NotesError("the state file's next_index values exceed its notes");
      scanner.#add(secret, kindOf(i.kind), nextIndex, jsonInteger(i.number, "number"));
    }
    scanner.directHighest = jsonInteger(state.direct_highest, "direct_highest");
    scanner.directIssued = jsonInteger(state.direct_issued, "direct_issued");
    scanner.leafBlock = jsonInteger(state.leaf_block, "leaf_block");
    for (const [epoch, next] of Object.entries(asObject(state.tree, "tree"))) {
      scanner.#tree.set(parseDec(epoch, "a tree epoch"), parseDec(next, "a tree size"));
    }
    for (const item of notes) {
      const r = asObject(item, "a note");
      const field = (key: string) => toBigint(fromHex(r[key], `a note's ${key}`, 32));
      const uint = (key: string) => parseDec(r[key], `a note's ${key}`);
      const { spent } = r;
      if (typeof spent !== "boolean") throw new NotesError("a note's spent is not true or false");
      const [cm, rho, nullifier] = ["cm", "rho", "nullifier"].map(field);
      const [epoch, index, value] = ["epoch", "index", "value"].map(uint);
      scanner.#record({ cm, epoch, index, value, rho, nullifier, spent, kind: kindOf(r.secret) });
    }
    scanner.scannedBlock = jsonInteger(state.scanned_block, "scanned_block");
    // Before version 3, a scan let an epoch begin after one not seen full without reading
    // receipts, so it could miss a payment in that epoch's last leaves for good. Such a state
    // scans again from the deployment block. It keeps the rest: direct_issued alone records the
    // numbers handed out but not yet paid, the watched secrets and direct_highest only grow as
    // notes are found, and a note found again is not counted twice. The tree starts at epoch 0,
    // where every pool starts, so a node that serves nothing of epoch 0 stops the rescan instead
    // of letting it begin at a later epoch and miss the payment again.
    const short = state.version === 2 ? shortClosedEpoch(scanner.#tree) : null;
    if (short !== null) {
      const seen = scanner.#tree.get(short) ?? 0n;
      scanner.#tree.clear();
      scanner.#tree.set(0n, 0n);
      scanner.scannedBlock = scanner.leafBlock = -1n;
      scanner.rescanReason =
        `it shows epoch ${short} closed with ${seen} of ${TREE_CAPACITY} leaves, and the ` +
        "earlier version that saved it could miss a payment in an epoch's last leaves";
    }
    return scanner;
  }
}

function kindOf(value: unknown): Kind {
  if (value === "self" || value === "direct" || value === "kem") return value;
  throw new NotesError(`the state file names a ${String(value)} secret`);
}

/**
 * A state file's signed integer, where -1 means "none yet": a JSON number, or a bigint for one
 * past 2^53. Text is refused, since the scanner writes these as numbers.
 */
function jsonInteger(value: unknown, what: string): bigint {
  if (typeof value === "bigint" || Number.isSafeInteger(value)) return BigInt(value as bigint);
  throw new NotesError(`the state file's ${what} is not an integer`);
}

// ---- chain ----

/** The bytes of a Notes(bytes) log's ABI-encoded data. */
export function decodeNotesData(data: unknown): Uint8Array {
  const raw = fromHex(data, "Notes log data");
  const offset = toBigint(raw.subarray(0, 32));
  const length = Number(toBigint(raw.subarray(32, 64)));
  const sizes = [...SPEND_NOTES_BYTES, ...SHIELD_NOTE_BYTES];
  if (offset !== 32n || !sizes.includes(length) || raw.length < 64 + length) {
    throw new NotesError("malformed Notes log");
  }
  return raw.slice(64, 64 + length);
}

/**
 * Groups the pool's logs into one PoolEvent per shield or settlement, in chain order. A
 * transaction may shield or settle several times, and each call emits Notes as its last pool log
 * and makes no external call before it, so the transaction's logs split at its Notes logs. Pass
 * only the pool's logs: other contracts can emit its topics.
 */
export function eventsFromLogs(logs: readonly unknown[]): PoolEvent[] {
  const sorted = logs
    .map((value) => {
      const log = asObject(value, "a log");
      const fields = ["blockNumber", "transactionIndex", "logIndex"];
      return { log, at: fields.map((field) => parseHex(log[field], `a log's ${field}`)) };
    })
    .sort((a, b) => compareKeys(a.at, b.at));
  const events: PoolEvent[] = [];
  const open = new Map<string, PoolEvent>();
  const calls = new Map<string, number>();
  for (const { log, at } of sorted) {
    const [block, tx] = at;
    const key = `${block},${tx}`;
    const call = calls.get(key) ?? 0;
    const event = open.get(key) ?? { block, tx, call, notes: EMPTY, leaves: [], spent: [] };
    open.set(key, event);
    const topics = asList(log.topics, "a log's topics");
    if (typeof topics[0] !== "string") throw new NotesError("a pool log has no topic");
    const topic = topics[0].toLowerCase();
    if (topic === LEAF_APPENDED) {
      const leaf = protocol.parseLeafAppended(log);
      if (leaf === null) throw new NotesError("malformed LeafAppended log");
      event.leaves.push({ cm: leaf.cm, epoch: leaf.epoch, index: leaf.index });
    } else if (topic === NOTE_SPENT) {
      event.spent.push(parseHex(topics[1], "a NoteSpent nullifier"));
    } else if (topic === NOTES) {
      event.notes = decodeNotesData(log.data);
      // A shield emits one leaf, then its note; a settlement two nullifiers, at most two
      // leaves, then its notes. Any other shape means the node left logs out.
      const complete = SHIELD_NOTE_BYTES.includes(event.notes.length)
        ? event.leaves.length === 1 && event.spent.length === 0
        : event.spent.length === 2 && event.leaves.length <= 2;
      if (!complete) {
        throw new NotesError(
          `a pool call in block ${block} shows ${event.leaves.length} leaves and ` +
            `${event.spent.length} nullifiers for ${event.notes.length} note bytes; this node is ` +
            "missing pool logs",
        );
      }
      events.push(event);
      open.delete(key);
      calls.set(key, call + 1);
    }
  }
  // Calls open in chain order, so the first one left open is the earliest.
  const [unfinished] = open.values();
  if (unfinished !== undefined) {
    throw new NotesError(
      `a pool call in block ${unfinished.block} has no Notes log; this node is missing pool logs`,
    );
  }
  return events;
}

type Rpc = Pick<RpcChain, "call">;

/**
 * The pool's LeafAppended, NoteSpent and Notes logs in [from, to], one eth_getLogs reply at a
 * time, so that no more than one reply is held at once.
 */
async function* fetchLogs(chain: Rpc, pool: bigint, from: bigint, to: bigint, chunk = 2000) {
  if (!(Number.isSafeInteger(chunk) && chunk >= 1)) {
    throw new NotesError("a chunk is at least one block");
  }
  for (let start = from, step = BigInt(chunk); start <= to; start += step) {
    const end = start + step - 1n < to ? start + step - 1n : to;
    const range = { fromBlock: hexPadded(start, 1), toBlock: hexPadded(end, 1) };
    const filter = { address: hexPadded(pool, 40), topics: [POOL_TOPICS], ...range };
    const found = await chain.call("eth_getLogs", [filter]).catch((error: unknown) => {
      // An honest chunk passes rpc()'s cap once it holds about 5,000 ML-KEM shields.
      if (error instanceof ChainError && error.message.endsWith(TOO_LARGE)) {
        throw new ChainError(`${error.message}; pass a smaller --chunk`, { cause: error });
      }
      throw error;
    });
    yield asList(found, "eth_getLogs's result");
  }
}

/**
 * The same logs, read from block receipts one block at a time. ethrex 247e2dd2 leaves out of
 * eth_getLogs every log of a frame transaction in which any frame failed, although the frames
 * that succeeded, settlement included, keep their effects.
 */
async function* receiptLogs(chain: Rpc, pool: bigint, from: bigint, to: bigint) {
  for (let block = from; block <= to; block++) {
    const logs: unknown[] = [];
    const receipts = await chain.call("eth_getBlockReceipts", [hexPadded(block, 1)]);
    for (const value of asList(receipts ?? [], "eth_getBlockReceipts's result")) {
      const receipt = asObject(value, "a receipt");
      // With frame receipts, each frame that succeeded counts, whatever the transaction's status.
      const frames = receipt.frameReceipts ?? null;
      const mine = (frames === null ? [receipt] : asList(frames, "frameReceipts"))
        .map((part) => asObject(part, "a receipt or frame"))
        .filter((part) => parseHex(part.status, "a receipt's status") === 1n)
        .flatMap((part) => asList(part.logs, "a receipt's logs"))
        .map((log) => asObject(log, "a log"))
        // Only the pool's logs are kept, before any is parsed: another contract can emit a log
        // with a pool topic, and its malformed fields must not stop the scan.
        .filter(
          ({ address, topics }) =>
            parseAddress(address, "a log's address") === pool &&
            Array.isArray(topics) &&
            typeof topics[0] === "string" &&
            POOL_TOPICS.includes(topics[0].toLowerCase()),
        );
      mine.forEach(({ topics, data }, position) =>
        logs.push({
          blockNumber: hexPadded(block, 1),
          transactionIndex: receipt.transactionIndex,
          logIndex: hexPadded(BigInt(position), 1),
          topics,
          data,
        }),
      );
    }
    yield logs;
  }
}

/**
 * Scans the pool's finalized logs from where the scanner stopped, or the deployment block, to the
 * finalized head, refused if the node is on another chain. An event whose leaves skip some never
 * seen, or begin an epoch after one not seen full, first brings in the calls the node's
 * eth_getLogs left out, rebuilt from block receipts. It never asks about single nullifiers, which
 * would link notes to their spends.
 */
export async function scanToFinalized(
  scanner: Scanner,
  chain: Pick<RpcChain, "call" | "chainId" | "finalizedBlock">,
  deployment: bigint,
  chunk?: number,
): Promise<void> {
  if ((await chain.chainId()) !== scanner.chainId) {
    throw new NotesError(`the RPC is not on chain ${scanner.chainId}`);
  }
  const start = maxBigint(scanner.scannedBlock + 1n, deployment);
  const head = await chain.finalizedBlock();
  // A state saved at a head the chain has not reached would skip every payment up to it, so a
  // finalized head behind the last scan is refused rather than read as nothing new.
  if (head < scanner.scannedBlock) {
    throw new NotesError(
      `the RPC's finalized block ${head} is behind block ${scanner.scannedBlock}, where this ` +
        "state's last scan stopped: the RPC lags, or a node used before reported a block the " +
        "chain had not reached, in which case this state skips every block the chain finalizes " +
        "up to that one. Unless the lag ends soon, scan into a new state file with a node you " +
        "trust",
    );
  }
  // Each reply's events are applied before the next reply is read, here and in the receipts
  // fallback, so a scan holds one reply at a time: a node that sends many eth_getLogs replies
  // under rpc()'s cap must not be able to fill the heap, which aborts the process. rpc() reads a
  // receipts reply whole, so the node can still do that with one.
  for await (const logs of fetchLogs(chain, scanner.pool, start, head, chunk)) {
    for (const event of eventsFromLogs(logs)) {
      if (scanner.skipsLeaves(event)) {
        // The missing calls came after the last leaf seen (possibly in its block) and before
        // this event. Apply each one not applied yet, whether or not this node's eth_getLogs
        // shows it, since an earlier scan may have used a node that left it out. A call
        // without leaves changes nothing when applied twice. In the event's own transaction,
        // the calls before it are those its receipt lists before the call with its first leaf:
        // call numbers cannot tell, since eth_getLogs numbers only the calls it shows.
        const from = maxBigint(scanner.leafBlock, deployment);
        const [first] = event.leaves;
        const sameTx: PoolEvent[] = [];
        for await (const logs of receiptLogs(chain, scanner.pool, from, event.block)) {
          for (const call of eventsFromLogs(logs)) {
            const order = compareKeys([call.block, call.tx], [event.block, event.tx]);
            if (order === 0) sameTx.push(call);
            else if (order < 0 && !scanner.applied(call)) scanner.scan(call, false);
          }
        }
        const own = sameTx.findIndex((call) =>
          call.leaves.some((l) => l.epoch === first.epoch && l.index === first.index),
        );
        for (const call of sameTx.slice(0, Math.max(own, 0))) {
          if (!scanner.applied(call)) scanner.scan(call, false);
        }
      }
      scanner.scan(event);
    }
  }
  scanner.scannedBlock = maxBigint(scanner.scannedBlock, head);
}
