/**
 * Disclosure receipts: which notes a spend consumed and created, without the spending key. A
 * nullifier is Poseidon3(4, nk, Poseidon2(cm, index)) with nk = Poseidon2(D, spend_key), so nk
 * and a note's position find the spend that published its nullifier, and the proof ties that
 * nullifier to exactly this note, yet only spend_key can spend. A receipt proves these links and
 * amounts, not who presents it or where the funds came from before the deposit. Notes paid to
 * one address share its spend key, so their nk covers every note of that address in the epoch.
 * Export cannot tell such a key from one a single note uses, so it refuses every nullifier key
 * unless --address-wide accepts that, and marks the notes that carry one.
 */
import { existsSync } from "node:fs";

import {
  compareBigint,
  equalBytes,
  hex32,
  hexPadded,
  parseAddress,
  parseConfigAddress,
  parseDec,
  parseHex,
} from "./bytes.ts";
import { checkDeployedProfile } from "./deployment.ts";
import { InputError, ReceiptError, UserError } from "./errors.ts";
import { readJson, writeNewPrivate } from "./files.ts";
import { MODE } from "./frametx.ts";
import { asList, asObject, isObject, stringify, type JsonObject } from "./json.ts";
import * as protocol from "./protocol.ts";
import {
  ChainError,
  poolNode,
  RpcChain,
  type Chain,
  type ChainTransaction,
  type RawLog,
} from "./rpc.ts";

const RECEIPT = "minimal-shielded-pool/disclosure";
const VERSION = 1;

/** A receipt as exportReceipt builds it; the file keeps its key order. */
export type Receipt = Awaited<ReturnType<typeof exportReceipt>>;
/** A note as verify reports it; spent is "not disclosed" without a nullifier key. */
interface VerifiedNote {
  cm: string;
  epoch: bigint;
  index: bigint;
  value: string;
  spent: string;
  origin: string;
}

type Position = { cm: bigint; epoch: bigint; index: bigint };
type Opening = { sk: bigint; inner: bigint; value: bigint; places: Map<string, Position> };
const at = ({ cm, epoch, index }: Position) => `${cm},${epoch},${index}`;

/**
 * A receipt for the chosen notes a generator fixture opens: `only` is a set of commitments, or
 * null for all. Logs are matched locally, but export reads a chosen note's nullifier slot in the
 * EIP-8250 nonce manager, keccak256(pool, nullifier), when the fixture spends the note and the
 * logs do not show that spend (also when the note is still unspent on this chain) or, for a real
 * note, its creation. The RPC can match that slot to the nullifier once a spend publishes it, so
 * use a node you control. A receipt never holds spend_key or rho, and only notes the fixture
 * spends get a nullifier key: a payment's output may be someone else's note, whose later spend
 * is theirs to disclose. A chain that cannot answer stops the export with its ChainError.
 */
export async function exportReceipt(
  chain: Chain,
  chainId: bigint,
  pool: bigint,
  fixture: unknown,
  only: ReadonlySet<bigint> | null,
  { fromBlock = 0n, addressWide = false } = {},
) {
  // The last transaction to append each position, and the spend of each nullifier.
  const leaves = new Map<string, Position & { created: string }>();
  const spentIn = new Map<bigint, string>();
  const topics = [[protocol.LEAF_APPENDED, protocol.NOTE_SPENT]];
  for (const log of await chain.logs(pool, topics, fromBlock)) {
    const leaf = leafOf(log);
    if (leaf === null) spentIn.set(parseHex(log.topics[1], "a NoteSpent nullifier"), log.tx);
    else leaves.set(at(leaf), { ...leaf, created: log.tx });
  }

  const fx = asObject(fixture, "the fixture");
  const notes = openings(fx);

  const out = [];
  // Real notes first, then dummies, each by commitment.
  const order = [...notes]
    .filter(([cm]) => only === null || only.has(cm))
    .sort(
      ([a, x], [b, y]) => Number(x.value === 0n) - Number(y.value === 0n) || compareBigint(a, b),
    );
  for (const [cm, note] of order) {
    const label = `note ${hex32(cm).slice(0, 18)}...`;
    const real = note.value !== 0n;
    // A note the fixture spends is disclosed where it spends it, and a dummy input, never in the
    // tree, only by its spend. Any other note is disclosed wherever it was appended.
    const own = note.places.size > 0;
    const places = own
      ? [...note.places.values()]
          .sort((p, q) => compareBigint(p.epoch, q.epoch) || compareBigint(p.index, q.index))
          .map((p) => ({ ...p, created: real ? leaves.get(at(p))?.created : undefined }))
      : [...leaves.values()].filter((leaf) => leaf.cm === cm);
    for (const { epoch, index, created } of places) {
      const key = protocol.nullifierKey(protocol.domainScalar(chainId, pool, epoch), note.sk);
      const nf = own ? protocol.nullifierFromKey(key, cm, index) : undefined;
      const spent = nf === undefined ? undefined : spentIn.get(nf);
      // ethrex leaves out of eth_getLogs every log of a frame transaction whose fourth frame
      // failed, settlement included.
      const unseen = nf !== undefined && (spent === undefined || (created === undefined && real));
      if (unseen && (await chain.nonceUsed(pool, nf))) {
        throw new ReceiptError(
          `${label} was spent, but this node's logs do not show the transactions involved; ` +
            "use a node that does",
        );
      }
      if (real ? created === undefined : spent === undefined) continue;
      // Any key may be an address's: every real note src/notes.ts makes carries one, at any
      // account number, and a zero-value dummy can carry one in a fixture made by hand.
      if (spent !== undefined && !addressWide) {
        throw new ReceiptError(
          `${label} may share its spend key with other notes, as notes paid to one address do: ` +
            `its nullifier key would show when every note of that key in epoch ${epoch} is ` +
            "spent. Pass --address-wide to disclose that",
        );
      }
      out.push({
        epoch,
        index,
        cm: hex32(cm),
        inner: hex32(note.inner),
        value: String(note.value),
        ...(real ? { created: created! } : { dummy: true as const }),
        ...(spent === undefined
          ? {}
          : { keyScope: "address" as const, spent, nullifierKey: hex32(key) }),
      });
    }
  }
  return { receipt: RECEIPT, version: VERSION, chainId, pool: hexPadded(pool, 40), notes: out };
}

/**
 * The notes a fixture opens, by commitment, with the positions where it spends them. Inputs
 * name their leaf, a dummy's nullifier uses leaf 0, and outputs are found by commitment.
 */
function openings(fx: JsonObject) {
  const notes = new Map<bigint, Opening>();
  const open = (opening: unknown, place?: { epoch: bigint; index: bigint }) => {
    const o = asObject(opening, "an opening");
    const sk = parseHex(o.spend_key, "an opening's spend_key");
    const rho = parseHex(o.rho, "an opening's rho");
    const value = parseDec(o.value, "an opening's value");
    const cm = protocol.commitment(sk, rho, value);
    const note = notes.get(cm) ?? { sk, inner: protocol.inner(sk, rho), value, places: new Map() };
    notes.set(cm, note);
    if (place) note.places.set(at({ cm, ...place }), { cm, ...place });
  };
  for (const entry of Object.values(fx)) {
    if (!isObject(entry) || !("inputs" in entry)) continue;
    const inputs = asList(entry.inputs, "inputs").map((input) => {
      const epoch = parseDec(entry.epoch, "an entry's epoch");
      const leaf = asObject(input, "an input").leaf;
      if (leaf !== null && typeof leaf !== "number" && typeof leaf !== "bigint") {
        throw new InputError("an input's leaf must be an integer or null");
      }
      return { input, epoch, index: parseDec(leaf ?? 0, "an input's leaf") };
    });
    const outputs =
      "output_openings" in entry ? asList(entry.output_openings, "output_openings") : [];
    for (const { input, ...place } of inputs) open(input, place);
    for (const output of outputs) open(output);
  }
  return notes;
}

/**
 * The settlement fields and inserted outputs (in log order) of a pool spend. A settlement that
 * failed is refused, or with `failed` read as one that inserted no outputs.
 */
export function decodeSpend(tx: ChainTransaction, pool: bigint, { failed = false } = {}) {
  if (tx.sender !== pool) throw new ReceiptError(`${tx.hash} is not a spend of this pool`);
  const frames = tx.frames.filter(
    (f) =>
      f.mode === MODE.SENDER &&
      f.to === pool &&
      equalBytes(f.data.subarray(0, 4), protocol.SETTLE_SELECTOR),
  );
  // settle(Spend) is followed by the spend's notes, which receipts do not need.
  const settled = frames.length === 1 ? protocol.decodeSettle(frames[0].data) : null;
  if (settled === null) throw new ReceiptError(`${tx.hash} has no canonical settlement frame`);
  const succeeded = frames[0].status === 1n;
  if (!succeeded && !failed) throw new ReceiptError(`${tx.hash}'s settlement did not succeed`);
  return { ...settled.spend, outputs: succeeded ? poolLeaves(frames[0].logs, pool) : [] };
}

type PoolCheck = (pool: bigint) => void | Promise<void>;

/**
 * Checks every note against the chain and summarizes each spend it names. poolCheck(pool) must
 * authenticate the pool, since any contract can emit logs shaped like its own. Throws
 * ReceiptError on the first failed claim, or "malformed receipt: ..." for one it cannot read. A
 * claim the chain cannot answer for, such as a transaction it does not hold, fails too.
 */
export function verifyReceipt(chain: Chain, receipt: unknown, poolCheck: PoolCheck) {
  const claims = () => prefixed("", [ChainError], () => verify(chain, receipt, poolCheck));
  return prefixed("malformed receipt: ", [InputError], claims);
}

async function verify(chain: Chain, receipt: unknown, poolCheck: PoolCheck) {
  const r = asObject(receipt, "the receipt");
  if (r.receipt !== RECEIPT || r.version !== VERSION) {
    throw new ReceiptError("not a version 1 disclosure receipt");
  }
  const [chainId, pool] = [signedDec(r.chainId, "chainId"), parseHex(r.pool, "the receipt's pool")];
  if ((await chain.chainId()) !== chainId) {
    throw new ReceiptError(`the RPC is not chain ${chainId}`);
  }
  await poolCheck(pool);
  const finalized = await chain.finalizedBlock();
  // Transactions are fetched in receipt order and a spend is decoded only when a note needs it,
  // so the first failed claim is the one reported.
  const txs = new Map<string, ChainTransaction>();
  const tx = async (h: string) => {
    if (!txs.has(h)) txs.set(h, await chain.transaction(h));
    // Evidence that a reorg could undo is not evidence.
    if (txs.get(h)!.block > finalized) throw new ReceiptError(`${h} is not finalized yet`);
    return txs.get(h)!;
  };
  const spends = new Map<string, ReturnType<typeof decodeSpend>>();
  const spendOf = async (h: string) => {
    if (!spends.has(h)) spends.set(h, decodeSpend(await tx(h), pool));
    return spends.get(h)!;
  };

  const notes = new Map<string, VerifiedNote & { nf?: bigint }>();
  for (const item of asList(r.notes, "notes")) {
    const n = asObject(item, "a note");
    const cm = parseHex(n.cm, "a note's cm");
    const [epoch, index, value] = ["epoch", "index", "value"].map((k) => signedDec(n[k], k));
    const label = `note ${(n.cm as string).slice(0, 18)}...`;
    const fail = (why: string) => new ReceiptError(`${label}: ${why}`);
    const position = at({ cm, epoch, index });
    if (index < 0n || index >= protocol.TREE_CAPACITY) {
      throw fail(`leaf ${index} is outside the tree`);
    }
    // A note listed twice would count twice.
    if (notes.has(position)) throw new ReceiptError(`${label} is listed twice`);
    const inRange = value >= 0n && value < protocol.MAX_VALUE;
    if (!inRange || protocol.tagged(protocol.TAG_LEAF, parseHex(n.inner, "inner"), value) !== cm) {
      throw fail("the opening does not match the commitment");
    }
    let origin = "dummy input";
    if (n.dummy === true) {
      if (value !== 0n || !("spent" in n)) throw fail("a dummy input has value 0 and a spend");
    } else {
      const h = lower(n.created, "created");
      const created = await tx(h);
      // A frame that reverted emitted nothing; a transaction without frames has only its logs.
      const emitted = created.frames.length
        ? created.frames.filter((f) => f.status === 1n).flatMap((f) => f.logs)
        : created.logs;
      if (!poolLeaves(emitted, pool).some((leaf) => at(leaf) === position)) {
        throw fail(`${h} did not create it at epoch ${epoch} leaf ${index}`);
      }
      if (created.sender !== pool) {
        origin = `deposit in ${h}, sent by ${hexPadded(created.sender, 40)}`;
      } else if (
        decodeSpend(created, pool, { failed: true }).outputs.some((o) => at(o) === position)
      ) {
        origin = `output of ${h}`;
      } else {
        // A spend's fourth frame can call a contract that shields, and runs even when the
        // settlement before it failed.
        origin = `deposit made from ${h}'s fourth frame`;
      }
    }
    let spent = "not disclosed";
    let nf: bigint | undefined;
    if ("spent" in n) {
      spent = lower(n.spent, "spent");
      const spend = await spendOf(spent);
      if (spend.epoch !== epoch) throw fail(`${spent} spends epoch ${spend.epoch}, not ${epoch}`);
      nf = protocol.nullifierFromKey(parseHex(n.nullifierKey, "nullifierKey"), cm, index);
      if (nf !== spend.nf1 && nf !== spend.nf2) {
        throw fail(`its nullifier is not one ${spent} spent`);
      }
    }
    notes.set(position, { cm: hex32(cm), epoch, index, value: String(value), spent, origin, nf });
  }

  // Each spend a note names, by lowercase hash in decode order. An output's value shows when the
  // receipt discloses it, and a spend is complete when the receipt discloses both its inputs.
  const summary = [...spends].flatMap(([h, s]) => {
    const inputs = [...notes.values()].filter((n) => n.spent === h);
    if (inputs.length === 0) return [];
    const nfs = new Set(inputs.map((n) => n.nf));
    const outputs = s.outputs.map((o) => {
      const shown = notes.get(at(o));
      const value = shown?.origin === `output of ${h}` ? shown.value : null;
      return { cm: hex32(o.cm), epoch: o.epoch, index: o.index, value };
    });
    const summarized = {
      complete: nfs.has(s.nf1) && nfs.has(s.nf2),
      inputValue: String(inputs.reduce((sum, n) => sum + BigInt(n.value), 0n)),
      outputs,
      publicAmount: String(s.publicAmount),
      fee: String(s.fee),
      recipient: s.publicAmount !== 0n ? hexPadded(s.recipient, 40) : null,
    };
    return [[h, summarized] as const];
  });
  const report = [...notes.values()].map(({ nf, ...note }): VerifiedNote => note);
  return { chainId, pool: hexPadded(pool, 40), notes: report, spends: new Map(summary) };
}

/** The pool's LeafAppended events among logs, in order; the address is checked before parsing. */
function poolLeaves(logs: readonly RawLog[], pool: bigint) {
  return logs.flatMap((log) =>
    parseAddress(log.address, "a log's address") === pool ? (leafOf(log) ?? []) : [],
  );
}

/**
 * A log's LeafAppended event or null. One with LeafAppended's topic that the parser cannot read
 * is refused: export would take it for a NoteSpent log and lose the note's creation.
 */
function leafOf(log: RawLog) {
  const leaf = protocol.parseLeafAppended(log);
  if (leaf === null && log.topics[0]?.toLowerCase() === protocol.LEAF_APPENDED) {
    throw new InputError(`a LeafAppended log must have 3 topics, not ${log.topics.length}`);
  }
  return leaf;
}

/** `export`: writes the receipt, readable only by its owner, and returns the line to print. */
export async function exportCommand(options: {
  rpc: string;
  config: string;
  fixture?: string;
  only?: string;
  all?: boolean;
  addressWide?: boolean;
  output?: string;
}) {
  // The config is read first, so a missing or non-JSON file is reported as a file error rather
  // than a rejected receipt; its shape is checked with the other refusals, after the flags.
  const parsed = readJson(options.config);
  return prefixed("receipt rejected: ", [ReceiptError, InputError, ChainError], async () => {
    const { fixture, output, addressWide } = options;
    if (!fixture || !output || existsSync(output)) {
      throw new ReceiptError("export needs --fixture and a new --output path");
    }
    if (Boolean(options.only) === Boolean(options.all)) {
      throw new ReceiptError("export needs --only with the notes to disclose, or --all");
    }
    // Full commitments only: a prefix could disclose notes the user did not name, and a
    // disclosure cannot be taken back.
    const chosen = options.only ? options.only.split(",") : null;
    if (chosen?.some((c) => !/^0x[0-9a-fA-F]{64}$/.test(c))) {
      throw new ReceiptError("--only takes full commitments: 0x and 64 hex digits each");
    }
    const config = asObject(parsed, options.config);
    const chainId = parseDec(config.chainId, "the config's chainId");
    const pool = parseConfigAddress(config.pool, "the config's pool");
    const fx = readJson(fixture);
    const only = chosen && new Set(chosen.map(BigInt));
    const from = "deploymentBlock" in config ? config.deploymentBlock : 0;
    const fromBlock = parseDec(from, "the config's deploymentBlock");
    const chain = new RpcChain(options.rpc);
    const receipt = await exportReceipt(chain, chainId, pool, fx, only, { fromBlock, addressWide });
    writeNewPrivate(output, stringify(receipt, 1) + "\n");
    return `wrote ${output}: ${receipt.notes.length} notes\n`;
  });
}

/** `verify`: checks the receipt against the RPC and the config's pool, and returns the report. */
export async function verifyCommand(options: { rpc: string; config: string; receipt?: string }) {
  const parsed = readJson(options.config);
  // The config is checked when the receipt's pool is, so a config that is not an object, or
  // has no readable pool, fails as a malformed receipt.
  const poolCheck = async (pool: bigint) => {
    const config = asObject(parsed, options.config);
    if (pool !== parseConfigAddress(config.pool, "the config's pool")) {
      throw new ReceiptError("the receipt names another pool than the config");
    }
    await prefixed("pool check failed: ", [UserError], async () => {
      const chainId = parseDec(config.chainId, "the config's chainId");
      const logic = parseConfigAddress(config.logic, "the config's logic");
      const verifier = parseConfigAddress(config.verifier, "the config's verifier");
      await checkDeployedProfile(poolNode(options.rpc), pool, chainId, logic, verifier);
    });
  };
  return prefixed("receipt rejected: ", [ReceiptError, InputError], async () => {
    const receipt = options.receipt ? readJson(options.receipt) : null;
    if (!isObject(receipt)) {
      throw new ReceiptError("verify needs --receipt naming a disclosure receipt");
    }
    const report = await verifyReceipt(new RpcChain(options.rpc), receipt, poolCheck);
    return stringify(report, 1) + "\n";
  });
}

/** Runs body, rethrowing an error of one of the given kinds as a ReceiptError with prefix. */
async function prefixed<T>(prefix: string, kinds: (typeof UserError)[], body: () => Promise<T>) {
  try {
    return await body();
  } catch (error) {
    if (!kinds.some((kind) => error instanceof kind)) throw error;
    throw new ReceiptError(prefix + (error as Error).message, { cause: error });
  }
}

// One spelling per hash: a node such as ethrex also takes a hash without 0x, and the report keys
// spends by spelling, so a second spelling would list one spend twice.
function lower(value: unknown, what: string): string {
  const hash = typeof value === "string" ? value.toLowerCase() : "";
  if (!hash.startsWith("0x")) throw new InputError(`${what} must be a 0x transaction hash`);
  return hash;
}

/**
 * A decimal integer, as a JSON number or a string of digits, like parseDec except that a minus
 * sign passes, so that a negative index or value meets its range check.
 */
function signedDec(value: unknown, what: string): bigint {
  if (typeof value === "bigint" || Number.isSafeInteger(value)) return BigInt(value as bigint);
  if (typeof value === "string" && /^-?[0-9]+$/.test(value)) return BigInt(value);
  throw new InputError(`${what} must be an integer`);
}
