/**
 * Note delivery: wallets find their notes and spends from their seed alone, through a public
 * address or a secret sent out of band, and senders cannot reuse an index or a ciphertext or
 * outrun the recipient's window. A state an earlier version saved is scanned again when it may
 * have missed a payment, keeping the direct numbers handed out. The chain is an in-memory list of
 * what the pool emits, and the notes CLI runs as a user runs it, against a local JSON-RPC server
 * serving the same logs and receipts.
 *
 * Run: node --test test/notes.test.ts (about 5 s, most of it the 35 CLI runs). ML-KEM
 * encapsulation draws fresh randomness, so ciphertexts differ between runs; every outcome
 * checked here does not depend on them.
 */
import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";

import { compareBigint, concat, fromHex, hex32, hexPadded, keccak, toHex } from "../src/bytes.ts";
import { NotesError } from "../src/errors.ts";
import { POOL_PROFILE, SHIELD_NOTE_BYTES, SPEND_NOTES_BYTES } from "../src/gas.ts";
import { parse, stringify } from "../src/json.ts";
import { directSecretCommand, scanCommand } from "../src/cli/notes.ts";
import * as n from "../src/notes.ts";
import {
  LEAF_APPENDED,
  NOTES,
  NOTE_SPENT,
  TREE_CAPACITY,
  domainScalar,
  nullifier,
} from "../src/protocol.ts";
import { seededRng } from "../src/random.ts";
import { RpcChain } from "../src/rpc.ts";
import {
  Scanner,
  decodeNotesData,
  eventsFromLogs,
  scanToFinalized,
  type Leaf,
  type PoolEvent,
  type ScannerOptions,
} from "../src/scan.ts";
import { rpcServer, runCli } from "./helpers.ts";

const CHAIN = 8141n;
const POOL = 0xcb83980f3cc99e258295814375b0a94fe0ac0e86n;
const ETH = 10n ** 18n;
const FEE = ETH / 100n;
// The BN254 scalar field order, written out so the address check is tested against the
// constant itself rather than the module's copy.
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Dummy notes and test secrets come from one seeded stream, so every run draws the same bytes.
const RNG = seededRng(20261008n);
const dummy = () => n.dummyNote(RNG);
const utf8 = (text: string) => new TextEncoder().encode(text);
const seedOf = (name: string) => keccak(utf8(name));
const [ALICE, BOB, CAROL] = ["alice", "bob", "carol"].map((name) => new n.WalletKeys(seedOf(name)));

const CLI = fileURLToPath(new URL("../src/cli/notes.ts", import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "notes-test-"));
after(() => rmSync(TMP, { recursive: true, force: true }));
const SEED = join(TMP, "seed");
writeFileSync(SEED, toHex(seedOf("alice")), { mode: 0o600 });

function raises(fn: () => unknown, expected: string): void {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof NotesError, `expected a NotesError, got ${String(error)}`);
    assert.ok(error.message.includes(expected), `"${expected}" not in "${error.message}"`);
    return true;
  });
}

type AddOptions = { sizes?: readonly number[]; sameTx?: true; sameBlock?: boolean; skip?: bigint };

/**
 * The pool's events, one per shield or settlement, and the leaves of its tree, which begins a
 * new epoch when a call's leaves do not fit, as the pool does. Each call gets its own block
 * unless it shares the previous call's transaction or block.
 */
class Chain {
  events: PoolEvent[] = [];
  epoch = 0n;
  size = 0n;
  block = 100n;

  add(notes: Uint8Array, outputs: bigint[], spent: bigint[] = [], options: AddOptions = {}) {
    assert.ok((options.sizes ?? SPEND_NOTES_BYTES).includes(notes.length), `${notes.length}`);
    if (BigInt(outputs.length) > TREE_CAPACITY - this.size) {
      [this.epoch, this.size] = [this.epoch + 1n, 0n];
    }
    const leaves = outputs.map((cm) => ({ cm, epoch: this.epoch, index: this.size++ }));
    const last = this.events.at(-1)!;
    let block: bigint, tx: bigint, call: number;
    if (options.sameTx) [block, tx, call] = [last.block, last.tx, last.call + 1];
    else if (options.sameBlock) [block, tx, call] = [last.block, last.tx + 1n, 0];
    else {
      this.block += 1n + (options.skip ?? 0n);
      [block, tx, call] = [this.block, this.block % 3n, 0];
    }
    this.events.push({ block, tx, call, notes, leaves, spent: [...spent] });
    return leaves;
  }
}

const SHIELD = { sizes: SHIELD_NOTE_BYTES };

/** A note on `channel` for value, and the commitment it opens to. */
function paid(ownerPk: bigint, channel: n.Outgoing, value: bigint) {
  const { note, rho, ciphertext } = n.reserve(channel, value);
  return { note, cm: n.outputCommitment(ownerPk, rho, value), ciphertext };
}
type Paid = ReturnType<typeof paid>;

function nullifierOf(keys: n.WalletKeys, cm: bigint, index: bigint, epoch = 0n): bigint {
  return nullifier(domainScalar(CHAIN, POOL, epoch), keys.spendKey, cm, index);
}

/** Bob shields, pays Alice four ways and withdraws; Carol pays Alice, then Bob. */
function story(): Chain {
  const chain = new Chain();
  const pay = (payee: Paid, change: Paid, spent: bigint[], outputs = [payee.cm, change.cm]) =>
    chain.add(n.spendNotes(payee.note, change.note, payee.ciphertext), outputs, spent);
  const bobSelf = n.directChannel(BOB.ownerPk, BOB.selfSecret);
  const carolSelf = n.directChannel(CAROL.ownerPk, CAROL.selfSecret);
  const deposit = paid(BOB.ownerPk, bobSelf, 5n * ETH);
  const [bobLeaf] = chain.add(n.shieldNotes(deposit.note), [deposit.cm], [], SHIELD);
  // Bob pays Alice's public address. The first payment carries the ciphertext.
  const toAlice = n.openChannel(ALICE.address().hex());
  let payee = paid(ALICE.ownerPk, toAlice, ETH);
  let change = paid(BOB.ownerPk, bobSelf, 4n * ETH - FEE);
  pay(payee, change, [nullifierOf(BOB, bobLeaf.cm, bobLeaf.index), 1n]); // with a dummy's nullifier
  assert.deepEqual(toAlice.ciphertext, payee.ciphertext);
  assert.equal(toAlice.nextIndex, 1n);
  // Until that payment is final, the channel takes no other payment. The next payment's outputs
  // land in the other order than its notes.
  raises(() => n.reserve(toAlice, ETH), "opening payment is not final yet");
  n.finalized(toAlice, 0n);
  payee = paid(ALICE.ownerPk, toAlice, ETH / 2n);
  assert.equal(payee.ciphertext.length, 0);
  change = paid(BOB.ownerPk, bobSelf, 3n * ETH);
  pay(payee, change, [2n, 3n], [change.cm, payee.cm]);
  // Alice handed Bob her third direct secret over Signal: nothing extra on chain.
  payee = paid(ALICE.ownerPk, n.directChannel(ALICE.ownerPk, ALICE.directSecret(3n)), ETH / 5n);
  pay(payee, paid(BOB.ownerPk, bobSelf, 2n * ETH), [4n, 5n]);
  // A withdrawal: the payee note is random and only the change is a leaf.
  change = paid(BOB.ownerPk, bobSelf, ETH);
  chain.add(n.spendNotes(dummy(), change.note), [change.cm], [6n, 7n]);
  // A shield straight to Alice's address, on a second secret.
  const shield = paid(ALICE.ownerPk, n.openChannel(ALICE.address()), 2n * ETH);
  chain.add(n.shieldNotes(shield.note, shield.ciphertext), [shield.cm], [], SHIELD);
  // Carol's first payment to Alice never lands. Sending its ciphertext again in another
  // transaction would link the two, so she opens a new channel.
  const lost = n.openChannel(ALICE.address());
  n.reserve(lost, ETH / 10n);
  raises(() => n.reserve(lost, ETH / 10n), "opening payment is not final yet");
  payee = paid(ALICE.ownerPk, n.openChannel(ALICE.address()), ETH / 10n);
  pay(payee, paid(CAROL.ownerPk, carolSelf, ETH / 3n), [10n, 11n]);
  // Carol pays Bob's address.
  payee = paid(BOB.ownerPk, n.openChannel(BOB.address()), 3n * ETH);
  pay(payee, paid(CAROL.ownerPk, carolSelf, ETH), [8n, 9n]);
  return chain;
}

function recover(keys: n.WalletKeys, events: PoolEvent[], options?: ScannerOptions): Scanner {
  const scanner = new Scanner(keys, CHAIN, POOL, options);
  for (const event of events) scanner.scan(event);
  return scanner;
}

const values = (scanner: Scanner) => [...scanner.notes.values()].map((r) => r.value);
const spentValues = (s: Scanner) =>
  [...s.notes.values()].filter((r) => r.spent).map((r) => r.value);
const sorted = (list: bigint[]) => [...list].sort(compareBigint);
/** A scanner's state as it is written to the state file and read back. */
const reloaded = (scanner: Scanner) =>
  Scanner.fromJson(scanner.keys, parse(stringify(scanner.toJson(), 1)));

test("primitives: a note opens only with its secret and index, and sizes are enforced", () => {
  const secret = RNG.bytes(32);
  const { note, rho } = n.sealNote(secret, 7n, 123n);
  assert.equal(note.length, 48);
  assert.equal(n.openNote(secret, 7n, note), 123n);
  assert.equal(rho, n.noteRho(secret, 7n));
  assert.equal(n.openNote(secret, 8n, note), null);
  assert.equal(n.openNote(RNG.bytes(32), 7n, note), null);
  for (const position of [0, 20, 40, 47]) {
    // The tag, the ciphertext and the authentication tag.
    const tampered = note.slice();
    tampered[position] ^= 1;
    assert.equal(n.openNote(secret, 7n, tampered), null, `byte ${position}`);
  }
  const tags = new Set(Array.from({ length: 1000 }, (_, i) => toHex(n.noteTag(secret, BigInt(i)))));
  assert.equal(tags.size, 1000);
  for (const value of [0n, 1n << 128n]) {
    raises(() => n.sealNote(secret, 0n, value), "positive and fit 128 bits");
  }
  for (let i = 0n; i < 20n; i++) assert.equal(n.openNote(secret, i, dummy()), null);
  // Settlement publishes the payee's note, then the change's.
  const change = n.sealNote(secret, 8n, 456n).note;
  assert.deepEqual(n.spendNotes(note, change), concat(note, change));
  raises(() => n.spendNotes(note, note.subarray(0, 47)), "two 48-byte notes");
  raises(() => n.spendNotes(note, note, new Uint8Array(1000)), "two 48-byte notes");
  raises(() => n.shieldNotes(concat(note, note)), "one 48-byte note");
});

test("keys and addresses: derived from the seed and account, and checked on decode", () => {
  const again = new n.WalletKeys(seedOf("alice"));
  assert.equal(again.address().hex(), ALICE.address().hex());
  assert.equal(again.spendKey, ALICE.spendKey);
  const second = new n.WalletKeys(seedOf("alice"), 1n);
  assert.notEqual(second.address().hex(), ALICE.address().hex());
  assert.notEqual(second.spendKey, ALICE.spendKey);
  assert.equal(n.Address.decode(ALICE.address().hex()).hex(), ALICE.address().hex());
  assert.equal(ALICE.address().encode().length, 1217);
  assert.equal(n.ADDRESS_BYTES, 1217);
  raises(() => new n.WalletKeys(new Uint8Array(31).fill(1)), "at least 32 bytes");
  const good = ALICE.address().encode();
  const refused = (expected: string, ...parts: Uint8Array[]) =>
    raises(() => n.Address.decode(concat(...parts)), expected);
  refused("starting with version 1", Uint8Array.of(2), good.subarray(1));
  refused("starting with version 1", good.subarray(0, -1));
  const [version, rest] = [good.subarray(0, 1), good.subarray(33)];
  refused("nonzero field element", version, new Uint8Array(32), rest);
  refused("nonzero field element", version, fromHex(hex32(P), "P"), rest);
  // ML-KEM's encapsulation key encodes coefficients below 3329; 0xff bytes are not.
  const ff = new Uint8Array(1152).fill(0xff);
  refused("ML-KEM-768 key is invalid", good.subarray(0, 33), ff, good.subarray(-32));
  raises(() => n.Address.decode("0xzz"), "an address is hex");
  for (const data of [null, [...good]]) {
    raises(() => n.Address.decode(data as never), "an address is hex or bytes");
  }
  raises(() => n.directChannel(ALICE.ownerPk, utf8("short")), "32 bytes");
});

test("recovery: each wallet rebuilds its notes, spends and change channel from its seed", () => {
  const chain = story();
  const [alice, bob, carol] = [ALICE, BOB, CAROL].map((keys) => recover(keys, chain.events));
  assert.deepEqual(sorted(values(alice)), [ETH / 10n, ETH / 5n, ETH / 2n, ETH, 2n * ETH]);
  const bobs = [ETH, 2n * ETH, 3n * ETH, 3n * ETH, 4n * ETH - FEE, 5n * ETH];
  assert.deepEqual(sorted(values(bob)), bobs);
  assert.deepEqual(sorted(values(carol)), [ETH / 3n, ETH]);
  // Every leaf has one owner.
  const place = ({ cm, epoch, index }: Leaf) => `${cm},${epoch},${index}`;
  const leaves = chain.events.flatMap((e) => e.leaves.map(place));
  const found = [alice, bob, carol].flatMap((s) => [...s.notes.values()].map(place));
  assert.deepEqual(found.sort(), leaves.sort());
  // Bob's deposit was spent by his first payment; the scanner saw its nullifier, and the state
  // file keeps which notes are spent.
  for (const s of [bob, reloaded(bob)]) assert.deepEqual(spentValues(s), [5n * ETH]);
  assert.equal(bob.unspent().length, 5);
  assert.equal(alice.unspent().length, 5);
  // Any ciphertext decapsulates, to a pseudorandom key if it was meant for another wallet, so a
  // wallet watches only the keys whose tags its notes carry: Alice's three paid channels, Carol's
  // payment to Bob, and none for Carol.
  const kemChannels = (s: Scanner) => s.incoming.filter((i) => i.kind === "kem").length;
  assert.deepEqual([alice, bob, carol].map(kemChannels), [3, 1, 0]);
  // Each note's nullifier is the circuit's, for a later spend.
  for (const s of [alice, bob]) {
    for (const r of s.notes.values()) assert.equal(r.nullifier, nullifierOf(s.keys, r.cm, r.index));
  }
  // A note in a later epoch takes that epoch's domain, and one published twice in an event is
  // found once.
  const late = paid(ALICE.ownerPk, n.directChannel(ALICE.ownerPk, ALICE.directSecret(0n)), ETH);
  const notes = n.spendNotes(late.note, late.note);
  const leaf = { cm: late.cm, epoch: 1n, index: 0n };
  const twice = { block: 1n, tx: 0n, call: 0, notes, leaves: [leaf], spent: [] };
  // A fresh scan cannot begin at epoch 1, since a node that served nothing of epoch 0 would hide
  // its notes. A scanner that has seen epoch 0 full takes the leaf.
  raises(() => new Scanner(ALICE, CHAIN, POOL).scan(twice), "missing pool logs");
  const fullEpoch0 = { ...new Scanner(ALICE, CHAIN, POOL).toJson(), tree: { "0": TREE_CAPACITY } };
  const lateFound = Scanner.fromJson(ALICE, parse(stringify(fullEpoch0))).scan(twice);
  assert.equal(lateFound.length, 1);
  assert.equal(lateFound[0].nullifier, nullifierOf(ALICE, late.cm, 0n, 1n));
  // A direct secret past the gap stays hidden until the wallet looks further.
  const near = recover(ALICE, chain.events, { gap: 3 });
  assert.ok(!values(near).includes(ETH / 5n));
  assert.equal(near.notes.size, alice.notes.size - 1);
  // Scanning in two runs, through the saved state, finds the same notes.
  const resumed = reloaded(recover(ALICE, chain.events.slice(0, 3)));
  for (const event of chain.events.slice(3)) resumed.scan(event);
  assert.deepEqual(resumed.toJson().notes, alice.toJson().notes);
  raises(() => Scanner.fromJson(BOB, alice.toJson()), "another wallet");
  // Each note found raises one secret's next_index by at most LOOKAHEAD, so a larger sum is a
  // corrupt file, whose tags would take without end to derive.
  const corrupt = alice.toJson();
  corrupt.incoming[0].next_index += BigInt(n.LOOKAHEAD * alice.notes.size) + 1n;
  raises(() => Scanner.fromJson(ALICE, parse(stringify(corrupt, 1))), "exceed its notes");
  // A node that drops a transaction's logs is caught by the next leaf's index.
  const [e0, e1] = chain.events;
  raises(() => recover(ALICE, [e0, e1, ...chain.events.slice(3)]), "missing pool logs");
  raises(() => recover(ALICE, [e0, e1, e0]), "chain order");
  // A wallet restored from its seed resumes its change past the indices it used.
  const next = bob.incoming.find((i) => i.kind === "self")!.nextIndex;
  const restored = n.selfChannel(bob);
  const used = new Set<string>();
  for (let i = 0n; i < next; i++) used.add(toHex(n.noteTag(BOB.selfSecret, i)));
  const change = paid(BOB.ownerPk, restored, ETH / 7n);
  assert.equal(restored.nextIndex, next + BigInt(n.RESTORE_SKIP) + 1n);
  assert.ok(!used.has(toHex(change.note.subarray(0, 16))));
  chain.add(n.spendNotes(dummy(), change.note), [change.cm], [20n, 21n]);
  assert.ok(values(recover(BOB, chain.events)).includes(ETH / 7n));
  // A second takeover on the same finalized view resumes at the index `restored` used, so it
  // waits until that change is final (SECURITY.md#note-delivery), and then moves past it.
  assert.equal(n.selfChannel(bob).nextIndex, next + BigInt(n.RESTORE_SKIP));
  const final = n.selfChannel(recover(BOB, chain.events)).nextIndex;
  assert.equal(final, next + 2n * BigInt(n.RESTORE_SKIP) + 1n);
  for (let i = 0; i < n.LOOKAHEAD - n.RESTORE_SKIP - 1; i++) n.reserve(restored, 1n);
  raises(() => n.reserve(restored, 1n), "the recipient watches only");
});

type Call = Pick<PoolEvent, "notes" | "leaves" | "spent">;

/** One call's logs as the pool emits them: settlement's nullifiers, its leaves, then Notes. */
function callLogs(event: Call) {
  const entries: [string[], string][] = event.spent.map((nf) => [[NOTE_SPENT, hex32(nf)], "0x"]);
  for (const { cm, epoch, index } of event.leaves) {
    entries.push([[LEAF_APPENDED, hex32(cm), hex32(epoch)], hex32(index) + "00".repeat(32)]);
  }
  const body = concat(event.notes, new Uint8Array((32 - (event.notes.length % 32)) % 32));
  const length = hex32(BigInt(event.notes.length)).slice(2);
  entries.push([[NOTES], hex32(32n) + length + toHex(body).slice(2)]);
  return entries.map(([topics, data]) => ({ address: hexPadded(POOL, 40), topics, data }));
}

const txOf = (e: PoolEvent) => `${e.block},${e.tx}`;

/** The chain's events as eth_getLogs results, without the transactions of `hidden` events. */
function rpcLogs(chain: Chain, hidden: readonly number[] = []) {
  const leftOut = new Set(hidden.map((i) => txOf(chain.events[i])));
  const counter = new Map<bigint, number>();
  return chain.events.flatMap((event) =>
    callLogs(event).flatMap((log) => {
      const position = counter.get(event.block) ?? 0;
      counter.set(event.block, position + 1);
      if (leftOut.has(txOf(event))) return [];
      const [block, tx] = [hexPadded(event.block, 1), hexPadded(event.tx, 1)];
      const transactionHash = hexPadded(event.block, 32) + hexPadded(event.tx, 32).slice(2);
      const logIndex = hexPadded(BigInt(position), 1);
      return [{ ...log, blockNumber: block, transactionIndex: tx, logIndex, transactionHash }];
    }),
  );
}

type Hiding = { hidden?: number[]; unreceipted?: number[]; reverted?: Call };

/**
 * A local JSON-RPC node. eth_getLogs leaves out the transactions of `hidden` events, as ethrex
 * does for a failed fourth frame; their receipts still show them unless also `unreceipted`, and
 * their failed frames list the logs of `reverted`, whose effects were undone, so a scan must not
 * count them. Every transaction is a frame transaction with its pool logs in frame 2, after a
 * copy of its first LeafAppended log that another contract emits, which a scan must skip.
 * `finalized` is read on every request, so a test can move the finalized head.
 */
async function serve(chain: Chain, finalized: { block: bigint }, hiding: Hiding = {}) {
  const { hidden = [], unreceipted = [], reverted } = hiding;
  const logs = rpcLogs(chain, hidden);
  const failed = new Set(hidden.map((i) => txOf(chain.events[i])));
  const receipted = chain.events.filter((_, i) => !unreceipted.includes(i));
  const receipts = (block: bigint) => {
    const byTx = new Map<bigint, ReturnType<typeof callLogs>>();
    for (const e of receipted.filter((e) => e.block === block)) {
      byTx.set(e.tx, [...(byTx.get(e.tx) ?? []), ...callLogs(e)]);
    }
    return [...byTx].map(([tx, logs]) => {
      const fails = failed.has(`${block},${tx}`);
      const fourth = fails ? [{ status: "0x0", logs: reverted ? callLogs(reverted) : [] }] : [];
      const leaf = logs.find((log) => log.topics[0] === LEAF_APPENDED);
      const foreign = { ...leaf!, address: "0x" + "22".repeat(20) };
      const frameReceipts = [
        { status: "0x1", logs: [] },
        { status: "0x1", logs: [foreign, ...logs] },
        ...fourth,
      ];
      const status = fails ? "0x0" : "0x1";
      return { transactionIndex: hexPadded(tx, 1), status, logs: [], frameReceipts };
    });
  };
  const ranges: [bigint, bigint][] = []; // the block range of each eth_getLogs call
  // Blocks whose receipts were asked for past the finalized head; the scan must ask none.
  const unfinalized: bigint[] = [];
  const node = await rpcServer(({ method, params }) => {
    let result: unknown = null;
    if (method === "eth_chainId") result = hexPadded(CHAIN, 1);
    else if (method === "eth_getBlockByNumber") result = { number: hexPadded(finalized.block, 1) };
    else if (method === "eth_getLogs") {
      const [lo, hi] = [BigInt(params[0].fromBlock), BigInt(params[0].toBlock)];
      ranges.push([lo, hi]);
      result = logs.filter((l) => lo <= BigInt(l.blockNumber) && BigInt(l.blockNumber) <= hi);
    } else if (method === "eth_getBlockReceipts") {
      const block = BigInt(params[0]);
      if (block > finalized.block) unfinalized.push(block);
      result = receipts(block);
    }
    return { result };
  });
  return { ...node, ranges, unfinalized };
}

/** The test pool's config, written to dir/config.json, with `fields` in place of its own. */
function writeConfig(dir: string, url: string, fields: Record<string, unknown> = {}): string {
  const config = join(dir, "config.json");
  const pool = hexPadded(POOL, 40);
  const data = { chainId: Number(CHAIN), pool, deploymentBlock: 0, profile: POOL_PROFILE };
  writeFileSync(config, JSON.stringify({ ...data, rpc: url, ...fields }));
  return config;
}

/**
 * What `node src/cli/notes.ts ...argv` prints, run from a directory of its own as a user would.
 * With `refusal`, it must instead exit 1, print nothing, and give that reason on stderr.
 */
async function cli(argv: string[], refusal?: string): Promise<string> {
  const { code, stdout, stderr } = await runCli(process.execPath, [CLI, ...argv], { cwd: TMP });
  assert.equal(code, refusal === undefined ? 0 : 1, `notes ${argv[0]}: ${stderr}`);
  if (refusal === undefined) return stdout;
  assert.equal(stdout, "");
  assert.ok(stderr.startsWith("notes: "), stderr);
  assert.ok(stderr.includes(refusal), `"${refusal}" not in "${stderr}"`);
  return stdout;
}

const record = (text: string) => parse(text) as Record<string, unknown>;

test("log decoding: every wallet reads a transaction's calls apart; bad logs are refused", () => {
  // A batching contract shields twice in one transaction, and a settlement's fourth frame
  // shields.
  const chain = story();
  let shield = paid(ALICE.ownerPk, n.openChannel(ALICE.address()), 7n * ETH);
  chain.add(n.shieldNotes(shield.note, shield.ciphertext), [shield.cm], [], SHIELD);
  shield = paid(BOB.ownerPk, n.directChannel(BOB.ownerPk, BOB.directSecret(0n)), 6n * ETH);
  chain.add(n.shieldNotes(shield.note), [shield.cm], [], { ...SHIELD, sameTx: true });
  const carolBefore = recover(CAROL, chain.events);
  const paying = [...carolBefore.notes.values()].find((r) => r.value === ETH && !r.spent)!;
  const toAlice = n.directChannel(ALICE.ownerPk, ALICE.directSecret(0n));
  const payee = paid(ALICE.ownerPk, toAlice, ETH / 4n);
  const change = paid(CAROL.ownerPk, n.selfChannel(carolBefore), ETH / 2n);
  chain.add(n.spendNotes(payee.note, change.note), [payee.cm, change.cm], [paying.nullifier, 12n]);
  shield = paid(ALICE.ownerPk, toAlice, ETH / 8n);
  chain.add(n.shieldNotes(shield.note), [shield.cm], [], { ...SHIELD, sameTx: true });
  // eth_getLogs results become the same events.
  const logs = rpcLogs(chain);
  const events = eventsFromLogs(logs);
  assert.deepEqual(events, chain.events);
  const [alice, bob, carol] = [ALICE, BOB, CAROL].map((keys) => recover(keys, events));
  for (const value of [7n * ETH, ETH / 4n, ETH / 8n]) assert.ok(values(alice).includes(value));
  assert.ok(values(bob).includes(6n * ETH));
  assert.deepEqual(sorted(values(carol)), [ETH / 3n, ETH / 2n, ETH]);
  assert.deepEqual(spentValues(carol), [ETH]);
  // A call missing its Notes log, or one of its nullifiers, means the node left logs out.
  const lastNotes = logs.findLast((l) => l.topics[0] === NOTES);
  raises(() => eventsFromLogs(logs.filter((l) => l !== lastNotes)), "has no Notes log");
  const firstSpent = logs.find((l) => l.topics[0] === NOTE_SPENT);
  raises(() => eventsFromLogs(logs.filter((l) => l !== firstSpent)), "missing pool logs");
  const firstLeaf = logs.find((l) => l.topics[0] === LEAF_APPENDED);
  raises(() => eventsFromLogs(logs.filter((l) => l !== firstLeaf)), "missing pool logs");
  // Notes data with another offset, or a length no call emits, is malformed.
  const word = (value: bigint) => hex32(value).slice(2);
  const offset64 = word(64n) + word(48n) + "00".repeat(48);
  for (const data of [offset64, word(32n) + word(97n) + "00".repeat(97)]) {
    raises(() => decodeNotesData("0x" + data), "malformed Notes log");
  }
});

/** What fn returns, and how many HMACs it computed; src/notes.ts derives each tag with one. */
function countingHmacs<T>(fn: () => T): [T, number] {
  const { createHmac } = nodeCrypto;
  let count = 0;
  nodeCrypto.createHmac = (...args: Parameters<typeof createHmac>) => {
    count++;
    return createHmac(...args);
  };
  syncBuiltinESMExports();
  try {
    return [fn(), count];
  } finally {
    nodeCrypto.createHmac = createHmac;
    syncBuiltinESMExports();
  }
}

test("a payment at the far edge of a channel's window derives only the tags it newly covers", () => {
  // Each payment at the edge moves the window LOOKAHEAD indices on, and the scanner derives only
  // the tags a move adds, so a scan takes between LOOKAHEAD and 2 LOOKAHEAD HMACs per payment.
  // Deriving the whole window again on every move would take about LOOKAHEAD * K^2 / 2. The last
  // payment sits at the first index the last move added, which an off-by-one would miss.
  const [L, K] = [n.LOOKAHEAD, 100];
  const secret = ALICE.directSecret(5n);
  const chain = new Chain();
  const pay = (index: bigint) => {
    const { note, rho } = n.sealNote(secret, index, ETH);
    chain.add(n.shieldNotes(note), [n.outputCommitment(ALICE.ownerPk, rho, ETH)], [], SHIELD);
  };
  for (let j = 1; j <= K; j++) pay(BigInt(j * L - 1));
  pay(BigInt(K * L));
  const [scanner, hmacs] = countingHmacs(() => recover(ALICE, chain.events));
  assert.equal(scanner.notes.size, K + 1);
  assert.ok(hmacs > L * K && hmacs < 2 * L * (K + 1), `${hmacs} HMACs`);
});

test("a ciphertext that lands twice opens one channel", () => {
  // A shield retried with the same bytes can land twice, since a shield spends no nullifier.
  const chain = new Chain();
  const shield = paid(ALICE.ownerPk, n.openChannel(ALICE.address()), ETH);
  for (let i = 0; i < 2; i++) {
    chain.add(n.shieldNotes(shield.note, shield.ciphertext), [shield.cm], [], SHIELD);
  }
  const scanner = recover(ALICE, chain.events);
  assert.equal(scanner.incoming.filter((i) => i.kind === "kem").length, 1);
  assert.equal(scanner.notes.size, 2);
});

test("channels: one ciphertext per transaction, a bounded window, and late payments found", () => {
  const L = n.LOOKAHEAD;
  // A channel's ciphertext goes into one transaction.
  let channel = n.openChannel(ALICE.address());
  const pay = (i: number) => paid(ALICE.ownerPk, channel, ETH + BigInt(i));
  const opening = n.reserve(channel, ETH);
  assert.equal(opening.index, 0n);
  assert.equal(opening.ciphertext.length, 1088);
  assert.equal(channel.ciphertextSent, true);
  raises(() => n.reserve(channel, ETH), "opening payment is not final yet");
  const saved = parse(stringify(n.outgoingToJson(channel), 1));
  assert.deepEqual(n.outgoingFromJson(saved), channel);
  raises(() => n.finalized(channel, 1n), "never reserved");
  n.finalized(channel, 0n);
  assert.equal(n.reserve(channel, ETH).ciphertext.length, 0);
  assert.equal(channel.confirmed, 1n);
  // A sender keeps fewer than LOOKAHEAD payments past its last final one.
  channel = n.directChannel(ALICE.ownerPk, ALICE.directSecret(1n));
  let notes = Array.from({ length: L }, (_, i) => pay(i));
  raises(() => n.reserve(channel, ETH), "the recipient watches only");
  n.finalized(channel, 0n);
  n.reserve(channel, ETH);
  // Indices 19, 0 and 5 land in that order; a fresh scan finds all three, and so does a scan
  // that saves and reloads its state between them.
  let chain = new Chain();
  for (const i of [19, 0, 5]) chain.add(n.shieldNotes(notes[i].note), [notes[i].cm], [], SHIELD);
  const landed = sorted([ETH + 19n, ETH, ETH + 5n]);
  assert.deepEqual(sorted(values(recover(ALICE, chain.events))), landed);
  let scanner = recover(ALICE, chain.events.slice(0, 1));
  for (const event of chain.events.slice(1)) {
    scanner = reloaded(scanner);
    scanner.scan(event);
  }
  assert.deepEqual(sorted(values(scanner)), landed);
  // A later final payment lets the sender run ahead of an older pending one; the older one
  // still lands and is found after a reload.
  channel = n.directChannel(ALICE.ownerPk, ALICE.directSecret(2n));
  notes = Array.from({ length: L }, (_, i) => pay(i));
  n.finalized(channel, BigInt(L - 1));
  notes.push(...Array.from({ length: L }, (_, i) => pay(L + i)));
  chain = new Chain();
  for (const i of [L - 1, 2 * L - 1, 0])
    chain.add(n.shieldNotes(notes[i].note), [notes[i].cm], [], SHIELD);
  scanner = reloaded(recover(ALICE, chain.events.slice(0, 2)));
  scanner.scan(chain.events[2]);
  assert.ok(values(scanner).includes(ETH));
  // Direct numbers are issued only within GAP of the highest paid one, so a fresh scan
  // watches each before its payment lands, in whatever order they pay.
  scanner = new Scanner(ALICE, CHAIN, POOL);
  const issue = () => Array.from({ length: n.GAP }, () => scanner.issueDirect());
  const firstNumbers = Array.from({ length: n.GAP }, (_, i) => BigInt(i));
  assert.deepEqual(issue(), firstNumbers);
  raises(() => scanner.issueDirect(), "waiting for a first payment");
  chain = new Chain();
  for (const [i, number] of [19n, 39n, 25n, 3n].entries()) {
    if (number === 39n) assert.equal(issue().at(-1), 39n);
    const direct = n.directChannel(ALICE.ownerPk, ALICE.directSecret(number));
    const { note, cm } = paid(ALICE.ownerPk, direct, BigInt(i + 1) * ETH);
    chain.add(n.shieldNotes(note), [cm], [], SHIELD);
    scanner.scan(chain.events.at(-1)!);
  }
  const recovered = sorted(values(recover(ALICE, chain.events)));
  assert.deepEqual(recovered, [ETH, 2n * ETH, 3n * ETH, 4n * ETH]);
});

test("hidden calls: calls left out of eth_getLogs are rebuilt from receipts or caught", async (t) => {
  // ethrex leaves out of eth_getLogs every log of a transaction whose fourth frame failed,
  // settlement included. Once a later leaf shows the gap, the scan rebuilds those calls from
  // receipts, in the same run or a later one and whichever node the later one uses; a call
  // missing from the receipts too still stops it. The scan never asks the node about single
  // nullifiers, and a failed frame counts for nothing, even with logs listed under it: here a
  // spend of Alice's first note that reverted.
  const chain = story();
  const [first] = chain.events[1].leaves;
  const revertedSpend = {
    notes: n.spendNotes(dummy(), dummy()),
    leaves: [],
    spent: [nullifierOf(ALICE, first.cm, first.index), 14n],
  };
  // Alice spends her direct payment in full: a settlement with no leaf. Left out of the logs,
  // it leaves no gap, so her note still shows as unspent.
  const [direct] = chain.events[3].leaves;
  chain.add(n.spendNotes(dummy(), dummy()), [], [nullifierOf(ALICE, direct.cm, direct.index), 13n]);
  const bobShield = paid(BOB.ownerPk, n.directChannel(BOB.ownerPk, BOB.selfSecret), ETH);
  chain.add(n.shieldNotes(bobShield.note), [bobShield.cm], [], SHIELD);
  const aliceNotes = new Map([ETH, ETH / 2n, ETH / 5n, 2n * ETH, ETH / 10n].map((v) => [v, false]));

  const shields = (sameBlock: number | null) => {
    const built = new Chain();
    const toAlice = n.directChannel(ALICE.ownerPk, ALICE.directSecret(0n));
    for (let i = 0; i < 5; i++) {
      const { note, cm } = paid(ALICE.ownerPk, toAlice, ETH + BigInt(i));
      const options = { ...SHIELD, sameBlock: i === sameBlock, skip: i === 3 ? 5n : 0n };
      built.add(n.shieldNotes(note), [cm], [], options);
    }
    return built;
  };
  const fives = new Map(Array.from({ length: 5 }, (_, i) => [ETH + BigInt(i), false]));
  // Each case scans to the chain's head. With `early` it first scans to three blocks past
  // event 2, and with `honest` the node of that last scan hides nothing.
  const cases = [
    { chain, hidden: [2, chain.events.length - 2], outcome: aliceNotes },
    { chain, hidden: [2], unreceipted: [2], outcome: "missing pool logs" },
    // The second sweep reaches back into the block of a call the first rebuilt.
    { chain: shields(2), hidden: [1, 3], outcome: fives },
    // A hidden call in the block of the event that shows the gap, after it.
    { chain: shields(3), hidden: [1, 3], outcome: fives },
    // The hidden call is the newest leaf when the first scan runs, which ends blocks after
    // it; a later leaf shows the gap in the next scan, through the same node or an honest one.
    { chain: shields(null), hidden: [2], early: true, outcome: fives },
    { chain: shields(null), hidden: [2], early: true, honest: true, outcome: fives },
  ];
  const dir = mkdtempSync(join(TMP, "hidden-"));
  for (const [number, c] of cases.entries()) {
    await t.test(`case ${number}`, async () => {
      const state = join(dir, `state-${number}.json`);
      const scan = async (block: bigint, hide: boolean) => {
        const hiding = { ...c, hidden: hide ? c.hidden : [], reverted: revertedSpend };
        const node = await serve(c.chain, { block }, hiding);
        try {
          const config = writeConfig(dir, node.url);
          const args = ["scan", "--config", config, "--state", state, "--seed-file", SEED];
          await cli(args, typeof c.outcome === "string" ? c.outcome : undefined);
          const asked = node.requests.some((call) => call.method === "eth_getStorageAt");
          assert.ok(!asked, "asked about a nullifier");
          assert.deepEqual(node.unfinalized, [], "read receipts past the finalized head");
        } finally {
          await node.close();
        }
      };
      if (c.early) await scan(c.chain.events[2].block + 3n, true);
      await scan(c.chain.events.at(-1)!.block, !c.honest);
      if (typeof c.outcome !== "string") {
        const saved = record(readFileSync(state, "utf8")).notes as Record<string, unknown>[];
        const spentByValue = new Map(saved.map((r) => [BigInt(r.value as bigint), r.spent]));
        assert.deepEqual(spentByValue, c.outcome);
      }
    });
  }
});

test("epoch rollover: a leaf that skips a whole epoch stops the scan", () => {
  // Epoch 0 closed full, and the next leaf the node shows is in epoch 2: all of epoch 1 is
  // missing from its logs.
  const chain = new Chain();
  chain.size = TREE_CAPACITY;
  const deposit = paid(BOB.ownerPk, n.directChannel(BOB.ownerPk, BOB.selfSecret), ETH);
  chain.add(n.shieldNotes(deposit.note), [deposit.cm], [], SHIELD);
  const event = chain.events.at(-1)!;
  const skipped = { ...event, leaves: event.leaves.map((leaf) => ({ ...leaf, epoch: 2n })) };
  const state = { ...new Scanner(ALICE, CHAIN, POOL).toJson(), tree: { "0": TREE_CAPACITY } };
  const scanner = Scanner.fromJson(ALICE, { ...state, scanned_block: 100n, leaf_block: 100n });
  raises(() => scanner.scan(skipped), "missing pool logs");
});

test("epoch rollover: a call left out at an epoch's end is rebuilt from receipts or caught", async (t) => {
  // The pool begins a new epoch only when a call's leaves do not fit, so an epoch closes full, or
  // one leaf short before a two-leaf settlement. Each case resumes a scan that saw `start` leaves
  // of epoch 0 through block 100, then the chain runs the steps in `run`, one block each. The scan
  // reads `receipts` from block 100 when a leaf skips some or begins an epoch after one not seen
  // full, and finds `found` notes of Alice's or gives `refusal`.
  const full = TREE_CAPACITY;
  const through102 = [100n, 101n, 102n];
  const steps = {
    // Bob pays Alice, with his change or none, or shields to himself.
    pay: (chain: Chain, toAlice: n.Outgoing) => {
      const payee = paid(ALICE.ownerPk, toAlice, ETH);
      chain.add(n.spendNotes(payee.note, dummy()), [payee.cm], [1n, 2n]);
    },
    payWithChange: (chain: Chain, toAlice: n.Outgoing) => {
      const payee = paid(ALICE.ownerPk, toAlice, ETH);
      const change = paid(BOB.ownerPk, n.directChannel(BOB.ownerPk, BOB.selfSecret), ETH);
      chain.add(n.spendNotes(payee.note, change.note), [payee.cm, change.cm], [3n, 4n]);
    },
    shield: (chain: Chain) => {
      const deposit = paid(BOB.ownerPk, n.directChannel(BOB.ownerPk, BOB.selfSecret), ETH);
      chain.add(n.shieldNotes(deposit.note), [deposit.cm], [], SHIELD);
    },
  };
  const cases = [
    // Alice's payment takes epoch 0's last leaf and is left out of the logs, and Bob's shield
    // begins epoch 1.
    { start: full - 1n, run: ["pay", "shield"], hidden: [0], receipts: through102, found: 1 },
    // Left out of the receipts too: Bob's shield fitted in epoch 0, so the scan stops.
    {
      start: full - 1n,
      run: ["pay", "shield"],
      hidden: [0],
      unreceipted: [0],
      receipts: through102,
      refusal: "which had room for its call",
    },
    // A two-leaf settlement begins epoch 1 after it, which the logs show as in the next case.
    {
      start: full - 1n,
      run: ["pay", "payWithChange"],
      hidden: [0],
      receipts: through102,
      found: 2,
    },
    // Nothing is left out: epoch 0 closes one leaf short, and its receipts add nothing.
    { start: full - 1n, run: ["payWithChange"], receipts: [100n, 101n], found: 1 },
    // Nothing is left out: epoch 0 closes full, and no receipt is read.
    { start: full - 1n, run: ["shield", "pay"], receipts: [], found: 1 },
    // Within one epoch, the next leaf shows the gap as before.
    { start: full - 3n, run: ["pay", "shield"], hidden: [0], receipts: through102, found: 1 },
  ];
  for (const [number, c] of cases.entries()) {
    await t.test(`case ${number}`, async () => {
      const chain = new Chain();
      chain.size = c.start;
      const toAlice = n.directChannel(ALICE.ownerPk, ALICE.directSecret(0n));
      for (const step of c.run) steps[step as keyof typeof steps](chain, toAlice);
      const state = { ...new Scanner(ALICE, CHAIN, POOL).toJson(), tree: { "0": c.start } };
      const scanner = Scanner.fromJson(ALICE, { ...state, scanned_block: 100n, leaf_block: 100n });
      const node = await serve(chain, { block: chain.block }, c);
      try {
        const scan = scanToFinalized(scanner, new RpcChain(node.url), 0n);
        if (c.refusal !== undefined) {
          await assert.rejects(scan, (error: unknown) => {
            assert.ok(error instanceof NotesError && error.message.includes(c.refusal), `${error}`);
            assert.ok(error.message.includes("missing pool logs"), error.message);
            return true;
          });
        } else {
          await scan;
          assert.equal(scanner.notes.size, c.found);
        }
        const read = node.requests.filter((call) => call.method === "eth_getBlockReceipts");
        const blocks = read.map((call) => BigInt(call.params[0]));
        assert.deepEqual(blocks, c.receipts);
      } finally {
        await node.close();
      }
    });
  }
});

/** The value as it is written to a file and read back. */
const json = (value: unknown) => record(stringify(value, 1));
/** What loading a state that must be rescanned changes in it. */
const RESCAN = { version: 3, tree: { "0": 0 }, scanned_block: -1, leaf_block: -1 };

test("state upgrade: only an earlier version's state with an epoch closed short is rescanned", () => {
  // Before state version 3, a scan let a new epoch begin after one not seen full without reading
  // receipts. Each state was saved through block 300; `short` is part of the reason a rescan
  // gives, and null where the state loads as it was saved.
  const full = TREE_CAPACITY;
  const cases = [
    { version: 2, tree: { "0": 5n }, short: null },
    { version: 2, tree: { "0": full, "1": full, "2": 3n }, short: null },
    { version: 2, tree: { "0": full - 1n, "1": 2n }, short: "epoch 0 closed with 1048575 of" },
    { version: 2, tree: { "0": full, "1": full - 3n, "2": 1n }, short: "epoch 1 closed with" },
    { version: 2, tree: { "0": full, "2": 1n }, short: "epoch 1 closed with 0 of 1048576" },
    // A scan of version 3 began epoch 1 only after reading receipts.
    { version: 3, tree: { "0": full - 1n, "1": 2n }, short: null },
  ];
  const fresh = new Scanner(ALICE, CHAIN, POOL).toJson();
  for (const { short, ...fields } of cases) {
    const blocks = { scanned_block: 300n, leaf_block: 290n };
    const state = json({ ...fresh, ...fields, ...blocks, direct_issued: 6n });
    const scanner = Scanner.fromJson(ALICE, state);
    const saved = json(scanner.toJson());
    if (short === null) {
      assert.equal(scanner.rescanReason, null, stringify(fields.tree));
      assert.deepEqual(saved, { ...state, version: 3 });
    } else {
      assert.ok(scanner.rescanReason?.includes(short), `${scanner.rescanReason}`);
      assert.deepEqual(saved, { ...state, ...RESCAN });
    }
  }
  raises(() => Scanner.fromJson(ALICE, { ...fresh, version: 1 }), "another wallet");
});

test("state upgrade: a rescan finds the payment an earlier version missed and keeps its numbers", async () => {
  // Alice's wallet scanned this chain with an earlier version and a node that left her payment
  // in epoch 0's last leaf out of its logs. It found her change at leaf 7, missed the payment,
  // and saw epoch 0 close one leaf short when Bob's shield began epoch 1. She had handed out
  // direct numbers 0 to 4, and the payment is on number 0.
  const chain = new Chain();
  chain.size = TREE_CAPACITY - 1n;
  const toAlice = n.directChannel(ALICE.ownerPk, ALICE.directSecret(0n));
  const payment = paid(ALICE.ownerPk, toAlice, ETH);
  chain.add(n.spendNotes(payment.note, dummy()), [payment.cm], [1n, 2n]);
  const deposit = paid(BOB.ownerPk, n.directChannel(BOB.ownerPk, BOB.selfSecret), ETH);
  chain.add(n.shieldNotes(deposit.note), [deposit.cm], [], SHIELD);
  const rollover = chain.events[1].block;
  // Epoch 0's other leaves are shields in block 100, too many to serve over RPC, so each scan
  // reads them here, as scanToFinalized would from the deployment block.
  const change = paid(ALICE.ownerPk, n.directChannel(ALICE.ownerPk, ALICE.selfSecret), 3n * ETH);
  const others = n.shieldNotes(dummy());
  const readEpoch0 = (scanner: Scanner) => {
    for (let index = 0n; index < TREE_CAPACITY - 1n; index++) {
      const [notes, cm] = index === 7n ? [n.shieldNotes(change.note), change.cm] : [others, 1n];
      const leaves = [{ cm, epoch: 0n, index }];
      scanner.scan({ block: 100n, tx: 0n, call: Number(index), notes, leaves, spent: [] });
    }
  };
  const earlier = new Scanner(ALICE, CHAIN, POOL);
  readEpoch0(earlier);
  for (let i = 0; i < 5; i++) earlier.issueDirect();
  const tree = { "0": TREE_CAPACITY - 1n, "1": 1n };
  const checkpoint = { scanned_block: rollover, leaf_block: rollover };
  const saved = json({ ...earlier.toJson(), version: 2, tree, ...checkpoint });
  // Loading it keeps everything but the scan's place, which goes back to the deployment block.
  const scanner = Scanner.fromJson(ALICE, saved);
  assert.ok(scanner.rescanReason?.includes("epoch 0 closed with 1048575 of 1048576 leaves"));
  assert.deepEqual(json(scanner.toJson()), { ...saved, ...RESCAN });
  readEpoch0(scanner);
  const node = await serve(chain, { block: rollover }, { hidden: [0] });
  try {
    await scanToFinalized(scanner, new RpcChain(node.url), 0n);
    const read = node.requests.filter((call) => call.method === "eth_getBlockReceipts");
    const blocks = read.map((call) => BigInt(call.params[0]));
    assert.deepEqual(blocks, [100n, 101n, 102n]);
  } finally {
    await node.close();
  }
  // The payment is found and the change is not counted twice; no issued number comes back.
  assert.deepEqual(sorted(values(scanner)), [ETH, 3n * ETH]);
  assert.equal(scanner.directHighest, 0n);
  assert.equal(scanner.issueDirect(), 5n);
});

test("a finalized head behind the state's last scan is refused, not taken as nothing new", async () => {
  // A node reported a head far past the chain's. Every later payment would sit below the saved
  // checkpoint, so an honest node's scan must stop rather than find nothing.
  const chain = story();
  const finalized = { block: 10n ** 12n };
  const node = await serve(chain, finalized);
  try {
    const scanner = new Scanner(ALICE, CHAIN, POOL);
    await scanToFinalized(scanner, new RpcChain(node.url), 0n, Number.MAX_SAFE_INTEGER);
    assert.equal(scanner.scannedBlock, 10n ** 12n);
    finalized.block = 10n ** 12n - 1n;
    await assert.rejects(scanToFinalized(scanner, new RpcChain(node.url), 0n), /is behind block/);
    finalized.block = chain.events.at(-1)!.block;
    await assert.rejects(scanToFinalized(scanner, new RpcChain(node.url), 0n), /is behind block/);
  } finally {
    await node.close();
  }
});

test("each eth_getLogs or eth_getBlockReceipts reply is applied before the next is read", async () => {
  // Replies under rpc()'s cap, kept until the last one arrives, would fill the heap and abort
  // the process before any of them is checked, so a malformed first reply stops the scan.
  const chain = new Chain();
  chain.size = 5n; // a shield at leaf 5 shows leaves 0 to 4 left out, so scan reads receipts
  const deposit = paid(BOB.ownerPk, n.directChannel(BOB.ownerPk, BOB.selfSecret), ETH);
  chain.add(n.shieldNotes(deposit.note), [deposit.cm], [], SHIELD);
  const notesLog = { address: hexPadded(POOL, 40), topics: [NOTES], data: "0x" };
  const receipts = [{ transactionIndex: "0x0", status: "0x1", logs: [notesLog] }];
  const cases = [
    ["eth_getLogs", [[{}]], /a log must be a JSON object/],
    ["eth_getBlockReceipts", rpcLogs(chain), /malformed Notes log/],
  ] as const;
  for (const [method, logs, refusal] of cases) {
    const node = await rpcServer((call) => ({
      result: {
        eth_chainId: hexPadded(CHAIN, 1),
        eth_getLogs: logs,
        eth_getBlockReceipts: receipts,
      }[call.method] ?? { number: "0xc8" },
    }));
    try {
      const scanner = new Scanner(ALICE, CHAIN, POOL);
      await assert.rejects(scanToFinalized(scanner, new RpcChain(node.url), 0n, 10), refusal);
      assert.equal(node.requests.filter((r) => r.method === method).length, 1);
    } finally {
      await node.close();
    }
  }
});

test("state upgrade: a rescan through a node that serves nothing of epoch 0 stops", async () => {
  // The earlier version missed Alice's payment in epoch 0's last leaf. This node serves nothing
  // of epoch 0 but that payment's receipt, so the rescan's first leaf in logs is epoch 1's first.
  // Accepting it would save the state as rescanned without the payment.
  const chain = new Chain();
  chain.size = TREE_CAPACITY - 1n;
  const toAlice = n.directChannel(ALICE.ownerPk, ALICE.directSecret(0n));
  const payment = paid(ALICE.ownerPk, toAlice, ETH);
  chain.add(n.spendNotes(payment.note, dummy()), [payment.cm], [1n, 2n]);
  const deposit = paid(BOB.ownerPk, n.directChannel(BOB.ownerPk, BOB.selfSecret), ETH);
  chain.add(n.shieldNotes(deposit.note), [deposit.cm], [], SHIELD);
  const rollover = chain.events[1].block;
  const tree = { "0": TREE_CAPACITY - 1n, "1": 1n };
  const checkpoint = { scanned_block: rollover, leaf_block: rollover };
  const old = { ...new Scanner(ALICE, CHAIN, POOL).toJson(), version: 2, tree, ...checkpoint };
  const node = await serve(chain, { block: rollover }, { hidden: [0] });
  try {
    const scanner = Scanner.fromJson(ALICE, json(old));
    await assert.rejects(scanToFinalized(scanner, new RpcChain(node.url), 0n), /missing pool logs/);
  } finally {
    await node.close();
  }
});

test("CLI: scan and direct-secret keep owner-only state and hand out each number once", async () => {
  const chain = story();
  const finalized = { block: chain.events[3].block };
  const node = await serve(chain, finalized);
  const dir = mkdtempSync(join(TMP, "cli-"));
  try {
    const seedFile = ["--seed-file", SEED];
    // A seed file other local users can read, as a group or as anyone, is refused.
    for (const mode of [0o644, 0o640]) {
      chmodSync(SEED, mode);
      await cli(["address", ...seedFile], "readable by other users");
    }
    chmodSync(SEED, 0o600);
    assert.equal((await cli(["address", ...seedFile])).trim(), ALICE.address().hex());
    const secondAccount = new n.WalletKeys(seedOf("alice"), 1n).address().hex();
    assert.equal((await cli(["address", "--account", "1", ...seedFile])).trim(), secondAccount);
    await cli(["address", "--account", String(1n << 256n), ...seedFile], "below 2^256");

    const state = join(dir, "state.json");
    const v2 = writeConfig(dir, node.url, { profile: "position-notes-v2" });
    await cli(["scan", "--config", v2, "--state", state, ...seedFile], "publishes notes");
    // An RPC on another chain than the config's is refused.
    const chain1 = writeConfig(dir, node.url, { chainId: 1 });
    await cli(["scan", "--config", chain1, "--state", state, ...seedFile], "not on chain 1");
    // A key pasted into a path does not come back in the refusal.
    const pasted = join(dir, "ab".repeat(32));
    writeFileSync(pasted, "not JSON");
    await cli(["scan", "--config", pasted, "--state", state, ...seedFile], "<redacted>");
    const config = writeConfig(dir, node.url);
    const scan = ["scan", "--config", config, "--state", state, ...seedFile];
    const direct = ["direct-secret", "--config", config, "--state", state, ...seedFile];
    await cli(direct, "scan first");
    const first = record(await cli(scan));
    assert.equal(statSync(state).mode & 0o777, 0o600);
    // A state file other local users can read is refused, as a seed file is.
    chmodSync(state, 0o644);
    await cli(direct, "readable by other users");
    chmodSync(state, 0o600);
    assert.equal(BigInt(first.scanned_block as number), finalized.block);
    assert.equal(first.unspent, 3);
    // Alice's number 3 is paid, so the next number she hands out is 4.
    const issued = record(await cli(direct));
    assert.equal(issued.number, 4);
    assert.deepEqual(fromHex(issued.secret, "secret"), ALICE.directSecret(4n));
    assert.deepEqual(record(await cli([...direct, "--number", "4"])), issued);
    await cli([...direct, "--number", "5"], "already handed out");
    // A run waits while another holds the state's lock, and goes on once it is released.
    const lock = `${state}.lock.d`;
    mkdirSync(lock);
    const before = readFileSync(state, "utf8");
    const waiting = directSecretCommand({ keys: ALICE, config, state });
    await sleep(300);
    assert.equal(readFileSync(state, "utf8"), before);
    rmdirSync(lock);
    assert.equal(record(await waiting).number, 5);
    // A run saves nothing if the state file changed after it loaded it, as when another run
    // wrote it after the lock was removed. A scan has loaded the state when its call returns.
    const scanning = scanCommand({ keys: ALICE, config, state });
    const changed = readFileSync(state, "utf8") + "\n";
    writeFileSync(state, changed);
    await assert.rejects(scanning, /changed during this run/);
    assert.equal(readFileSync(state, "utf8"), changed);
    // Only finalized events count; the next run picks up where this one stopped.
    finalized.block = chain.events.at(-1)!.block;
    const second = record(await cli(scan));
    assert.equal(second.unspent, 5);
    const balance = ETH + ETH / 2n + ETH / 5n + 2n * ETH + ETH / 10n;
    assert.equal(BigInt(second.balance as string), balance);
    assert.deepEqual(record(await cli(scan)), second);
    // A run that finds no new event still records the finalized head it read to.
    finalized.block += 2n;
    const third = record(await cli(scan));
    assert.deepEqual(third, { ...second, scanned_block: Number(finalized.block) });
    // Read five blocks per eth_getLogs call, a fresh scan covers each block from the
    // deployment to the head once and finds the same notes.
    node.ranges.length = 0;
    const chunked = ["scan", "--config", config, "--state", join(dir, "chunked.json")];
    assert.deepEqual(record(await cli([...chunked, "--chunk", "5", ...seedFile])), third);
    const head = finalized.block;
    const tiles: [bigint, bigint][] = [];
    for (let from = 0n; from <= head; from += 5n)
      tiles.push([from, from + 4n < head ? from + 4n : head]);
    assert.deepEqual(node.ranges, tiles);
    // A config naming another pool than the state file's is refused.
    const pool2 = writeConfig(dir, node.url, { pool: hexPadded(POOL + 1n, 40) });
    await cli(["scan", "--config", pool2, "--state", state, ...seedFile], "another chain or pool");
  } finally {
    await node.close();
  }
});

test("CLI: a state named through a symbolic link is locked and saved as the file it names", async () => {
  // A save renames a new file over the path it is given. Through the link itself, the first save
  // would replace the link with a file, and the file it named would hand out the same numbers.
  const chain = story();
  const node = await serve(chain, { block: chain.block });
  const dir = mkdtempSync(join(TMP, "link-"));
  try {
    const [state, link] = [join(dir, "state.json"), join(dir, "link.json")];
    const config = writeConfig(dir, node.url);
    const args = (path: string) => ["--config", config, "--state", path, "--seed-file", SEED];
    await cli(["scan", ...args(state)]);
    symlinkSync(state, link);
    assert.equal(record(await cli(["direct-secret", ...args(link)])).number, 4);
    assert.ok(lstatSync(link).isSymbolicLink());
    assert.equal(record(await cli(["direct-secret", ...args(state)])).number, 5);
    // A run through the link waits for the lock that a run through the file holds.
    mkdirSync(`${state}.lock.d`);
    const before = readFileSync(state, "utf8");
    const waiting = directSecretCommand({ keys: ALICE, config, state: link });
    await sleep(300);
    assert.equal(readFileSync(state, "utf8"), before);
    rmdirSync(`${state}.lock.d`);
    assert.equal(record(await waiting).number, 6);
  } finally {
    await node.close();
  }
});

test("CLI: a node's oversized reply is refused before parsing, and the state lock is released", async () => {
  // About 18 MiB of tiny values. Parsed with exact integers, 200 MiB of them aborts V8, which
  // skips the exit handler that removes the lock.
  const huge = new Array(9 * 2 ** 20).fill(0);
  const node = await rpcServer(({ method }) => ({
    result: { eth_chainId: hexPadded(CHAIN, 1), eth_getLogs: huge }[method] ?? { number: "0x10" },
  }));
  const dir = mkdtempSync(join(TMP, "huge-"));
  try {
    const state = join(dir, "state.json");
    const config = writeConfig(dir, node.url);
    const scan = ["scan", "--config", config, "--state", state, "--seed-file", SEED];
    await cli(scan, "the reply is larger than 16 MiB; pass a smaller --chunk");
    assert.equal(existsSync(`${state}.lock.d`), false);
  } finally {
    await node.close();
  }
});

test("CLI: an earlier version's state is rescanned before direct-secret issues a number", async () => {
  // An earlier version saved this state after scanning the story to its end. Its tree shows epoch
  // 0 closed one leaf short, and Alice had handed out direct numbers 0 to 9. The node serves only
  // the story, since a full epoch is too large to serve, so this checks how the CLI runs the
  // rescan; the state upgrade tests check what a rescan finds.
  const chain = story();
  const node = await serve(chain, { block: chain.block });
  const dir = mkdtempSync(join(TMP, "upgrade-"));
  try {
    const state = join(dir, "state.json");
    const old = {
      ...new Scanner(ALICE, CHAIN, POOL).toJson(),
      version: 2,
      tree: { "0": TREE_CAPACITY - 1n, "1": 1n },
      scanned_block: chain.block,
      leaf_block: chain.block,
      direct_issued: 9n,
    };
    writeFileSync(state, stringify(old, 1), { mode: 0o600 });
    const saved = readFileSync(state, "utf8");
    const args = ["--config", writeConfig(dir, node.url), "--state", state, "--seed-file", SEED];
    const reason =
      "since it shows epoch 0 closed with 1048575 of 1048576 leaves, and the earlier version " +
      "that saved it could miss a payment in an epoch's last leaves";
    // direct-secret issues nothing and saves nothing before the rescan.
    const first = `scan first, which rescans the state from the deployment block, ${reason}`;
    await cli(["direct-secret", ...args], first);
    assert.equal(readFileSync(state, "utf8"), saved);
    // The scan reads from the deployment block, finds the story's notes, and says why in one line.
    const run = await runCli(process.execPath, [CLI, "scan", ...args], { cwd: TMP });
    assert.equal(run.code, 0, run.stderr);
    const line =
      "notes: rescanned the state from the deployment block, keeping the direct numbers " +
      `handed out, ${reason}\n`;
    assert.equal(run.stderr, line);
    assert.equal(node.ranges[0][0], 0n);
    assert.equal(record(run.stdout).unspent, 5);
    const { version, direct_issued, direct_highest } = record(readFileSync(state, "utf8"));
    assert.deepEqual([version, direct_issued, direct_highest], [3, 9, 3]);
    // A fresh state would issue 4, past the highest number paid; this one goes on from 9.
    assert.equal(record(await cli(["direct-secret", ...args])).number, 10);
    const again = await runCli(process.execPath, [CLI, "scan", ...args], { cwd: TMP });
    assert.deepEqual([again.code, again.stderr], [0, ""]);
  } finally {
    await node.close();
  }
});

test("smoke fixture: the committed fixture's notes open for its wallets", () => {
  // Replaying the story as the pool would emit it, each wallet finds and then sees spent its
  // notes.
  const path = new URL("fixtures/smoke_fixture.json", import.meta.url);
  const fixture = parse(readFileSync(path, "utf8")) as Record<string, any>;
  const [alice, bob] = ["alice", "bob"].map((name) => {
    const keys = new n.WalletKeys(fromHex(fixture.wallets[name].seed, "seed"));
    assert.equal(fixture.wallets[name].address, keys.address().hex());
    return keys;
  });
  const { transfer: t, withdraw_seed: ws, withdraw: wd } = fixture;
  const event = (block: bigint, notes: string, leaves: Leaf[], spent: string[] = []) => {
    const bytes = fromHex(notes, "notes");
    return { block, tx: 0n, call: 0, notes: bytes, leaves, spent: spent.map(BigInt) };
  };
  const leaf = (cm: string, index: bigint) => ({ cm: BigInt(cm), epoch: 0n, index });
  const events: PoolEvent[] = [
    event(1n, fixture.shield_note, [leaf(fixture.cm_a, 0n)]),
    event(2n, t.notes, [leaf(t.out_cm1, 1n), leaf(t.out_cm2, 2n)], [t.nf1, t.nf2]),
    event(3n, wd.notes, [], [wd.nf1, wd.nf2]),
    event(4n, ws.notes, [], [ws.nf1, ws.nf2]),
  ];
  // Each note as "index value spent", in leaf order.
  const found = (keys: n.WalletKeys) => {
    const scanner = new Scanner(keys, BigInt(fixture.chain_id), BigInt(fixture.pool_address));
    for (const e of events) scanner.scan(e);
    return [...scanner.notes.values()].map((r) => `${r.index} ${r.value} ${r.spent}`).sort();
  };
  const shield = BigInt(fixture.shield_value);
  const payment = BigInt(t.out_value1);
  const change = shield - payment - BigInt(t.fee);
  assert.deepEqual(found(alice), [`0 ${shield} true`, `2 ${change} true`]);
  assert.deepEqual(found(bob), [`1 ${payment} true`]);
});
