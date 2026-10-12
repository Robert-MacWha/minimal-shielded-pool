/**
 * Disclosure receipts verify only what the chain shows and reject every altered claim. The
 * chain here is a small in-memory copy of what the pool emits after a proof verifies:
 * LeafAppended and NoteSpent, in the frames that emit them, plus the EIP-8250 keys spends
 * consume.
 *
 * Run: node --test test/disclosure.test.ts (about 1 s, most of it the ten CLI runs).
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";

import { concat, hex32, hexPadded, keccak, toBigint, toHex, word } from "../src/bytes.ts";
import {
  decodeSpend,
  exportReceipt,
  verifyCommand,
  verifyReceipt,
  type Receipt,
} from "../src/disclosure.ts";
import { InputError, ReceiptError, type UserError } from "../src/errors.ts";
import { writeNewPrivate } from "../src/files.ts";
import { parse, stringify } from "../src/json.ts";
import { WalletKeys } from "../src/notes.ts";
import * as pr from "../src/protocol.ts";
import { seededRng } from "../src/random.ts";
import { ChainError, RpcChain, type Chain as ChainReader, type RawLog } from "../src/rpc.ts";
import { newNote } from "../src/wallet.ts";
import { rpcServer, runCli } from "./helpers.ts";

const CHAIN = 8141n;
const POOL = 0xcb83980f3cc99e258295814375b0a94fe0ac0e86n;
const POOL_HEX = "0xcb83980f3cc99e258295814375b0a94fe0ac0e86";
const ALICE = 0xa11cen;
const ETH = 10n ** 18n;
/** The owner set every note of the story belongs to. */
const OWNER_ROOT = toBigint(keccak(new TextEncoder().encode("the story's owner set"))) % pr.P;
const CLI = fileURLToPath(new URL("../src/cli/disclosure.ts", import.meta.url));

const TMP = mkdtempSync(join(tmpdir(), "disclosure-test-"));
after(() => rmSync(TMP, { recursive: true, force: true }));
const CONFIG = join(TMP, "config.json");
writeFileSync(CONFIG, JSON.stringify({ chainId: Number(CHAIN), pool: POOL_HEX }));

const log = (first: string, topics: bigint[], data = "0x"): RawLog => {
  return { address: POOL_HEX, topics: [first, ...topics.map(hex32)], data };
};
const leaf = (cm: bigint, epoch: bigint, index: bigint) =>
  log(pr.LEAF_APPENDED, [cm, epoch], hex32(index) + "00".repeat(32));

type Frame = { mode: bigint; to: bigint; data: Uint8Array; status: bigint; logs: RawLog[] };
type Tx = { hash: string; sender: bigint; block: bigint; frames: Frame[]; logs: RawLog[] };

/** Transactions by hash, as a node would return them. */
class Chain implements ChainReader {
  id = CHAIN;
  finalized = 10n ** 9n;
  txs = new Map<string, Tx>();
  // Models ethrex leaving a transaction out of eth_getLogs.
  unindexed = new Set<string>();
  chainId() {
    return this.id;
  }
  finalizedBlock() {
    return this.finalized;
  }
  add(hash: string, sender: bigint, frames: Frame[]): void {
    const logs = frames.filter((f) => f.status === 1n).flatMap((f) => f.logs);
    this.txs.set(hash, { hash, sender, block: BigInt(this.txs.size + 1), frames, logs });
  }
  transaction(hash: string): Tx {
    const tx = this.txs.get(hash);
    if (tx === undefined) throw new ChainError(`transaction ${hash} is not on this chain`);
    return structuredClone(tx);
  }
  logs(address: bigint, topics: readonly unknown[]) {
    const matches = (l: RawLog) =>
      BigInt(l.address) === address && topics.every((t, i) => [t].flat().includes(l.topics[i]));
    return [...this.txs]
      .filter(([hash]) => !this.unindexed.has(hash))
      .flatMap(([hash, tx]) => tx.logs.filter(matches).map((l) => ({ ...l, tx: hash })));
  }
  nonceUsed(sender: bigint, key: bigint): boolean {
    const consumed = (l: RawLog) =>
      l.topics.length === 2 && l.topics[0] === pr.NOTE_SPENT && l.topics[1] === hex32(key);
    return sender === POOL && [...this.txs.values()].some((tx) => tx.logs.some(consumed));
  }
  copy(): Chain {
    return Object.assign(new Chain(), structuredClone({ ...this }));
  }
}

function frame(logs: RawLog[], data: Uint8Array = new Uint8Array(), mode = 2n, status = 1n): Frame {
  return { mode, to: POOL, data, status, logs };
}

// The words of settle(Spend), in the order of ShieldedPoolLogic.Spend, written out so the decoder
// is checked against the contract's layout rather than against its own field list.
const SETTLE_WORDS =
  "root rootSlot epoch domain nf1 nf2 outCm1 outCm2 publicAmount fee recipient authorizer";

/** A settlement frame: settle(Spend) followed by the spend's notes. */
function settle(spend: pr.Spend, logs: RawLog[]): Frame {
  const words = SETTLE_WORDS.split(" ").map((field) => word(spend[field as keyof pr.Spend]));
  return frame(logs, concat(pr.SETTLE_SELECTOR, ...words, new Uint8Array(96)));
}

const NAMES = ["a", "b", "c", "d1", "d2", "d3", "e"] as const;
type Name = (typeof NAMES)[number];
const byName = <T>(f: (k: Name) => T) =>
  Object.fromEntries(NAMES.map((k) => [k, f(k)])) as Record<Name, T>;

/**
 * Alice deposits 1 ETH, pays Bob 0.6 privately keeping 0.35 change, and withdraws 0.3 of the
 * change; a contract the withdrawal's fourth frame calls shields 5 ETH. Bob later withdraws his
 * note. The same commitment as Alice's deposit also lands at leaf 3, and at leaf 0 of epoch 1
 * after a rollover. With sharedKey, Alice's change uses her deposit's nullifier key, as two
 * notes paid to one address (src/notes.ts) do. With aliceKey, her deposit uses that nullifier
 * key. Every note is in one owner set, and every call draws the same notes.
 */
function story(sharedKey = false, aliceKey?: bigint, dummyKey?: bigint) {
  const rng = seededRng(7n);
  const D = pr.domainScalar(CHAIN, POOL_HEX, 0n);
  const notes = byName(() => newNote(rng));
  if (aliceKey !== undefined) notes.a = [aliceKey, notes.a[1]];
  if (sharedKey) notes.c = [notes.a[0], notes.c[1]];
  if (dummyKey !== undefined) notes.d1 = [dummyKey, notes.d1[1]];
  const values = { a: ETH, b: (6n * ETH) / 10n, c: (35n * ETH) / 100n, e: 5n * ETH };
  const valueOf = (k: Name) => (k in values ? values[k as keyof typeof values] : 0n);
  const pk = (k: Name) => pr.ownerPk(OWNER_ROOT, notes[k][0]);
  const cm = byName((k) => pr.commitment(pk(k), notes[k][1], valueOf(k)));
  // Each input's nullifier is at its leaf: b at 1, c at 2, and a and the dummy d notes at 0.
  const at: Partial<Record<Name, bigint>> = { b: 1n, c: 2n };
  const nf = byName((k) => pr.nullifier(D, notes[k][0], cm[k], at[k] ?? 0n));
  const base = { root: 1n, rootSlot: 5n, epoch: 0n, domain: D, authorizer: 0xaaaan };
  const [sink1, sink2] = pr.sinkCommitments();
  const spend = (i1: Name, i2: Name, outs: bigint[], publicAmount: bigint, recipient: bigint) => {
    const [outCm1, outCm2] = outs.length === 0 ? [sink1, sink2] : outs;
    const spent = [log(pr.NOTE_SPENT, [nf[i1]]), log(pr.NOTE_SPENT, [nf[i2]])];
    // Only the transfer has outputs, at leaves 1 and 2 after the deposit.
    const leaves = outs.map((out, i) => leaf(out, 0n, BigInt(i + 1)));
    const fields = { nf1: nf[i1], nf2: nf[i2], outCm1, outCm2, publicAmount, recipient };
    return settle({ ...base, ...fields, fee: ETH / 20n }, [...spent, ...leaves]);
  };
  const chain = new Chain();
  chain.add("0xdep0", ALICE, [frame([leaf(cm.a, 0n, 0n)])]);
  chain.add("0xtransfer", POOL, [spend("a", "d1", [cm.b, cm.c], 0n, 0n)]);
  chain.add("0xwithdraw", POOL, [
    spend("c", "d2", [], (3n * ETH) / 10n, 0x9271fb61n),
    frame([leaf(cm.e, 0n, 4n)], new Uint8Array(), 0n),
  ]);
  chain.add("0xbobexit", POOL, [spend("b", "d3", [], (55n * ETH) / 100n, 0xb0bn)]);
  chain.add("0xdep3", ALICE, [frame([leaf(cm.a, 0n, 3n)])]);
  chain.add("0xdep_epoch1", ALICE, [frame([leaf(cm.a, 1n, 0n)])]);
  const op = (k: Name, leafIndex: number | null = null) => {
    const [nk, rho] = notes[k].map(hex32);
    const owner_root = hex32(OWNER_ROOT);
    return { owner_root, nk, rho, value: String(valueOf(k)), leaf: leafIndex };
  };
  // Like the repository's generators, Alice's fixture also holds Bob's key.
  const fixture = {
    transfer: { epoch: 0, inputs: [op("a", 0), op("d1")], output_openings: [op("b"), op("c")] },
    withdraw: { epoch: 0, inputs: [op("c", 2), op("d2")] },
  };
  return { chain, fixture, notes, cm, nf, op };
}

const verify = (chain: ChainReader, receipt: unknown) =>
  verifyReceipt(chain, receipt, (pool) => {
    if (pool !== POOL) throw new ReceiptError("the receipt names another pool than the config");
  });

function exportFor(chain: ChainReader, fixture: unknown, only?: bigint[], addressWide = false) {
  const chosen = only === undefined ? null : new Set(only);
  return exportReceipt(chain, CHAIN, POOL, fixture, chosen, { addressWide });
}

function refusal(expected: string, kind: typeof UserError = ReceiptError) {
  return (error: unknown): true => {
    assert.ok(error instanceof kind, `expected a ${kind.name}, got ${String(error)}`);
    assert.ok(error.message.includes(expected), `"${expected}" not in "${error.message}"`);
    return true;
  };
}

async function rejected(chain: ChainReader, receipt: unknown, expected: string): Promise<void> {
  await assert.rejects(verify(chain, receipt), refusal(expected));
}

// Export cannot tell any nullifier key from an address's, so these disclose with consent.
const { chain, fixture, notes, cm, nf, op } = story();
const receipt = await exportFor(chain, fixture, undefined, true);
const deposit = await exportFor(chain, fixture, [cm.a], true);
const outputsOnly = (k: Name) => ({ x: { epoch: 0, inputs: [], output_openings: [op(k)] } });

/** The receipt note for `key`, at epoch 0. */
function noteOf(r: Receipt, key: Name) {
  const found = r.notes.find((n) => BigInt(n.cm) === cm[key] && n.epoch === 0n);
  assert.ok(found, `no note ${key}`);
  return found;
}

test("an honest receipt traces the deposit through the transfer to the withdrawal", async () => {
  // It discloses both dummies, so each spend is fully explained.
  const report = await verify(chain, receipt);
  const pairs = report.notes.map((n) => `${n.origin.split(" ")[0]} ${n.spent}`);
  assert.deepEqual(pairs.sort(), [
    "deposit 0xtransfer",
    "dummy 0xtransfer",
    "dummy 0xwithdraw",
    "output 0xwithdraw",
    "output not disclosed",
  ]);
  const [t, wd] = ["0xtransfer", "0xwithdraw"].map((hash) => report.spends.get(hash)!);
  assert.equal(t.complete, true);
  assert.equal(t.inputValue, "1000000000000000000");
  const outputs = t.outputs.map((o) => o.value);
  assert.deepEqual(outputs, ["600000000000000000", "350000000000000000"]);
  assert.equal(wd.complete, true);
  assert.equal(wd.recipient, "0x000000000000000000000000000000009271fb61");
  assert.deepEqual(wd.outputs, []);
  const text = stringify(receipt);
  for (const secret of Object.values(notes).flat()) assert.ok(!text.includes(hex32(secret)));
  // Bob's note is only an output of Alice's payment, so his later withdrawal stays his to
  // disclose, although her fixture holds his key.
  assert.ok(!("nullifierKey" in noteOf(receipt, "b")));
  assert.ok(!text.includes("0xbobexit"));
});

test("an altered note is rejected", async (t) => {
  const keyA = noteOf(receipt, "a").nullifierKey;
  const cases: [Name, Record<string, unknown>, string, string?][] = [
    ["a", { nullifierKey: hex32(12345n) }, "not one 0xtransfer spent"],
    ["a", { index: 1n }, "did not create it"],
    ["a", { value: "2000000000000000000" }, "opening does not match"],
    // Poseidon reads a value mod P, so value + P would hash as value.
    ["c", { value: String((35n * ETH) / 100n + pr.P) }, "opening does not match"],
    ["a", { epoch: 1n }, "did not create it"],
    ["a", { epoch: 1n, created: "0xdep_epoch1" }, "spends epoch 0, not 1"],
    ["a", { spent: "0xwithdraw" }, "not one 0xwithdraw spent"],
    ["a", { created: "0xdep3" }, "did not create it"],
    ["a", { index: 3n, created: "0xdep3", nullifierKey: keyA }, "not one 0xtransfer spent"],
    ["d1", { value: "1" }, "opening does not match"],
    ["d1", {}, "a dummy input has value 0 and a spend", "spent"],
    // A dummy's index is not in the tree, so index + P would alias its nullifier.
    ["d1", { index: noteOf(receipt, "d1").index + pr.P }, "outside the tree"],
  ];
  for (const [key, change, expected, drop] of cases) {
    await t.test(`${key} ${Object.keys(change).join(", ") || `without ${drop}`}`, async () => {
      const forged = structuredClone(receipt);
      const target: Record<string, unknown> = noteOf(forged, key);
      Object.assign(target, change);
      if (drop !== undefined) delete target[drop];
      await rejected(chain, forged, expected);
    });
  }
});

test("a malformed or foreign receipt is rejected, and hash case does not matter", async () => {
  const doubled = structuredClone(receipt);
  doubled.notes.push(structuredClone(noteOf(receipt, "a")));
  await rejected(chain, doubled, "listed twice");
  await rejected(chain, { ...receipt, version: 2 }, "not a version 1 disclosure receipt");
  await rejected(chain, { ...receipt, pool: "0x1111" }, "another pool than the config");
  await rejected(chain, { ...receipt, notes: [{ cm: "0x1" }] }, "malformed");
  await rejected(chain, [receipt], "malformed");
  // ethrex also finds a hash written without 0x; a second spelling would list its spend twice.
  const unprefixed = { ...noteOf(receipt, "a"), spent: "0xtransfer".slice(2) };
  await rejected(chain, { ...receipt, notes: [unprefixed] }, "must be a 0x transaction hash");
  const shouting = structuredClone(receipt);
  for (const n of shouting.notes as Record<string, unknown>[]) {
    for (const k of ["created", "spent"]) {
      if (k in n) n[k] = (n[k] as string).toUpperCase().replace("0X", "0x");
    }
  }
  const report = await verify(chain, shouting);
  assert.deepEqual(new Set(report.spends.keys()), new Set(["0xtransfer", "0xwithdraw"]));
});

test("evidence must come from a successful, canonical, finalized spend on this chain", async (t) => {
  // Logs from a reverted frame are not evidence. Each case edits a copy of the chain, where `tx`
  // is 0xtransfer, the spend of Alice's deposit, and verifies `deposit`, the receipt of that note
  // alone, unless it names another receipt.
  const onlyB = { ...receipt, notes: [noteOf(receipt, "b")] };
  const cases: [string, string, (c: Chain, tx: Tx) => unknown, Receipt?][] = [
    ["reverted settlement", "settlement did not succeed", (_, tx) => (tx.frames[0].status = 0n)],
    ["sent by another sender", "not a spend of this pool", (_, tx) => (tx.sender = ALICE)],
    // Any contract can emit a log shaped like the pool's.
    [
      "a deposit logged by another contract",
      "0xdep0 did not create it",
      (c) => {
        const logs = c.txs.get("0xdep0")!.frames[0].logs;
        logs[0] = { ...logs[0], address: "0x" + "77".repeat(20) };
      },
    ],
    [
      "short settlement data",
      "no canonical settlement frame",
      (_, tx) => (tx.frames[0].data = tx.frames[0].data.subarray(0, -32)),
    ],
    // 0xdep0, in block 1, is at the finalized head, which counts; 0xtransfer is one block past.
    ["not finalized", "0xtransfer is not finalized", (c) => (c.finalized = 1n)],
    ["another chain", "not chain 8141", (c) => (c.id = 1n), receipt],
    ["missing transaction", "not on this chain", (c) => c.txs.delete("0xwithdraw"), receipt],
    [
      "a reverted spend's output",
      "did not create it",
      (_, tx) => (tx.frames[0].status = 0n),
      onlyB,
    ],
  ];
  for (const [name, expected, mutate, r = deposit] of cases) {
    await t.test(name, async () => {
      const broken = chain.copy();
      mutate(broken, broken.txs.get("0xtransfer")!);
      await rejected(broken, r, expected);
    });
  }
});

test("export fails on a consumed spend the node's logs miss and skips one never sent", async () => {
  // As ethrex does when a spend's fourth frame fails, rather than call the note unspent.
  const gap = chain.copy();
  gap.unindexed.add("0xtransfer");
  await assert.rejects(exportFor(gap, fixture, [cm.a]), refusal("logs do not show"));
  // A spend the fixture holds but that was never sent consumed nothing: its dummy is left out.
  const unsent = { epoch: 0, inputs: [{ ...op("d1"), nk: hex32(1n) }] };
  assert.deepEqual(await exportFor(chain, { ...fixture, unsent }, undefined, true), receipt);
});

test("what a receipt shows about origins, completeness and positions", async () => {
  // A deposit made from a spend's fourth frame is not one of its outputs, even when the spend
  // has outputs: moved to the transfer, it keeps its origin.
  const shielded = await exportFor(chain, outputsOnly("e"));
  const [first] = (await verify(chain, shielded)).notes;
  assert.equal(first.origin, "deposit made from 0xwithdraw's fourth frame");
  const moved = chain.copy();
  moved.txs.get("0xtransfer")!.frames.push(moved.txs.get("0xwithdraw")!.frames.pop()!);
  Object.assign(shielded.notes[0], { created: "0xtransfer" });
  const [second] = (await verify(moved, shielded)).notes;
  assert.equal(second.origin, "deposit made from 0xtransfer's fourth frame");
  // The fourth frame runs even when the settlement before it failed, and its deposit is real.
  const unsettled = chain.copy();
  unsettled.txs.get("0xwithdraw")!.frames[0].status = 0n;
  Object.assign(shielded.notes[0], { created: "0xwithdraw" });
  const [third] = (await verify(unsettled, shielded)).notes;
  assert.equal(third.origin, "deposit made from 0xwithdraw's fourth frame");
  // A disclosed input with its partner hidden leaves the spend unexplained.
  assert.equal((await verify(chain, deposit)).spends.get("0xtransfer")!.complete, false);
  // An input names its leaf and epoch; a note known only by commitment covers each leaf it
  // occupies, without a nullifier key.
  const places = (r: Receipt) => r.notes.map((n) => `${n.epoch} ${n.index} ${"nullifierKey" in n}`);
  assert.deepEqual(places(deposit), ["0 0 true"]);
  const anywhere = places(await exportFor(chain, outputsOnly("a")));
  assert.deepEqual(anywhere.sort(), ["0 0 false", "0 3 false", "1 0 false"]);
});

test("the RPC reader resolves a frame without a target and rejects malformed answers", async () => {
  const { data: calldata, logs } = chain.txs.get("0xtransfer")!.frames[0];
  const data = toHex(calldata);
  const tx = { sender: POOL_HEX, frames: [{ mode: "0x2", to: null, data }] };
  const answer = { blockNumber: "0x1", logs, frameReceipts: [{ status: "0x1", logs }] };
  // An RPC reader replaying canned answers.
  const replay = (byHash: unknown, txReceipt: unknown) => {
    const answers = { eth_getTransactionByHash: byHash, eth_getTransactionReceipt: txReceipt };
    const call = async (method: string) => answers[method as keyof typeof answers];
    return Object.assign(new RpcChain("http://127.0.0.1:1"), { call }).transaction("0x1");
  };
  const replayed = decodeSpend(await replay(tx, answer), POOL);
  assert.equal(replayed.nf1, nf.a);
  assert.equal(replayed.nf1, decodeSpend(chain.transaction("0xtransfer"), POOL).nf1);
  const bad: [unknown, unknown, string][] = [
    [{ frames: [{ mode: "zz" }] }, answer, "unexpected RPC response"],
    [tx, { ...answer, frameReceipts: [] }, "unexpected RPC response"],
    // The first case stops at the missing sender; this one reaches the strict mode parser.
    [{ sender: POOL_HEX, frames: [{ mode: "zz", to: null, data }] }, answer, "mode"],
  ];
  for (const [badTx, badAnswer, expected] of bad) {
    const checks = [refusal("unexpected RPC response", ChainError), refusal(expected, ChainError)];
    await assert.rejects(replay(badTx, badAnswer), (e: unknown) => checks.every((c) => c(e)));
  }
});

test("the RPC reader finds a consumed nonce key at its EIP-8250 storage slot", async () => {
  // EIP-8250's nonce manager keeps a sender's key at keccak256(sender || key), each a word.
  const manager = "0x0000000000000000000000000000000000008250";
  const slot = toHex(keccak(concat(word(POOL), word(nf.a))));
  const call = async (method: string, params: readonly unknown[]) =>
    method === "eth_getStorageAt" && params[0] === manager && params[1] === slot ? "0x2" : "0x0";
  const reader = Object.assign(new RpcChain("http://127.0.0.1:1"), { call });
  assert.equal(await reader.nonceUsed(POOL, nf.a), true);
  assert.equal(await reader.nonceUsed(POOL, nf.b), false);
});

test("the RPC reader reads logs 2,000 blocks per call, up to the latest block", async () => {
  // One eth_getLogs call over the pool's whole history would pass rpc()'s 16 MiB cap once the
  // pool held about 25,000 shields, and export would be refused for everyone.
  const ranges: string[][] = [];
  const call = async (method: string, params: readonly unknown[]) => {
    if (method === "eth_blockNumber") return "0x1388";
    const { fromBlock, toBlock } = params[0] as { fromBlock: string; toBlock: string };
    ranges.push([fromBlock, toBlock]);
    return [{ ...leaf(BigInt(ranges.length), 0n, 0n), transactionHash: `0xA${ranges.length}` }];
  };
  const reader = Object.assign(new RpcChain("http://127.0.0.1:1"), { call });
  const logs = await reader.logs(POOL, [], 1000n);
  assert.deepEqual(ranges, [
    ["0x3e8", "0xbb7"],
    ["0xbb8", "0x1387"],
    ["0x1388", "0x1388"],
  ]);
  assert.deepEqual(
    logs.map((l) => l.tx),
    ["0xa1", "0xa2", "0xa3"],
  );
});

const run = (args: string[]) => runCli(process.execPath, [CLI, ...args], { cwd: TMP });

/**
 * A local node for the CLI. It answers eth_chainId, eth_blockNumber with block 1, and
 * eth_getLogs from `source`, the calls an export of output notes makes. Any other call gets
 * null, which the client reports as a malformed answer, and a request to /moved is redirected
 * to /.
 */
function node(source: Chain) {
  return rpcServer(({ method, params, path }) => {
    if (path === "/moved") return { redirect: "/" };
    const found =
      method === "eth_getLogs" ? source.logs(BigInt(params[0].address), params[0].topics) : null;
    const logs = found?.map(({ tx, ...l }) => ({ ...l, transactionHash: tx })) ?? null;
    const fixed = { eth_chainId: hexPadded(CHAIN, 1), eth_blockNumber: "0x1" }[method];
    return { result: fixed ?? logs };
  });
}

test("export discloses only notes named in full, owner-only and never through a link", async () => {
  const { url: rpc, close } = await node(chain);
  try {
    const dir = mkdtempSync(join(TMP, "export-"));
    const outputs = join(dir, "fixture.json");
    writeFileSync(outputs, stringify(outputsOnly("e")));
    // Alice's fixture with a second note under her deposit's key, as notes paid to one address are.
    const sharing = join(dir, "sharing.json");
    const second = { epoch: 0, inputs: [], output_openings: [{ ...op("a"), rho: hex32(1n) }] };
    writeFileSync(sharing, stringify({ ...fixture, second }));
    const exporting = (output: string, choice = ["--all"]) => {
      const args = ["export", "--rpc", rpc, "--config", CONFIG, "--fixture", outputs, ...choice];
      return run([...args, "--output", output]);
    };
    // A prefix could match notes the user did not mean to disclose, and a disclosure cannot be
    // taken back. The last --fixture or --rpc given is the one used.
    const refused: [string[], string][] = [
      [[], "--only with the notes to disclose, or --all"],
      [["--all", "--only", hex32(cm.a)], "--only with the notes to disclose, or --all"],
      [["--only", "0x"], "full commitments"],
      [["--only", hex32(cm.a) + ","], "full commitments"],
      [["--only", hex32(cm.a).slice(0, -1)], "full commitments"],
      // A key the fixture's notes share is disclosed only with --address-wide.
      [["--all", "--fixture", sharing], "--address-wide"],
      // A redirect could take the request to another host.
      [["--all", "--rpc", `${rpc}/moved`], "request failed"],
    ];
    await Promise.all(
      refused.map(async ([choice, expected]) => {
        const { code, stderr } = await exporting(join(dir, "never.json"), choice);
        assert.equal(code, 1, `${choice.join(" ")}: ${stderr}`);
        assert.ok(stderr.includes(expected), `${choice.join(" ")}: ${stderr}`);
      }),
    );
    // The child inherits the umask, which would leave a plainly written file world-readable.
    const output = join(dir, "r.json");
    const old = process.umask(0o022);
    const exported = exporting(output);
    process.umask(old);
    const { code, stdout, stderr } = await exported;
    assert.equal(code, 0, stderr);
    assert.equal(stdout, `wrote ${output}: 1 notes\n`);
    assert.equal(statSync(output).mode & 0o777, 0o600);
    const written = parse(readFileSync(output, "utf8")) as { notes: Record<string, unknown>[] };
    const pairs = written.notes.map((n) => [n.cm, n.created]);
    assert.deepEqual(pairs, [[hex32(cm.e), "0xwithdraw"]]);
    // A link planted at the output is not written through, and an existing receipt is not
    // replaced, a race the export's own check for a new path would miss.
    const planted = join(dir, "planted");
    symlinkSync(planted, join(dir, "link.json"));
    const linked = await exporting(join(dir, "link.json"));
    assert.equal(linked.code, 1, linked.stderr);
    assert.ok(linked.stderr.includes("exists"), linked.stderr);
    assert.equal(statSync(planted, { throwIfNoEntry: false }), undefined);
    assert.throws(() => writeNewPrivate(output, "{}"), InputError);
    assert.deepEqual(parse(readFileSync(output, "utf8")), written);
  } finally {
    await close();
  }
});

test("a CLI error about a file redacts a key pasted as its path", async () => {
  const key = "ab".repeat(32);
  const args = ["verify", "--rpc", "http://127.0.0.1:1", "--config", join(TMP, `0x${key}`)];
  const { code, stderr } = await run(args);
  assert.equal(code, 1, stderr);
  assert.ok(stderr.includes("<redacted>") && !stderr.includes(key), stderr);
});

test("verify takes only a receipt for the config's pool", async () => {
  // Any deployment of the pool's profile would pass the profile check that follows.
  const { url: rpc, close } = await node(chain);
  try {
    const foreign = join(TMP, "foreign.json");
    writeFileSync(foreign, stringify({ ...receipt, pool: "0x" + "11".repeat(20) }));
    const verified = verifyCommand({ rpc, config: CONFIG, receipt: foreign });
    await assert.rejects(verified, refusal("another pool than the config"));
  } finally {
    await close();
  }
});

test("a nullifier key shared by an address's notes needs consent and is marked", async () => {
  // Two notes under one nullifier key, as one address's notes are: a domain key would show
  // when either is spent, so export refuses unless asked, and then marks the scope. The
  // receipt still verifies.
  const shared = story(true);
  await assert.rejects(exportFor(shared.chain, shared.fixture), refusal("--address-wide"));
  const wide = await exportFor(shared.chain, shared.fixture, undefined, true);
  // The two notes under that key, and the two dummies, whose keys export cannot tell from it.
  const scoped = wide.notes.filter((n) => n.keyScope === "address");
  assert.equal(scoped.length, 4);
  assert.ok(scoped.every((n) => "nullifierKey" in n));
  await verify(shared.chain, wide);
  // A wallet's own key is its address's, even under the one note the fixture holds.
  const seed = new Uint8Array(32).fill(1);
  const paid = story(false, new WalletKeys(seed, OWNER_ROOT).nk);
  const withWallet = { ...paid.fixture, wallets: { alice: { seed: toHex(seed) } } };
  await assert.rejects(exportFor(paid.chain, withWallet), refusal("--address-wide"));
});

test("a real note's key needs consent at any account", async () => {
  // A seed has an address for every account number, so a lone note's key may be an address's
  // whether the fixture names its wallet, with its account or without, or names none. Export
  // refuses the key unless asked and then marks it, at account 1 as at account 0.
  const seed = new Uint8Array(32).fill(1);
  for (const account of [0n, 1n]) {
    const paid = story(false, new WalletKeys(seed, OWNER_ROOT, account).nk);
    const named = [{ seed: toHex(seed), account: Number(account) }, { seed: toHex(seed) }];
    const fixtures = [
      ...named.map((alice) => ({ ...paid.fixture, wallets: { alice } })),
      paid.fixture,
    ];
    for (const fx of fixtures) {
      await assert.rejects(exportFor(paid.chain, fx, [paid.cm.a]), refusal("--address-wide"));
      const wide = await exportFor(paid.chain, fx, [paid.cm.a], true);
      assert.deepEqual(
        wide.notes.map((n) => [n.cm, n.keyScope, "nullifierKey" in n]),
        [[hex32(paid.cm.a), "address", true]],
      );
      await verify(paid.chain, wide);
    }
  }
});

test("a dummy input's key needs consent too, and a receipt without a key does not", async () => {
  // Zero value does not show that a dummy's key was drawn for its spend alone: a fixture can
  // give a dummy any account's key, which covers that address's notes in the epoch. Export
  // refuses every dummy's key unless asked, fresh ones too, and then marks it.
  await assert.rejects(exportFor(chain, fixture, [cm.d1, cm.d2]), refusal("--address-wide"));
  const dummies = await exportFor(chain, fixture, [cm.d1, cm.d2], true);
  const shown = dummies.notes.map((n) => ["dummy" in n, n.keyScope, "nullifierKey" in n]);
  assert.deepEqual(shown, [
    [true, "address", true],
    [true, "address", true],
  ]);
  await verify(chain, dummies);
  const scopes = (["a", "c", "d1", "d2"] as const).map((k) => noteOf(receipt, k).keyScope);
  assert.deepEqual(scopes, ["address", "address", "address", "address"]);
  const seed = new Uint8Array(32).fill(1);
  const D = pr.domainScalar(CHAIN, POOL, 0n);
  for (const account of [0n, 1n]) {
    const key = new WalletKeys(seed, OWNER_ROOT, account).nk;
    const reused = story(false, undefined, key);
    const alice = { seed: toHex(seed), account: Number(account) };
    for (const fx of [{ ...reused.fixture, wallets: { alice } }, reused.fixture]) {
      const only = [reused.cm.d1];
      await assert.rejects(exportFor(reused.chain, fx, only), refusal("--address-wide"));
      const [note] = (await exportFor(reused.chain, fx, only, true)).notes;
      assert.equal(note.keyScope, "address");
      assert.equal(note.nullifierKey, hex32(pr.domainKey(D, key)), "the address's key");
    }
  }
  // A payment's output the fixture does not spend, such as Bob's, needs no consent.
  const output = await exportFor(chain, fixture, [cm.b]);
  const unkeyed = output.notes.map((n) => [n.cm, "keyScope" in n, "nullifierKey" in n]);
  assert.deepEqual(unkeyed, [[hex32(cm.b), false, false]]);
});
