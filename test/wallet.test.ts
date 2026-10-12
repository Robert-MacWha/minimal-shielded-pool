/**
 * The wallet's tree. seededTree rebuilds a live pool's tree from its LeafAppended logs before
 * the nonce-race generator proves against it: duplicate commitments stay distinct leaves in
 * logged index order, other epochs' logs are ignored, and a mismatched epoch, gap or root stops
 * it. The smoke fixture's openings reproduce its nullifiers, Tree matches the incremental-tree
 * vectors at both depths, a new note's secrets are distinct field elements, an authorizer key is
 * never zero, each zero output must use its own position's sink, an output inner must be below
 * p, and the owner must be a nonzero address with a depth-16 path. Runtime: about 0.2 s.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { word } from "../src/bytes.ts";
import { seededTree, type Call } from "../src/nonce-race.ts";
import { OwnerSet } from "../src/owner.ts";
import {
  LEAF_APPENDED,
  OWNER_DEPTH,
  P,
  commitment,
  inputNullifiers,
  ownerPk,
  p2,
  sinkOutputs,
  type Output,
} from "../src/protocol.ts";
import { seededRng } from "../src/random.ts";
import { Tree, buildWitness, dummyInput, newAuthorizer, newNote } from "../src/wallet.ts";

const POOL = "0x" + "12".repeat(20);
const FILTER = { address: POOL, topics: [LEAF_APPENDED], fromBlock: "0x0", toBlock: "latest" };
const json = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
/** Unpadded lowercase hex, as nodes write quantities. */
const hex = (x: bigint) => "0x" + x.toString(16);
const hex64 = (x: bigint) => x.toString(16).padStart(64, "0");

interface Pool {
  epoch?: bigint;
  expectedEpoch?: bigint;
  foreign?: bigint[];
  order?: number[];
  indices?: bigint[];
  root?: bigint;
}

/**
 * seededTree against a fake pool at `epoch` whose currentRoot() is `root` (by default the
 * leaves' root). The pool logs leaf i at indices[i] (by default i), in `order`, then one log at
 * index 0 for each epoch in `foreign`, which would replace leaf 0 unless it is filtered out.
 * The fake answers only the calls seededTree should make, and checks that eth_getLogs filters
 * by the pool's address, since the LeafAppended parser trusts the logs it is given.
 */
function rebuild(leaves: bigint[], pool: Pool = {}) {
  const { epoch = 0n, expectedEpoch = epoch, foreign = [epoch + 1n] } = pool;
  const root = pool.root ?? leaves.reduce((tree, cm) => (tree.append(cm), tree), new Tree()).root();
  const log = (cm: bigint, epoch: bigint, index: bigint) => ({
    topics: [LEAF_APPENDED, hex(cm), hex(epoch)],
    data: "0x" + hex64(index) + hex64(root),
  });
  const own = leaves.map((cm, i) => log(cm, epoch, pool.indices?.[i] ?? BigInt(i)));
  const logs = [...(pool.order?.map((i) => own[i]) ?? own), ...foreign.map((e) => log(17n, e, 0n))];
  const call: Call = async (method, params) => {
    if (method === "eth_getLogs") {
      assert.deepEqual(params, [FILTER]);
      return logs;
    }
    assert.equal(method, "eth_call");
    const [{ to, data }] = params as [{ to: string; data: string }];
    assert.equal(to, POOL);
    if (data === "0x76671808") return hex(epoch); // currentEpoch()
    if (data === "0xfdab463d") return hex(root); // currentRoot()
    throw new Error(`unexpected eth_call ${data}`);
  };
  return seededTree(call, POOL, expectedEpoch);
}

const keeps = async (leaves: bigint[], pool?: Pool) =>
  assert.deepEqual((await rebuild(leaves, pool)).leaves, leaves);
const refuses = (leaves: bigint[], pool: Pool, message: RegExp) =>
  assert.rejects(rebuild(leaves, pool), { name: "GeneratorError", message });

/** A one-address owner set's leaf, for witnesses whose owner does not matter. */
const OWNER = new OwnerSet([0xabcn]).leaf(0);
const cm = commitment(123n, 456n, 100n);
const other = commitment(321n, 654n, 200n);

test("duplicate commitments stay distinct leaves", () => keeps([cm, cm]));
test("leaves follow their logged index, not the log order", () =>
  keeps([cm, other, commitment(1n, 2n, 3n)], { order: [2, 0, 1] }));
test("logs of an older and a newer epoch are ignored", () =>
  keeps([cm], { epoch: 1n, foreign: [0n, 2n] }));
test("an epoch mismatch stops before proving", () =>
  refuses([cm], { epoch: 1n, expectedEpoch: 0n }, /does not match the live tree epoch/));
test("a gap in the logged indices is refused", () =>
  refuses([cm, other], { indices: [0n, 2n] }, /skip leaf 1/));
test("a rebuilt root that differs from currentRoot() is refused", () =>
  refuses([cm], { root: other }, /tree reconstruction mismatch/));

test("the smoke fixture's input openings reproduce its nullifiers", () => {
  // After another deposit changes the tree, only these openings let the owner prove the same
  // spend, with the same nullifiers, on a newer root.
  const fixture = json("fixtures/smoke_fixture.json");
  type Opening = { owner_root: string; nk: string; rho: string; value: string };
  const open = (i: Opening & { leaf: number | null }) => {
    const [nk, rho, value] = [i.nk, i.rho, i.value].map(BigInt);
    return { nk, rho, value, idx: i.leaf === null ? null : BigInt(i.leaf) };
  };
  for (const name of ["transfer", "withdraw_seed", "withdraw"]) {
    const { domain, inputs, nf1, nf2 } = fixture[name];
    // Both inputs, the dummy included, belong to the spend's owner set.
    assert.equal(inputs[0].owner_root, inputs[1].owner_root, name);
    const ownerRoot = BigInt(inputs[0].owner_root);
    const nullifiers = inputNullifiers(BigInt(domain), ownerRoot, inputs.map(open));
    assert.deepEqual(nullifiers, [BigInt(nf1), BigInt(nf2)], name);
  }
  const input = fixture.transfer.inputs[0];
  const { nk, rho, value } = open(input);
  assert.equal(commitment(ownerPk(BigInt(input.owner_root), nk), rho, value), BigInt(fixture.cm_a));
});

test("Tree matches the exported incremental-tree vectors", () => {
  const v = json("vectors/poseidon_bn254_vectors.json").tree;
  const tree = new Tree();
  assert.equal(tree.root(), BigInt(v.root_empty), "empty root");
  tree.append(BigInt(v.cm0));
  assert.equal(tree.root(), BigInt(v.root_after_cm0), "root after cm0");
  tree.append(BigInt(v.cm1));
  assert.equal(tree.root(), BigInt(v.root_after_cm0_cm1), "root after cm0, cm1");
});

test("a depth-16 Tree matches the exported owner set and holds 2^16 leaves", () => {
  const v = json("vectors/poseidon_bn254_vectors.json").owner_set;
  const tree = new Tree(OWNER_DEPTH);
  assert.equal(tree.root(), BigInt(v.root_empty), "empty root");
  for (const address of v.addresses) tree.append(BigInt(address));
  assert.equal(tree.root(), BigInt(v.root), "root");
  assert.equal(tree.authPath(0n).siblings.length, OWNER_DEPTH);
  for (let i = v.addresses.length; i < 2 ** OWNER_DEPTH; i++) tree.append(1n);
  assert.throws(() => tree.append(1n), /tree full/);
  for (const depth of [0, 21, 1.5]) assert.throws(() => new Tree(depth), RangeError, `${depth}`);
});

test("a value note's auth path reproduces the root", () => {
  const [nk, rho] = newNote(seededRng(1n));
  const note = commitment(nk, rho, 10n ** 18n);
  const tree = new Tree();
  const { siblings, bits } = tree.authPath(tree.append(note));
  let node = note;
  bits.forEach((bit, d) => (node = bit === 0 ? p2(node, siblings[d]) : p2(siblings[d], node)));
  assert.equal(node, tree.root());
});

test("a new note's nullifier key and rho are distinct field elements", () => {
  // rho is less private than nk (the sender derives it in note delivery), so a draw repeating
  // nk or another note's secret would let whoever learns rho see when the note is spent.
  const rng = seededRng(2n);
  const secrets = Array.from({ length: 4 }, () => newNote(rng)).flat();
  assert.equal(new Set(secrets).size, secrets.length);
  for (const secret of secrets) assert.ok(0n <= secret && secret < P, `${secret}`);
});

test("an authorizer key is one more than its draw below n - 1, so never zero", () => {
  const rng = { ...seededRng(3n), below: () => 0n };
  assert.deepEqual(newAuthorizer(rng)[0], word(1n));
});

test("a withdrawal's zero outputs must each use their own position's sink", () => {
  const inputs = [{ nk: 1n, rho: 2n, value: 5n, idx: 0n }, dummyInput(seededRng(4n))];
  const terms = { authorizer: 1n, owner: OWNER, publicAmount: 5n, recipient: 9n };
  const withdraw = (outputs: Output[]) => buildWitness(new Tree(), inputs, outputs, 0n, terms);
  assert.deepEqual(withdraw(sinkOutputs()).out_inner, ["1", "2"]);
  assert.throws(() => withdraw(sinkOutputs().reverse()), /must use its positional sink/);
});

test("an output inner past p is refused, so an alias of a sink inner cannot slip through", () => {
  const inputs = [{ nk: 1n, rho: 2n, value: 5n, idx: 0n }, dummyInput(seededRng(4n))];
  const spend = (first: Output, second: Output) =>
    buildWitness(new Tree(), inputs, [first, second], 0n, { authorizer: 1n, owner: OWNER });
  // The circuit reads P + 2 as sink inner 2 and refuses it for a positive output.
  assert.throws(() => spend([3n, 3n], [P + 2n, 2n]), /must be in \[0, p\)/);
  assert.throws(() => spend([P + 1n, 0n], [3n, 5n]), /must be in \[0, p\)/);
  assert.throws(() => spend([-1n, 3n], [3n, 2n]), /must be in \[0, p\)/);
  assert.throws(() => spend([P, 3n], [3n, 2n]), /must be in \[0, p\)/);
  assert.deepEqual(spend([P - 1n, 3n], [3n, 2n]).out_inner, [String(P - 1n), "3"]);
});

test("the owner is a nonzero address with a depth-16 path, and the witness carries it", () => {
  const inputs = [{ nk: 1n, rho: 2n, value: 5n, idx: 0n }, dummyInput(seededRng(5n))];
  const outputs: Output[] = [[3n, 5n], sinkOutputs()[1]];
  const spend = (owner: typeof OWNER) =>
    buildWitness(new Tree(), inputs, outputs, 0n, { authorizer: 1n, owner });
  const w = spend(OWNER);
  assert.equal(w.owner, String(OWNER.address));
  assert.equal(w.owner_root, String(OWNER.root));
  assert.deepEqual(w.owner_siblings, OWNER.path.siblings.map(String));
  assert.deepEqual(w.owner_bits, OWNER.path.bits.map(String));
  for (const address of [0n, 1n << 160n]) {
    assert.throws(() => spend({ ...OWNER, address }), /owner must be a nonzero address/);
  }
  const { siblings, bits } = OWNER.path;
  const short = { siblings: siblings.slice(1), bits: bits.slice(1) };
  assert.throws(() => spend({ ...OWNER, path: short }), /an owner's path has 16 levels/);
});
