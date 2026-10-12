/**
 * Disposable real-proof vectors for the occurrence-nullifier deployment: one .hex file per
 * transaction, entries.json and manifest.json in test/native/fixtures/. The native harness
 * executes every deployment, deposit, publication and spend; only the labelled large-tree
 * boundary cases seed reachable storage. Proofs are cached beside them, keyed by witness,
 * proving key and circuit, so a rerun with the fixed seed proves only what changed.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { p256 } from "@noble/curves/nist.js";

import { compareBigint, concat, fromHex, hex32, hexPadded, keccak } from "../../../src/bytes.ts";
import { toBigint, toBytes, toHex, word } from "../../../src/bytes.ts";
import { parseArgs, runCli } from "../../../src/cli/args.ts";
import { GeneratorError } from "../../../src/errors.ts";
import { spendEntry, type Proved } from "../../../src/fixtures.ts";
import { addressOf, APPROVE, ATOMIC_BATCH, MODE, rawTx, SCHEME } from "../../../src/frametx.ts";
import { rlpBytes, rlpInt, rlpList, sigHash } from "../../../src/frametx.ts";
import { signHash, totalGasLimit, type Frame, type FrameTx } from "../../../src/frametx.ts";
import type { FrameSig } from "../../../src/frametx.ts";
import * as gas from "../../../src/gas.ts";
import { canonical, isObject, parse, stringify } from "../../../src/json.ts";
import { OwnerSet, SoftwareOwner, type IndexedLeaf, type OwnerSigner } from "../../../src/owner.ts";
import * as protocol from "../../../src/protocol.ts";
import { prove, terminate, verify, WASM, ZKEY } from "../../../src/prover.ts";
import { seededRng } from "../../../src/random.ts";
import {
  defaultClaimTail,
  entryProofBytes,
  ownerSignature,
  parseSpend,
  settleCalldata,
  shieldCalldata,
  signTransaction,
  spendFrames,
  spendNonceKeys,
} from "../../../src/spend.ts";
import { buildWitness, dummyInput, newAuthorizer, newNote } from "../../../src/wallet.ts";
import { RepeatedTree, Tree, type MerkleTree, type Witness } from "../../../src/wallet.ts";
import { initcode } from "../../../tools/dispatcher.ts";

const { P, TREE_CAPACITY } = protocol;
const [CHAIN, SLOT, ETH] = [8141n, 100n, 10n ** 18n];
const eth = (hundredths: bigint) => (hundredths * ETH) / 100n;
const FEE = eth(5n);
const KEY = word(0xd3e10n);
const DEPLOYER = addressOf(KEY);
const [EOA, REJECTOR] = [0xcafebaben, 0xdeadn];
const ATTACKER = word(0xa77ac4e5n);
const P256_N = p256.Point.Fn.ORDER;
// One software owner holds every note's owner set and signs each spend with a fresh leaf.
const OWNER = new SoftwareOwner(
  keccak(new TextEncoder().encode("minimal-shielded-pool:native-owner")),
  64,
);

const addr = (x: bigint) => hexPadded(x, 40);
const utf8 = (text: string) => new TextEncoder().encode(text);
const createAddress = (nonce: bigint) =>
  toBigint(keccak(rlpList([rlpBytes(toBytes(DEPLOYER, 20)), rlpInt(nonce)])).slice(-20));
const NAMES = ["poseidon4", "verifier", "logic", "pool"];
const A = Object.fromEntries(NAMES.map((name, i) => [name, createAddress(BigInt(i))]));
const POOL = A.pool;

// The pool publishes notes without reading them, so these vectors carry fixed test bytes; the
// settlement gas cases carry a first payment's 1,184 bytes, the largest notes.
const repeat = (bytes: Uint8Array, n: number) => concat(...Array<Uint8Array>(n).fill(bytes));
const TEST_NOTE = repeat(keccak(utf8("minimal-shielded-pool:native-test-note")).slice(0, 16), 3);
const TEST_NOTES = toHex(repeat(TEST_NOTE, 2));
const CIPHERTEXT = repeat(keccak(utf8("minimal-shielded-pool:native-test-ciphertext")), 34);
const FIRST_PAYMENT_NOTES = toHex(concat(CIPHERTEXT, TEST_NOTE, TEST_NOTE));

// The statement values the settlement calldata carries, before the frontier's roots, in the
// order the proof binds them, and each one's word there: the selector, then
// protocol.SPEND_FIELDS, matched ignoring case, then the frontier's roots. The owner, which the
// proof binds after the authorizer, is the owner signature's signer, so it has no word here.
const STATEMENT =
  "nf1 nf2 out-cm1 out-cm2 domain public-amount fee recipient authorizer packed-ranks depth".split(
    " ",
  );
const settleWord = (value: string) =>
  4 + 32 * protocol.SPEND_FIELDS.findIndex((f) => f.toLowerCase() === value.replace("-", ""));
const frontierWord = (i: number) => 4 + 32 * (protocol.SPEND_FIELDS.length + i);

type Entry = Record<string, unknown>;
/** Storage slots in insertion order: a plain object would move "47" ahead of hashed keys. */
type Slots = Map<string, string>;
type Pair = [slot: string, value: bigint | number];
type Step = { raw?: string; storage?: Record<string, Slots>; [key: string]: unknown };
type Mutation = (frames: Frame[]) => void;

/** An entry's integer field, which spendEntry writes as 0x hex or decimal digits. */
const int = (entry: Entry, key: string) => BigInt(String(entry[key]));

// Pool storage: slot 0 holds the root, 1 a mapping of withdrawal credit by recipient, 2 the
// epoch, 3 a mapping of final roots by epoch, and 4 to 90 the epoch's MMR (LibSkewMmr.State):
// roots from 4, the packed ranks at 46, depth and count at 47, maxDepth at 48 and chains from 49.
const [ROOT_SLOT, EPOCH_SLOT, RANKS_SLOT, DEPTH_COUNT_SLOT] = ["0", "2", "46", "47"];
const [CREDITS, FINAL_ROOTS, MMR_ROOTS, MMR_CHAINS] = [1n, 3n, 4n, 49n];
function update(slots: Slots, ...pairs: Pair[]): Slots {
  for (const [slot, value] of pairs) slots.set(slot, String(value));
  return slots;
}
const slots = (...pairs: Pair[]) => update(new Map(), ...pairs);
const atPool = <T>(value: T) => ({ [addr(POOL)]: value });
/** keccak(word(key) || word(slot)): a Solidity mapping's storage key. */
const mapping = (key: bigint, slot: bigint) => toHex(keccak(concat(word(key), word(slot))));
const finalRoot = (root: bigint): Pair => [mapping(0n, FINAL_ROOTS), root];
/** The EIP-8250 nonce manager's slot for one of a spend's nullifier keys, by its entry field. */
const keySlot = (entry: Entry, key: string) => toHex(protocol.nonceKeySlot(POOL, int(entry, key)));
/** The slots of a spend's two nullifier keys, 1 once consumed. */
const keySlots = (entry: Entry, nf1: bigint, nf2 = nf1) =>
  slots([keySlot(entry, "nf1"), nf1], [keySlot(entry, "nf2"), nf2]);
/** The words an append changes: the root, the packed ranks, and depth with count. */
function mmrWords(tree: MerkleTree): Pair[] {
  const { roots, ranks, count } = tree.frontier();
  const depthCount = BigInt(roots.length) | (count << 8n);
  return [
    [ROOT_SLOT, tree.root()],
    [RANKS_SLOT, protocol.packRanks(ranks)],
    [DEPTH_COUNT_SLOT, depthCount],
  ];
}
/**
 * The pool's whole MMR as LibSkewMmr holds `tree`: mmrWords, each root, and each chain folding
 * the roots up to it, which the next append extends. Roots and chains above the depth are zero,
 * as in a pool whose epochs never reached them.
 */
function mmrSlots(tree: MerkleTree): Pair[] {
  const { roots } = tree.frontier();
  const pairs = mmrWords(tree);
  let chain = 0n;
  for (let i = 0; i < protocol.MAX_TREES; i++) {
    if (i < roots.length) chain = toBigint(keccak(concat(word(chain), word(roots[i]))));
    const at = (base: bigint) => String(base + BigInt(i));
    pairs.push([at(MMR_ROOTS), roots[i] ?? 0n], [at(MMR_CHAINS), i < roots.length ? chain : 0n]);
  }
  return pairs;
}
const synthetic = (seed: Slots, balance?: bigint): Step => ({
  synthetic_storage: atPool(seed),
  ...(balance === undefined ? {} : { synthetic_balances: atPool(String(balance)) }),
});
/** The pool after the tree's identical one-ether deposits: its MMR and balance. */
function seeded(tree: RepeatedTree): Step {
  return synthetic(slots(...mmrSlots(tree)), tree.frontier().count * ETH);
}
function treeOf(...cms: bigint[]): Tree {
  const tree = new Tree();
  for (const cm of cms) tree.append(cm);
  return tree;
}

/** A signed type-2 transaction from the deployer: deployments, deposits and publications. */
function ordinary(nonce: bigint, to: bigint | null, data: Uint8Array, value = 0n): Uint8Array {
  const fields = [CHAIN, nonce, 1n, 2n, 60_000_000n].map(rlpInt);
  fields.push(rlpBytes(to === null ? new Uint8Array(0) : toBytes(to, 20)), rlpInt(value));
  fields.push(rlpBytes(data), rlpList([]));
  const type = Uint8Array.of(0x02);
  const sig = signHash(keccak(concat(type, rlpList(fields))), KEY);
  const vrs = [sig.slice(0, 1), sig.slice(1, 33), sig.slice(33)].map((x) => rlpInt(toBigint(x)));
  return concat(type, rlpList([...fields, ...vrs]));
}

/** How a spend is built and what the harness expects of it. */
interface SpendOptions {
  mutate?: Mutation;
  maxFee?: bigint;
  nonceSeq?: bigint;
  nonceKeys?: bigint[];
  /** Sent in place of the built transaction. */
  raw?: Uint8Array;
  slot?: bigint;
  rejected?: boolean;
  error?: string;
  /**
   * The signatures after the authorizer's, from the entry and the settlement calldata the spend
   * carries: by default the entry's owner signature alone.
   */
  owners?: (entry: Entry, settle: Uint8Array) => FrameSig[];
  /** The withdrawal leaves credit instead of paying out. */
  failedClaim?: boolean;
  paid?: bigint;
  statuses?: number[];
  /** The nonce manager's slots afterwards, when not the spend's keys, consumed if accepted. */
  keys?: Slots;
  /** Pool slots settlement changes besides the recipient's credit. */
  pool?: Slots;
}

/**
 * A spend as the wallet builds it, changed by `mutate`, with the entry's owner signature (or
 * what `owners` makes of it) and signed by the entry's authorizer. Nothing is checked beyond the
 * owner signature, so an invalid spend still builds.
 */
function frameTx(entry: Entry, o: SpendOptions = {}): FrameTx {
  const source = protocol.sourceId(POOL, int(entry, "epoch"));
  const recentRoot = protocol.recentRootTuple(source, int(entry, "root_slot"), int(entry, "root"));
  const settle = settleCalldata(entry, entry.root_slot);
  const withdraws = int(entry, "public_amount") !== 0n;
  const tail = withdraws ? defaultClaimTail(POOL, int(entry, "recipient")) : null;
  const proof = entryProofBytes(entry);
  const frames = spendFrames({ pool: POOL, recentRoot, proof, settle, tail });
  o.mutate?.(frames);
  const tx: FrameTx = {
    chainId: CHAIN,
    nonceKeys: o.nonceKeys ?? spendNonceKeys(settle),
    nonceSeq: o.nonceSeq ?? 0n,
    sender: POOL,
    frames,
    signatures: [],
    maxPriorityFee: 1n,
    maxFee: o.maxFee ?? 2n,
    maxBlobFee: 0n,
    blobHashes: [],
  };
  const key = fromHex(entry.authorizer_private_key, "authorizer key");
  const owners = o.owners ?? ((e) => [honestOwner(e)]);
  return signTransaction(tx, key, ...owners(entry, frames[2].data));
}

/** The owner signature a fixture entry records, as the wallet sends it. */
const honestOwner = (entry: Entry) => ownerSignature(entry, CHAIN, POOL);

/**
 * The entry's owner leaf signing the intent of the settlement calldata as it stands, changed or
 * aliased words included. A case that changes a statement value the intent covers uses it, so
 * that only the proof or a range check can refuse the spend.
 */
function resigned(entry: Entry, settle: Uint8Array): FrameSig[] {
  const msg = protocol.intentDigest(CHAIN, POOL, protocol.decodeSettle(settle)!.spend);
  const signature = OWNER.sign(Number(entry.owner_leaf), msg);
  return [{ scheme: SCHEME.SECP256K1, signer: int(entry, "owner"), msg, signature }];
}

/** A DEFAULT frame that moves no value. */
function call(target: bigint, gasLimit: bigint, data: Uint8Array, stateLimit = 0n): Frame {
  return { mode: MODE.DEFAULT, flags: APPROVE.NONE, target, gasLimit, stateLimit, value: 0n, data };
}
const accountTail = () => call(EOA, gas.CLAIM_FRAME_GAS, Uint8Array.of(0x12, 0x34));
const addAccountTail: Mutation = (frames) => void frames.push(accountTail());
const setTail: Mutation = (frames) => void frames.splice(3, Infinity, accountTail());
function set(index: number, fields: Partial<Frame>): Mutation {
  return (frames) => void Object.assign(frames[index], fields);
}
/** Writes over a frame's data at `offset` with what `value` makes of the bytes there. */
function overwrite(index: number, offset: number, value: (old: Uint8Array) => Uint8Array) {
  return (frames: Frame[]) => {
    const data = frames[index].data.slice();
    data.set(value(data.subarray(offset)), offset);
    frames[index].data = data;
  };
}
const bumpWord = (index: number, offset: number, delta = 1n) =>
  overwrite(index, offset, (old) => word(toBigint(old.subarray(0, 32)) + delta));
function publishTail(epoch: bigint, stateLimit = gas.CLAIM_FRAME_STATE_GAS): Mutation {
  const data = protocol.encodePublish(epoch);
  return (frames) => void frames.push(call(POOL, gas.CLAIM_FRAME_GAS, data, stateLimit));
}

/**
 * The proof cached in dir as NAME-proof.json for this witness digest, or undefined if there is
 * none. A hit must verify against the committed verification key: CI builds the fixtures from
 * committed proofs without proving, and a case that expects a rejection would still pass on an
 * invalid proof, since the harness cannot tell it from the pool's own check refusing the spend.
 */
export async function readCachedProof(
  dir: string,
  name: string,
  digest: string,
): Promise<Proved | undefined> {
  const cache = join(dir, `${name}-proof.json`);
  const cached = existsSync(cache) ? parse(readFileSync(cache, "utf8")) : {};
  // A damaged cache file stops the run instead of being silently proved over.
  if (!isObject(cached)) throw new GeneratorError(`proof cache ${cache} is not a JSON object`);
  if (cached.witness_hash !== digest) return undefined;
  const publics = (cached.publics as bigint[]).map(BigInt);
  const proof = cached.proof as Proved["proof"];
  if (!(await verify(publics, proof))) {
    throw new GeneratorError(`the cached proof of ${name} does not verify`);
  }
  return { publics, proof };
}

/**
 * Writes every native fixture; see the module comment. With cacheOnly, a proof missing from the
 * cache fails the run instead of being proved.
 */
async function generateFixtures(cacheOnly: boolean): Promise<void> {
  // The source of every secret the fixtures hold.
  const rng = seededRng(20260921n);
  // The repository: core/contracts/out* are read and test/native/fixtures is written.
  const root = resolve(import.meta.dirname, "../../..");
  const out = join(root, "test", "native", "fixtures");
  mkdirSync(out, { recursive: true });
  const write = (name: string, text: string) => writeFileSync(join(out, name), text + "\n");
  const save = (name: string, raw: Uint8Array, expect: Step = {}): Step => {
    write(`${name}.hex`, toHex(raw));
    return { raw: `${name}.hex`, ...expect };
  };
  const artifact = (name: string, small = false) => {
    const build = join(root, "core", "contracts", small ? "out-libsmall" : "out");
    const json = parse(readFileSync(join(build, `${name}.sol`, `${name}.json`), "utf8"));
    return fromHex((json as { bytecode: { object: string } }).bytecode.object, name);
  };

  const constructors = [
    artifact("PoseidonT4", true),
    artifact("Groth16Verifier"),
    concat(artifact("ShieldedPoolLogic"), word(A.poseidon4)),
    initcode(A.logic, A.verifier),
  ];
  const setup = constructors.map((code, i) =>
    save(`deploy-${NAMES[i]}`, ordinary(BigInt(i), null, code)),
  );

  /** A note of `value` wei in the owner set `owners`. */
  const noteIn = (owners: OwnerSet, value: bigint) => {
    const [nk, rho] = newNote(rng);
    const pk = protocol.ownerPk(owners.root, nk);
    const inner = protocol.inner(pk, rho);
    return { nk, rho, value, inner, cm: protocol.commitment(pk, rho, value) };
  };
  const note = (value: bigint) => noteIn(OWNER.set, value);
  type Note = ReturnType<typeof note>;
  const [NA, NB, NC, ND] = [eth(100n), eth(95n), eth(70n), eth(60n)].map(note);
  const BASE = treeOf(NA.cm, NB.cm);

  const deposit = (name: string, n: Note, nonce: bigint, tree: Tree, slot = SLOT): Step => {
    const shield = shieldCalldata(hex32(n.inner), { note: toHex(TEST_NOTE) });
    return save(name, ordinary(nonce, POOL, shield, n.value), {
      slot_number: slot,
      storage: atPool(slots(...mmrWords(tree))),
      balance_delta_before_gas: atPool(String(n.value)),
    });
  };
  const publish = (name: string, nonce: bigint, epoch = 0n, slot = SLOT): Step =>
    save(name, ordinary(nonce, POOL, protocol.encodePublish(epoch)), { slot_number: slot });

  setup.push(deposit("deposit-a", NA, 4n, treeOf(NA.cm)), deposit("deposit-b", NB, 5n, BASE));
  setup.push(publish("publish-initial", 6n));
  const NEXT = 7n;
  const entries: Record<string, Entry> = {};
  const sha256 = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
  const ARTIFACT_HASHES = sha256(ZKEY) + sha256(WASM);

  /** The cached proof of a witness, or a new one. */
  async function cachedProof(name: string, witness: Witness): Promise<Proved> {
    // Keyed on the witness's canonical form, which earlier caches used, so they still hit.
    const digest = toHex(keccak(utf8(canonical(witness) + ARTIFACT_HASHES))).slice(2);
    const cached = await readCachedProof(out, name, digest);
    if (cached) return cached;
    if (cacheOnly) throw new GeneratorError(`proof cache miss for ${name}`);
    console.log(`proving ${name}`);
    const proved = await prove(witness, name);
    const record = { witness_hash: digest, publics: proved.publics, proof: proved.proof };
    write(`${name}-proof.json`, stringify(record, 2));
    return proved;
  }

  interface Proving {
    outputs?: protocol.Output[];
    recipient?: bigint;
    epoch?: bigint;
    rootSlot?: bigint;
    notes?: string;
    /** Proves against alpha over this statement value plus P; see the alias cases. */
    alias?: number;
    /** Reveals this owner leaf instead of OWNER's next one. */
    owner?: IndexedLeaf;
    /** Holds the leaf's key, by default OWNER. */
    device?: OwnerSigner;
    /** Spends beside this dummy instead of a fresh one. */
    dummy?: protocol.SpendInput;
  }

  /** Draws a spend's dummy input and authorizer, then proves it or reads its cached proof. */
  async function proveSpend(name: string, tree: MerkleTree, n: Note, i: bigint, o: Proving = {}) {
    const { outputs = protocol.sinkOutputs(), epoch = 0n, rootSlot = SLOT, alias } = o;
    const publicAmount = n.value - FEE - outputs.reduce((sum, [, v]) => sum + v, 0n);
    assert(publicAmount >= 0n, `${name} spends more than its input`);
    const recipient = publicAmount === 0n ? 0n : (o.recipient ?? EOA);
    const inputs = [{ nk: n.nk, rho: n.rho, value: n.value, idx: i }, o.dummy ?? dummyInput(rng)];
    const [authorizerKey, authorizer] = newAuthorizer(rng);
    const owner = o.owner ?? OWNER.nextLeaf();
    const domain = protocol.domainScalar(CHAIN, POOL, epoch);
    const terms = { authorizer, owner, publicAmount, fee: FEE, recipient };
    const witness = buildWitness(tree, inputs, outputs, domain, terms);
    let stmt: bigint[] | undefined;
    if (alias !== undefined) {
      // An honest witness proved against alpha over an aliased word, the statement value plus
      // P. gamma reduces the word modulo P, so only the pool's range checks tell them apart.
      const [nf1, nf2] = protocol.inputNullifiers(domain, owner.root, inputs);
      const [outCm1, outCm2] = protocol.outputCommitments(outputs);
      const values = { publicAmount, fee: FEE, recipient, authorizer, owner: owner.address };
      const { packedRanks, depth, frontier } = protocol.frontierFields(tree.frontier());
      const mmr = { packedRanks, depth, frontier };
      stmt = protocol.statement({ nf1, nf2, outCm1, outCm2, domain, ...values, ...mmr });
      const words = stmt.map((x, j) => (j === alias ? x + P : x));
      witness.alpha = String(toBigint(keccak(concat(...words.map(word)))) % P);
    }
    let proved = await cachedProof(name, witness);
    if (stmt) {
      // The publics the honest statement has, so spendEntry's wallet checks pass for an entry
      // whose proof binds the aliased alpha.
      const [beta] = proved.publics;
      const alpha = protocol.compressionAlpha(stmt);
      const gamma = protocol.fingerprint((alpha + beta) % P, stmt);
      proved = { ...proved, publics: [beta, gamma, alpha] };
    }
    const extra = { root_slot: String(rootSlot), notes: o.notes ?? TEST_NOTES };
    const signing = { device: o.device ?? OWNER, chainId: CHAIN, pool: POOL };
    const entryTerms = { ...terms, ...signing, epoch, authorizerKey };
    const entry: Entry = spendEntry(tree, domain, inputs, outputs, entryTerms, proved, extra);
    return (entries[name] = entry);
  }

  /** A spend step and what the harness expects of it: rejected, or its statuses and storage. */
  function spend(name: string, entry: Entry, o: SpendOptions = {}): Step {
    const amount = int(entry, "public_amount");
    const credit = slots([mapping(int(entry, "recipient"), CREDITS), o.failedClaim ? amount : 0n]);
    for (const [slot, value] of o.pool ?? []) credit.set(slot, value);
    const keys = o.keys ?? keySlots(entry, o.rejected ? 0n : 1n);
    const storage = { [addr(protocol.NONCE_MANAGER_ADDRESS)]: keys, ...atPool(credit) };
    const expect: Step = { slot_number: o.slot ?? 101n, storage };
    if (o.rejected) {
      expect.accepted = false;
    } else {
      const statuses = o.failedClaim ? [1, 1, 1, 0] : Array<number>(amount ? 4 : 3).fill(1);
      expect.statuses = o.statuses ?? statuses;
      expect.payer = addr(POOL);
      expect.balance_delta_before_gas = atPool(o.failedClaim ? "0" : String(-amount));
      if (o.paid !== undefined) expect.balances = { [addr(EOA)]: String(o.paid) };
    }
    if (o.error !== undefined) expect.error_contains = o.error;
    return save(name, o.raw ?? rawTx(frameTx(entry, o)), expect);
  }
  const POOL_VERIFY = `VERIFY frame 1 (target ${addr(POOL)}`;
  /** A spend the pool must refuse in its VERIFY frame, before approval. */
  const refused = (name: string, entry: Entry, mutate?: Mutation, more: SpendOptions = {}) =>
    spend(name, entry, { rejected: true, error: POOL_VERIFY, mutate, ...more });

  const cases: { name: string; transactions: Step[]; setup?: Step[] }[] = [];
  const addCase = (name: string, transactions: Step[], setup?: Step[]) =>
    void cases.push(setup ? { name, transactions, setup } : { name, transactions });

  // Two identical deposits share a nullifier, so only one of them can be withdrawn.
  const dupTree = treeOf(NA.cm, NB.cm, NA.cm);
  const dup0 = await proveSpend("deposit-copy-first", dupTree, NA, 0n, { rootSlot: 101n });
  const dup2 = await proveSpend("deposit-copy-second", dupTree, NA, 2n, { rootSlot: 101n });
  assert(dup0.nf1 === dup2.nf1, "duplicate deposits have two nullifiers");
  addCase("identical-funded-deposits-withdrawn-once", [
    deposit("deposit-a-again", NA, NEXT, dupTree, 101n),
    publish("publish-duplicates", NEXT + 1n, 0n, 101n),
    spend("withdraw-first-deposit", dup0, { slot: 102n, paid: ETH - FEE }),
    spend("withdraw-second-deposit", dup2, {
      slot: 103n,
      rejected: true,
      keys: keySlots(dup2, 1n, 0n),
    }),
  ]);

  // Private settlement may create a commitment that already exists. Settlement appends it, and
  // the two share a nullifier.
  const copyOutputs: protocol.Output[] = [[NB.inner, NB.value], protocol.sinkOutputs()[1]];
  const duplicate = await proveSpend("private-duplicate", BASE, NA, 0n, { outputs: copyOutputs });
  const privateTree = treeOf(NA.cm, NB.cm, NB.cm);
  const b1 = await proveSpend("private-copy-original", privateTree, NB, 1n, { rootSlot: 102n });
  const b2 = await proveSpend("private-copy-new", privateTree, NB, 2n, { rootSlot: 102n });
  assert(b1.nf1 === b2.nf1, "duplicate outputs have two nullifiers");
  const transfer = { pool: slots(...mmrWords(privateTree)) };
  addCase("private-duplicate-output-withdrawn-once", [
    spend("create-private-copy", duplicate, transfer),
    publish("publish-private-copy", NEXT, 0n, 102n),
    spend("withdraw-original-private", b1, { slot: 103n, paid: NB.value - FEE }),
    spend("withdraw-created-private", b2, {
      slot: 104n,
      rejected: true,
      keys: keySlots(b2, 1n, 0n),
    }),
  ]);

  // Different roots/slots do not turn the same occurrence into a new spend.
  const initial = await proveSpend("initial-a-withdrawal", BASE, NA, 0n);
  const paidA = { paid: NA.value - FEE };
  const later = treeOf(NA.cm, NB.cm, NC.cm);
  const replay = await proveSpend("same-occurrence-later-root", later, NA, 0n, { rootSlot: 102n });
  assert(initial.nf1 === replay.nf1, "one occurrence has two nullifiers");
  const replayed = { slot: 103n, rejected: true, keys: keySlots(replay, 1n, 0n) };
  addCase("same-occurrence-replay-later-root-and-slot", [
    spend("first-a-withdrawal", initial, paidA),
    deposit("append-after-spend", NC, NEXT, later, 102n),
    publish("publish-after-spend", NEXT + 1n, 0n, 102n),
    spend("replay-later-root", replay, replayed),
  ]);
  // The same spend proved again against a later root, beside the same dummy input and with the
  // same owner leaf, has the same nullifiers and outputs. Its intent omits the root, so the
  // owner's signature carries over unchanged and the wallet needs no new one.
  const [, recorded] = initial.inputs as { nk: string; rho: string }[];
  const dummy = { nk: BigInt(recorded.nk), rho: BigInt(recorded.rho), value: 0n, idx: null };
  const sameLeaf = OWNER.set.leaf(Number(initial.owner_leaf));
  const again = { rootSlot: 102n, owner: sameLeaf, dummy };
  const reproof = await proveSpend("reproof-later-root", later, NA, 0n, again);
  assert(reproof.nf2 === initial.nf2, "the re-proof has another dummy nullifier");
  assert(initial.owner_signature === reproof.owner_signature, "a re-proof needs a new signature");
  addCase("reproof-against-later-root-keeps-owner-signature", [
    deposit("append-before-reproof", NC, NEXT, later, 102n),
    publish("publish-before-reproof", NEXT + 1n, 0n, 102n),
    spend("withdraw-with-reproof", reproof, { slot: 103n, ...paidA }),
  ]);

  const badDomain = { ...initial, domain: hex32(protocol.domainScalar(CHAIN, POOL, 1n)) };
  const domainStep = spend("mutated-domain", badDomain, { rejected: true });
  addCase("mutated-domain-rejected-before-approval", [domainStep]);
  const epochStep = spend("mutated-epoch", { ...initial, epoch: "1" }, { rejected: true });
  addCase("mutated-epoch-rejected-before-approval", [epochStep]);

  // Reorg: restore the whole EVM database (keys, roots, balances and nonces), reorder two real
  // deposits, reject the old root, then rebuild the proof.
  const branchA = treeOf(NA.cm, NB.cm, NC.cm, ND.cm);
  const branchB = treeOf(NA.cm, NB.cm, ND.cm, NC.cm);
  const old = await proveSpend("reorg-old-branch", branchA, NC, 2n, { rootSlot: 101n });
  const rebuilt = await proveSpend("reorg-new-branch", branchB, NC, 3n, { rootSlot: 101n });
  assert(old.nf1 === rebuilt.nf1, "reordered deposits have two nullifiers");
  // The current root and frontier, which the dispatcher accepts, so the proof check refuses it.
  const frontierOf = ({ root, count, packed_ranks, depth, frontier }: Entry) => ({
    root,
    count,
    packed_ranks,
    depth,
    frontier,
  });
  const atBranchRoot = { ...old, ...frontierOf(rebuilt) };
  addCase("reorg-reordered-deposits-rebuild-proof", [
    { checkpoint: "before-branches" },
    deposit("branch-a-c", NC, NEXT, treeOf(NA.cm, NB.cm, NC.cm), 101n),
    deposit("branch-a-d", ND, NEXT + 1n, branchA, 101n),
    publish("publish-branch-a", NEXT + 2n, 0n, 101n),
    spend("spend-on-old-branch", old, { slot: 102n, paid: NC.value - FEE }),
    { restore: "before-branches" },
    deposit("branch-b-d", ND, NEXT, treeOf(NA.cm, NB.cm, ND.cm), 101n),
    deposit("branch-b-c", NC, NEXT + 1n, branchB, 101n),
    publish("publish-branch-b", NEXT + 2n, 0n, 101n),
    spend("old-branch-proof-rejected", old, { slot: 102n, rejected: true }),
    spend("old-branch-proof-current-root-rejected", atBranchRoot, { slot: 102n, rejected: true }),
    spend("rebuilt-branch-proof", rebuilt, { slot: 102n, paid: NC.value - FEE }),
  ]);

  const reject = await proveSpend("rejecting-recipient", BASE, NA, 0n, { recipient: REJECTOR });
  const rejectStep = spend("rejecting-recipient", reject, { failedClaim: true });
  addCase("failed-recipient-preserves-withdrawal-credit", [rejectStep]);

  const [OUT1, OUT2] = [eth(60n), eth(35n)].map(note);
  const outputs = [OUT1, OUT2].map((n): protocol.Output => [n.inner, n.value]);
  const newCredit: protocol.Output[] = [outputs[0], [OUT2.inner, eth(30n)]];
  // An append hashes at most once. With trees of ranks 18 down to 2, then 1 and 1, both outputs
  // merge: the most hashing a settlement does. With trees of ranks 18 down to 1, both outputs
  // start a tree at a depth no epoch has reached, so each writes a new root and chain; with a
  // retained credit, that is the five new storage slots check-gas-profile.ts bounds.
  const merges = (1n << 20n) - 19n;
  const pushes = (1n << 20n) - 22n;
  const rollover = TREE_CAPACITY - 1n;
  const gasCases: [string, bigint, protocol.Output[]][] = [
    ["two-merges", merges, outputs],
    ["two-merges-new-credit", merges, newCredit],
    ["two-merges-retained-credit", merges, newCredit],
    ["two-merges-one-output-new-credit", merges, [outputs[0], protocol.sinkOutputs()[1]]],
    ["two-new-trees-retained-credit", pushes, newCredit],
    ["rollover", rollover, outputs],
    ["rollover-new-credit", rollover, newCredit],
    ["rollover-retained-credit", rollover, newCredit],
    ["full-tree-rollover", TREE_CAPACITY, outputs],
  ];
  // The rollover settlement starts epoch 1 with its two outputs; later cases spend from it.
  let rolledOutputs = new Tree();
  let epochOutput: Entry = {};
  for (const [label, count, boundary] of gasCases) {
    const large = new RepeatedTree(NA.cm, count);
    const retained = label.includes("retained-credit");
    const recipient = retained ? REJECTOR : EOA;
    const proving = { outputs: boundary, rootSlot: 101n, recipient, notes: FIRST_PAYMENT_NOTES };
    const entry = await proveSpend(label, large, NA, 0n, proving);
    const added = protocol.outputCommitments(boundary).filter((_, i) => boundary[i][1]);
    const filled = count + BigInt(added.length);
    const next = treeOf(...added);
    const changed =
      filled > TREE_CAPACITY
        ? slots(...mmrWords(next), [EPOCH_SLOT, 1], finalRoot(large.root()))
        : slots(...mmrWords(new RepeatedTree(NA.cm, count, added)), [EPOCH_SLOT, 0]);
    const steps = [
      seeded(large),
      publish(`publish-${label}`, NEXT, 0n, 101n),
      spend(`settle-${label}`, entry, { slot: 102n, failedClaim: retained, pool: changed }),
    ];
    if (label === "rollover") {
      rolledOutputs = next;
      const epochOne = { epoch: 1n, rootSlot: 103n };
      epochOutput = await proveSpend("rolled-epoch-output", next, OUT1, 0n, epochOne);
      const paid = { slot: 104n, paid: OUT1.value - FEE };
      steps.push(
        publish("publish-rolled-epoch", NEXT + 1n, 1n, 103n),
        spend("withdraw-rolled-epoch-output", epochOutput, paid),
      );
    }
    addCase(`synthetic-reachable-${label}`, steps);
  }

  // A settlement limit below what settlement needs, pinned by a dispatcher with the sole
  // settlement gas literal (PUSH3 limit) changed: approval consumes the keys, then settlement
  // runs out. It is an expected failing settlement, which is why the pin covers the heaviest one.
  const LOW_LIMIT = 100_000n;
  const pin = (limit: bigint) => concat(Uint8Array.of(0x62), toBytes(limit, 3));
  const lowDispatcher = Buffer.from(constructors[3]);
  const at = lowDispatcher.indexOf(pin(gas.SETTLE_FRAME_GAS));
  const once = at >= 0 && lowDispatcher.indexOf(pin(gas.SETTLE_FRAME_GAS), at + 1) < 0;
  assert(once, "the dispatcher initcode must hold the settlement gas pin once");
  lowDispatcher.set(pin(LOW_LIMIT), at);
  const lowSetup = setup.with(3, save("deploy-pool-low-limit", ordinary(3n, null, lowDispatcher)));
  const lowEntry = entries["two-merges"];
  const lowBoundary = new RepeatedTree(NA.cm, merges);
  const lowSettlement = rawTx(frameTx(lowEntry, { mutate: set(2, { gasLimit: LOW_LIMIT }) }));
  const lowSteps = [
    seeded(lowBoundary),
    publish("publish-low-limit", NEXT, 0n, 101n),
    save("low-limit-settlement-failure", lowSettlement, {
      slot_number: 102n,
      statuses: [1, 1, 0],
      payer: addr(POOL),
      balance_delta_before_gas: atPool("0"),
      storage: {
        [addr(protocol.NONCE_MANAGER_ADDRESS)]: keySlots(lowEntry, 1n),
        ...atPool(slots(...mmrWords(lowBoundary))),
      },
    }),
  ];
  addCase("low-limit-consumes-keys-before-settlement-failure", lowSteps, lowSetup);

  // The rollover cases above create the first outputs of a fresh epoch from a closed epoch's
  // input. An MMR emptied by a rollover takes its first notes in the same transaction, and a
  // full epoch has reached every depth, so no settlement starts on an MMR with fresh slots below
  // the depth it reaches: two-new-trees-retained-credit is the five new slots bound.
  const baseFinal = finalRoot(BASE.root());

  // Same tree contents at a different authenticated epoch require a new proof and a different
  // nullifier, even when the occurrence index is identical.
  const epoch1 = await proveSpend("epoch-one-a", BASE, NA, 0n, { epoch: 1n, rootSlot: 101n });
  const rebound = { ...initial, epoch: "1", root_slot: "101", domain: epoch1.domain };
  addCase("authenticated-epoch-proof-binding", [
    synthetic(slots([EPOCH_SLOT, 1], baseFinal), 4n * ETH),
    publish("publish-epoch-one", NEXT, 1n, 101n),
    spend("old-proof-rebound-epoch", rebound, { slot: 102n, rejected: true }),
    spend("epoch-one-proof", epoch1, { slot: 102n, ...paidA }),
  ]);

  // Fourth-frame rules. Each rejected case breaks one rule of an otherwise valid spend and must
  // fail in the pool's VERIFY frame, before approval, so nonce keys, credits and balances stay
  // unchanged. The accepted controls keep that rule.
  const withdrawal = { failedClaim: true, paid: 0n };
  const [tailRuns, tailReverts] = [{ statuses: [1, 1, 1, 1] }, { statuses: [1, 1, 1, 0] }];
  const pop: Mutation = (frames) => void frames.pop();
  const noTail = { ...withdrawal, statuses: [1, 1, 1], mutate: pop };
  addCase("tail-omitted-withdrawal-leaves-credit", [
    spend("withdrawal-without-tail", initial, noTail),
  ]);
  const accountWithdrawal = { ...withdrawal, ...tailRuns, mutate: setTail };
  const accountTransfer = { ...transfer, ...tailRuns, mutate: addAccountTail };
  addCase("tail-generic-account-call-on-withdrawal-accepted", [
    spend("withdrawal-account-tail", initial, accountWithdrawal),
  ]);
  addCase("tail-generic-account-call-on-transfer-accepted", [
    spend("transfer-account-tail", duplicate, accountTransfer),
  ]);
  for (const [label, mutate] of [
    // A SENDER tail repeating the settlement frame would run as the pool and settle twice.
    ["sender-mode-second-settlement", (frames: Frame[]) => void (frames[3] = { ...frames[2] })],
    ["zero-target", set(3, { target: 0n })],
    ["approval-flag", set(3, { flags: APPROVE.PAYMENT })],
    ["settlement-atomic-batch-with-tail", set(2, { flags: ATOMIC_BATCH })],
    ["fifth-frame", addAccountTail],
  ] as const) {
    addCase(`tail-rejected-${label}`, [refused(`tail-${label}`, initial, mutate)]);
  }
  // Any spend's tail may call the pool but reaches only what any caller can: a transfer's tail
  // repeating the settlement call (which requires the pool as sender) or the proof call (frame
  // 1 only) reverts on its own, and the settlement stands with its keys consumed once. Each tail
  // has the gas to finish the call it repeats, so only the pool's checks stop it.
  for (const [label, index, execution, state] of [
    ["settlement", 2, gas.SETTLE_FRAME_GAS, gas.SETTLE_FRAME_STATE_GAS],
    ["verify-entry", 1, 500_000n, gas.VERIFY_FRAME_STATE_GAS],
  ] as const) {
    const mutate: Mutation = (frames) =>
      void frames.push(call(POOL, execution, frames[index].data, state));
    const reverting = { ...transfer, ...tailReverts, mutate };
    const step = spend(`transfer-pool-tail-${label}`, duplicate, reverting);
    addCase(`tail-pool-call-repeating-${label}-on-transfer-reverts`, [step]);
  }
  // EIP-8141 statically forbids value outside SENDER frames, so the client rejects this before
  // the dispatcher's own value check can run.
  const valueError = { error: "non-zero value only allowed in SENDER mode" };
  const nonzeroValue = refused("tail-nonzero-value", initial, set(3, { value: 1n }), valueError);
  addCase("tail-rejected-nonzero-value", [nonzeroValue]);

  // Validation-frame limits are wallet defaults, not dispatcher pins. Raising them is accepted;
  // a limit below what a frame needs makes the transaction invalid before approval, so nonce
  // keys and balances stay unchanged.
  const raised: Mutation = (frames) => {
    frames[0].gasLimit = 50_000n;
    Object.assign(frames[1], { gasLimit: 400_000n, stateLimit: 300_000n });
  };
  const raisedStep = spend("validation-limits-raised", initial, { ...paidA, mutate: raised });
  addCase("validation-limits-raised-accepted", [raisedStep]);
  for (const [label, index, change] of [
    ["recent-root-execution", 0, { gasLimit: 5_000n }],
    ["proof-execution", 1, { gasLimit: 200_000n }],
    ["proof-state", 1, { stateLimit: gas.VERIFY_FRAME_STATE_GAS - 1n }],
  ] as const) {
    const error = { error: `VERIFY frame ${index}` };
    const step = refused(`too-low-${label}`, initial, set(index, change), error);
    addCase(`validation-limit-too-low-${label}`, [step]);
  }

  // The pool approves payment only if the proof's fee covers the maximum cost of every declared
  // limit. At a price where the default limits just fit the fee, the spend is accepted, and
  // raising either validation frame's limit pushes the maximum cost past the fee.
  const maxFee = FEE / totalGasLimit(frameTx(initial)) - 1_000_000n;
  const covered = spend("fee-covers-defaults", initial, { ...paidA, maxFee });
  addCase("validation-fee-covers-defaults", [covered]);
  for (const [label, change] of [
    ["recent-root-execution", set(0, { gasLimit: 100_000n })],
    ["proof-state", set(1, { stateLimit: 300_000n })],
  ] as const) {
    const step = refused(`beyond-fee-${label}`, initial, change, { maxFee });
    addCase(`validation-limit-raised-beyond-fee-${label}`, [step]);
  }

  // Hybrid compression: the proof binds the statement values through alpha and gamma, which the
  // pool recomputes from the settlement calldata, and through beta, which follows the proof in
  // frame 1, so changing any one of them fails the pool's VERIFY frame. The owner signs each
  // changed intent again, so only the proof check can refuse it. nf1 and nf2 change in the entry
  // so the EIP-8250 keys follow, and the authorizer case re-signs the proof with an attacker's
  // key, so all three reach the proof check. The domain and the frontier (packed ranks, depth
  // and roots) are refused earlier by exact checks (old-branch-proof-current-root-rejected and
  // old-proof-rebound-epoch take changed ones to the verifier). The owner is the owner
  // signature's signer, which owner-signature-by-a-key-outside-the-set changes. The dispatcher
  // and the verifier both refuse a beta outside the field.
  const stolen: Entry = { ...initial, authorizer: addr(addressOf(ATTACKER)) };
  stolen.authorizer_private_key = toHex(ATTACKER);
  const resign = { owners: resigned };
  for (const value of STATEMENT) {
    const name = `changed-${value}`;
    const step =
      value === "authorizer"
        ? refused(name, stolen, undefined, resign)
        : value.startsWith("nf")
          ? refused(
              name,
              { ...initial, [value]: hex32(int(initial, value) + 1n) },
              undefined,
              resign,
            )
          : refused(name, initial, bumpWord(2, settleWord(value)), resign);
    addCase(`compression-statement-${value}-changed-rejected`, [step]);
  }
  const rootStep = refused("changed-frontier-root", initial, bumpWord(2, frontierWord(0)));
  addCase("compression-statement-frontier-root-changed-rejected", [rootStep]);
  const betaStep = refused("changed-beta", initial, bumpWord(1, 256));
  addCase("compression-beta-changed-rejected", [betaStep]);
  const outside = refused("beta-outside-field", initial, bumpWord(1, 256, P));
  addCase("compression-beta-outside-field-rejected", [outside]);

  // Two independently signed private transfers are reusable policy fixtures.
  const policyOutputs: protocol.Output[] = [
    [NC.inner, eth(50n)],
    [ND.inner, eth(40n)],
  ];
  const policyB = await proveSpend("policy-second", BASE, NB, 1n, { outputs: policyOutputs });
  save("policy-first", rawTx(frameTx(duplicate)));
  save("policy-second", rawTx(frameTx(policyB)));

  // What a pool tail is for: a transfer that publishes its own root, so the note it creates can
  // be spent from the next slot without a separate publication. Proved last so the earlier
  // proofs keep their witnesses.
  const created = await proveSpend("tail-published-copy", privateTree, NB, 2n, { rootSlot: 101n });
  const paidB = { paid: NB.value - FEE };
  const publishing = { ...transfer, ...tailRuns, mutate: publishTail(0n) };
  addCase("tail-transfer-publishes-root-then-created-note-withdrawn", [
    spend("transfer-publishes-root", duplicate, publishing),
    spend("withdraw-note-from-tail-root", created, { slot: 102n, ...paidB }),
  ]);

  // If the tail's publication fails, only the publication is retried: settlement stands and has
  // already consumed the inputs. Here the tail has no state gas for the new root slot.
  const failing = { ...transfer, ...tailReverts, mutate: publishTail(0n, 0n) };
  const retry = { ...created, root_slot: "102" };
  addCase("tail-publication-fails-then-publication-retried", [
    spend("transfer-publication-fails", duplicate, failing),
    publish("publish-retried", NEXT, 0n, 102n),
    spend("withdraw-after-retried-publication", retry, { slot: 103n, ...paidB }),
  ]);

  // The tail must publish the epoch the outputs land in. This transfer's two outputs do not fit
  // in the tree's one free leaf, so settlement starts epoch 1 and inserts them there. Publishing
  // epoch 1 makes them spendable from the next slot. Publishing epoch 0 still succeeds, with
  // epoch 0's final root, which lacks them; only a later publication of epoch 1 helps.
  const rolled = new RepeatedTree(NA.cm, rollover);
  const rolledState = seeded(rolled);
  const rolledRoot = finalRoot(rolled.root());
  const epochOne = slots(...mmrWords(rolledOutputs), [EPOCH_SLOT, 1], rolledRoot);
  const rolledSpend = { slot: 102n, ...tailRuns, pool: epochOne };
  const rolledTransfer = (name: string, epoch: bigint) =>
    spend(name, entries.rollover, { ...rolledSpend, mutate: publishTail(epoch) });
  const outputNextSlot = { ...epochOutput, root_slot: "102" };
  const paidOut1 = { paid: OUT1.value - FEE };
  addCase("tail-publishes-output-epoch-after-rollover", [
    rolledState,
    publish("publish-before-rollover-tail", NEXT, 0n, 101n),
    rolledTransfer("rollover-tail-publishes-epoch-one", 1n),
    spend("withdraw-output-from-tail-root", outputNextSlot, { slot: 103n, ...paidOut1 }),
  ]);
  const unpublished = { slot: 103n, error: "VERIFY frame 0" };
  addCase("tail-publishing-input-epoch-after-rollover-misses-outputs", [
    rolledState,
    publish("publish-before-wrong-epoch-tail", NEXT, 0n, 101n),
    rolledTransfer("rollover-tail-publishes-epoch-zero", 0n),
    refused("output-root-not-published", outputNextSlot, undefined, unpublished),
    publish("publish-epoch-one-later", NEXT + 1n, 1n, 103n),
    spend("withdraw-output-after-later-publication", epochOutput, { slot: 104n, ...paidOut1 }),
  ]);

  // The pool's range checks are load-bearing: the verifier no longer sees the statement. Each
  // case proves an honest withdrawal against alpha over one value plus P, with the nonce keys
  // following, and the owner signs the aliased intent, as an owner who wanted the pool to pay
  // for a settlement bound to revert could, so only the range check can refuse it before
  // approval. The domain, the authorizer and the frontier are pinned by exact checks instead,
  // and the owner is a signer's address. entries.json holds the changed entries.
  for (const [alias, value] of STATEMENT.entries()) {
    if (["domain", "authorizer", "packed-ranks", "depth"].includes(value)) continue;
    const aliased = await proveSpend(`alias-${value}`, BASE, NA, 0n, { alias });
    // The recipient moves in the settlement calldata; the other values move in the entry, so
    // the settlement and, for nf1 and nf2, the nonce keys carry them.
    const key = value.replace("-", "_");
    if (value !== "recipient") {
      const moved = int(aliased, key) + P;
      aliased[key] = key === "public_amount" || key === "fee" ? String(moved) : hex32(moved);
    }
    const mutate = value === "recipient" ? bumpWord(2, settleWord(value), P) : undefined;
    const step = refused(`aliased-${value}`, aliased, mutate, resign);
    addCase(`compression-${value}-aliased-by-p-rejected`, [step]);
  }

  // The frontier must open the root the recent-root frame names (LibSkewMmrVerifier), with no
  // root above its depth and no depth above MAX_TREES, or a spend could prove membership in a
  // frontier the pool never held under a root it did.
  const depth = Number(int(initial, "depth"));
  for (const [label, mutate] of [
    ["changed-count", bumpWord(2, settleWord("count"))],
    ["nonzero-root-above-depth", bumpWord(2, frontierWord(depth))],
    ["depth-above-max-trees", bumpWord(2, settleWord("depth"), BigInt(protocol.MAX_TREES))],
  ] as const) {
    addCase(`frontier-${label}-rejected`, [refused(`frontier-${label}`, initial, mutate)]);
  }

  // These dispatcher checks stop theft, a burn or a gas drain, yet every case above passed with
  // any one of them deleted, so each case below breaks one in an otherwise valid spend. A spent
  // key set replayed at nonce_seq 1 would pay out again.
  const spent = { slot: 102n, keys: keySlots(initial, 1n) };
  addCase("spent-keys-replayed-at-seq-one-rejected", [
    spend("spend-before-seq-replay", initial, paidA),
    refused("replay-spent-keys-at-seq-one", initial, undefined, { ...spent, nonceSeq: 1n }),
  ]);
  // The victim's signature over the transaction hash, re-sent as an explicit message in a
  // transaction with another fourth frame, is valid under EIP-8141.
  const victim = frameTx(initial);
  const rewrap = frameTx(initial, { mutate: setTail });
  rewrap.signatures[0] = { ...victim.signatures[0], msg: sigHash(victim) };
  const rewrapRaw = { raw: rawTx(rewrap) };
  const rewrapped = refused("signature-explicit-message", initial, undefined, rewrapRaw);
  addCase("signature-rewrapped-as-explicit-message-rejected", [rewrapped]);
  // A signature by another key, here the attacker's own over another fourth frame, would let
  // anyone who sees a pending spend choose its tail and fees.
  const other = signTransaction(
    frameTx(initial, { mutate: setTail }),
    ATTACKER,
    honestOwner(initial),
  );
  const otherKey = refused("signature-other-key", initial, undefined, { raw: rawTx(other) });
  addCase("signature-by-another-key-rejected", [otherKey]);

  // The owner's signature. Each case changes only the signatures of a valid spend, so the pool
  // must refuse it in VERIFY frame 1, before approval. A spend without the owner's signature,
  // or with a third signature, has another shape. A signature over another intent, over the
  // same intent for another pool, or over the transaction hash does not carry the spend's
  // intent digest. The intent signed by a key outside the owner set makes that key the owner,
  // which the proof does not name. The owner signs second, after the authorizer.
  const authorizerKey = fromHex(initial.authorizer_private_key, "authorizer key");
  const leaf = Number(initial.owner_leaf);
  const intent = parseSpend(initial, 0n);
  const signed = (msg: Uint8Array, key?: Uint8Array): FrameSig => ({
    scheme: SCHEME.SECP256K1,
    signer: key === undefined ? int(initial, "owner") : addressOf(key),
    msg,
    signature: key === undefined ? OWNER.sign(leaf, msg) : signHash(msg, key),
  });
  const otherIntent = protocol.intentDigest(CHAIN, POOL, { ...intent, fee: intent.fee + 1n });
  const otherPool = protocol.intentDigest(CHAIN, DEPLOYER, intent);
  for (const [label, owners] of [
    ["missing", () => []],
    ["repeated", (e: Entry) => [honestOwner(e), honestOwner(e)]],
    ["over-another-intent", () => [signed(otherIntent)]],
    ["for-another-pool", () => [signed(otherPool)]],
    ["by-a-key-outside-the-set", (e: Entry) => [signed(honestOwner(e).msg, ATTACKER)]],
  ] as const) {
    addCase(`owner-signature-${label}-rejected`, [
      refused(`owner-signature-${label}`, initial, undefined, { owners }),
    ]);
  }
  const empty = new Uint8Array(0);
  const overHash = frameTx(initial, {
    owners: (e) => [{ ...honestOwner(e), msg: empty, signature: empty }],
  });
  overHash.signatures[1].signature = OWNER.sign(leaf, sigHash(overHash));
  const hashStep = refused("owner-signature-over-transaction-hash", initial, undefined, {
    raw: rawTx(overHash),
  });
  addCase("owner-signature-over-transaction-hash-rejected", [hashStep]);
  const swapped = frameTx(initial);
  const [authorizerSig, ownerSig] = swapped.signatures;
  swapped.signatures = [ownerSig, { ...authorizerSig, signature: empty }];
  swapped.signatures[1].signature = signHash(sigHash(swapped), authorizerKey);
  const swappedStep = refused("owner-signature-first", initial, undefined, {
    raw: rawTx(swapped),
  });
  addCase("owner-signature-before-authorizer-rejected", [swappedStep]);

  // A P-256 owner: the protocol validates its signature, and its address is a leaf of the
  // owner set its note belongs to, but the pool takes secp256k1 owners only, so every spend
  // has one shape.
  const p256Key = word(
    1n + (toBigint(keccak(utf8("minimal-shielded-pool:native-p256-owner"))) % (P256_N - 1n)),
  );
  const p256Point = p256.getPublicKey(p256Key, false).subarray(1);
  const p256Set = new OwnerSet([toBigint(keccak(p256Point).subarray(12))]);
  const p256Device = {
    sign: (_: number, digest: Uint8Array) =>
      concat(p256.sign(digest, p256Key, { prehash: false, lowS: true }), p256Point),
  };
  const NP = noteIn(p256Set, eth(80n));
  const p256Tree = treeOf(NA.cm, NB.cm, NP.cm);
  const p256Proving = { owner: p256Set.leaf(0), device: p256Device, rootSlot: 101n };
  const p256Entry = await proveSpend("p256-owner", p256Tree, NP, 2n, p256Proving);
  const p256Owner = (e: Entry): FrameSig[] => [
    {
      scheme: SCHEME.P256,
      signer: int(e, "owner"),
      msg: protocol.intentDigest(CHAIN, POOL, parseSpend(e, 0n)),
      signature: fromHex(e.owner_signature, "the P-256 owner signature", 128),
    },
  ];
  const p256Steps = [
    deposit("deposit-p256-note", NP, NEXT, p256Tree, 101n),
    publish("publish-p256-note", NEXT + 1n, 0n, 101n),
    refused("owner-signature-p256", p256Entry, undefined, { owners: p256Owner, slot: 102n }),
  ];
  addCase("owner-signature-p256-rejected", p256Steps);
  // A DEFAULT settlement frame would run after approval, revert on its sender check and leave
  // the input keys consumed.
  const defaultMode = refused("settlement-default-mode", initial, set(2, { mode: MODE.DEFAULT }));
  addCase("settlement-default-mode-rejected", [defaultMode]);
  // Frame 0 must be the recent-root verifier. The identity precompile echoes any tuple, so a
  // root of the attacker's own tree, holding a note nobody deposited, would withdraw other
  // users' deposits. Proved last so earlier proofs keep their witnesses.
  const toIdentity = set(0, { target: 4n });
  const identity = refused("recent-root-identity", initial, toIdentity);
  addCase("recent-root-frame-to-identity-precompile-rejected", [identity]);
  const UNDEPOSITED = note(eth(190n));
  const forgedTree = treeOf(NA.cm, NB.cm, UNDEPOSITED.cm);
  const forged = await proveSpend("forged-root", forgedTree, UNDEPOSITED, 2n);
  const forgedIdentity = refused("forged-root-identity", forged, toIdentity);
  addCase("forged-root-through-identity-precompile-rejected", [forgedIdentity]);

  // The same forged root through a genuine recent-root frame. Anyone can publish a root to
  // EIP-8272 under their own source, so frame 0 must name the pool's source for the epoch; and
  // a genuine tuple for the pool's real root must match the root the proof uses.
  const forgedTuple = concat(word(0n), word(int(forged, "root")));
  const ownSource = overwrite(0, 0, () => protocol.sourceId(DEPLOYER, 0n));
  const forgedPublication = ordinary(NEXT, protocol.RECENT_ROOT_ADDRESS, forgedTuple);
  addCase("forged-root-published-under-another-source-rejected", [
    save("publish-forged-root", forgedPublication, { slot_number: 101n }),
    refused("forged-root-other-source", { ...forged, root_slot: "101" }, ownSource, { slot: 102n }),
  ]);
  const genuineTuple = overwrite(0, 40, () => word(BASE.root()));
  const genuine = refused("forged-root-genuine-tuple", forged, genuineTuple);
  addCase("forged-root-beside-genuine-tuple-rejected", [genuine]);
  // The consumed keys must be the proof's nullifiers. Fresh keys would let a spent note settle
  // again.
  const freshKeys = [int(initial, "nf1") ^ 1n, int(initial, "nf2") ^ 1n].sort(compareBigint);
  addCase("spent-note-with-fresh-keys-rejected", [
    spend("spend-before-fresh-keys", initial, paidA),
    refused("respend-with-fresh-keys", initial, undefined, { ...spent, nonceKeys: freshKeys }),
  ]);
  // A valid proof over another epoch's domain would pass the proof check and then revert in
  // settlement, with the pool paying the gas.
  const foreign = refused("foreign-domain", { ...epoch1, epoch: "0", root_slot: String(SLOT) });
  addCase("proof-over-another-epochs-domain-rejected", [foreign]);
  // Settlement's limits are pinned exactly. One below each pin is the tightest boundary; 20,000
  // execution gas or no state gas would run out after approval and leave the inputs spent with
  // nothing paid or credited.
  for (const [label, change] of [
    ["execution-limit-one-below-profile", { gasLimit: gas.SETTLE_FRAME_GAS - 1n }],
    ["state-limit-one-below-profile", { stateLimit: gas.SETTLE_FRAME_STATE_GAS - 1n }],
    ["execution-limit-that-runs-out", { gasLimit: 20_000n }],
    ["state-limit-that-runs-out", { stateLimit: 0n }],
  ] as const) {
    addCase(`settlement-${label}-rejected`, [refused(`settle-${label}`, initial, set(2, change))]);
  }

  // Checks that cover each other: each case survives deleting either check alone and fails only
  // when both go. A DEFAULT-mode frame 0 whose validation reverts would pass on its bytes alone
  // without both the mode and the status check, and a settlement frame to the attacker carrying
  // the pool's balance would pay out without both the target and the value check.
  const toDefault = set(0, { mode: MODE.DEFAULT });
  const defaultFrame0 = refused("forged-root-default-frame", forged, toDefault);
  addCase("forged-root-in-failed-default-frame-rejected", [defaultFrame0]);
  const toAttacker = set(2, { target: addressOf(ATTACKER), value: eth(190n) });
  const drained = refused("settlement-to-another-account", initial, toAttacker);
  addCase("settlement-frame-paying-the-pool-to-another-account-rejected", [drained]);

  write("rejector-runtime.hex", "0x60006000fd");
  write("entries.json", stringify(entries, 2));
  const deployer = { address: addr(DEPLOYER), balance: String(100n * ETH) };
  const rejector = { address: addr(REJECTOR), balance: "0", code: "rejector-runtime.hex" };
  const chain = { chain_id: CHAIN, slot_number: SLOT, base_fee: 1, block_gas_limit: 60_000_000 };
  write("manifest.json", stringify({ ...chain, accounts: [deployer, rejector], setup, cases }, 2));
  console.log(`generated ${cases.length} native cases, ${Object.keys(entries).length} real proofs`);
}

const SPEC = {
  prog: "generate-fixtures.ts",
  description:
    "Write the native fixtures under test/native/fixtures/, proving what the cache lacks.",
  options: {
    "--cache-only": { kind: "flag", help: "fail on a proof missing from the cache, never prove" },
  },
} as const;

if (import.meta.main) {
  await runCli(async () => {
    const { options } = parseArgs(SPEC, process.argv.slice(2));
    await generateFixtures(options["--cache-only"]).finally(terminate);
  });
}
