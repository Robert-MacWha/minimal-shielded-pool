/**
 * The pool's protocol: note hashes, the nullifier and its domain, the proof statement and its
 * hybrid compression, the owner's EIP-712 spend intent, EIP-8272 recent-root keys, and the
 * pool's ABI and events. The circuit, the dispatcher and the logic contract compute the same
 * values, so every encoding here is consensus-critical. Hashes reduce any bigint modulo P, as
 * the circuit does; encoders check only ABI ranges, since wallet policy belongs to callers and
 * the native generator encodes deliberately invalid words.
 */
import {
  addressFromText,
  concat,
  equalBytes,
  fromHex,
  keccak,
  mod,
  parseHex,
  toBigint,
  toBytes,
  toHex,
  word,
} from "./bytes.ts";
import { InputError } from "./errors.ts";
import {
  SETTLE_FRAME_DATA_BYTES,
  SETTLE_SPEND_BYTES,
  SHIELD_NOTE_BYTES,
  SPEND_NOTES_BYTES,
} from "./gas.ts";
import { P, poseidon } from "./poseidon.ts";

export { P };

const utf8 = (text: string) => new TextEncoder().encode(text);
const fits = (value: bigint, bits: bigint) => value >= 0n && value < 1n << bits;

// ---- field, tree and note hashes (mirror core/circuits/spend.circom) ----

/** The most trees an epoch's skew-MMR holds, as in the circuit, the dispatcher and the pool. */
export const MAX_TREES = 20;
/** An MMR of at most MAX_TREES trees holds 2^(MAX_TREES + 1) - MAX_TREES - 2 notes. */
export const TREE_CAPACITY = (1n << BigInt(MAX_TREES + 1)) - BigInt(MAX_TREES) - 2n;
/** An owner set is a depth-16 tree of addresses, so it holds up to 2^16 one-time signers. */
export const OWNER_DEPTH = 16;
/** Values are below 2^128, so the circuit's conservation sum cannot wrap the field. */
export const MAX_VALUE = 1n << 128n;

export const TAG_PK = 1n;
export const TAG_LEAF = 2n;
export const TAG_OCCURRENCE_NULL = 4n;

export function p2(a: bigint, b: bigint): bigint {
  return poseidon([a, b]);
}

/** Poseidon(tag, a, b): the tag separates owner keys, leaves and nullifiers. */
export function tagged(tag: bigint, a: bigint, b: bigint): bigint {
  return poseidon([tag, a, b]);
}

/**
 * A note's owner key: the root of the owner set whose addresses can authorize its spend, and
 * the nullifier key nk, which the wallet holds to prove its notes and see when they are
 * spent. Neither spends.
 */
export function ownerPk(ownerRoot: bigint, nk: bigint): bigint {
  return tagged(TAG_PK, ownerRoot, nk);
}

/** What a recipient reveals to be paid: it hides the owner key pk and rho. */
export function inner(pk: bigint, rho: bigint): bigint {
  return p2(pk, rho);
}

/** A note's commitment and tree leaf, as shield computes it. */
export function commitment(pk: bigint, rho: bigint, value: bigint): bigint {
  return tagged(TAG_LEAF, inner(pk, rho), value);
}

/**
 * The domain key p2(domain, nk). With a note's position, it finds when the note is spent in that
 * epoch's domain, so disclosure receipts publish it and never nk.
 */
export function domainKey(domain: bigint, nk: bigint): bigint {
  return p2(domain, nk);
}

/**
 * A note occurrence's nullifier from its domain key. The index, the note's position in its
 * epoch's MMR in insertion order, is hashed in, so two deposits of one commitment are spent
 * independently.
 */
export function nullifierFromKey(key: bigint, cm: bigint, index: bigint): bigint {
  if (index < 0n || index >= TREE_CAPACITY) {
    throw new InputError("note index outside the epoch's MMR");
  }
  return tagged(TAG_OCCURRENCE_NULL, key, p2(cm, index));
}

/** A note occurrence's nullifier in the domain of the epoch it was appended to. */
export function nullifier(domain: bigint, nk: bigint, cm: bigint, index: bigint): bigint {
  return nullifierFromKey(domainKey(domain, nk), cm, index);
}

export const DOMAIN_TAG = keccak(utf8("minimal-shielded-pool:occurrence-domain:v1"));

/**
 * The nullifier domain of a pool epoch: keccak256(DOMAIN_TAG || chainId || pool || epoch) over
 * 32-byte words, mod P. The pool is an integer or "0x" and 40 hex digits.
 */
export function domainScalar(chainId: bigint, pool: bigint | string, epoch = 0n): bigint {
  const address = typeof pool === "bigint" ? pool : addressFromText(pool);
  if (address === null || !fits(address, 160n) || !fits(chainId, 256n) || !fits(epoch, 64n)) {
    throw new InputError("domain inputs must be uint256 chain_id, address20 pool and uint64 epoch");
  }
  return toBigint(keccak(concat(DOMAIN_TAG, word(chainId), word(address), word(epoch)))) % P;
}

// ---- the MMR's frontier (mirrors LibSkewMmr and LibSkewMmrVerifier) ----

/** An epoch's MMR as the pool holds it: its tree roots, oldest first, and their ranks. */
export interface Frontier {
  roots: readonly bigint[];
  ranks: readonly number[];
  /** The number of notes the MMR holds. */
  count: bigint;
}

/** The ranks as LibSkewMmr packs them, tree i's rank at bits 6i to 6i + 6. */
export function packRanks(ranks: readonly number[]): bigint {
  return ranks.reduce((packed, rank, i) => packed | (BigInt(rank) << BigInt(6 * i)), 0n);
}

/**
 * The root the pool publishes for a frontier: keccak256(chain, packedRanks, depth, count) over
 * words, where chain folds keccak256(chain, root) over the roots from zero.
 */
export function frontierRoot({ roots, ranks, count }: Frontier): bigint {
  const chain = roots.reduce((c, root) => toBigint(keccak(concat(word(c), word(root)))), 0n);
  const depth = BigInt(roots.length);
  return toBigint(keccak(concat(word(chain), word(packRanks(ranks)), word(depth), word(count))));
}

/** The root of an empty MMR, which the dispatcher stores at deployment. */
export const EMPTY_ROOT = frontierRoot({ roots: [], ranks: [], count: 0n });

/** The frontier's fields of a Spend: the roots padded with zeros to MAX_TREES. */
export function frontierFields(
  f: Frontier,
): Pick<Spend, "count" | "packedRanks" | "depth" | "frontier"> {
  const padding = Array<bigint>(MAX_TREES - f.roots.length).fill(0n);
  const depth = BigInt(f.roots.length);
  return {
    count: f.count,
    packedRanks: packRanks(f.ranks),
    depth,
    frontier: [...f.roots, ...padding],
  };
}

// ---- statement and hybrid compression ----

/**
 * One spend input as the witness takes it: its nullifier key, rho, value and leaf, idx being null
 * for a zero-value dummy. Both inputs belong to the spend's owner set.
 */
export interface SpendInput {
  nk: bigint;
  rho: bigint;
  value: bigint;
  idx: bigint | null;
}

export type Output = readonly [inner: bigint, value: bigint];

/** Output k with value 0 must use SINK_INNERS[k]. */
export const SINK_INNERS: readonly bigint[] = Object.freeze([1n, 2n]);

export function sinkOutputs(): Output[] {
  return SINK_INNERS.map((sink) => [sink, 0n] as const);
}

/** The sink outputs' commitments, which the pool recognises and does not append. */
export function sinkCommitments(): bigint[] {
  return outputCommitments(sinkOutputs());
}

/**
 * The nullifiers of inputs in the owner set with root ownerRoot, in order. A zero-value input is
 * never in the MMR, so the circuit gives it index 0.
 */
export function inputNullifiers(
  domain: bigint,
  ownerRoot: bigint,
  inputs: readonly SpendInput[],
): bigint[] {
  return inputs.map((i) => {
    const cm = commitment(ownerPk(ownerRoot, i.nk), i.rho, i.value);
    return nullifier(domain, i.nk, cm, i.value === 0n || i.idx === null ? 0n : i.idx);
  });
}

export function outputCommitments(outputs: readonly Output[]): bigint[] {
  return outputs.map(([out, value]) => tagged(TAG_LEAF, out, value));
}

/**
 * What a proof binds: the settlement's values but its root, root slot, epoch and count, then the
 * owner, the address the pool reads from the owner's signature entry.
 */
export type Statement = Omit<Spend, "root" | "rootSlot" | "epoch" | "count"> & { owner: bigint };

/** The statement's length: ten spend values, packedRanks, depth and the padded frontier. */
export const STATEMENT_LENGTH = 12 + MAX_TREES;

/** The values a proof binds, in the order the circuit and the pool hash them. */
export function statement(s: Statement): bigint[] {
  const hashes = [s.nf1, s.nf2, s.outCm1, s.outCm2, s.domain];
  const terms = [s.publicAmount, s.fee, s.recipient, s.authorizer, s.owner];
  return [...hashes, ...terms, s.packedRanks, s.depth, ...s.frontier];
}

/**
 * The contract-side hash: keccak256 of the values as words, mod P. The pool refuses a word at
 * or above P, since x + P would give another alpha for the same statement, and so does this.
 */
export function compressionAlpha(stmt: readonly bigint[]): bigint {
  if (stmt.length !== STATEMENT_LENGTH || stmt.some((x) => x < 0n || x >= P)) {
    throw new RangeError(`a statement is ${STATEMENT_LENGTH} field elements`);
  }
  return toBigint(keccak(concat(...stmt.map(word)))) % P;
}

/** The circuit-side hash: the values chained into Poseidon of two, from zero (StatementDigest). */
export function compressionBeta(stmt: readonly bigint[]): bigint {
  if (stmt.length !== STATEMENT_LENGTH) {
    throw new RangeError(`a statement is ${STATEMENT_LENGTH} values`);
  }
  return stmt.reduce((digest, x) => poseidon([digest, x]), 0n);
}

/** x0 + x1 * sigma + ... + xn * sigma^n mod P. The pool's gamma uses sigma = alpha + beta. */
export function fingerprint(sigma: bigint, stmt: readonly bigint[]): bigint {
  return stmt.reduceRight((acc, x) => mod(acc * sigma + x, P), 0n);
}

// ---- the owner's spend intent (EIP-712) ----

/**
 * The owner signs the spend's EIP-712 intent, which an Ethereum wallet or hardware device can
 * sign as typed data: its nullifiers and outputs, which name the notes it spends and creates,
 * and its withdrawal and fee. It omits the root, the epoch and the authorizer, so a wallet can
 * prove a spend again against a newer root, or under a new authorizer, without a new signature.
 * The dispatcher computes the same digest and requires it as the owner signature's msg.
 */
export const INTENT_DOMAIN_TYPE =
  "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
export const INTENT_DOMAIN_NAME = "Minimal Shielded Pool";
export const INTENT_TYPE =
  "Spend(bytes32 nullifier1,bytes32 nullifier2,bytes32 output1,bytes32 output2," +
  "uint256 amount,address recipient,uint256 fee)";

/** The values of a spend that the owner's intent names. */
export type Intent = Pick<
  Statement,
  "nf1" | "nf2" | "outCm1" | "outCm2" | "publicAmount" | "recipient" | "fee"
>;

/** EIP-712's domain separator for the pool at `pool` on chain `chainId`. */
export function intentDomainSeparator(chainId: bigint, pool: bigint): Uint8Array {
  const [type, name] = [INTENT_DOMAIN_TYPE, INTENT_DOMAIN_NAME].map((text) => keccak(utf8(text)));
  const fields = [abiWord(chainId, "uint256", "chain id"), abiWord(pool, "address", "pool")];
  return keccak(concat(type, name, ...fields));
}

/**
 * The digest an owner signs to authorize `intent`: keccak256(0x1901 || domain || struct). Like
 * the dispatcher, it hashes each field as the 32-byte word the settlement carries, so for a
 * recipient that is an address, the digest is EIP-712's. Callers check that it is one.
 */
export function intentDigest(chainId: bigint, pool: bigint, intent: Intent): Uint8Array {
  const { nf1, nf2, outCm1, outCm2, publicAmount, recipient, fee } = intent;
  const fields = [nf1, nf2, outCm1, outCm2, publicAmount, recipient, fee].map(word);
  const struct = keccak(concat(keccak(utf8(INTENT_TYPE)), ...fields));
  return keccak(concat(Uint8Array.of(0x19, 0x01), intentDomainSeparator(chainId, pool), struct));
}

// ---- EIP-8250 keyed nonces ----

/** The nonce manager, whose storage records the nonce keys each sender has consumed. */
export const NONCE_MANAGER_ADDRESS = 0x8250n;

/** The nonce manager's storage slot for a sender's nonce key: keccak256(sender || key) as words. */
export function nonceKeySlot(sender: bigint, key: bigint): Uint8Array {
  return keccak(concat(word(sender), word(key)));
}

// ---- EIP-8272 recent roots ----

/** Spends lead with a VERIFY frame to this contract, which stores roots for 8192 slots. */
export const RECENT_ROOT_ADDRESS = 0x8272n;
export const RECENT_ROOT_LENGTH = 8192n;

/** The source a pool epoch publishes roots under: keccak256(pool || epoch word). */
export function sourceId(pool: bigint, epoch: bigint): Uint8Array {
  return keccak(concat(toBytes(pool, 20), word(epoch)));
}

/** VERIFY frame 0's data: sourceId (32 bytes) || slot (8 bytes) || root (32 bytes). */
export function recentRootTuple(source: Uint8Array, slot: bigint, root: bigint): Uint8Array {
  return concat(source, toBytes(slot, 8), word(root));
}

// These equal ethrex's RecentRootReference::{entry_hash, storage_key}, which is how a wallet
// checks that a root is published before it signs.
const RECENT_ROOT_ENTRY = keccak(utf8("RECENT_ROOT_ENTRY"));
const RECENT_ROOT_STORAGE = keccak(utf8("RECENT_ROOT_STORAGE"));

/** The value EIP-8272 stores for a root published under `source` in `slot`. */
export function recentRootEntry(source: Uint8Array, slot: bigint, root: bigint): Uint8Array {
  return keccak(concat(RECENT_ROOT_ENTRY, recentRootTuple(source, slot, root)));
}

/** The storage slot of `source` at `slot`'s place in the ring. */
export function recentRootStorageKey(source: Uint8Array, slot: bigint): Uint8Array {
  return keccak(concat(RECENT_ROOT_STORAGE, source, toBytes(slot % RECENT_ROOT_LENGTH, 8)));
}

// ---- pool ABI ----

/**
 * settle(Spend)'s fields in ABI order, each one word of the calldata, with their types. The
 * frontier's MAX_TREES words follow them.
 */
const SPEND_ABI = {
  root: "bytes32",
  rootSlot: "uint64",
  epoch: "uint64",
  domain: "bytes32",
  nf1: "bytes32",
  nf2: "bytes32",
  outCm1: "bytes32",
  outCm2: "bytes32",
  publicAmount: "uint256",
  fee: "uint256",
  recipient: "address",
  authorizer: "address",
  count: "uint64",
  packedRanks: "uint256",
  depth: "uint256",
} as const;

export type Spend = Record<keyof typeof SPEND_ABI, bigint> & { frontier: readonly bigint[] };
export const SPEND_FIELDS = Object.keys(SPEND_ABI) as (keyof typeof SPEND_ABI)[];

export const SPEND_TUPLE = `(${[...Object.values(SPEND_ABI), `bytes32[${MAX_TREES}]`].join(",")})`;

export function selector(signature: string): Uint8Array {
  return keccak(utf8(signature)).slice(0, 4);
}

const eventTopic = (signature: string) => toHex(keccak(utf8(signature)));

export const SETTLE_SELECTOR = selector(`settle(${SPEND_TUPLE})`);
export const SHIELD_SELECTOR = selector("shield(bytes32,bytes)");
export const PUBLISH_SELECTOR = selector("publishEpochRoot(uint64)");
export const CLAIM_SELECTOR = selector("claimWithdrawal(address)");
export const DOMAIN_SELECTOR = selector("domain(uint64)");
export const VERIFY_PROOF_SELECTOR = selector(
  "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])",
);

export const LEAF_APPENDED = eventTopic("LeafAppended(bytes32,uint64,uint64,bytes32)");
export const NOTE_SPENT = eventTopic("NoteSpent(bytes32)");
export const NOTES = eventTopic("Notes(bytes)");

type AbiType = "bytes32" | "uint64" | "uint256" | "address";

function abiWord(value: bigint, type: AbiType, what: string): Uint8Array {
  const bits = type === "uint64" ? 64n : type === "address" ? 160n : 256n;
  if (!fits(value, bits)) throw new InputError(`${what} must be a ${type}`);
  return word(value);
}

function checkNotes(notes: Uint8Array, sizes: readonly number[], what: string): void {
  if (!sizes.includes(notes.length)) {
    const allowed = sizes.join(" or ");
    throw new InputError(`the ${what}'s notes must be ${allowed} bytes, not ${notes.length}`);
  }
}

/**
 * settle(Spend) calldata followed by the spend's notes, as the SENDER frame carries them. The
 * tuple is static, so its 15 + MAX_TREES words follow the selector with no offset word. The
 * pool publishes the notes and never reads them.
 */
export function encodeSettle(spend: Spend, notes: Uint8Array): Uint8Array {
  const words = SPEND_FIELDS.map((f) => abiWord(spend[f], SPEND_ABI[f], `settle ${f}`));
  if (spend.frontier.length !== MAX_TREES)
    throw new InputError(`settle frontier must be ${MAX_TREES} roots`);
  const frontier = spend.frontier.map((root) => abiWord(root, "bytes32", "settle frontier"));
  checkNotes(notes, SPEND_NOTES_BYTES, "spend");
  return concat(SETTLE_SELECTOR, ...words, ...frontier, notes);
}

/**
 * The Spend and notes of settlement calldata, or null unless it has the selector and a length
 * the dispatcher accepts. Words are read whole: the pool's checks, not this decoder, decide what
 * an out-of-range word means.
 */
export function decodeSettle(calldata: Uint8Array): { spend: Spend; notes: Uint8Array } | null {
  const sized = SETTLE_FRAME_DATA_BYTES.includes(calldata.length);
  if (!sized || !equalBytes(calldata.subarray(0, 4), SETTLE_SELECTOR)) return null;
  const at = (i: number) => toBigint(calldata.subarray(4 + 32 * i, 36 + 32 * i));
  const fields = Object.fromEntries(SPEND_FIELDS.map((f, i) => [f, at(i)])) as Omit<
    Spend,
    "frontier"
  >;
  const frontier = Array.from({ length: MAX_TREES }, (_, i) => at(SPEND_FIELDS.length + i));
  return { spend: { ...fields, frontier }, notes: calldata.slice(SETTLE_SPEND_BYTES) };
}

/** shield(bytes32 inner, bytes note): inner, offset 0x40, length, the note padded to words. */
export function encodeShield(inner: bigint, note: Uint8Array): Uint8Array {
  checkNotes(note, SHIELD_NOTE_BYTES, "shield");
  const head = [abiWord(inner, "bytes32", "shield inner"), word(0x40n), word(BigInt(note.length))];
  return concat(SHIELD_SELECTOR, ...head, note, new Uint8Array((32 - (note.length % 32)) % 32));
}

export function encodePublish(epoch: bigint): Uint8Array {
  return concat(PUBLISH_SELECTOR, abiWord(epoch, "uint64", "publish epoch"));
}

/** claimWithdrawal(recipient), the default withdrawal tail. */
export function encodeClaim(recipient: bigint): Uint8Array {
  return concat(CLAIM_SELECTOR, abiWord(recipient, "address", "claim recipient"));
}

/** domain(epoch), the view a deployment check reads. */
export function encodeDomainCall(epoch: bigint): Uint8Array {
  return concat(DOMAIN_SELECTOR, abiWord(epoch, "uint64", "domain epoch"));
}

/**
 * A Groth16 proof with pB in the verifier's calldata order: snarkjs's soliditycalldata has
 * already swapped each G2 coordinate pair, so encoders never swap again.
 */
export interface Proof {
  pA: readonly [bigint, bigint];
  pB: readonly [readonly [bigint, bigint], readonly [bigint, bigint]];
  pC: readonly [bigint, bigint];
}

function proofWords({ pA, pB, pC }: Proof, extra: readonly bigint[], what: string): Uint8Array[] {
  const words = [pA[0], pA[1], pB[0][0], pB[0][1], pB[1][0], pB[1][1], pC[0], pC[1], ...extra];
  return words.map((x) => abiWord(x, "uint256", what));
}

/**
 * VERIFY frame 1's 288 bytes: the proof's eight words, then hybrid compression's beta. The pool
 * recomputes alpha and gamma from the settlement, which never carries the proof.
 */
export function proofBytes(proof: Proof, beta: bigint): Uint8Array {
  return concat(...proofWords(proof, [beta], "proof word"));
}

/** verifyProof calldata with the public signals [beta, gamma, alpha], as the pool calls it. */
export function verifyProofCall(
  proof: Proof,
  publics: readonly [bigint, bigint, bigint],
): Uint8Array {
  return concat(VERIFY_PROOF_SELECTOR, ...proofWords(proof, publics, "verifier argument"));
}

// ---- events ----

export interface LeafAppended {
  cm: bigint;
  epoch: bigint;
  index: bigint;
  newRoot: bigint;
}

/**
 * The fields of a LeafAppended(bytes32 indexed cm, uint64 indexed epoch, uint64 index, bytes32
 * newRoot) log, or null for any other log; one with this topic but malformed fields throws.
 * Topics may be unpadded and topic 0 in any case. Check the log's address first: any contract
 * can emit this topic, and a malformed look-alike would make a shield, disclosure or note scan
 * refuse a receipt that holds.
 */
export function parseLeafAppended(log: { topics?: unknown; data?: unknown }): LeafAppended | null {
  const topics = log.topics;
  if (
    !Array.isArray(topics) ||
    topics.length !== 3 ||
    typeof topics[0] !== "string" ||
    topics[0].toLowerCase() !== LEAF_APPENDED
  ) {
    return null;
  }
  const data = fromHex(log.data, "LeafAppended data");
  if (data.length < 64) {
    throw new InputError(`LeafAppended data must hold index and newRoot, not ${data.length} bytes`);
  }
  return {
    cm: parseHex(topics[1], "LeafAppended cm"),
    epoch: parseHex(topics[2], "LeafAppended epoch"),
    index: toBigint(data.subarray(0, 32)),
    newRoot: toBigint(data.subarray(32, 64)),
  };
}

// ---- addresses a withdrawal must not pay ----

/**
 * A withdrawal credit is paid by an empty-calldata call to its recipient, with no claim to
 * another address. These system contracts revert on that call, and nobody controls the entry
 * point, so a credit to any of them is stranded or lost. Any contract that rejects a plain ETH
 * transfer strands a credit the same way; these are the known protocol addresses.
 */
export const UNCLAIMABLE_RECIPIENTS: ReadonlyMap<bigint, string> = new Map([
  [0xaan, "the EIP-8141 entry point, which no one controls"],
  [0x8141n, "the EIP-8141 expiry verifier"],
  [NONCE_MANAGER_ADDRESS, "the EIP-8250 nonce manager"],
  [RECENT_ROOT_ADDRESS, "the EIP-8272 recent root contract"],
  [0x000f3df6d732807ef1319fb7b8bb8522d0beac02n, "the EIP-4788 beacon roots contract"],
  [0x0000f90827f1c53a10cb7a02335b175320002935n, "the EIP-2935 history contract"],
  [0x00000961ef480eb55e80d19ad83579a64c007002n, "the EIP-7002 withdrawal request contract"],
  [0x0000bbddc7ce488642fb579f8b00f3a590007251n, "the EIP-7251 consolidation request contract"],
  [0x00000000219ab540356cbb839cbe05303d7705fan, "the beacon deposit contract"],
  [0x0000bff46984e3725691fa540a8c7589300d8282n, "the EIP-8282 builder deposit contract"],
  [0x000064d678505ad48f8ccb093bc65613800e8282n, "the EIP-8282 builder exit contract"],
]);

/** Precompiles 0x01 to 0x11 and P256VERIFY at 0x100: a claim there strands or keeps the ETH. */
export const PRECOMPILES: ReadonlySet<bigint> = new Set([
  ...Array.from({ length: 0x11 }, (_, i) => BigInt(i + 1)),
  0x100n,
]);
