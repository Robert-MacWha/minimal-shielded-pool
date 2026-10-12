/**
 * The wallet's side of a spend: fresh secrets drawn from an Rng, the skew-MMR of note
 * commitments as the pool builds it, the Merkle trees of owner sets, and the circom input map
 * that prover.ts proves against core/artifacts/spend_final.zkey. The hashes themselves live in
 * protocol.ts, which mirrors the circuit and the pool, and src/owner.ts holds owner sets.
 */
import type { Hasher } from "@skew-mmr/core/hasher";
import { SkewMmr } from "@skew-mmr/core/mmr";
import type { Proof as Opening } from "@skew-mmr/core/proof";

import { word } from "./bytes.ts";
import { addressOf, SECP256K1_N } from "./frametx.ts";
import { poseidon } from "./poseidon.ts";
import {
  MAX_TREES,
  MAX_VALUE,
  OWNER_DEPTH,
  P,
  SINK_INNERS,
  compressionAlpha,
  frontierFields,
  frontierRoot,
  inputNullifiers,
  outputCommitments,
  p2,
  statement,
  type Frontier,
  type Output,
  type SpendInput,
} from "./protocol.ts";
import type { Rng } from "./random.ts";

// ---- secrets ----

/**
 * Fresh note secrets (nk, rho): uniform field elements, drawn in that order. A wallet's nk names
 * one of its addresses, so a fresh one makes an address for a single payment.
 */
export function newNote(rng: Rng): [nk: bigint, rho: bigint] {
  return [rng.below(P), rng.below(P)];
}

/** A fresh one-time secp256k1 key, uniform in [1, n - 1], and its Ethereum address. */
export function newAuthorizer(rng: Rng): [privateKey: Uint8Array, address: bigint] {
  const privateKey = word(1n + rng.below(SECP256K1_N - 1n));
  return [privateKey, addressOf(privateKey)];
}

/**
 * A zero-value dummy input: fabricated secrets, never in the tree. Its nullifier derives from
 * its own fabricated commitment, so it cannot collide with a real note's, and it contributes
 * zero to conservation.
 */
export function dummyInput(rng: Rng): SpendInput {
  const [nk, rho] = newNote(rng);
  return { nk, rho, value: 0n, idx: null };
}

// ---- the tree ----

/** A tree node: Poseidon(element, left, right), as LibSkewMmr's append and the circuit hash it. */
const NODE_HASHER: Hasher<bigint> = {
  hash: (element, left, right) => poseidon([element, left, right]),
};

export type { Opening };

/** What a witness needs from an epoch's MMR. */
export interface MerkleTree {
  root(): bigint;
  frontier(): Frontier;
  /** The opening of the note at `index`, counted in insertion order. */
  open(index: bigint): Opening<bigint>;
}

/**
 * The pool's skew-MMR of commitments (@skew-mmr/core), capped at MAX_TREES trees as the pool
 * caps it, so an append the pool would refuse throws here too.
 */
export class Tree implements MerkleTree {
  readonly #leaves: bigint[] = [];
  readonly #mmr: SkewMmr<bigint>;

  constructor(hasher: Hasher<bigint> = NODE_HASHER) {
    this.#mmr = new SkewMmr(hasher, MAX_TREES);
  }

  /** The commitments appended with append, in insertion order. */
  get leaves(): readonly bigint[] {
    return this.#leaves;
  }

  /** Appends a commitment and returns its index. */
  append(cm: bigint): bigint {
    const index = BigInt(this.#mmr.len());
    this.#mmr.append(cm);
    this.#leaves.push(cm);
    return index;
  }

  root(): bigint {
    return frontierRoot(this.frontier());
  }

  frontier(): Frontier {
    const mmr = this.#mmr;
    return { roots: mmr.roots(), ranks: mmr.ranks(), count: BigInt(mmr.len()) };
  }

  open(index: bigint): Opening<bigint> {
    if (index < 0n) throw new RangeError(`note index ${index} is negative`);
    return this.#mmr.prove(Number(index));
  }
}

/**
 * The native generator's pool near capacity: `count` copies of `cm`, followed by the commitments
 * `extras`. The copies stand in for the deposits before the extras and share one nullifier.
 * Subtrees of the repeated commitment are equal, so the hasher keeps each answer and only the
 * few distinct nodes are hashed.
 */
export class RepeatedTree extends Tree {
  constructor(cm: bigint, count: bigint, extras: readonly bigint[] = []) {
    const hashed = new Map<string, bigint>();
    super({
      hash: (element, left, right) => {
        const key = `${element}:${left}:${right}`;
        let node = hashed.get(key);
        if (node === undefined) {
          node = NODE_HASHER.hash(element, left, right);
          hashed.set(key, node);
        }
        return node;
      },
    });
    for (let i = 0n; i < count; i++) this.append(cm);
    for (const extra of extras) this.append(extra);
  }
}

// ---- owner sets' trees ----

/** ZEROS[d] is the root of an empty subtree of height d; an empty leaf is 0. */
const ZEROS = [0n];
for (let d = 0; d < OWNER_DEPTH; d++) ZEROS.push(p2(ZEROS[d], ZEROS[d]));

/** A membership path, leaf level first: each height's sibling and the index's bit there. */
export interface AuthPath {
  siblings: bigint[];
  bits: number[];
}

/** The depth-`depth` path of `index`, reading the node at (height, position) through `node`. */
function pathOf(
  index: bigint,
  node: (height: number, position: bigint) => bigint,
  depth: number,
): AuthPath {
  if (index < 0n) throw new RangeError(`leaf index ${index} is negative`);
  const siblings: bigint[] = [];
  const bits: number[] = [];
  for (let d = 0; d < depth; d++) {
    const position = index >> BigInt(d);
    siblings.push(node(d, position ^ 1n));
    bits.push(Number(position & 1n));
  }
  return { siblings, bits };
}

/**
 * A Poseidon tree padded on the right with empty subtrees: by default an owner set's depth-16
 * tree. Each level is kept and rehashed only above leaves appended since the last read, so a
 * tree is hashed once, not once per root or path.
 */
export class OwnerTree {
  readonly depth: number;
  readonly #leaves: bigint[] = [];
  // #levels[d] holds the height-d nodes over the first #hashed leaves; #levels[0] is the leaves.
  readonly #levels: bigint[][];
  #hashed = 0;

  constructor(depth = OWNER_DEPTH) {
    if (!Number.isInteger(depth) || depth < 1 || depth > OWNER_DEPTH) {
      throw new RangeError(`a tree's depth is 1 to ${OWNER_DEPTH}, not ${depth}`);
    }
    this.depth = depth;
    this.#levels = [this.#leaves, ...Array.from({ length: depth }, () => [])];
  }

  /** The leaves in order. */
  get leaves(): readonly bigint[] {
    return this.#leaves;
  }

  /** Appends a leaf and returns its index. */
  append(leaf: bigint): bigint {
    if (this.#leaves.length >= 2 ** this.depth) throw new Error("tree full");
    return BigInt(this.#leaves.push(leaf) - 1);
  }

  root(): bigint {
    this.#rehash();
    return this.#leaves.length === 0 ? ZEROS[this.depth] : this.#levels[this.depth][0];
  }

  /** The path of any index; one past the last leaf gives an empty slot's path. */
  authPath(index: bigint): AuthPath {
    this.#rehash();
    const node = (d: number, position: bigint) =>
      position < BigInt(this.#levels[d].length) ? this.#levels[d][Number(position)] : ZEROS[d];
    return pathOf(index, node, this.depth);
  }

  #rehash(): void {
    const first = this.#hashed;
    if (first === this.#leaves.length) return;
    for (let d = 0; d < this.depth; d++) {
      const below = this.#levels[d];
      const above = this.#levels[d + 1];
      for (let j = first >> (d + 1); 2 * j < below.length; j++) {
        above[j] = p2(below[2 * j], below[2 * j + 1] ?? ZEROS[d]);
      }
    }
    this.#hashed = this.#leaves.length;
  }
}

// ---- witness ----

/** The spend circuit's input map, keyed by signal name, every value a decimal string. */
export interface Witness {
  alpha: string;
  roots: string[];
  packed_ranks: string;
  depth: string;
  domain: string;
  owner_root: string;
  owner: string;
  owner_siblings: string[];
  owner_bits: string[];
  in_nk: string[];
  in_rho: string[];
  in_value: string[];
  in_tree: string[];
  in_children: string[][];
  in_path_len: string[];
  in_path_elements: string[][];
  in_path_siblings: string[][];
  in_path_right: string[][];
  out_inner: string[];
  out_value: string[];
  public_amount: string;
  fee: string;
  recipient: string;
  authorizer: string;
}

/** The leaf of an owner set a spend reveals: the set's root, the address and its path. */
export interface OwnerLeaf {
  root: bigint;
  address: bigint;
  path: AuthPath;
}

/** The public terms of a spend besides its notes. */
export interface SpendTerms {
  /** The spend's one-time signer, as an address integer. */
  authorizer: bigint;
  /** The owner set both inputs belong to, and the address in it that signs the spend. */
  owner: OwnerLeaf;
  publicAmount?: bigint;
  fee?: bigint;
  /** The withdrawal's recipient as an address integer, 0 when nothing is withdrawn. */
  recipient?: bigint;
}

// A witness the circuit would refuse is a bug in the caller, so these are plain Errors.
function check(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

/**
 * A join-split witness against the tree's current frontier. inputs are exactly two notes of the
 * owner set terms.owner names, a dummyInput (value 0, no index) in place of a missing one;
 * outputs are exactly two (inner, value) pairs, a zero-value output being its position's sink.
 * Values must conserve exactly: sum(inputs) = sum(outputs) + publicAmount + fee. Neither tree is
 * checked to hold its leaf, and the same note may fill both inputs: the circuit refuses those
 * witnesses.
 */
export function buildWitness(
  tree: MerkleTree,
  inputs: readonly SpendInput[],
  outputs: readonly Output[],
  domain: bigint,
  terms: SpendTerms,
): Witness {
  const { authorizer, owner, publicAmount = 0n, fee = 0n, recipient = 0n } = terms;
  check(inputs.length === 2 && outputs.length === 2, "a spend has two inputs and two outputs");
  check(
    inputs.some((i) => i.value > 0n),
    "at least one real input is required",
  );
  check(
    inputs.every((i) => i.idx !== null || i.value === 0n),
    "a dummy input must have value 0",
  );
  const totalIn = inputs.reduce((sum, i) => sum + i.value, 0n);
  const totalOut = outputs.reduce((sum, [, value]) => sum + value, 0n) + publicAmount + fee;
  check(totalIn === totalOut, `not conserved: ${totalIn} != ${totalOut}`);
  const values = [publicAmount, fee, ...inputs.map((i) => i.value), ...outputs.map(([, v]) => v)];
  check(
    values.every((v) => v >= 0n && v < MAX_VALUE),
    "every value must be in [0, 2^128)",
  );
  check(authorizer > 0n && authorizer < 1n << 160n, "the authorizer must be a nonzero address");
  check(owner.address > 0n && owner.address < 1n << 160n, "the owner must be a nonzero address");
  check(
    owner.path.siblings.length === OWNER_DEPTH && owner.path.bits.length === OWNER_DEPTH,
    `an owner's path has ${OWNER_DEPTH} levels`,
  );
  outputs.forEach(([out, value], k) => {
    // The circuit reduces inners mod p, so the sink checks below hold only for canonical ones.
    check(out >= 0n && out < P, "every output inner must be in [0, p)");
    if (value === 0n) check(out === SINK_INNERS[k], "zero output must use its positional sink");
    else check(!SINK_INNERS.includes(out), "positive output uses a reserved sink inner");
  });
  const [outCm1, outCm2] = outputCommitments(outputs);
  check(outCm1 !== outCm2, "output commitments must be distinct");

  const [nf1, nf2] = inputNullifiers(domain, owner.root, inputs);
  const { packedRanks, depth, frontier } = frontierFields(tree.frontier());
  const hashes = { nf1, nf2, outCm1, outCm2, domain };
  const given = { publicAmount, fee, recipient, authorizer, owner: owner.address };
  const mmr = { packedRanks, depth, frontier };
  const alpha = compressionAlpha(statement({ ...hashes, ...given, ...mmr }));
  // The circuit does not check a dummy's membership, so it opens tree 0 with no path.
  const openings = inputs.map((i): Opening<bigint> =>
    i.idx === null ? { tree: 0, children: null, path: [] } : tree.open(i.idx),
  );
  const decimal = (xs: readonly (bigint | number)[]) => xs.map(String);
  const steps = (o: Opening<bigint>, step: (s: Opening<bigint>["path"][number]) => bigint) =>
    decimal(pad(o.path.map(step), MAX_TREES - 1));
  return {
    alpha: String(alpha),
    roots: decimal(frontier),
    packed_ranks: String(packedRanks),
    depth: String(depth),
    domain: String(domain),
    owner_root: String(owner.root),
    owner: String(owner.address),
    owner_siblings: decimal(owner.path.siblings),
    owner_bits: decimal(owner.path.bits),
    in_nk: decimal(inputs.map((i) => i.nk)),
    in_rho: decimal(inputs.map((i) => i.rho)),
    in_value: decimal(inputs.map((i) => i.value)),
    in_tree: openings.map((opening) => String(opening.tree)),
    in_children: openings.map((opening) => decimal(opening.children ?? [0n, 0n])),
    in_path_len: openings.map((opening) => String(opening.path.length)),
    in_path_elements: openings.map((opening) => steps(opening, (s) => s.element)),
    in_path_siblings: openings.map((opening) => steps(opening, (s) => s.sibling)),
    in_path_right: openings.map((opening) => steps(opening, (s) => (s.right ? 1n : 0n))),
    out_inner: decimal(outputs.map(([out]) => out)),
    out_value: decimal(outputs.map(([, value]) => value)),
    public_amount: String(publicAmount),
    fee: String(fee),
    recipient: String(recipient),
    authorizer: String(authorizer),
  };
}

function pad(values: readonly bigint[], length: number): bigint[] {
  return [...values, ...Array<bigint>(length - values.length).fill(0n)];
}
