/**
 * Regenerates test/vectors/poseidon_bn254_vectors.json and src/poseidon-constants.json from
 * circomlibjs itself.
 *
 *   node tools/export-vectors.ts
 *
 * circomlibjs is the same package the circuit's poseidon.circom pairs with, so these vectors
 * close the loop circuit <-> reference <-> Solidity from a single constants source. Every
 * vector is computed with BOTH the reference and the wasm implementation and asserted equal,
 * so a constants mismatch inside circomlibjs itself would fail here, not later.
 *
 * Vector set: zero, unit, counter, and LCG-seeded states for Poseidon(2) and Poseidon(3), plus
 * the pool chain from seed 2026 (owner_pk, cm, the domain-separated nf, out_cm) and a depth-16
 * owner set.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";

// @ts-expect-error circomlibjs 0.1.7 ships no type declarations; Poseidon types what is used.
import { buildPoseidon, buildPoseidonReference } from "circomlibjs";

interface Poseidon {
  (inputs: unknown[]): unknown;
  F: { p: bigint; e(x: bigint): unknown; toString(x: unknown): string };
}

const ROOT = resolve(import.meta.dirname, "..");
const OWNER_DEPTH = 16;

/**
 * Field elements from a deterministic LCG, each built from four 48-bit draws, so the vectors
 * are reproducible without a random number dependency.
 */
function lcg(seed: bigint, p: bigint): () => bigint {
  let s = seed;
  const next48 = () => {
    s = (s * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn;
    return (s >> 16n) & 0xffffffffffffn;
  };
  return () => ((next48() << 144n) | (next48() << 96n) | (next48() << 48n) | next48()) % p;
}

/** The vectors and constants files' contents. */
async function exportVectors() {
  const ref: Poseidon = await buildPoseidonReference();
  const wasm: Poseidon = await buildPoseidon();
  const F = ref.F;
  const p = F.p;

  function hash(inputs: bigint[]): bigint {
    const a = F.toString(ref(inputs.map((x) => F.e(x))));
    if (a !== F.toString(wasm(inputs.map((x) => F.e(x))))) {
      throw new Error("reference and default poseidon disagree");
    }
    return BigInt(a);
  }
  const p2 = (a: bigint, b: bigint) => hash([a, b]);
  const p3 = (a: bigint, b: bigint, c: bigint) => hash([a, b, c]);

  function cases(n: number) {
    const next = lcg(42n, p);
    const states = [
      Array(n).fill(0n),
      [1n, ...Array(n - 1).fill(0n)],
      Array.from({ length: n }, (_, i) => BigInt(i + 1)),
      ...Array.from({ length: 13 }, () => Array.from({ length: n }, next)),
    ];
    return states.map((state) => ({ in: state.map(String), out: hash(state).toString() }));
  }

  // The pool's tagged chain (mirrors core/circuits/spend.circom), seed 2026: the value-carrying
  // note and the join-split outputs.
  const next = lcg(2026n, p);
  const [nk, rho, out_inner1, out_inner2] = Array.from({ length: 4 }, next);
  const mask128 = (1n << 128n) - 1n;
  const [value, out_value1, out_value2] = Array.from({ length: 3 }, () => next() & mask128);
  // Drawn after the others so that their values stay as earlier vectors drew them.
  const domain = next(); // stands in for keccak(TAG||chain||pool||epoch) mod p
  const owner_root = next(); // stands in for the root of an owner set
  const owner_pk = p3(1n, owner_root, nk);
  const inner = p2(owner_pk, rho);
  const cm = p3(2n, inner, value);
  // Nullifiers, mirroring core/circuits/spend.circom. Even with the same secret, a zero-value
  // dummy has a different identity.
  const nf = p3(4n, p2(domain, nk), cm);
  const nf2 = p3(4n, p2(domain, nk), p3(2n, inner, 0n));
  const out_cm1 = p3(2n, out_inner1, out_value1);
  const out_cm2 = p3(2n, out_inner2, out_value2);
  const chain = {
    ...{ owner_root, nk, rho, value, out_inner1, out_inner2, out_value1, out_value2, domain },
    ...{ owner_pk, inner, cm, nf, nf2, out_cm1, out_cm2 },
  };

  // An owner set's root at depth 16, where the leaves are addresses and empty leaves are 0.
  const zeros = [0n];
  for (let l = 0; l < OWNER_DEPTH; l++) zeros.push(p2(zeros[l], zeros[l]));
  function incrementalRoot(leaves: bigint[], depth: number): bigint {
    const filled: bigint[] = Array(depth).fill(0n);
    let root = zeros[depth];
    leaves.forEach((leaf, index) => {
      let node = leaf;
      for (let l = 0, idx = index; l < depth; l++, idx >>= 1) {
        if ((idx & 1) === 0) {
          filled[l] = node;
          node = p2(node, zeros[l]);
        } else {
          node = p2(filled[l], node);
        }
      }
      root = node;
    });
    return root;
  }

  const owners = Array.from({ length: 3 }, () => next() & ((1n << 160n) - 1n)); // addresses
  const vectors = {
    poseidon2: cases(2),
    poseidon3: cases(3),
    pool_chain: Object.fromEntries(Object.entries(chain).map(([k, v]) => [k, v.toString()])),
    owner_set: {
      depth: OWNER_DEPTH,
      addresses: owners.map(String),
      root_empty: zeros[OWNER_DEPTH].toString(),
      root: incrementalRoot(owners, OWNER_DEPTH).toString(),
    },
  };

  // Constants for src/poseidon.ts and tools/poseidon-sol.ts. C[t-2] is (8 + N_ROUNDS_P[t-2]) * t
  // round constants and M[t-2] is t x t, with new_state[i] = sum_j M[i][j] * state[j]
  // (poseidon_reference.js). circomlibjs stores them as hex; the file holds decimal. The
  // package's exports map hides the file, so it is found from its CommonJS entry, build/main.cjs.
  const circomlibjs = createRequire(import.meta.url).resolve("circomlibjs");
  const { C, M } = JSON.parse(
    readFileSync(join(circomlibjs, "../../src/poseidon_constants.json"), "utf8"),
  );
  const toDec = (x: string) => BigInt(x).toString();
  const params = (i: number, roundsP: number) => ({
    rounds_f: 8,
    rounds_p: roundsP,
    C: C[i].map(toDec),
    M: M[i].map((row: string[]) => row.map(toDec)),
  });
  const constants = {
    prime: p.toString(),
    t3: params(1, 57),
    t4: params(2, 56),
  };
  return { vectors, constants };
}

if (import.meta.main) {
  const { vectors, constants } = await exportVectors();
  const vpath = join(ROOT, "test", "vectors", "poseidon_bn254_vectors.json");
  const cpath = join(ROOT, "src", "poseidon-constants.json");
  for (const [path, value] of [
    [vpath, vectors],
    [cpath, constants],
  ] as const) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(value, null, 1));
  }
  console.log(`wrote ${vpath} (16+16 vectors + pool chain + owner set)`);
  console.log(`wrote ${cpath}`);
}
