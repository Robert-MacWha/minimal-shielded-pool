/**
 * circomlib's Poseidon over the BN254 scalar field: x^5 S-box, 8 full rounds plus 57 (t=3),
 * 56 (t=4) or 60 (t=12) partial rounds, state initialised as [0, in_0, ..., in_{n-1}],
 * output state[0]. The constants and the mix convention (new[i] = sum_j M[i][j] * state[j])
 * are circomlibjs's poseidon_reference.js, exported to poseidon-constants.json by
 * tools/export-vectors.ts. The spend circuit, the Solidity library generated from the same
 * file and this module must agree, which test/vectors/poseidon_bn254_vectors.json checks.
 */
import { readFileSync } from "node:fs";

import { mod } from "./bytes.ts";

interface Params {
  t: number;
  fullRounds: number;
  partialRounds: number;
  C: bigint[];
  M: bigint[][];
}

// Read once at import, relative to this file so any working directory works.
const constants = JSON.parse(
  readFileSync(new URL("./poseidon-constants.json", import.meta.url), "utf8"),
);

/** The BN254 scalar field modulus. */
export const P: bigint = BigInt(constants.prime);

const PARAMS = new Map<number, Params>();
for (const t of [3, 4, 12]) {
  const c = constants[`t${t}`];
  const params: Params = {
    t,
    fullRounds: c.rounds_f,
    partialRounds: c.rounds_p,
    C: c.C.map(BigInt),
    M: c.M.map((row: string[]) => row.map(BigInt)),
  };
  if (
    params.C.length !== t * (params.fullRounds + params.partialRounds) ||
    params.M.length !== t ||
    params.M.some((row) => row.length !== t)
  ) {
    throw new Error(`poseidon-constants.json has malformed t${t} parameters`);
  }
  PARAMS.set(t, params);
}

function pow5(x: bigint): bigint {
  const x2 = (x * x) % P;
  return (((x2 * x2) % P) * x) % P;
}

/**
 * Poseidon of 2, 3 or 11 inputs. Inputs are reduced modulo P first, so x and x + P hash
 * alike; disclosure relies on that when it hashes a receipt's unchecked values.
 */
export function poseidon(inputs: readonly bigint[]): bigint {
  const params = PARAMS.get(inputs.length + 1);
  if (params === undefined) {
    throw new RangeError(`unsupported Poseidon arity: ${inputs.length} inputs`);
  }
  const { t, fullRounds, partialRounds, C, M } = params;
  let state = [0n, ...inputs.map((x) => mod(x, P))];
  for (let r = 0; r < fullRounds + partialRounds; r++) {
    for (let i = 0; i < t; i++) state[i] = (state[i] + C[r * t + i]) % P;
    if (r < fullRounds / 2 || r >= fullRounds / 2 + partialRounds) {
      for (let i = 0; i < t; i++) state[i] = pow5(state[i]);
    } else {
      state[0] = pow5(state[0]);
    }
    state = M.map((row) => row.reduce((acc, m, j) => acc + m * state[j], 0n) % P);
  }
  return state[0];
}
