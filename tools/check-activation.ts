/**
 * Fail-closed artifact, ceremony and gas-profile activation gate. A testbed manifest
 * (production: false) passes only with --allow-testbed. A production manifest needs at least
 * two phase-2 contributions, a count the proving key must record, independent_verification set
 * to true, and --ptau naming the phase-1 file whose SHA-256 the manifest pins and against which
 * snarkjs verifies the proving key. Every profile field is checked: the frame limits and EIP
 * revisions against this tree's dispatcher profile, and the gas evidence against the figures in
 * tools/check-gas-profile.ts, which the deploy script runs too.
 *
 *   node tools/check-activation.ts MANIFEST [--allow-testbed] [--ptau PATH]
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, existsSync, openSync, readFileSync, readSync } from "node:fs";
import { resolve } from "node:path";

import { parseArgs, runCli } from "../src/cli/args.ts";
import { CheckError } from "../src/errors.ts";
import * as gas from "../src/gas.ts";
import { canonical, stringify } from "../src/json.ts";
import { check, field, get, object, parseInOrder, readText, ROOT } from "./check.ts";
import * as measured from "./check-gas-profile.ts";

// The one profile this tree can activate. The dispatcher pins the settlement limits; the
// validation limits and the claim frame's limits are the wallet defaults in src/gas.ts. A
// manifest for any other profile is rejected: its artifact hashes could only match this
// tree's files if it were mislabeled.
const EXPECTED_PROFILE = {
  pool_profile: gas.POOL_PROFILE,
  claim_frame_gas: gas.CLAIM_FRAME_GAS,
  claim_frame_state_gas: gas.CLAIM_FRAME_STATE_GAS,
  recent_root_frame_gas: gas.RECENT_ROOT_FRAME_GAS,
  verify_frame_gas: gas.VERIFY_FRAME_GAS,
  verify_frame_state_gas: gas.VERIFY_FRAME_STATE_GAS,
  signature_gas: gas.SIGNATURE_GAS,
  spend_signatures: gas.SPEND_SIGNATURES,
  settle_frame_gas: gas.SETTLE_FRAME_GAS,
  settle_frame_state_gas: gas.SETTLE_FRAME_STATE_GAS,
  // The EIP revisions the dispatcher implements, and EIP-8141's public-mempool verify gas.
  eip_8250_merge: "f3079a09e8c606afcb0e5e1a309ff228b88dc067",
  eip_8272_pin: "824cbc0b0e",
  eip_8272_carrier: "canonical-verifier-frame",
  eip_8141_public_mempool_budget: 100_000n,
};

// The gas evidence: what tools/check-gas-profile.ts measured on native ethrex or derived from
// those measurements, and checks against the frame limits. The manifest records the same
// figures, so it cannot carry evidence that no check has seen.
const EXPECTED_EVIDENCE = {
  pre_pr_12279_max_observed_verify_execution_gas:
    measured.PRE_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS,
  post_pr_12279_max_observed_verify_execution_gas:
    measured.POST_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS,
  max_observed_recent_root_frame_gas: measured.MAX_OBSERVED_RECENT_ROOT_FRAME_GAS,
  conservative_settle_bound: measured.CONSERVATIVE_SETTLEMENT_EXECUTION_BOUND,
  conservative_settle_state_bound: measured.CONSERVATIVE_SETTLEMENT_STATE_BOUND,
};

// Every profile field is checked, so "profile": "match" covers the whole profile.
const PROFILE_FIELDS = new Set([
  "wire_profile",
  "required_verify_budget",
  "hegota_profile_2_budget",
  "chain_id",
  ...Object.keys(EXPECTED_PROFILE),
  ...Object.keys(EXPECTED_EVIDENCE),
]);

// Every active artifact must be pinned, or a manifest that omits one passes without its hash
// being checked. check-forge-config.ts checks the settings forge resolves beyond foundry.toml.
// The client is not an activation input; the gas constants it signs with are.
const REQUIRED_ARTIFACTS = [
  "core/artifacts/spend.r1cs",
  "core/artifacts/spend_final.zkey",
  "core/artifacts/spend_js/spend.wasm",
  "core/circuits/spend.circom",
  "core/contracts/foundry.toml",
  "core/contracts/src/Groth16Verifier.sol",
  "core/contracts/src/PoseidonT3.sol",
  "core/contracts/src/PoseidonT4.sol",
  "core/contracts/src/ShieldedPoolLogic.sol",
  "core/dispatcher/ShieldedPoolDispatcher.yul",
  "core/artifacts/shielded_pool_dispatcher_init.hex",
  "src/gas.ts",
];
export const R1CS = "core/artifacts/spend.r1cs";
export const ZKEY = "core/artifacts/spend_final.zkey";
export const VERIFIER = "core/contracts/src/Groth16Verifier.sol";

/** An iden3 binary file's bytes, a little-endian uint32 reader and where each section starts. */
export function sections(path: string, magic: string, ...needed: number[]) {
  const data = readFileSync(path);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const u32 = (at: number) => view.getUint32(at, true);
  check(data.subarray(0, 4).toString("latin1") === magic, `${path} is not a ${magic} file`);
  const found = new Map<number, number>();
  // circom declares five r1cs sections and writes three, so the data may end first.
  for (let i = u32(8), offset = 12; i > 0 && offset !== data.length; i--) {
    const kind = u32(offset);
    const size = Number(view.getBigUint64(offset + 4, true));
    check(!found.has(kind), `${path} repeats section ${kind}`);
    found.set(kind, offset + 12);
    offset += 12 + size;
  }
  const missing = needed.find((kind) => !found.has(kind));
  check(missing === undefined, `${path} has no section ${missing}`);
  return { data, u32, found };
}

/** The phase-2 contribution count a snarkjs zkey records in section 10. */
function zkeyContributions(path: string): number {
  const { u32, found } = sections(path, "zkey", 10);
  return u32(found.get(10)! + 64);
}

// A little-endian integer from data[start, start + length), cut short at the end of the data;
// an empty slice reads as 0. Buffer.from copies, so reverse() leaves the file's bytes alone.
function le(data: Uint8Array, start: number, length: number): bigint {
  const bytes = Buffer.from(data.subarray(start, start + length)).reverse();
  return BigInt("0x0" + bytes.toString("hex"));
}

function powMod(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n % modulus;
  for (base %= modulus; exponent > 0n; exponent >>= 1n, base = (base * base) % modulus) {
    if (exponent & 1n) result = (result * base) % modulus;
  }
  return result;
}

/** A term of zkey section 4: matrix (0 for A, 1 for B), constraint, signal and coefficient. */
type Term = [number, number, number, bigint];

/** The R1CS field and sizes, and its A and B terms as snarkjs writes them to zkey section 4. */
function r1csTerms(path: string) {
  const { data, u32, found } = sections(path, "r1cs", 1, 2);
  const header = found.get(1)!;
  const n8 = u32(header);
  const prime = le(data, header + 4, n8);
  const [nVars, nOut, nPubIn, nConstraints] = [0, 4, 8, 24].map((k) => u32(header + 4 + n8 + k));
  const nPublic = nOut + nPubIn;
  // snarkjs stores a coefficient v as v * R^2 mod r, with R = 2^256 for BN254.
  const r2 = powMod(2n, BigInt(16 * n8), prime);
  const terms: Term[] = [];
  let offset = found.get(2)!;
  for (let constraint = 0; constraint < nConstraints; constraint++) {
    // A, B and C; the zkey keeps no C terms.
    for (let matrix = 0; matrix < 3; matrix++) {
      const count = u32(offset);
      offset += 4;
      for (let i = 0; i < count; i++, offset += 4 + n8) {
        if (matrix === 2) continue;
        const value = le(data, offset + 4, n8);
        terms.push([matrix, constraint, u32(offset), (value * r2) % prime]);
      }
    }
  }
  // snarkjs appends one A row per public input and the constant wire.
  for (let s = 0; s <= nPublic; s++) terms.push([0, nConstraints + s, s, r2]);
  return { prime, nVars, nPublic, terms };
}

/** A snarkjs Groth16 zkey's field and sizes, verification key and section 4 terms. */
function zkeySetup(path: string) {
  const { data, u32, found } = sections(path, "zkey", 2, 3, 4);
  let offset = found.get(2)!;
  const n8q = u32(offset);
  const q = le(data, offset + 4, n8q);
  offset += 4 + n8q;
  const n8r = u32(offset);
  const r = le(data, offset + 4, n8r);
  offset += 4 + n8r;
  const [nVars, nPublic] = [0, 4, 8].map((k) => u32(offset + k));
  offset += 12;

  // Points are affine, with each coordinate x stored as x * 2^256 mod q. A G2 point is
  // (x.c0, x.c1, y.c0, y.c1); the verifier names these x2, x1, y2, y1. 2^-1 mod an odd q is
  // (q + 1) / 2; an even q has no inverse of 2.
  if (q % 2n === 0n) throw new RangeError("the zkey's base field modulus is even");
  const rInv = powMod((q + 1n) / 2n, BigInt(8 * n8q), q);
  const coords = (at: number, count: number) =>
    Array.from({ length: count }, (_, i) => (le(data, at + i * n8q, n8q) * rInv) % q);

  // Section 2 holds alpha1, beta1, beta2, gamma2, delta1, delta2; section 3 holds IC.
  const [alphax, alphay] = coords(offset, 2);
  const vk = new Map(Object.entries({ r, q, alphax, alphay }));
  for (const [name, at] of Object.entries({ beta: 4, gamma: 8, delta: 14 })) {
    const [x0, x1, y0, y1] = coords(offset + at * n8q, 4);
    vk.set(`${name}x1`, x1).set(`${name}x2`, x0).set(`${name}y1`, y1).set(`${name}y2`, y0);
  }
  for (let i = 0; i <= nPublic; i++) {
    const [x, y] = coords(found.get(3)! + 2 * i * n8q, 2);
    vk.set(`IC${i}x`, x).set(`IC${i}y`, y);
  }

  const start = found.get(4)! + 4;
  const terms = Array.from({ length: u32(found.get(4)!) }, (_, i): Term => {
    const at = start + i * (12 + n8r);
    const [matrix, constraint, signal] = [0, 4, 8].map((k) => u32(at + k));
    return [matrix, constraint, signal, le(data, at + 12, n8r)];
  });
  return { r, nVars, nPublic, vk, terms };
}

// \w and \d match ASCII only, which suffices: snarkjs writes the verifier in ASCII, and solc
// accepts no other letters or digits outside comments.
const CONSTANT = /uint256 constant (\w+)\s*=\s*(\d+);/g;

/**
 * Checks that the proving key was set up from the R1CS and that the verifier holds its key.
 *
 * A key set up from a different R1CS, say one missing a constraint that honest witnesses
 * satisfy anyway, passes every honest-proof test while letting anyone prove what the committed
 * circuit forbids. snarkjs copies the R1CS's A and B terms into section 4, so comparing it and
 * the header's nVars and nPublic pins the constraint count and every A and B coefficient. The
 * C terms exist only inside the IC and L points, which only the ptau can check (--ptau): this
 * catches a stale key, not one built to disagree with its own section 4.
 */
export function checkSetup(r1cs: string, zkey: string, verifier: string): void {
  const circuit = r1csTerms(r1cs);
  const key = zkeySetup(zkey);
  if (key.r !== circuit.prime || key.nVars !== circuit.nVars || key.nPublic !== circuit.nPublic) {
    throw new CheckError("proving key field, nVars or nPublic does not match the R1CS");
  }
  const [a, b] = [key.terms, circuit.terms];
  let first = 0;
  const same = (x: Term, y: Term) => x.every((value, k) => value === y[k]);
  while (first < a.length && first < b.length && same(a[first], b[first])) first++;
  if (first !== a.length || first !== b.length) {
    throw new CheckError(
      `proving key A/B terms do not match the R1CS: ${a.length} terms against ${b.length}, ` +
        `first difference at term ${first}`,
    );
  }
  const text = readText(verifier);
  const constants = new Map<string, bigint>();
  for (const [, name, value] of text.matchAll(CONSTANT)) constants.set(name, BigInt(value));
  const names = new Set([...constants.keys(), ...key.vk.keys()]);
  const wrong = [...names].filter((name) => constants.get(name) !== key.vk.get(name)).sort();
  if (wrong.length > 0) {
    throw new CheckError(`verifier constants do not match the proving key: ${wrong.join(", ")}`);
  }
}

/** The lowercase hex SHA-256 of a file, read in 1 MiB chunks: a phase-1 ptau can exceed 2 GiB. */
function sha256File(path: string): string {
  const hash = createHash("sha256");
  const chunk = Buffer.alloc(1 << 20);
  const fd = openSync(path, "r");
  try {
    for (let n: number; (n = readSync(fd, chunk)) > 0;) hash.update(chunk.subarray(0, n));
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

/**
 * Runs snarkjs's full zkey check against the phase-1 file the manifest pins. It runs the pinned
 * snarkjs command because zKey.verifyFromR1cs leaves a file handle open, which Node 26 turns
 * into an error when it is garbage collected.
 */
function verifyWithPtau(root: string, ptau: string, pinned: unknown): void {
  if (typeof pinned !== "string") {
    throw new CheckError("--ptau requires ceremony.phase1_ptau_sha256 in the manifest");
  }
  check(sha256File(ptau) === pinned, "ptau hash does not match ceremony.phase1_ptau_sha256");
  const snarkjs = resolve(root, "node_modules/.bin/snarkjs");
  if (!existsSync(snarkjs)) throw new CheckError("--ptau requires the pinned snarkjs: npm ci");
  const args = ["zkey", "verify", resolve(root, R1CS), ptau, resolve(root, ZKEY)];
  const result = spawnSync(snarkjs, args, { encoding: "utf8", maxBuffer: 1 << 26 });
  if (result.error || result.status !== 0) {
    const output = result.stdout.slice(-2000) + result.stderr.slice(-2000);
    throw new CheckError(`snarkjs zkey verify failed:\n${output}`);
  }
}

const isNumber = (value: unknown): value is bigint | number =>
  typeof value === "bigint" || typeof value === "number";

// A number matches by value (5000 matches 5000.0); a string matches only the same string.
const matches = (actual: unknown, expected: string | bigint) =>
  typeof expected === "string" ? actual === expected : isNumber(actual) && actual == expected;

/** A manifest with every integer a bigint read from its text: 1.0 is not one, none is rounded. */
export function parseManifest(text: string): unknown {
  return parseInOrder(text, (value, source) =>
    /^-?[0-9]+$/.test(source) ? BigInt(source) : value,
  );
}

/** Checks a manifest from parseManifest against the tree at root; returns the summary line. */
export function checkActivation(
  manifest: unknown,
  options: { allowTestbed?: boolean; ptau?: string; root?: string } = {},
): string {
  const root = options.root ?? ROOT;
  const artifacts = object(field(manifest, "artifacts", "the manifest"), "artifacts");
  const missing = REQUIRED_ARTIFACTS.filter((rel) => !artifacts.has(rel));
  check(missing.length === 0, `manifest does not pin required artifacts: ${missing.join(", ")}`);
  for (const [rel, expected] of artifacts) {
    const actual = sha256File(resolve(root, rel));
    if (actual !== expected) {
      const shown = typeof expected === "string" ? expected : stringify(expected);
      throw new CheckError(`artifact hash mismatch: ${rel}\nexpected ${shown}\nactual   ${actual}`);
    }
  }
  // The hashes pin each file; these check that the circuit, key and verifier belong together.
  checkSetup(resolve(root, R1CS), resolve(root, ZKEY), resolve(root, VERIFIER));
  const ceremony = () => field(manifest, "ceremony", "the manifest");
  if (options.ptau !== undefined) {
    verifyWithPtau(root, options.ptau, get(ceremony(), "phase1_ptau_sha256", "ceremony"));
  }

  const profile = object(field(manifest, "profile", "the manifest"), "profile");
  const read = (key: string) => field(profile, key, "profile");
  // Gas and the chain ID are counts: a negative, fractional or infinite value (1e400 parses as
  // Infinity) is refused before any comparison.
  const number = (key: string) => {
    const value = read(key);
    if (typeof value !== "bigint" || value < 0n) {
      throw new CheckError(`${key} must be a nonnegative JSON integer`);
    }
    return value;
  };
  for (const key of profile.keys()) check(PROFILE_FIELDS.has(key), `unknown profile field: ${key}`);
  const wire = read("wire_profile");
  check(wire === gas.POOL_PROFILE, `unsupported transaction wire profile: ${stringify(wire)}`);
  for (const [key, value] of Object.entries(EXPECTED_PROFILE)) {
    if (!matches(get(profile, key, "profile"), value)) {
      throw new CheckError(`${key} does not match the immutable dispatcher profile`);
    }
  }
  // The loop above pinned the two frames and the signatures that make up this budget to the
  // wallet's constants.
  if (!matches(read("required_verify_budget"), gas.REQUIRED_VERIFY_BUDGET)) {
    throw new CheckError("required verify budget is inconsistent");
  }
  if (gas.REQUIRED_VERIFY_BUDGET > number("hegota_profile_2_budget")) {
    throw new CheckError("transaction exceeds the configured Hegota Profile 2 budget");
  }
  check(number("chain_id") > 0n, "chain_id must be a positive JSON integer");
  for (const [key, value] of Object.entries(EXPECTED_EVIDENCE)) {
    if (number(key) !== value) throw new CheckError(`${key} differs from check-gas-profile.ts`);
  }

  // Truthiness would read the JSON string "false" as true, so require real types, and take
  // the contribution count from the pinned proving key.
  const evidence = ceremony();
  const production = field(manifest, "production", "the manifest");
  const contributions = field(evidence, "phase2_contributions", "ceremony");
  const verified = field(evidence, "independent_verification", "ceremony");
  check(typeof production === "boolean", "production must be a JSON boolean");
  check(typeof contributions === "bigint", "phase2_contributions must be a JSON integer");
  if (verified !== null && typeof verified !== "boolean") {
    throw new CheckError("independent_verification must be a JSON boolean or null");
  }
  if (contributions !== BigInt(zkeyContributions(resolve(root, ZKEY)))) {
    throw new CheckError("phase2_contributions does not match the proving key");
  }
  if (!production) {
    if (!options.allowTestbed) throw new CheckError("activation blocked: manifest is testbed-only");
  } else if (contributions < 2n || verified !== true) {
    throw new CheckError("activation blocked: production ceremony evidence is incomplete");
  } else if (options.ptau === undefined) {
    // Without the phase-1 file, nothing checks the key's IC and L points against the circuit.
    throw new CheckError("activation blocked: production activation requires --ptau");
  }

  // "partial": A/B terms and verifier checked, the key's points not (see checkSetup).
  const setup = options.ptau !== undefined ? "verified" : "partial";
  return canonical({ artifacts: "match", profile: "match", production, setup });
}

if (import.meta.main) {
  await runCli(() => {
    const { positionals, options } = parseArgs(
      {
        prog: "check-activation.ts",
        positionals: [{ name: "manifest" }],
        options: { "--allow-testbed": { kind: "flag" }, "--ptau": { kind: "string" } },
      },
      process.argv.slice(2),
    );
    const manifest = parseManifest(readText(positionals.manifest));
    const { "--allow-testbed": allowTestbed, "--ptau": ptau } = options;
    process.stdout.write(checkActivation(manifest, { allowTestbed, ptau }) + "\n");
  });
}
