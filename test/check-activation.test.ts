/**
 * The activation gate must reject malformed or self-certified manifests and mismatched setups.
 * The manifest rules run in process through checkActivation; five runs of the CLI pin its
 * contract (exit status, the summary on stdout, the refusal on stderr, the manifest and --ptau
 * reaching the gate). Runtime: about 3 s.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { after, describe, test } from "node:test";

import { CheckError } from "../src/errors.ts";
import {
  checkActivation,
  checkSetup,
  parseManifest,
  R1CS,
  sections,
  VERIFIER,
  ZKEY,
} from "../tools/check-activation.ts";
import { ROOT } from "../tools/check.ts";
import { runCli, type CliResult } from "./helpers.ts";

const GATE = resolve(ROOT, "tools/check-activation.ts");
const BASE_TEXT = readFileSync(resolve(ROOT, "core/activation_manifest.testbed.json"), "utf8");
const PINNED = Object.keys(JSON.parse(BASE_TEXT).artifacts);
const tmp = mkdtempSync(join(tmpdir(), "msp-check-activation-"));
after(() => rmSync(tmp, { recursive: true, force: true }));
let files = 0;
const scratch = (name: string) => join(tmp, `${files++}-${name}`);

type Manifest = Record<string, any>;

/** The committed manifest with `changes` applied, as JSON text (JSON.parse keeps it intact). */
function mutated(...changes: ((manifest: Manifest) => unknown)[]): string {
  const manifest = JSON.parse(BASE_TEXT);
  for (const change of changes) change(manifest);
  return JSON.stringify(manifest);
}

const ceremony = (fields: Manifest) => (m: Manifest) => Object.assign(m.ceremony, fields);
/** Claims production, with `fields` added to the ceremony evidence. */
function production(fields: Manifest) {
  return (m: Manifest) => ceremony(fields)(Object.assign(m, { production: true }));
}

const checkError = (message: string) => (error: unknown) =>
  error instanceof CheckError && error.message.includes(message);
type Options = Parameters<typeof checkActivation>[1];
/** checkActivation must refuse the manifest with a CheckError whose message holds `message`. */
function refused(text: string, message: string, options: Options) {
  assert.throws(() => checkActivation(parseManifest(text), options), checkError(message));
}

/** Runs the gate CLI on the manifest, written to a file as the deploy script would. */
function run(manifest: string | Uint8Array, ...flags: string[]) {
  const path = scratch("manifest.json");
  writeFileSync(path, manifest);
  return runCli(process.execPath, [GATE, path, ...flags]);
}

// The testbed manifest passes only with --allow-testbed, --ptau runs snarkjs only on a file
// whose hash the manifest pins, and a byte that is not UTF-8 is refused, not replaced. The last
// manifest differs from the committed one, so it also shows the gate reads its argument.
test("the gate CLI", async () => {
  const ptau = ["--allow-testbed", "--ptau", resolve(ROOT, R1CS)];
  const pinned = mutated(ceremony({ phase1_ptau_sha256: "0".repeat(64) }));
  // The label's U+00FF written as the single byte 0xff.
  const latin1 = Buffer.from(mutated(ceremony({ label: "\xff" })), "latin1");
  const accepted = run(mutated(), "--allow-testbed");
  const refusals: [Promise<CliResult>, RegExp][] = [
    [run(mutated()), /testbed-only/],
    [run(mutated(), ...ptau), /requires ceremony\.phase1_ptau_sha256/],
    [run(latin1, "--allow-testbed"), /not valid for encoding utf-8/],
    [run(pinned, ...ptau), /ptau hash does not match/],
  ];
  const { code, stdout, stderr } = await accepted;
  assert.equal(code, 0, stderr);
  assert.equal(
    stdout,
    '{"artifacts": "match", "production": false, "profile": "match", "setup": "partial"}\n',
  );
  for (const [result, pattern] of refusals) {
    const { code, stderr } = await result;
    assert.equal(code, 1, stderr);
    assert.match(stderr, pattern);
  }
});

const GAS_EVIDENCE = [
  "hegota_profile_2_budget",
  "post_pr_12279_max_observed_verify_execution_gas",
  "conservative_settle_bound",
  "conservative_settle_state_bound",
];

// None of these refusals depends on --allow-testbed.
describe("malformed or self-certified manifests", () => {
  const verified = { independent_verification: true };
  const overstated = production({ ...verified, phase2_contributions: 2 });
  const wrongHash = (m: Manifest) => (m.artifacts["src/gas.ts"] = "0".repeat(64));
  const set = (key: string, value: unknown) => (m: Manifest) => (m.profile[key] = value);
  // Each value is compared with the dispatcher's; no later check reads these two.
  const profile = (key: string, value: unknown): [string, (m: Manifest) => void, string] => [
    `a ${key} other than the dispatcher's`,
    set(key, value),
    `${key} does not match the immutable dispatcher profile`,
  ];
  const cases: [label: string, change: (m: Manifest) => void, message: string][] = [
    ["empty artifacts", (m) => (m.artifacts = {}), "required artifacts"],
    ["string production", (m) => (m.production = "false"), "JSON boolean"],
    ["string contribution count", ceremony({ phase2_contributions: "1" }), "JSON integer"],
    ["boolean contribution count", ceremony({ phase2_contributions: true }), "JSON integer"],
    ["string verification", ceremony({ independent_verification: "false" }), "boolean or null"],
    ["overstated contributions", overstated, "does not match the proving key"],
    ["production without ceremony", production(verified), "ceremony evidence is incomplete"],
    ["a pinned hash the file does not have", wrongHash, "artifact hash mismatch: src/gas.ts"],
    profile("verify_frame_gas", 225001),
    profile("pool_profile", "position-notes-v2"),
    ["string verify_frame_gas", set("verify_frame_gas", "225000"), "verify_frame_gas does not"],
    ["the previous wire_profile", set("wire_profile", "position-notes-v2"), "wire profile"],
    // The budget is the recent root, VERIFY and two signatures' gas: 8000 + 225000 + 2 * 2800 =
    // 238600.
    ["a verify budget one over", set("required_verify_budget", 238601), "budget is inconsistent"],
    ["a verify budget one under", set("required_verify_budget", 238599), "budget is inconsistent"],
    // The settle frame must have more gas than the bound, not just as much.
    ["a settle bound at the frame gas", set("conservative_settle_bound", 2000000), "fork bound"],
  ];
  for (const allowTestbed of [false, true]) {
    const mode = allowTestbed ? ", --allow-testbed" : "";
    for (const [label, change, message] of cases) {
      test(`${label}${mode}`, () => refused(mutated(change), message, { allowTestbed }));
    }
    test(`a contribution count written as 1.0${mode}`, () => {
      const text = BASE_TEXT.replace('"phase2_contributions": 1,', '"phase2_contributions": 1.0,');
      refused(text, "JSON integer", { allowTestbed });
    });
    // The gas evidence is checked against one-sided bounds, so it must be a count.
    for (const key of GAS_EVIDENCE) {
      for (const value of ["-1", "0.5", "1e400"]) {
        test(`${key} written as ${value}${mode}`, () => {
          const token = new RegExp(`("${key}": )[0-9]+`);
          assert.match(BASE_TEXT, token);
          const text = BASE_TEXT.replace(token, `$1${value}`);
          refused(text, `${key} must be a nonnegative JSON integer`, { allowTestbed });
        });
      }
    }
    test(`every artifact the committed manifest pins is required${mode}`, () => {
      for (const rel of PINNED) {
        const text = mutated((m) => delete m.artifacts[rel]);
        refused(text, `pin required artifacts: ${rel}`, { allowTestbed });
      }
    });
  }
});

/** A copy of a committed iden3 binary file, a view of it, and where section n's body starts. */
function edit(rel: string, magic: string, n: number) {
  const { data, found } = sections(resolve(ROOT, rel), magic, n);
  const bytes = Uint8Array.from(data);
  return { bytes, view: new DataView(bytes.buffer), at: found.get(n)! };
}

// The committed key records one phase-2 contribution, so production can pass only on a key
// that records two: here a copy of the pinned tree whose key claims a second contribution. The
// gate reads the count from section 10 and checks no other part of the key against it. No
// phase-1 file is committed, so the copy's snarkjs is a stand-in whose `zkey verify` passes
// with one stand-in ptau and fails with any other.
describe("production needs two contributions, independent verification and --ptau", () => {
  const root = join(tmp, "two-contributions");
  for (const rel of PINNED) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    copyFileSync(resolve(ROOT, rel), join(root, rel));
  }
  // Section 10: the 64-byte circuit hash, then the u32 contribution count.
  const zkey = edit(ZKEY, "zkey", 10);
  zkey.view.setUint32(zkey.at + 64, 2, true);
  writeFileSync(join(root, ZKEY), zkey.bytes);
  const sha256 = (data: Uint8Array | string) => createHash("sha256").update(data).digest("hex");
  const hash = sha256(zkey.bytes);
  // Each stand-in ptau holds its own path.
  const [ptau, other] = ["phase1.ptau", "other.ptau"].map((name) => {
    const path = scratch(name);
    writeFileSync(path, path);
    return path;
  });
  const snarkjs = join(root, "node_modules/.bin/snarkjs");
  mkdirSync(dirname(snarkjs), { recursive: true });
  writeFileSync(snarkjs, `#!/bin/sh\n[ "$1 $2 $4" = 'zkey verify ${ptau}' ]\n`, { mode: 0o755 });
  const claim = (verified: boolean | null, pinned = ptau) =>
    mutated(
      production({ phase2_contributions: 2, independent_verification: verified }),
      ceremony({ phase1_ptau_sha256: sha256(pinned) }),
      (m) => (m.artifacts[ZKEY] = hash),
    );

  test("accepted with independent verification and --ptau", () => {
    assert.equal(
      checkActivation(parseManifest(claim(true)), { root, ptau }),
      '{"artifacts": "match", "production": true, "profile": "match", "setup": "verified"}',
    );
  });

  test("refused without --ptau, even with --allow-testbed", () => {
    for (const allowTestbed of [false, true]) {
      const message = "activation blocked: production activation requires --ptau";
      refused(claim(true), message, { root, allowTestbed });
    }
  });

  test("refused with a pinned ptau the key does not verify against", () => {
    refused(claim(true, other), "snarkjs zkey verify failed", { root, ptau: other });
  });

  test("refused with independent verification null or false, with or without --ptau", () => {
    for (const verified of [null, false]) {
      for (const options of [{ root }, { root, ptau }]) {
        refused(claim(verified), "ceremony evidence is incomplete", options);
      }
    }
  });
});

/** A file of the iden3 binary format: magic, version 1, then each section's kind, size and body. */
function binary(magic: string, ...parts: [kind: number, body: string][]): string {
  const le = (n: number, size: number) =>
    Buffer.from(n.toString(16).padStart(2 * size, "0"), "hex").reverse();
  const head = [Buffer.from(magic), le(1, 4), le(parts.length, 4)];
  const chunks = parts.flatMap(([k, body]) => [le(k, 4), le(body.length, 8), Buffer.from(body)]);
  const path = scratch("sections.bin");
  writeFileSync(path, Buffer.concat([...head, ...chunks]));
  return path;
}

test("sections finds each section and refuses a repeated or missing one", () => {
  // 12 header bytes, then each section's 12-byte header before its body.
  const path = binary("zkey", [1, "ab"], [2, "cd"]);
  assert.deepEqual([...sections(path, "zkey", 1, 2).found].flat(), [1, 24, 2, 38]);
  assert.throws(() => sections(path, "zkey", 1, 3), checkError("has no section 3"));
  const repeated = binary("zkey", [1, "ab"], [1, "cd"]);
  assert.throws(() => sections(repeated, "zkey"), checkError("repeats section 1"));
});

type Replaced = { r1cs?: Uint8Array; zkey?: Uint8Array; verifier?: string };
/** checkSetup must reject the committed artifacts with some of them replaced. */
function setupRejected(message: string, { r1cs, zkey, verifier }: Replaced) {
  const path = (rel: string, content?: Uint8Array | string) => {
    if (content === undefined) return resolve(ROOT, rel);
    const path = scratch(basename(rel));
    writeFileSync(path, content);
    return path;
  };
  const paths = [path(R1CS, r1cs), path(ZKEY, zkey), path(VERIFIER, verifier)] as const;
  assert.throws(() => checkSetup(...paths), checkError(message));
}

// A key, R1CS or verifier that honest proofs cannot tell apart must still fail.
describe("mismatched key setups", () => {
  const verifier = readFileSync(resolve(ROOT, VERIFIER), "utf8");
  const lines = verifier.split("\n");
  /** The verifier without the lines `pattern` matches, which must number `count`. */
  const without = (pattern: RegExp, count: number) => {
    const kept = lines.filter((line) => !pattern.test(line));
    assert.equal(kept.length, lines.length - count);
    return kept.join("\n");
  };

  test("a key with its first or last term changed, a circuit with one constraint fewer", () => {
    // Section 4: a u32 count, then 44-byte entries of u32 matrix, constraint and signal and a
    // 32-byte value.
    const zkey = edit(ZKEY, "zkey", 4);
    for (const term of [0, zkey.view.getUint32(zkey.at, true) - 1]) {
      const value = zkey.at + 4 + 44 * term + 12;
      setupRejected("A/B terms", { zkey: zkey.bytes.with(value, zkey.bytes[value] ^ 1) });
    }
    // Header: u32 n8, the n8-byte prime, four u32 counts and a u64, then u32 nConstraints.
    const { bytes, view, at } = edit(R1CS, "r1cs", 1);
    const count = at + 4 + view.getUint32(at, true) + 24;
    view.setUint32(count, view.getUint32(count, true) - 1, true);
    setupRejected("A/B terms", { r1cs: bytes });
  });

  // Constants compare in both directions: one missing from either side is a difference.
  test("a verifier with a changed, a missing or an extra constant", () => {
    assert.equal(verifier.split("deltax1 = ").length, 2);
    setupRejected("deltax1", { verifier: verifier.replace("deltax1 = ", "deltax1 = 1") });
    setupRejected("deltax1", { verifier: without(/constant deltax1 = /, 1) });
    // An IC point for a public input the key does not have.
    setupRejected("IC99x", { verifier: `${verifier}\nuint256 constant IC99x = 1;\n` });
  });

  // A key whose header claims one public input fewer than the circuit has, with a verifier
  // that agrees with it, would leave that input unchecked.
  test("a key and verifier that agree with each other but drop a public input", () => {
    // Section 2: u32 n8q and q, u32 n8r and r, then u32 nVars and u32 nPublic.
    const { bytes, view, at } = edit(ZKEY, "zkey", 2);
    const n8q = view.getUint32(at, true);
    const nPublicAt = at + 4 + n8q + 4 + view.getUint32(at + 4 + n8q, true) + 4;
    const nPublic = view.getUint32(nPublicAt, true);
    view.setUint32(nPublicAt, nPublic - 1, true);
    // The key now reads IC points 0 to nPublic - 1; drop the last one from the verifier too.
    const agreeing = without(new RegExp(`constant IC${nPublic}[xy] `), 2);
    setupRejected("nVars or nPublic", { zkey: bytes, verifier: agreeing });
  });
});
