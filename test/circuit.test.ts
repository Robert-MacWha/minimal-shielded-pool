/**
 * The occurrence nullifier circuit, with real witnesses against the committed artifacts and one
 * real Groth16 proof: duplicates of one commitment at different positions get distinct
 * nullifiers, the committed R1CS (not only the WASM's runtime asserts) rejects every broken
 * witness, beta and gamma are constrained, assertUnprovable (the smoke generator's soundness
 * gate) counts only an in-circuit assertion as a refusal, verify() accepts the call the pool
 * probes a deployed verifier with, and it refuses every mutated statement value and the
 * out-of-field words and signals that snarkjs alone would accept. The consumed-key registry and
 * the authentication of epoch roots are left to the native tests.
 *
 * Runtime: about 17 s, including six circom2 compiles run in parallel.
 * Everything is built in a fresh temporary directory, so a changed circuit is never checked
 * against stale variants, and the file can run alongside other tests.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { keccak_256 } from "@noble/hashes/sha3.js";
// @ts-expect-error snarkjs 0.7.5 ships no type declarations; Snarkjs below types what is used.
import * as untyped from "snarkjs";

import { mod } from "../src/bytes.ts";
import { InputError } from "../src/errors.ts";
import { referenceVerifierCalls } from "../src/deployment.ts";
import { WASM, assertUnprovable, prove, terminate, verify } from "../src/prover.ts";
import type { ProofWords } from "../src/prover.ts";
import * as pr from "../src/protocol.ts";
import { seededRng } from "../src/random.ts";
import {
  Tree,
  buildWitness,
  dummyInput,
  newAuthorizer,
  newNote,
  type Witness,
} from "../src/wallet.ts";

interface Snarkjs {
  wtns: {
    calculate(input: Witness, wasm: string, wtns: string): Promise<void>;
    // 0.7.5 calls logger.warn on a failing witness without checking it has a logger.
    check(r1cs: string, wtns: string, logger: object): Promise<boolean>;
    exportJson(wtns: string): Promise<bigint[]>;
  };
}
const snarkjs: Snarkjs = untyped;
const quiet = { debug() {}, info() {}, warn() {}, error() {} };

const path = (relative: string) => fileURLToPath(new URL(`../${relative}`, import.meta.url));
const ROOT = path("");
const CIRCUIT = path("core/circuits/spend.circom");
const R1CS = path("core/artifacts/spend.r1cs");
const CIRCOM = path("node_modules/.bin/circom2");

/** The BN254 base field modulus: every proof word the deployed verifier takes is below it. */
const Q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;

const word = (x: bigint) => x.toString(16).padStart(64, "0");

/** The pool's alpha, computed here: keccak256 of the ten 32-byte big-endian words, mod P. */
function keccakAlpha(stmt: readonly bigint[]): bigint {
  const hash = keccak_256(Buffer.from(stmt.map(word).join(""), "hex"));
  return BigInt("0x" + Buffer.from(hash).toString("hex")) % pr.P;
}

function edited<T>(value: T, edit: (copy: T) => unknown): T {
  const copy = structuredClone(value);
  edit(copy);
  return copy;
}

/** Starts make() on first use and hands every caller the same promise. */
function once<T>(make: () => Promise<T>): () => Promise<T> {
  let promise: Promise<T> | undefined;
  return () => (promise ??= make());
}

let work = "";

// ---- the circuit variants ----

// The generated WASM asserts every constraint while computing a witness, so a rejection
// there alone would not notice a constraint that became a runtime-only check and left the
// R1CS. A variant circuit without the targeted constraints computes a complete witness that
// breaks only them; mapped by signal name onto the committed wire layout (the optimizer
// merges signals differently once constraints are removed), the committed R1CS must reject
// it. Each range check gets its own variant so its case stays isolated from the other ranges.
const UNCHECKED = [
  "    in_value[0] + in_value[1] === out_value[0] + out_value[1] + public_amount + fee;\n",
  "        bits[i] * (bits[i] - 1) === 0;\n",
  "    (cur[DEPTH] - root) * value === 0;\n",
  "            (out_inner[k] - SINK_INNER_0) * outIsZero[k].out === 0;\n",
  "            (out_inner[k] - SINK_INNER_1) * outIsZero[k].out === 0;\n",
  "        outEqSink0[k].out * (1 - outIsZero[k].out) === 0;\n",
  "        outEqSink1[k].out * (1 - outIsZero[k].out) === 0;\n",
  "    sameNullifier.out === 0;\n",
  "    sameOutput.out === 0;\n",
  "    noRealInput.out === 0;\n",
  "    authorizerIsZero.out === 0;\n",
  "    publicIsZero.out === recipientIsZero.out;\n",
];
const RANGE = "        rc[k].in <== vals[k];\n";
// The wide variant decomposes every amount and both addresses into 254 bits. Below each check's
// width the low bits are the committed ones, so an honest witness still holds, while a value at
// or above the width leaves the committed bits short of it. Unlike range-k, it also covers
// ranges whose value in the template witness is not zero.
const WIDE = [
  ["        rc[k] = Num2Bits(128);\n", "        rc[k] = Num2Bits(254);\n"],
  [
    "    component recipientBits = Num2Bits(160);\n",
    "    component recipientBits = Num2Bits(254);\n",
  ],
  [
    "    component authorizerBits = Num2Bits(160);\n",
    "    component authorizerBits = Num2Bits(254);\n",
  ],
];

// range-k drops the 128-bit range check of vals[k], where vals is [in_value[0], in_value[1],
// out_value[0], out_value[1], public_amount, fee].
const VARIANTS = ["unchecked", "range-2", "range-3", "range-5", "wide"] as const;
type Variant = (typeof VARIANTS)[number];

/** The variant's source; every line it edits must occur exactly once in the circuit. */
function variantSource(variant: Variant): string {
  const k = variant.slice("range-".length);
  const edits =
    variant === "unchecked"
      ? UNCHECKED.map((line) => [line, ""])
      : variant === "wide"
        ? WIDE
        : [[RANGE, `        if (k == ${k}) { rc[k].in <== 0; } else { rc[k].in <== vals[k]; }\n`]];
  let source = readFileSync(CIRCUIT, "utf8");
  for (const [line, replacement] of edits) {
    assert.equal(source.split(line).length, 2, line);
    source = source.replace(line, replacement);
  }
  return source;
}

function perVariant<T>(make: (variant: Variant) => Promise<T>): Record<Variant, () => Promise<T>> {
  const entries = VARIANTS.map((variant) => [variant, once(() => make(variant))] as const);
  return Object.fromEntries(entries) as Record<Variant, () => Promise<T>>;
}

// circom2 rewrites every path relative to its working directory and cannot resolve an include
// path that starts with "..", so it runs from the repository root, next to node_modules.
async function circom(source: string, out: string, flags: string[]): Promise<void> {
  mkdirSync(out, { recursive: true });
  const args = [source, ...flags, "-l", "node_modules", "-o", out];
  await promisify(execFile)(CIRCOM, args, { cwd: ROOT, maxBuffer: 1 << 26 });
}

/** Signal name to wire from a .sym file (label,wire,component,name; wire -1 means optimized away). */
function symbolWires(sym: string): Map<string, number> {
  const rows = readFileSync(sym, "utf8").matchAll(/^[^,\n]*,([^,\n]*),[^,\n]*,(.*)$/gm);
  return new Map([...rows].map(([, wire, name]): [string, number] => [name, Number(wire)]));
}

/** The committed build's wires by signal name, from a symbol build of the same source. */
const committedWires = once(async () => {
  const out = join(work, "sym");
  await circom(CIRCUIT, out, ["--r1cs", "--sym"]);
  const r1cs = readFileSync(join(out, "spend.r1cs"));
  assert.ok(r1cs.equals(readFileSync(R1CS)), "the symbol build differs from the committed R1CS");
  return symbolWires(join(out, "spend.sym"));
});

const builds = perVariant(async (variant) => {
  const out = join(work, `variant-${variant}`);
  const source = join(out, "circuits", "spend.circom");
  mkdirSync(join(out, "circuits"), { recursive: true });
  writeFileSync(source, variantSource(variant));
  await circom(source, out, ["--wasm", "--sym"]);
  return { wasm: join(out, "spend_js", "spend.wasm"), wires: symbolWires(join(out, "spend.sym")) };
});

// ---- witnesses ----

/** Computes a witness with a WASM (the committed one by default) into work/<label>.wtns. */
async function calculate(label: string, witness: Witness, wasm = WASM): Promise<string> {
  const target = join(work, `${label}.wtns`);
  await snarkjs.wtns.calculate(witness, wasm, target);
  return target;
}

const satisfies = (wtns: string) => snarkjs.wtns.check(R1CS, wtns, quiet);

/**
 * Writes work/<label>.wtns, a copy of the .wtns file `from` with some wire values replaced. The
 * file is "wtns", u32 version, u32 section count, then sections of u32 type and u64 size;
 * section 1 starts with u32 n8 and section 2 holds one n8-byte little-endian value per wire.
 */
function patched(label: string, from: string, values: ReadonlyMap<number, bigint>): string {
  const data = readFileSync(from);
  assert.equal(data.toString("latin1", 0, 4), "wtns");
  const offsets = new Map<number, [start: number, size: number]>();
  for (let i = 0, pos = 12; i < data.readUInt32LE(8); i++) {
    const size = Number(data.readBigUInt64LE(pos + 4));
    offsets.set(data.readUInt32LE(pos), [pos + 12, size]);
    pos += 12 + size;
  }
  const n8 = data.readUInt32LE(offsets.get(1)![0]);
  const [wires, size] = offsets.get(2)!;
  for (const [index, value] of values) {
    assert.ok((index + 1) * n8 <= size, `wire ${index} is outside the witness`);
    let v = mod(value, pr.P);
    for (let b = 0; b < n8; b++, v >>= 8n) data[wires + index * n8 + b] = Number(v & 0xffn);
  }
  const target = join(work, `${label}.wtns`);
  writeFileSync(target, data);
  return target;
}

/**
 * The variant's witness for `witness`, placed on the committed wires by signal name. Every
 * committed wire must get a value from the variant, so nothing of the template survives.
 */
async function onCommittedWires(variant: Variant, witness: Witness, label: string) {
  const compiled = await builds[variant]();
  const committed = await committedWires();
  const computed = await calculate(`${label}.variant`, witness, compiled.wasm).catch((error) =>
    assert.fail(`variant ${variant} did not compute a witness: ${error}`),
  );
  const values = await snarkjs.wtns.exportJson(computed);
  const placed = new Map([[0, 1n]]);
  for (const [name, wire] of committed) {
    if (wire < 0) continue;
    const source = compiled.wires.get(name) ?? -1;
    assert.ok(source >= 0, `${name} has no wire in variant ${variant}`);
    placed.set(wire, values[source]);
  }
  return patched(label, await template(), placed);
}

/** The ten statement values a witness should prove, given the nullifiers it should compute. */
function statementFor(w: Witness, [nf1, nf2]: readonly bigint[]): bigint[] {
  const outputs = w.out_inner.map((out, k): pr.Output => [BigInt(out), BigInt(w.out_value[k])]);
  const [outCm1, outCm2] = pr.outputCommitments(outputs);
  const [root, domain, publicAmount, fee] = [w.root, w.domain, w.public_amount, w.fee].map(BigInt);
  const [recipient, authorizer] = [w.recipient, w.authorizer].map(BigInt);
  const terms = { root, domain, publicAmount, fee, recipient, authorizer };
  return pr.statement({ nf1, nf2, outCm1, outCm2, ...terms });
}

/**
 * The committed WASM computes the witness and the committed R1CS accepts it. The statement is
 * private: beta and gamma (wires 1 and 2, then alpha) match the expected statement only if the
 * circuit computed exactly these ten values, which binds its nullifiers to the expected ones.
 */
async function accepted(name: string, witness: Witness, expected: readonly bigint[]) {
  const wtns = await calculate(name, witness);
  assert.equal(await satisfies(wtns), true, `${name}: the committed R1CS rejects it`);
  const [, beta, gamma, alpha] = await snarkjs.wtns.exportJson(wtns);
  assert.equal(beta, pr.compressionBeta(expected), `${name}: beta`);
  assert.equal(gamma, pr.fingerprint(mod(alpha + beta, pr.P), expected), `${name}: gamma`);
}

/**
 * The committed WASM refuses the witness with an in-circuit assertion, and the committed R1CS
 * rejects the complete witness that the variant without the broken constraints computes for it.
 */
async function rejected(name: string, witness: Witness, variant: Variant) {
  await assertUnprovable(witness, name);
  await honest[variant]();
  const wtns = await onCommittedWires(variant, witness, `${name}-${variant}`);
  assert.equal(await satisfies(wtns), false, `${name}: the committed R1CS accepts it`);
}

// ---- the notes, drawn in a fixed order from one seeded stream ----

const rng = seededRng(20260921n);
const pool = "0x" + "12".repeat(20);
const recipient = BigInt("0x" + "34".repeat(20));
const [domain0, domain1] = [0n, 1n].map((epoch) => pr.domainScalar(31337n, pool, epoch));
const [sk, rho] = newNote(rng);
const real: pr.SpendInput = { sk, rho, value: 100n, idx: 0n };
const duplicate: pr.SpendInput = { ...real, idx: 1n };
const cm = pr.commitment(sk, rho, 100n);
const treeOf = (leaves: readonly bigint[]) =>
  leaves.reduce((tree, leaf) => (tree.append(leaf), tree), new Tree());
const tree = treeOf([cm, cm, pr.commitment(...newNote(rng), 17n)]);
const dummy = dummyInput(rng);
const [, authorizer] = newAuthorizer(rng);
// The same tree after one more deposit: a later root.
const later = treeOf([...tree.leaves, pr.commitment(...newNote(rng), 29n)]);
// A reorg can change the insertion order of the same two deposits.
const otherCm = pr.commitment(...newNote(rng), 37n);
const [branchA, branchB] = [treeOf([cm, otherCm]), treeOf([otherCm, cm])];
const transferOutputs = [60n, 40n].map((value): pr.Output => [pr.inner(...newNote(rng)), value]);
// Two funded inputs of 2^128 - 1 and 1, and an output that takes all but 1 of them.
const max = (1n << 128n) - 1n;
const wideInputs = [max, 1n].map((value, i): pr.SpendInput => {
  const [sk, rho] = newNote(rng);
  return { sk, rho, value, idx: BigInt(i) };
});
const wideOutputs: pr.Output[] = [pr.sinkOutputs()[0], [pr.inner(...newNote(rng)), max]];

/** A withdrawal of every input to the fixed recipient through both sinks, and its statement. */
function spend(inputs: pr.SpendInput[], on = tree, domain = domain0): [Witness, bigint[]] {
  const publicAmount = inputs.reduce((sum, i) => sum + i.value, 0n);
  const terms = { authorizer, publicAmount, recipient };
  const witness = buildWitness(on, inputs, pr.sinkOutputs(), domain, terms);
  return [witness, statementFor(witness, pr.inputNullifiers(domain, inputs))];
}

const [first, firstStmt] = spend([real, dummy]);
const [second, secondStmt] = spend([duplicate, dummy]);
const [pair, pairStmt] = spend([real, duplicate]);
// The same input epoch, commitment and position on a later root; the publication slot is
// intentionally absent.
const [laterFirst, laterStmt] = spend([real, dummy], later);
// Both epochs have to be authenticated independently by the dispatcher. This circuit test
// only checks domain separation, not root provenance.
const [otherEpoch, otherEpochStmt] = spend([real, dummy], later, domain1);
// After the reorg the note is leaf 1 of branchB: the wallet rebuilds the canonical tree and
// spends it at that index, which is `duplicate`'s opening, before reproving.
const [rebuilt, rebuiltStmt] = spend([duplicate, dummy], branchB);
const [dummyPair, dummyStmt] = spend([real, { sk, rho, value: 0n, idx: null }], later);
const atMax = edited(dummyPair, (w) => (w.in_bits[1] = Array(pr.DEPTH).fill("1")));
const maxNf = pr.nullifier(domain0, sk, pr.commitment(sk, rho, 0n), (1n << BigInt(pr.DEPTH)) - 1n);
const atMaxStmt = statementFor(atMax, [dummyStmt[0], maxNf]);

const [twice] = spend([real, real]);
const transfer = buildWitness(later, [real, dummy], transferOutputs, domain0, { authorizer });
const [negative, inflated] = [String(pr.P - 10n ** 21n), String(100n + 10n ** 21n)];
const wideTree = treeOf(wideInputs.map((i) => pr.commitment(i.sk, i.rho, i.value)));
const wideTerms = { authorizer, publicAmount: 1n, recipient };
const wide = buildWitness(wideTree, wideInputs, wideOutputs, domain0, wideTerms);
// A one-leaf tree whose note holds exactly 2^128, which no wallet can make: buildWitness takes
// the note at 2^128 - 1 and the case below raises it, so the root still proves its membership.
const [bigSk, bigRho] = newNote(rng);
const bigTree = treeOf([pr.commitment(bigSk, bigRho, 1n << 128n)]);
const bigNote: pr.SpendInput = { sk: bigSk, rho: bigRho, value: max, idx: 0n };
const bigOutputs: pr.Output[] = [pr.sinkOutputs()[0], [pr.inner(...newNote(rng)), max - 1n]];
const bigTerms = { authorizer, fee: 1n };
/** An input of exactly 2^128 in position k, paying 2^128 - 1 and a fee of 1. */
const bigInput = (k: number) =>
  edited(
    buildWitness(
      bigTree,
      k === 0 ? [bigNote, dummy] : [dummy, bigNote],
      bigOutputs,
      domain0,
      bigTerms,
    ),
    (w) => {
      w.in_value[k] = String(1n << 128n);
      w.out_value[1] = String(max);
    },
  );

/** first-occurrence's witness from the committed WASM, the template variants are placed on. */
const template = once(() => calculate("template", first));

/** Each variant's honest witness for first-occurrence, placed on the committed wires, holds. */
const honest = perVariant(async (variant) => {
  const wtns = await onCommittedWires(variant, first, `honest-${variant}`);
  const wrong = "the committed R1CS rejects the honest witness, so the wire mapping is wrong";
  assert.equal(await satisfies(wtns), true, `variant ${variant}: ${wrong}`);
});

before(() => {
  work = mkdtempSync(join(tmpdir(), "msp-occurrence-"));
  // Compile everything at once; each test awaits the builds it needs and reports their failure.
  for (const build of [committedWires, ...Object.values(builds)]) build().catch(() => {});
});

after(async () => {
  await terminate();
  if (work !== "") rmSync(work, { recursive: true, force: true });
});

// ---- cases ----

test("the circuit has no unconstrained assignment", () => {
  // `<--` and `-->` assign a signal without constraining it, the classic way a circuit ends up
  // accepting forged values, so a new one fails here until it gets its own constraint and review.
  const source = readFileSync(CIRCUIT, "utf8").split("\n");
  const lines = source.flatMap((line, i) => (/<--|-->/.test(line.split("//")[0]) ? [i + 1] : []));
  assert.deepEqual(lines, [], "core/circuits/spend.circom assigns without a constraint");
});

test("the symbol build reproduces the committed R1CS", async () => {
  await committedWires();
});

for (const variant of VARIANTS) {
  test(`variant ${variant} maps the honest witness onto the committed wires`, honest[variant]);
}

test("assertUnprovable counts only an in-circuit assertion as a refusal", async () => {
  // Every rejected case and the smoke generator's soundness gate rely on it: it must report a
  // witness the WASM accepts, and surface another failure (a missing signal) as that error.
  await assertUnprovable(twice, "same-occurrence-twice");
  const unsound = { name: "GeneratorError", message: "UNSOUND: circuit accepted first-occurrence" };
  await assert.rejects(assertUnprovable(first, "first-occurrence"), unsound);
  const { fee: _, ...missing } = first;
  const withoutFee = assertUnprovable(missing as Witness, "a witness without fee");
  await assert.rejects(withoutFee, /Not all inputs have been set/);
});

const ACCEPTED: Record<string, [Witness, bigint[]]> = {
  "first-occurrence": [first, firstStmt],
  "identical-second-occurrence": [second, secondStmt],
  "both-identical-funded-occurrences": [pair, pairStmt],
  "same-occurrence-later-root": [laterFirst, laterStmt],
  "same-position-other-authenticated-epoch": [otherEpoch, otherEpochStmt],
  "reorg-rebuilt-tree-and-index": [rebuilt, rebuiltStmt],
  "dummy-same-secret-and-position": [dummyPair, dummyStmt],
  "dummy-arbitrary-maximum-position": [atMax, atMaxStmt],
};
for (const [name, [witness, stmt]] of Object.entries(ACCEPTED)) {
  test(name, () => accepted(name, witness, stmt));
}

test("the accepted cases' nullifiers follow the position and epoch, not the root", () => {
  // statement[0] and [1] are the nullifiers, and statement[4] the root.
  assert.notEqual(secondStmt[0], firstStmt[0], "identical-second-occurrence");
  const both = [firstStmt[0], secondStmt[0]];
  assert.deepEqual(pairStmt.slice(0, 2), both, "both-identical-funded-occurrences");
  assert.notEqual(laterStmt[4], firstStmt[4], "same-occurrence-later-root: root");
  assert.deepEqual(laterStmt.slice(0, 2), firstStmt.slice(0, 2), "same-occurrence-later-root");
  assert.notEqual(otherEpochStmt[0], laterStmt[0], "same-position-other-authenticated-epoch");
  assert.notEqual(rebuiltStmt[0], firstStmt[0], "reorg-rebuilt-tree-and-index");
  assert.notEqual(dummyStmt[0], dummyStmt[1], "dummy-same-secret-and-position");
  assert.notEqual(atMaxStmt[1], laterStmt[0], "dummy-arbitrary-maximum-position");
});

type Rejected = [name: string, witness: Witness, variant?: Variant];
const REJECTED: Rejected[] = [
  ["same-occurrence-twice", twice],
  [
    "same-output-twice-in-one-spend",
    edited(pair, (w) => {
      w.out_inner = Array(2).fill(String(pr.inner(sk, rho)));
      w.out_value = ["100", "100"];
      w.public_amount = "0";
      w.recipient = "0";
    }),
  ],
  // Selects a different branch of the same tree.
  ["forged-real-position", edited(first, (w) => (w.in_bits[0][1] = "1"))],
  ["nonboolean-path-bit", edited(first, (w) => (w.in_bits[0][0] = "2"))],
  ["incorrect-root", edited(first, (w) => (w.root = String(mod(BigInt(w.root) + 1n, pr.P))))],
  [
    "reorg-stale-membership-path",
    edited(spend([real, dummy], branchA)[0], (w) => (w.root = String(branchB.root()))),
  ],
  // Each witness below breaks exactly one constraint, so deleting or weakening that constraint
  // alone would let it through.
  ["outputs-exceed-inputs", edited(first, (w) => (w.public_amount = "101"))],
  ["inputs-exceed-outputs", edited(first, (w) => (w.public_amount = "99"))],
  // Conserved modulo p only.
  [
    "value-wraps-the-field",
    edited(first, (w) => Object.assign(w, { public_amount: "101", fee: String(pr.P - 1n) })),
    "range-5",
  ],
  // A dummy's membership is gated off by its zero value, so a non-boolean path bit there
  // breaks only the booleanity constraint, at any depth.
  ...[0, 10, 19].map((d): Rejected => [
    `nonboolean-dummy-path-bit-${d}`,
    edited(first, (w) => (w.in_bits[1][d] = "2")),
  ]),
  ...[0, 1].map((k): Rejected => [
    `zero-output-${k}-without-its-sink`,
    edited(transfer, (w) => (w.out_value = ["100", "100"].with(k, "0"))),
  ]),
  ["positive-output-with-the-second-sink", edited(transfer, (w) => (w.out_inner[0] = "2"))],
  // A negative output paid for by an inflated other output conserves value modulo p and breaks
  // only that output's 128-bit range: without it, 100 wei of input would create a 10^21 wei note.
  ...[0, 1].map((k): Rejected => [
    `output-${k}-below-zero`,
    edited(transfer, (w) => (w.out_value = [inflated, inflated].with(k, negative))),
    k === 0 ? "range-2" : "range-3",
  ]),
  // The width itself, without a wrap: the two inputs pay one output of exactly 2^128.
  [
    "output-of-exactly-2^128",
    edited(wide, (w) => {
      w.public_amount = "0";
      w.recipient = "0";
      w.out_value[1] = String(1n << 128n);
    }),
    "range-3",
  ],
  // The rules below had no case: the smoke generator checks three of them only against the
  // WASM's runtime asserts.
  [
    "no-real-input",
    edited(first, (w) =>
      Object.assign(w, { in_value: ["0", "0"], public_amount: "0", recipient: "0" }),
    ),
  ],
  ["zero-authorizer", edited(first, (w) => (w.authorizer = "0"))],
  ["withdrawal-without-recipient", edited(first, (w) => (w.recipient = "0"))],
  ["recipient-without-withdrawal", edited(transfer, (w) => (w.recipient = String(recipient)))],
  [
    "recipient-of-2^160-or-more",
    edited(first, (w) => (w.recipient = String(recipient + (1n << 160n)))),
    "wide",
  ],
  [
    "authorizer-of-2^160-or-more",
    edited(first, (w) => (w.authorizer = String(authorizer + (1n << 160n)))),
    "wide",
  ],
  ...[0, 1].map((k): Rejected => [`input-${k}-of-exactly-2^128`, bigInput(k), "wide"]),
  // The inputs pay a withdrawal of exactly 2^128 through both sinks.
  [
    "public-amount-of-exactly-2^128",
    edited(wide, (w) => {
      w.out_inner[1] = String(pr.sinkOutputs()[1][0]);
      w.out_value[1] = "0";
      w.public_amount = String(1n << 128n);
    }),
    "wide",
  ],
];
for (const [name, witness, variant = "unchecked"] of REJECTED) {
  test(name, () => rejected(name, witness, variant));
}

test("reference-canonical-epoch-and-index-bounds", () => {
  // The helpers' ranges must agree with the dispatcher's uint64 epochs and depth-20 indices.
  for (const epoch of [-1n, 1n << 64n]) {
    assert.throws(() => pr.domainScalar(31337n, pool, epoch), InputError, `epoch ${epoch}`);
  }
  for (const index of [-1n, 1n << BigInt(pr.DEPTH)]) {
    assert.throws(() => pr.nullifier(domain0, sk, cm, index), InputError, `index ${index}`);
  }
});

test("r1cs-rejects-forged-beta-and-gamma", async () => {
  // A malicious prover cannot pick beta or gamma: a witness whose beta is not Poseidon of the
  // statement, with sigma, the Horner accumulators and gamma recomputed to match, must be
  // rejected. This fails if beta or gamma is ever assigned without a constraint.
  const [, beta, gamma, alpha] = await snarkjs.wtns.exportJson(await template());
  const wires = await committedWires();
  const forgedBeta = mod(beta + 1n, pr.P);
  const sigma = mod(alpha + forgedBeta, pr.P);
  const acc = [firstStmt[9]];
  for (let i = 8; i >= 0; i--) acc.unshift(mod(acc[0] * sigma + firstStmt[i], pr.P));
  const forged = new Map<number, bigint>().set(1, forgedBeta).set(2, acc[0]);
  const named = new Map([["main.sigma", sigma]]);
  acc.forEach((a, i) => named.set(`main.acc[${i}]`, a));
  for (const [name, value] of named) {
    const wire = wires.get(name) ?? -1;
    if (wire >= 0) forged.set(wire, value);
  }
  const patches = { "forged-beta": forged, "forged-gamma": new Map([[2, gamma + 1n]]) };
  for (const [label, values] of Object.entries(patches)) {
    const wtns = patched(label, await template(), values);
    assert.equal(await satisfies(wtns), false, `${label}: the committed R1CS accepts it`);
  }
});

test("real-groth16-proof", async () => {
  // prove() itself checks the proof against the committed verification key.
  const { publics, proof } = await prove(first, "first-occurrence");
  assert.equal(await verify(publics, proof), true);
  // The verifier sees (beta, gamma, alpha), and the pool recomputes alpha and gamma from the
  // statement it settles, as here.
  const [beta, gamma, alpha] = publics;
  const settled = (stmt: bigint[]) => {
    const a = keccakAlpha(stmt);
    return [beta, pr.fingerprint(mod(a + beta, pr.P), stmt), a];
  };
  assert.deepEqual(settled(firstStmt), publics, "alpha or gamma does not follow the statement");
  // The deployed verifier refuses a proof word at or above q (the pairing precompile) and a
  // signal outside [0, P) (checkField). snarkjs alone reduces words modulo q and reads -x as x
  // when x has 64 hex digits, so it accepts the shifted words and negated signals below, a gap
  // that verify()'s own range checks close. snarkjs refuses x + P itself; that case stays to
  // cover the rest of the out-of-field range.
  const reachesGap = publics.some((x) => x >= 1n << 252n);
  assert.ok(reachesGap, "no signal has 64 hex digits, so no negated signal below reaches the gap");
  const shift = (w: string) => "0x" + word(BigInt(w) + Q);
  type Refused = [label: string, signals: bigint[], words: typeof proof];
  const refused: Refused[] = [
    ...firstStmt.map((x, i): Refused => {
      const stmt = firstStmt.with(i, i === 5 ? domain1 : mod(x + 1n, pr.P));
      return [`statement[${i}]`, settled(stmt), proof];
    }),
    ["beta", [mod(beta + 1n, pr.P), gamma, alpha], proof],
    ["gamma", [beta, mod(gamma + 1n, pr.P), alpha], proof],
    ["pA[0] + q", publics, edited(proof, (w) => (w.pA[0] = shift(w.pA[0])))],
    ["pB[0][1] + q", publics, edited(proof, (w) => (w.pB[0][1] = shift(w.pB[0][1])))],
    ["pB[1][0] + q", publics, edited(proof, (w) => (w.pB[1][0] = shift(w.pB[1][0])))],
    ["pC[1] + q", publics, edited(proof, (w) => (w.pC[1] = shift(w.pC[1])))],
    ...publics.flatMap((x, i): Refused[] => [
      [`signal ${i}: -x`, publics.with(i, -x), proof],
      [`signal ${i}: x + P`, publics.with(i, x + pr.P), proof],
    ]),
  ];
  for (const [label, signals, words] of refused) {
    assert.equal(await verify(signals, words), false, label);
  }
});

// checkDeployedProfile probes a deployed verifier with these two calls, expecting 1 then 0.
test("the pool's reference verifier call verifies, and its changed copy does not", async () => {
  // Each call is a 4-byte selector, then the eight proof words and the three signals.
  const verdicts: boolean[] = [];
  for (const call of referenceVerifierCalls()) {
    const w = (i: number) => "0x" + call.slice(10 + 64 * i, 74 + 64 * i);
    const pB: ProofWords["pB"] = [
      [w(2), w(3)],
      [w(4), w(5)],
    ];
    const signals = [8, 9, 10].map((i) => BigInt(w(i)));
    verdicts.push(await verify(signals, { pA: [w(0), w(1)], pB, pC: [w(6), w(7)] }));
  }
  assert.deepEqual(verdicts, [true, false]);
});
