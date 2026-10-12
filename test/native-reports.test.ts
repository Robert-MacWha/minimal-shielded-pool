/**
 * CI rebuilds the native fixtures from the committed proofs, so test/native/compare-reports.ts
 * must accept only reports identical to the committed ones. A changed transaction hash, fee,
 * payer or gas figure fails it whether or not the transaction carries a proof, as do a missing
 * case and a changed policy fixture hash. Each test runs the CLI on the committed reports and a
 * copy the test may change; no ethrex runs. Runtime: about 1 s.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, test } from "node:test";

import { runCli } from "./helpers.ts";

const NATIVE = resolve(import.meta.dirname, "native");
const COMPARE = join(NATIVE, "compare-reports.ts");
const read = (name: string) => JSON.parse(readFileSync(join(NATIVE, name), "utf8"));
const COMMITTED = { native: read("native-report.json"), policy: read("policy-report.json") };
const tmp = mkdtempSync(join(tmpdir(), "msp-native-reports-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

type Report = Record<string, any>;
let runs = 0;
/** Runs the comparator on the committed reports and a copy that `change` edits. */
function compare(change: (native: Report, policy: Report) => void = () => {}) {
  const fresh = join(tmp, String(runs++));
  mkdirSync(fresh);
  const { native, policy } = structuredClone(COMMITTED);
  change(native, policy);
  writeFileSync(join(fresh, "native-report.json"), JSON.stringify(native));
  writeFileSync(join(fresh, "policy-report.json"), JSON.stringify(policy));
  return runCli(process.execPath, [COMPARE, NATIVE, fresh]);
}

/** The first case's step that sends `raw`, and the path the comparator reports it under. */
function step(report: Report, raw: string): [Report, string] {
  const j = report.cases[0].steps.findIndex((s: Report) => s.raw === raw);
  assert.ok(j >= 0, `the first case sends no ${raw}`);
  return [report.cases[0].steps[j], `cases[0].steps[${j}]`];
}
// A deployment, the same bytes on every run, and a withdrawal, which carries a proof.
const DEPLOYMENT = "deploy-poseidon4.hex";
const WITHDRAWAL = "withdraw-first-deposit.hex";
const [, DEPLOYED] = step(COMMITTED.native, DEPLOYMENT);
const [withdrawal, WITHDRAWN] = step(COMMITTED.native, WITHDRAWAL);
assert.ok(withdrawal.paid_fee && withdrawal.execution.frames, `${WITHDRAWAL} is not a paid spend`);

const OTHER_HASH = "0x" + "ab".repeat(32);
/** What a new proof would change: the transaction's hash. */
const reproved = (s: Report) => (s.raw_hash = OTHER_HASH);
/** Moves a step's gas by `delta` and its fee with it, as the fee rule requires. */
function regas(s: Report, delta: number) {
  s.execution.gas_spent += delta;
  s.paid_fee.amount =
    "0x" + (BigInt(s.execution.gas_spent) * BigInt(s.effective_gas_price)).toString(16);
}

test("identical reports pass", async () => {
  const { code, stdout, stderr } = await compare();
  assert.equal(code, 0, stderr);
  assert.equal(stdout, "the fresh native run reproduces the committed reports\n");
  assert.equal(stderr, "");
});

// Each refusal lists the start of every line the comparator must print for it.
const refusals: [name: string, change: (n: Report, p: Report) => void, lines: string[]][] = [
  ["a deployment's hash", (n) => reproved(step(n, DEPLOYMENT)[0]), [`${DEPLOYED}.raw_hash:`]],
  [
    "a deployment's gas and fee, moved by one calldata byte",
    (n) => {
      const [s] = step(n, DEPLOYMENT);
      reproved(s);
      regas(s, 12);
    },
    [`${DEPLOYED}.execution.gas_spent:`, `${DEPLOYED}.paid_fee.amount:`],
  ],
  [
    "a re-proved withdrawal's hash",
    (n) => reproved(step(n, WITHDRAWAL)[0]),
    [`${WITHDRAWN}.raw_hash:`],
  ],
  [
    "a re-proved withdrawal without its fee",
    (n) => {
      const [s] = step(n, WITHDRAWAL);
      reproved(s);
      delete s.paid_fee;
    },
    [`${WITHDRAWN}.paid_fee:`],
  ],
  [
    "a re-proved withdrawal without its fee, using a billion gas",
    (n) => {
      const [s] = step(n, WITHDRAWAL);
      reproved(s);
      delete s.paid_fee;
      s.execution.gas_spent = 1_000_000_000;
    },
    [`${WITHDRAWN}.paid_fee:`, `${WITHDRAWN}.execution.gas_spent:`],
  ],
  [
    "a re-proved withdrawal's fee amount",
    (n) => {
      const [s] = step(n, WITHDRAWAL);
      reproved(s);
      s.paid_fee.amount = "0x1";
    },
    [`${WITHDRAWN}.paid_fee.amount:`],
  ],
  [
    "a re-proved withdrawal's fee payer",
    (n) => {
      const [s] = step(n, WITHDRAWAL);
      reproved(s);
      s.paid_fee.payer = "0x" + "12".repeat(20);
    },
    [`${WITHDRAWN}.paid_fee.payer:`],
  ],
  [
    "a re-proved withdrawal's gas and fee",
    (n) => {
      const [s] = step(n, WITHDRAWAL);
      reproved(s);
      regas(s, -24);
    },
    [`${WITHDRAWN}.execution.gas_spent:`, `${WITHDRAWN}.paid_fee.amount:`],
  ],
  [
    "a frame's gas",
    (n) => (step(n, WITHDRAWAL)[0].execution.frames[1].execution_gas += 1),
    [`${WITHDRAWN}.execution.frames[1].execution_gas:`],
  ],
  [
    "a missing case",
    (n) => n.cases.pop(),
    [`cases: ${COMMITTED.native.cases.length} entries, now ${COMMITTED.native.cases.length - 1}`],
  ],
  [
    "a policy fixture's hash",
    (_, p) => (p.fixture_keccak256["policy-first.hex"] = OTHER_HASH),
    ["fixture_keccak256.policy-first.hex:"],
  ],
];

for (const [name, change, lines] of refusals) {
  test(`a changed report fails: ${name}`, async () => {
    const { code, stdout, stderr } = await compare(change);
    assert.equal(code, 1, stdout);
    assert.equal(stdout, "");
    assert.match(stderr, /^the fresh native run differs from the committed reports:\n {2}/);
    for (const line of lines) assert.ok(stderr.includes(`\n  ${line}`), `no ${line}\n${stderr}`);
  });
}
