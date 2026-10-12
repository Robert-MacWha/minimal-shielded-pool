/**
 * The deployment script's code checks must reject every mismatch and failed read, its early
 * guards must stop it before cast or an unpinned build, and no script may put a key on a command
 * line. The script calls each code check on the left of `||`, where Bash ignores `set -e`; this
 * runs its own functions that way, against a fake `cast`, so a check whose failure is overwritten
 * by a later line is caught. The tools around a deployment are checked too: the dispatcher's
 * initcode, the verifier patch, and the gas profile and formal pins checks. Needs bash and a real
 * forge (1.7.1 in CI) on PATH. The initcode test needs solc 0.8.30: without it the test is
 * skipped locally but fails when CI is set, so every CI job that runs these tests must install
 * solc first (`forge build --root core/contracts` does). About 1.5 s.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { after, describe, test } from "node:test";

import { POOL_PROFILE } from "../src/gas.ts";
import { report } from "../tools/check-formal-pins.ts";
import { checkGasProfile } from "../tools/check-gas-profile.ts";
import { patchVerifier } from "../tools/patch-verifier.ts";
import { runCli, type Env } from "./helpers.ts";

const ROOT = resolve(import.meta.dirname, "..");
const SCRIPT = join(ROOT, "tools/run_live_dispatcher.sh");
const SOURCE = readFileSync(SCRIPT, "utf8");
const MANIFEST = join(ROOT, "core/activation_manifest.testbed.json");
const DISPATCHER = join(ROOT, "tools/dispatcher.ts");
const tmp = mkdtempSync(join(tmpdir(), "msp-deploy-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

// The caller's environment, without the variables forge reads its settings from.
const clean: Env = Object.fromEntries(
  Object.entries(process.env).filter(([k]) => !/^(foundry_|dapp_)/.test(k.toLowerCase())),
);

const T4 = "0x00000000000000000000000000000000000000A4";
const LIB = "0x00000000000000000000000000000000000000b1";
const LIB_CODE = "0x73" + LIB.slice(2) + "3014";
const LOGIC_CODE = "0x60016002";
const POOL_CODE = "0x6005";
const CHECKS = ["verify_library_runtime", "verify_logic_runtime", "verify_created_runtime"];

// cast code prints $CODE, cast call --create prints $CREATED, the Poseidon getter prints
// $GOT_T4; each returns its *_STATUS, and any other call fails.
const FAKE_CAST = `
cast() {
  local out status
  case "$1 $2 $3" in
    code*) out=$CODE status=\${CODE_STATUS:-0} ;;
    "call --rpc-url"*) out=$CREATED status=\${CREATED_STATUS:-0} ;;
    *POSEIDON_T4*) out=$GOT_T4 status=\${T4_STATUS:-0} ;;
    *) return 2 ;;
  esac
  printf '%s\\n' "$out"
  return "$status"
}
`;
const FAKE_VARIABLES = /^(CODE|CREATED|GOT_T4)(_STATUS)?$|^T4_STATUS$|^BN$/;

/** The script's definition of `name`, from "name() {" through the first line holding "}". */
function definition(name: string): string {
  const start = SOURCE.indexOf(`${name}() {`);
  assert.notEqual(start, -1, `${name} is not defined`);
  return SOURCE.slice(start, SOURCE.indexOf("\n}\n", start) + 3);
}

/** Whether the script's check accepts, called as the script calls it, with `env` for cast. */
async function accepts(call: string, env: Env): Promise<boolean> {
  const program =
    `set -euo pipefail\nRPC=offline\nT4=${T4}\n${FAKE_CAST}` +
    CHECKS.map(definition).join("") +
    `${call} || { echo REJECT; exit 7; }\necho ACCEPT\n`;
  const inherited = Object.entries(process.env).filter(([k]) => !FAKE_VARIABLES.test(k));
  const merged = { ...Object.fromEntries(inherited), ...env };
  const result = await runCli("bash", ["-c", program], { env: merged });
  assert.ok(["ACCEPT\n", "REJECT\n"].includes(result.stdout), JSON.stringify(result));
  return result.stdout === "ACCEPT\n";
}

describe("the code checks reject every mismatch and failed read", { concurrency: 8 }, () => {
  const bn = join(tmp, "contracts");
  const artifact = join(bn, "out/ShieldedPoolLogic.sol/ShieldedPoolLogic.json");
  mkdirSync(join(artifact, ".."), { recursive: true });
  // Byte 1 holds an immutable, so it may differ from the simulated deployment.
  const refs = { 7: [{ start: 1, length: 1 }] };
  writeFileSync(artifact, JSON.stringify({ deployedBytecode: { immutableReferences: refs } }));
  const logic = { BN: bn, CODE: LOGIC_CODE, GOT_T4: T4 };
  const library = { CODE: LIB_CODE };
  const pool = { CODE: POOL_CODE, CREATED: POOL_CODE };
  const calls = {
    library: `verify_library_runtime ${LIB} ${LIB_CODE}`,
    logic: `verify_logic_runtime 0x01 ${LOGIC_CODE}`,
    pool: "verify_created_runtime 0x02 0xinit",
  };
  // "0x", the PUSH20 opcode and the 40-digit address take 44 characters.
  const afterAddress = { CODE: LIB_CODE.slice(0, 44) + "40" + LIB_CODE.slice(46) };
  const bothFailed = { CODE: "", CREATED: "", CODE_STATUS: "1", CREATED_STATUS: "1" };
  const cases: [kind: keyof typeof calls, label: string, env: Env, expected: boolean][] = [
    ["library", "matching code", library, true],
    ["library", "a different tail", { ...library, CODE: LIB_CODE.slice(0, -1) + "5" }, false],
    ["library", "a different first byte after the address", afterAddress, false],
    ["library", "a PUSH20 of another address", { CODE: "0x73" + "00".repeat(20) + "3014" }, false],
    ["library", "a failed code read", { ...library, CODE_STATUS: "1" }, false],
    ["logic", "matching code and libraries", logic, true],
    ["logic", "a different immutable byte", { ...logic, CODE: "0x60ff6002" }, true],
    ["logic", "a different byte", { ...logic, CODE: "0x60016003" }, false],
    ["logic", "a different length", { ...logic, CODE: "0x600160" }, false],
    ["logic", "the wrong POSEIDON_T4", { ...logic, GOT_T4: LIB }, false],
    ["logic", "a failed code read", { ...logic, CODE_STATUS: "1" }, false],
    ["logic", "a failed POSEIDON_T4 read", { ...logic, T4_STATUS: "1" }, false],
    ["pool", "matching code", pool, true],
    ["pool", "different code", { ...pool, CODE: "0x6006" }, false],
    ["pool", "empty code on both sides", { CODE: "0x", CREATED: "0x" }, false],
    ["pool", "a failed code read", { ...pool, CODE_STATUS: "1" }, false],
    ["pool", "a failed simulation", { ...pool, CREATED_STATUS: "1" }, false],
    ["pool", "two failed reads with equal output", bothFailed, false],
  ];
  for (const [kind, label, env, expected] of cases) {
    test(`${kind}: ${label} is ${expected ? "accepted" : "rejected"}`, async () => {
      assert.equal(await accepts(calls[kind], env), expected);
    });
  }
});

describe("the script's text", () => {
  test("every call site of a check exits on failure", () => {
    const lines = SOURCE.split("\n");
    let calls = 0;
    for (const name of CHECKS) {
      assert.equal(SOURCE.split(`${name}() {`).length, 2, `${name} must be defined exactly once`);
      lines.forEach((line, i) => {
        if (!line.startsWith(`${name} `)) return;
        const block = lines.slice(i, i + 4).join("\n");
        assert.ok(line.includes("|| {"), line);
        assert.ok(block.slice(0, block.indexOf("}") + 1).includes("exit 1"), line);
        calls++;
      });
    }
    assert.equal(calls, 3);
  });

  test("no inline comparison of two command substitutions; the pinned dispatcher initcode", () => {
    assert.doesNotMatch(SOURCE, /\[\[ *\$\(.*\) *== *\$\(/);
    // The dispatcher deployed is the pinned initcode, not a fresh compile.
    const pinned = 'DISP_INIT="$(cat ../core/artifacts/shielded_pool_dispatcher_init.hex)';
    assert.ok(SOURCE.includes(pinned));
    assert.doesNotMatch(SOURCE, /dispatcher\.(py|ts) --initcode/);
  });

  // Any local user can read a process's arguments, so no key may be one. forge and cast sign
  // from a keystore named in the environment, and the pool CLI reads the funded key from
  // standard input, filled by the builtin printf.
  test("no script passes --private-key; only funded_key reads the key, into a pipe", () => {
    const scripts = ["tools", "test"].flatMap((dir) =>
      readdirSync(join(ROOT, dir))
        .filter((name) => name.endsWith(".sh"))
        .map((name) => join(ROOT, dir, name)),
    );
    assert.ok(scripts.includes(SCRIPT));
    for (const script of scripts) {
      assert.ok(!readFileSync(script, "utf8").includes("--private-key"), script);
    }
    const uses = SOURCE.split("\n").filter((line) => /\$DEPLOYER_KEY\b/.test(line));
    assert.deepEqual(uses, [`funded_key() { printf '%s\\n' "$DEPLOYER_KEY"; }`]);
  });
});

// The script stops before calling cast, or building with forge, without ALLOW_TESTBED_SETUP=1,
// when its fixture path already exists or when forge would build with unpinned settings. Every
// run past the first guard passes the real activation gate.
describe("the early guards", { concurrency: true }, () => {
  const bin = join(tmp, "bin");
  mkdirSync(bin);
  const reached = "echo REACHED >&2\nexit 99\n";
  writeFileSync(join(bin, "cast"), `#!/bin/sh\n${reached}`, { mode: 0o755 });
  // forge answers `config` from FAKE_CONFIG_<profile> and fails any build.
  writeFileSync(
    join(bin, "forge"),
    "#!/bin/sh\n" +
      'if [ "$1" = config ]; then eval cat "\\$FAKE_CONFIG_${FOUNDRY_PROFILE:-default}"; exit 0; fi\n' +
      reached,
    { mode: 0o755 },
  );
  const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
  // The pinned settings, via_ir flipped, or via_ir left out as a forge that no longer reports it.
  const settings = (profile: string, label: "pinned" | "drifted" | "unreported") => {
    const { via_ir, ...rest } = manifest.compiler[profile];
    const variants = { pinned: { ...rest, via_ir }, drifted: { ...rest, via_ir: !via_ir } };
    const path = join(tmp, `${profile}-${label}.json`);
    writeFileSync(path, JSON.stringify(label === "unreported" ? rest : variants[label]));
    return path;
  };
  const profiles = Object.keys(manifest.compiler);
  const base: Env = {
    ...clean,
    PATH: `${bin}${delimiter}${process.env.PATH}`,
    RPC_URL: "offline",
    DEPLOYER_KEYSTORE: join(tmp, "keystore"),
    DEPLOYER_PASSWORD_FILE: join(tmp, "pw"),
    ALLOW_TESTBED_SETUP: "1",
    SMOKE_OUTPUT: join(tmp, "new.json"),
    ...Object.fromEntries(profiles.map((p) => [`FAKE_CONFIG_${p}`, settings(p, "pinned")])),
  };
  const existing = join(tmp, "existing.json");
  writeFileSync(existing, "{}");
  const deploy = (extra: Env) => runCli("bash", [SCRIPT], { env: { ...base, ...extra } });

  // A pinned setting that forge does not report reads as null and does not match the pin.
  const unreported = { FAKE_CONFIG_default: settings("default", "unreported") };
  const stops: [label: string, extra: Env, expected: string][] = [
    ["no ALLOW_TESTBED_SETUP", { ALLOW_TESTBED_SETUP: undefined }, "set ALLOW_TESTBED_SETUP=1"],
    ["an existing fixture path", { SMOKE_OUTPUT: existing }, "may hold the only secrets"],
    ...profiles.map((p): [string, Env, string] => [
      `a drifted ${p} profile`,
      { [`FAKE_CONFIG_${p}`]: settings(p, "drifted") },
      `profile ${p} differently`,
    ]),
    ["a default profile without via_ir", unreported, "via_ir=null (pinned true)"],
  ];
  for (const [label, extra, expected] of stops) {
    test(`${label} stops the script before cast or forge build`, async () => {
      const { code, stderr } = await deploy(extra);
      assert.notEqual(code, 0);
      assert.ok(stderr.includes(expected), stderr.slice(-400));
      assert.ok(!stderr.includes("REACHED"), stderr.slice(-400));
    });
  }

  test("with pinned settings the guards pass and the script goes on to cast", async () => {
    const { stderr } = await deploy({});
    assert.ok(stderr.includes("REACHED"), stderr.slice(-400));
  });

  // Object-valued settings compare by content. The committed manifest pins none, so the check
  // runs on a manifest of its own.
  test("an optimizer_details unlike its pinned object fails the settings check", async () => {
    const pinned = { ...manifest.compiler.default, optimizer_details: { yul: true } };
    const [own, reported] = [join(tmp, "details-manifest.json"), join(tmp, "details.json")];
    writeFileSync(own, JSON.stringify({ compiler: { default: pinned } }));
    writeFileSync(reported, JSON.stringify({ ...pinned, optimizer_details: { yul: false } }));
    const env = { ...base, FAKE_CONFIG_default: reported };
    const check = join(ROOT, "tools/check-forge-config.ts");
    const { code, stderr } = await runCli(process.execPath, [check, own, tmp], { env });
    assert.equal(code, 1, stderr);
    assert.ok(stderr.includes("from the manifest: optimizer_details="), stderr);
  });
});

// Against the real forge, a lowercase variable that changes the build is caught. The CLI runs
// as run_live_dispatcher.sh runs it, from tools/ with the script's relative paths, so this also
// checks that it hands forge its contracts root and the caller's environment.
test("the compiler settings check against the real forge", async () => {
  const args = ["check-forge-config.ts", "../core/activation_manifest.testbed.json"];
  const check = (env: Env) =>
    runCli(process.execPath, [...args, "../core/contracts"], { cwd: join(ROOT, "tools"), env });
  // A per-file restriction recompiles the logic with other settings, the profile unchanged.
  const restricted = {
    ...clean,
    FOUNDRY_ADDITIONAL_COMPILER_PROFILES: '[{name="cheap",via_ir=false,optimizer_runs=1}]',
    FOUNDRY_COMPILATION_RESTRICTIONS:
      '[{paths="src/ShieldedPoolLogic.sol",via_ir=false,max_optimizer_runs=1}]',
  };
  const [ok, bad, perFile] = await Promise.all(
    [clean, { ...clean, foundry_via_ir: "false" }, restricted].map(check),
  );
  assert.equal(ok.code, 0, ok.stderr);
  assert.equal(ok.stdout, '{"compiler": "match", "profiles": ["default", "libsmall"]}\n');
  assert.equal(bad.code, 1);
  assert.ok(bad.stderr.includes("via_ir"), bad.stderr);
  assert.equal(perFile.code, 1);
  assert.ok(perFile.stderr.includes("compilation_restrictions="), perFile.stderr);
  assert.ok(perFile.stderr.includes("additional_compiler_profiles="), perFile.stderr);
});

const initcode = (...addresses: string[]) =>
  runCli(process.execPath, [DISPATCHER, "--initcode", ...addresses]);

// The dispatcher's runtime reads the implementation from the first appended word and the
// verifier from the second (impl() and verifierAddr() in its Yul). Without solc 0.8.30 the test
// is skipped locally, but fails when CI is set, since a skip there would hide a check that never
// ran. So every CI job that runs these tests must install solc first, as
// `forge build --root core/contracts` does by putting the pinned version under ~/.svm.
test("the dispatcher initcode is the pinned artifact, the implementation, then the verifier", async (t) => {
  const { code, stdout, stderr } = await initcode("0x1", "0x2");
  const missing = stderr.includes("solc 0.8.30 not found");
  if (missing && !process.env.CI) return t.skip("solc 0.8.30 not found");
  assert.equal(code, 0, stderr);
  const artifact = join(ROOT, "core/artifacts/shielded_pool_dispatcher_init.hex");
  const word = (n: number) => n.toString(16).padStart(64, "0");
  assert.equal(stdout, readFileSync(artifact, "utf8") + word(1) + word(2) + "\n");
});

test("the dispatcher CLI refuses a zero implementation or verifier address", async () => {
  const refusals = await Promise.all([initcode("0x0", "0x2"), initcode("0x1", "0x00")]);
  for (const { code, stderr } of refusals) {
    assert.equal(code, 1, stderr);
    assert.ok(stderr.includes("invalid address: 0x0"), stderr);
  }
});

test("the dispatcher CLI takes addresses as 0x and hex digits only", async () => {
  for (const address of ["1", "0X1", "0x1_0", " 0x1"]) {
    const { code, stderr } = await initcode(address, "0x2");
    assert.equal(code, 1, stderr);
    assert.ok(stderr.includes(`invalid address: ${address}`), stderr);
  }
});

test("the verifier patch refuses a verifier without exactly three GAS calls", () => {
  const call = "staticcall(sub(gas(), 2000),";
  for (const calls of [2, 4]) {
    const patch = () => patchVerifier(call.repeat(calls), () => {});
    assert.throws(patch, new RegExp(`expected 3 snarkjs GAS calls, found ${calls}`));
  }
});

test("the gas profile check refuses one changed settlement pin or recorded limit", () => {
  const yulPath = "core/dispatcher/ShieldedPoolDispatcher.yul";
  const recordPath = "core/deploy_config.json";
  const root = mkdtempSync(join(tmp, "gas-"));
  mkdirSync(join(root, "core/dispatcher"), { recursive: true });
  const yul = readFileSync(join(ROOT, yulPath), "utf8");
  const record = JSON.parse(readFileSync(join(ROOT, recordPath), "utf8"));
  const check = (dispatcher: string, deployment: object) => () => {
    writeFileSync(join(root, yulPath), dispatcher);
    writeFileSync(join(root, recordPath), JSON.stringify(deployment));
    checkGasProfile(root);
  };
  // Either settlement limit changing while the other still matches is caught.
  for (const [pin, other] of [
    ["frameParam(2, 0x09), 550000)", "frameParam(2, 0x09), 550001)"],
    ["frameParam(2, 0x01), 2000000)", "frameParam(2, 0x01), 2000001)"],
  ]) {
    assert.ok(yul.includes(pin), pin);
    assert.throws(check(yul.replace(pin, other), record), /dispatcher gas limits differ/);
  }
  // The committed record names the previous profile, whose limits are not compared.
  const current = { ...record, profile: POOL_PROFILE, settleGas: 1 };
  assert.throws(check(yul, current), /settleGas differs/);
});

test("the formal pins check reports a pinned file that no longer exists", () => {
  const spec = `| File | SHA-256 |\n|---|---|\n| \`core/gone.sol\` | \`${"0".repeat(64)}\` |\n`;
  const [warning] = report(spec, "SPEC.md", tmp).lines;
  assert.ok(warning.startsWith("::warning file=core/gone.sol::"), warning);
});
