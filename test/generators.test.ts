/**
 * The fixture generators refuse, before proving, anything that would put live notes at risk: the
 * public seed off the test chain, a recipient that strands its credit, and overwriting a fixture
 * that may hold the only secrets of unspent notes. A refusal never echoes a key pasted as an
 * argument. Secrets are owner-only, --random draws fresh wallets, live fixtures default to the
 * ignored artifacts/, a state lock admits one run at a time and passes to a single run once its
 * holder dies, and a real nonce-race run records what recovery and the shield check need.
 *
 * Run: node --test test/generators.test.ts (about 2 s, most of it the run that proves two
 * transfers).
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import fs, {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { after, suite, test } from "node:test";

import { GeneratorError } from "../src/errors.ts";
import { fileIdentity, readJson, withLock, writePrivate } from "../src/files.ts";
import {
  ARTIFACTS,
  TEST_POOL,
  defaultOutput,
  refuseOverwrite,
  resolvePath,
  writeFixture,
  type Proved,
  type Prover,
} from "../src/fixtures.ts";
import { parse } from "../src/json.ts";
import { NONCE_RACE_OUTPUT } from "../src/nonce-race.ts";
import { commitment, domainScalar } from "../src/protocol.ts";
import { generateSmoke } from "../src/smoke.ts";
import { Tree, type Witness } from "../src/wallet.ts";
import { rpcServer, runCli } from "./helpers.ts";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SMOKE = join(ROOT, "src/cli/smoke.ts");
const NONCE_RACE = join(ROOT, "src/cli/nonce-race.ts");

const TMP = mkdtempSync(join(tmpdir(), "generators-test-"));
after(() => rmSync(TMP, { recursive: true, force: true }));

const recipient = (address: string) => `--recipient=0x${address.padStart(40, "0")}`;
const POOL_ADDRESS = "0x1111111111111111111111111111111111111111";
const POOL = `--pool-address=${POOL_ADDRESS}`;
const LIVE = ["--chain-id=8141", POOL];
const RECIPIENT = recipient("ff");
const OUT = `--output=${join(TMP, "fixture.json")}`;
/** Pasted where an address or a path belongs, a key must not come back in the refusal. */
const KEY = "ab".repeat(32);
const LIVE_FIXTURE = join(TMP, "live.json");
const KEY_FIXTURE = join(TMP, `${KEY}.json`);
for (const path of [LIVE_FIXTURE, KEY_FIXTURE]) {
  writeFileSync(path, JSON.stringify({ chain_id: 8141 }));
}
const OVER_LIVE = `--output=${LIVE_FIXTURE}`;

/** Runs a generator CLI from a directory of its own, so no run depends on the caller's. */
const run = (script: string, args: string[]) =>
  runCli(process.execPath, [script, ...args], { cwd: TMP });

async function refused(script: string, args: string[], expected: string, code = 1) {
  const result = await run(script, args);
  assert.ok(result.stderr.includes(expected), result.stderr.slice(-500));
  assert.equal(result.code, code, result.stderr.slice(-500));
}

suite("refusals before proving", { concurrency: true }, () => {
  const SEED = "fixed seed is public";
  const STRANDS = "would strand the withdrawal credit";
  const HOLDS = "holds a fixture for chain 8141";
  const cases: [script: string, args: string[], expected: string, code?: number][] = [
    [SMOKE, [...LIVE, RECIPIENT, OUT], SEED],
    // The test chain with another pool than the committed fixture's is live too.
    [SMOKE, ["--chain-id=31337", POOL, RECIPIENT, OUT], SEED],
    [SMOKE, ["--random", ...LIVE, OUT], "test placeholder"],
    [SMOKE, ["--random", ...LIVE, recipient("0"), OUT], "invalid --recipient"],
    [SMOKE, ["--random", ...LIVE, `--recipient=0x${KEY}`, OUT], "invalid --recipient: <redacted>"],
    // A precompile, the EIP-8250 nonce manager and the pool itself would strand the credit.
    [SMOKE, ["--random", ...LIVE, recipient("1"), OUT], STRANDS],
    [SMOKE, ["--random", ...LIVE, recipient("8250"), OUT], STRANDS],
    [SMOKE, ["--random", ...LIVE, recipient("1".repeat(40)), OUT], STRANDS],
    [SMOKE, ["--random", ...LIVE, RECIPIENT, OVER_LIVE], HOLDS],
    [SMOKE, [OVER_LIVE], HOLDS],
    [NONCE_RACE, [...LIVE, OUT], SEED],
    [NONCE_RACE, ["--chain-id=31337", POOL, "--rpc=http://127.0.0.1:1", OUT], SEED],
    [NONCE_RACE, ["--random", ...LIVE, OVER_LIVE], HOLDS],
    [NONCE_RACE, ["--random", ...LIVE, `--output=${KEY_FIXTURE}`], `<redacted>.json ${HOLDS}`],
    // A mistyped flag stops the run instead of falling back to a default, such as the
    // committed test chain's fixture path.
    [SMOKE, ["--random", "--chain_id=8141", OUT], "Unknown option '--chain_id'", 2],
    [SMOKE, ["--rand", OUT], "Unknown option '--rand'", 2],
    [NONCE_RACE, [POOL, "--note_wei=1", OUT], "Unknown option '--note_wei'", 2],
  ];
  for (const [script, args, expected, code] of cases) {
    const shown = args.map((arg) => arg.replace(TMP, "TMP").replace(KEY, "KEY")).join(" ");
    test(`${basename(script, ".ts")} ${shown}`, () => refused(script, args, expected, code));
  }
});

test("secret files are owner-only and never replace another run's fixture", () => {
  const dir = mkdtempSync(join(TMP, "secrets-"));
  const mode = (path: string) => statSync(path).mode & 0o777;
  // A new secret file is owner-only, and replacing an old world-readable one gives a new
  // file, so a reader holding the old one open sees none of it.
  const target = join(dir, "witness.json");
  writeFileSync(target, "old");
  chmodSync(target, 0o644);
  const before = statSync(target).ino;
  const held = openSync(target, "r");
  writePrivate(target, "secret");
  assert.equal(readFileSync(held, "utf8"), "old");
  closeSync(held);
  assert.equal(readFileSync(target, "utf8"), "secret");
  assert.notEqual(statSync(target).ino, before);
  assert.equal(mode(target), 0o600);
  const fresh = join(dir, "fresh.json");
  writePrivate(fresh, "secret");
  assert.equal(mode(fresh), 0o600);

  // The final write refuses a fixture that appeared, or was replaced by another run, since
  // the overwrite check.
  const refusal = (expected: string) => (error: unknown) =>
    error instanceof GeneratorError && error.message.includes(expected);
  assert.throws(() => writeFixture(fresh, {}, null), refusal("appeared while generating"));
  const other = join(dir, "test.json");
  writeFileSync(other, JSON.stringify({ chain_id: 31337 }));
  const previous = refuseOverwrite(other);
  writeFileSync(other, JSON.stringify({ chain_id: 8141, secrets: "another run" }));
  assert.throws(
    () => writeFixture(other, { mine: true }, previous),
    refusal("changed while generating"),
  );
  assert.ok(readFileSync(other, "utf8").includes("another run"));
  // It also refuses a rewrite in place of the same size, which only the modification time
  // shows. That time is set forward here, since a coarse clock could leave it unchanged.
  const seen = fileIdentity(other);
  writeFileSync(other, JSON.stringify({ chain_id: 8141, secrets: "a third run" }));
  utimesSync(other, new Date(), new Date(Date.now() + 60_000));
  assert.throws(() => writeFixture(other, {}, seen), refusal("changed while generating"));

  // A file that is not a JSON object with an integer chain_id may still hold secrets, so it
  // counts as another chain's fixture.
  const unreadable = [Buffer.from("not json"), Buffer.from([0xff, 0xfe]), "[31337]", "{}"];
  for (const [i, content] of unreadable.entries()) {
    const path = join(dir, `unreadable-${i}.json`);
    writeFileSync(path, content);
    assert.throws(() => refuseOverwrite(path), refusal("holds a fixture for chain -1"), path);
  }
  // Read directly, such a file is refused without a lossy decode, and without V8's excerpt of
  // the text, which could be part of a seed.
  const seed = join(dir, "seed.json");
  writeFileSync(seed, Buffer.from([0x7b, 0xff, 0x7d]));
  assert.throws(() => readJson(seed), { message: `${seed} is not UTF-8 text` });
  writeFileSync(seed, KEY);
  assert.throws(() => readJson(seed), { message: `${seed} is not JSON: Unexpected token` });
  const left = readdirSync(dir).filter((name) => name.startsWith("."));
  assert.deepEqual(left, [], "temporary file left behind");
});

test("a save syncs its directory, so a crash cannot bring back the earlier file", () => {
  // A rename is atomic but durable only once its directory is synced. Only a crash shows the
  // difference, so the syncs are counted.
  const dir = realpathSync(mkdtempSync(join(TMP, "durable-")));
  const { openSync: open, fsyncSync: fsync } = fs;
  const opened = new Map<number, string>();
  const synced: string[] = [];
  fs.openSync = (...args: Parameters<typeof open>) => {
    const fd = open(...args);
    opened.set(fd, String(args[0]));
    return fd;
  };
  fs.fsyncSync = (fd: number) => (synced.push(opened.get(fd) ?? ""), fsync(fd));
  syncBuiltinESMExports();
  try {
    const state = join(dir, "state.json");
    writePrivate(state, "{}", null);
    writePrivate(state, "{}", fileIdentity(state));
    writePrivate(state, "{}");
  } finally {
    Object.assign(fs, { openSync: open, fsyncSync: fsync });
    syncBuiltinESMExports();
  }
  assert.equal(synced.filter((path) => path === dir).length, 3);
});

test("an --output path follows links as the kernel does", () => {
  const dir = realpathSync(mkdtempSync(join(TMP, "links-")));
  mkdirSync(join(dir, "a", "b"), { recursive: true });
  symlinkSync(join(dir, "a", "b"), join(dir, "link"));
  // ".." after a link leaves the directory the link leads to, not the one holding the link.
  assert.equal(resolvePath(`${dir}/link/../f.json`), join(dir, "a", "f.json"));
});

test("a state lock admits one run at a time and is released when its process exits", async () => {
  const state = join(TMP, "state.json");
  const second = () => withLock(state, () => {}, { waitMs: 0 });
  await withLock(state, () => assert.rejects(second(), /held by another run/));
  // A run that exits inside the lock, as Ctrl-C makes it, still removes the lock.
  const files = JSON.stringify(new URL("../src/files.ts", import.meta.url).href);
  const exits = `import { withLock } from ${files};
    await withLock(${JSON.stringify(state)}, () => process.exit(3));`;
  assert.equal(spawnSync(process.execPath, ["--input-type=module", "-e", exits]).status, 3);
  assert.equal(existsSync(`${state}.lock.d`), false);
});

const FILES = JSON.stringify(new URL("../src/files.ts", import.meta.url).href);

/**
 * The holder record left in the lock of `state` by a run that dies inside it. SIGKILL skips the
 * exit handler that removes the lock, as V8 does when it aborts on an exhausted heap.
 */
function diedHolding(state: string): string {
  const dies = `import { withLock } from ${FILES};
    await withLock(${JSON.stringify(state)}, () => process.kill(process.pid, "SIGKILL"));`;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", dies]);
  assert.equal(run.signal, "SIGKILL");
  const record = readFileSync(join(`${state}.lock.d`, "holder.json"), "utf8");
  assert.equal((parse(record) as { pid: unknown }).pid, run.pid);
  return record;
}

test("a lock whose holder died on this host is taken over, and no other lock is", async () => {
  const state = join(TMP, "died.json");
  const lock = `${state}.lock.d`;
  const takeover = `${lock}.takeover`;
  const record = diedHolding(state);
  const attempt = () => withLock(state, () => {}, { waitMs: 0 });
  const refusal = (held: string) => (error: Error) =>
    error.message.startsWith(`${held} is held by another run`);
  // The same lock naming this live process, pid 1, which only root may signal, another host or
  // another pid namespace, or with its record missing, perhaps not written yet, or cut short, is
  // held. So is a record whose pid is not a positive safe integer, such as minus the dead pid,
  // which process.kill would read as a process group that does not exist.
  const holder = parse(record) as { pid: number; host: string; pidns: string | null };
  const held = [
    { ...holder, pid: process.pid },
    { ...holder, pid: 1 },
    { ...holder, host: `not-${holder.host}` },
    { ...holder, pidns: "pid:[1]" },
    ...[0, -1, -holder.pid, 1.5, "123", null, 2 ** 53 + 2].map((pid) => ({ ...holder, pid })),
  ];
  for (const text of [...held.map((h) => JSON.stringify(h)), null, record.slice(0, -1)]) {
    if (text === null) rmSync(join(lock, "holder.json"));
    else writeFileSync(join(lock, "holder.json"), text);
    await assert.rejects(attempt(), refusal(lock));
  }
  writeFileSync(join(lock, "holder.json"), record);
  // A takeover directory left by a run that stopped inside it is named in the refusal, also
  // when the lock's holder is alive.
  mkdirSync(takeover);
  await assert.rejects(attempt(), refusal(takeover));
  writeFileSync(join(lock, "holder.json"), JSON.stringify(held[0]));
  await assert.rejects(attempt(), (error: Error) =>
    error.message.startsWith(`${lock} is held by another run, and ${takeover} is left`),
  );
  writeFileSync(join(lock, "holder.json"), record);
  rmSync(takeover, { recursive: true });
  const mine = await withLock(state, () => readFileSync(join(lock, "holder.json"), "utf8"));
  assert.equal((parse(mine) as { pid: unknown }).pid, process.pid);
  assert.equal(existsSync(lock), false);
  assert.equal(existsSync(takeover), false);
});

test("of eight runs that find one dead lock at once, exactly one takes it", async () => {
  // Eight processes run 500 rounds. Each round they find the same dead lock and try to take it
  // at the same moment, without waiting. Whichever takes it holds it until all have answered, so
  // a second taker would show as a second holder.
  const state = join(TMP, "race.json");
  const lock = `${state}.lock.d`;
  const record = diedHolding(state);
  const taker = `import { withLock } from ${FILES};
    import { createInterface } from "node:readline";
    const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
    const hold = async () => { console.log("held"); await lines.next(); };
    const refused = async (error) => { console.log(error.message); await lines.next(); };
    while (!(await lines.next()).done) {
      await withLock(${JSON.stringify(state)}, hold, { waitMs: 0 }).catch(refused);
      console.log("next");
    }`;
  const takers = Array.from({ length: 8 }, () =>
    spawn(process.execPath, ["--input-type=module", "-e", taker]),
  );
  const exits = takers.map((child) => once(child, "exit"));
  const outputs = takers.map((child) =>
    createInterface({ input: child.stdout! })[Symbol.asyncIterator](),
  );
  const tell = (line: string) => takers.forEach((child) => child.stdin!.write(`${line}\n`));
  const answers = () =>
    Promise.all(outputs.map(async (output) => (await output.next()).value ?? "exited"));
  try {
    for (let round = 0; round < 500; round++) {
      if (round > 0) {
        mkdirSync(lock);
        writeFileSync(join(lock, "holder.json"), record);
      }
      tell("go");
      const answered = await answers();
      tell("done");
      assert.deepEqual(await answers(), Array(8).fill("next"));
      const refused = answered.filter((answer) => answer !== "held");
      assert.equal(refused.length, 7, answered.join(" | "));
      assert.ok(
        refused.every((answer) => /held by another run/.test(answer)),
        refused.join(" | "),
      );
      assert.equal(existsSync(lock), false);
      assert.equal(existsSync(`${lock}.takeover`), false);
    }
  } finally {
    takers.forEach((child) => child.stdin!.end());
    await Promise.all(exits);
  }
});

test("live fixtures default to the ignored artifacts directory", () => {
  const committed = fileURLToPath(new URL("fixtures/smoke_fixture.json", import.meta.url));
  assert.equal(defaultOutput(31337n, BigInt(TEST_POOL)), committed);
  // Only the committed fixture's chain and pool write there; another pool on the test chain
  // is a live deployment.
  const otherPool = defaultOutput(31337n, BigInt(POOL_ADDRESS));
  for (const live of [defaultOutput(8141n, BigInt(TEST_POOL)), otherPool, NONCE_RACE_OUTPUT]) {
    assert.equal(dirname(live), ARTIFACTS, live);
    const ignored = spawnSync("git", ["check-ignore", "-q", live], { cwd: ROOT }).status;
    assert.equal(ignored, 0, `${live} is not ignored`);
  }
});

test("--random draws fresh wallets, and the withdrawals pay --recipient", async () => {
  const payee = "0x" + "cd".repeat(20);
  const output = join(TMP, "smoke.json");
  const options = {
    random: true,
    chainId: 8141n,
    poolAddress: POOL_ADDRESS,
    recipient: payee,
    output,
  };
  // Keeps each witness it is asked to prove, and stops the run at the first soundness check,
  // which follows the last proof and comes before anything is written.
  const witnesses = async () => {
    const proved = new Map<string, Witness>();
    const prover: Prover = {
      async prove(witness, tag) {
        proved.set(tag, witness);
        return {} as Proved;
      },
      assertUnprovable: () => Promise.reject(new Error("stopped")),
    };
    await assert.rejects(generateSmoke(options, { prover, log: () => {} }), /stopped/);
    return proved;
  };
  const [first, second] = [await witnesses(), await witnesses()];
  for (const tag of ["withdraw", "withdraw_seed"]) {
    assert.equal(first.get(tag)?.recipient, String(BigInt(payee)), tag);
  }
  // Alice spends in the transfer and Bob in the withdrawal.
  for (const tag of ["transfer", "withdraw"]) {
    assert.notEqual(first.get(tag)?.in_spend_key[0], second.get(tag)?.in_spend_key[0], tag);
  }
});

test("a nonce-race fixture binds --epoch and records what recovery and the shield check need", async () => {
  const output = join(TMP, "race.json");
  const listing = () => (existsSync(ARTIFACTS) ? readdirSync(ARTIFACTS).sort() : []);
  const before = listing();
  const args = ["--chain-id=31337", POOL, "--epoch=3", `--output=${output}`];
  const result = await run(NONCE_RACE, args);
  assert.equal(result.code, 0, result.stderr.slice(-500));
  // Proving leaves no witness or proof behind, so concurrent runs cannot swap proofs.
  assert.deepEqual(listing(), before, "proving left files behind");
  const fixture = parse(readFileSync(output, "utf8")) as Record<string, any>;
  assert.equal(BigInt(fixture.domain), domainScalar(31337n, POOL_ADDRESS, 3n));
  for (const name of ["transfer", "transfer_c"]) {
    const entry = fixture[name];
    const cms = entry.output_openings.map((o: Record<string, string>) =>
      commitment(BigInt(o.spend_key), BigInt(o.rho), BigInt(o.value)),
    );
    assert.deepEqual(cms, [BigInt(entry.out_cm1), BigInt(entry.out_cm2)], name);
  }
  const tree = new Tree();
  for (const shield of fixture.shields) {
    assert.equal(BigInt(shield.prior_root), tree.root(), `leaf ${shield.leaf}`);
    assert.equal(tree.append(BigInt(shield.cm)), BigInt(shield.leaf));
  }
});

test("with --rpc, the chain the node reads must be the one named", async () => {
  // Every answer is "0x1", so eth_chainId reads chain 1.
  const node = await rpcServer(() => ({ result: "0x1" }));
  try {
    const args = ["--random", ...LIVE, `--rpc=${node.url}`, `--output=${join(TMP, "rpc.json")}`];
    await refused(NONCE_RACE, args, "does not match the chain");
  } finally {
    await node.close();
  }
});
