/**
 * The pool CLI never submits this profile's proofs to the recorded old deployment. It refuses
 * other profile labels before any RPC; a pool whose deployed code, linked verifier or domain do
 * not match; a shield whose fixture cannot spend the funded note; and unknown or misplaced
 * flags. It also checks that the flags it accepts reach the sender, that the funded key is read
 * from standard input or a prompt that does not echo it, and that a key given as an argument is
 * refused without being printed. Runs in about 2 s, most of it in 49 CLI subprocesses that pin
 * the exit statuses.
 *
 *   node --test test/pool-cli.test.ts
 */
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { concat, fromHex, hex32, keccak, toBytes, toHex } from "../src/bytes.ts";
import { main } from "../src/cli/pool.ts";
import { readSecretLine } from "../src/cli/secret.ts";
import { checkDeployedProfile, referenceVerifierCalls, shieldLeaf } from "../src/deployment.ts";
import { PoolError, UserError } from "../src/errors.ts";
import { POOL_PROFILE, PREVIOUS_POOL_PROFILE } from "../src/gas.ts";
import {
  domainScalar,
  EMPTY_ROOT,
  LEAF_APPENDED,
  recentRootEntry,
  sourceId,
  TREE_CAPACITY,
} from "../src/protocol.ts";
import { poolNode, RpcError, RpcTransportError, type PoolNode } from "../src/rpc.ts";
import type { Send } from "../src/send.ts";
import type { Action } from "../src/spend.ts";
import { rpcServer, runCli, type CliResult } from "./helpers.ts";

type Json = Record<string, unknown>;
const path = (relative: string) => fileURLToPath(new URL(`../${relative}`, import.meta.url));
const CLI = path("src/cli/pool.ts");
const FIXTURE = path("test/fixtures/smoke_fixture.json");
const readJson = (file: string) => JSON.parse(readFileSync(file, "utf8")) as Json;
const DEPLOYED = readJson(path("core/deploy_config.json"));
const CHAIN = BigInt(DEPLOYED.chainId as number);
const POOL = BigInt(DEPLOYED.pool as string);
const LOGIC = BigInt(DEPLOYED.logic as string);
const VERIFIER = BigInt(DEPLOYED.verifier as string);
const FUNDED = "01".repeat(32);

let tmp = "";
before(() => {
  tmp = mkdtempSync(join(tmpdir(), "pool-cli-"));
});
after(() => rmSync(tmp, { recursive: true, force: true }));

/** Writes `value` as JSON to a new file in the test's temporary directory. */
let written = 0;
function writeTemp(name: string, value: unknown): string {
  const file = join(tmp, `${written++}-${name}`);
  writeFileSync(file, JSON.stringify(value));
  return file;
}

/**
 * Runs the CLI as a user would, from `cwd`, by default the test's temporary directory. runCli
 * closes its standard input and kills it after a timeout, so a CLI that waits for the funded key
 * fails the test instead of hanging it; a killed CLI reports status -1, and its signal is added
 * to stderr, which the assertions print.
 */
async function runPoolCli(args: string[], cwd = tmp): Promise<CliResult> {
  const result = await runCli(process.execPath, [CLI, ...args], { cwd });
  const { signal, stderr } = result;
  return { ...result, stderr: signal ? `${stderr}\n[killed by ${signal}]` : stderr };
}

/**
 * Runs main in process and returns the error it threw, or null. Its progress lines are kept off
 * the test runner's stdout, which carries the runner's own events as bytes, so only strings are
 * dropped.
 */
async function runMain(argv: string[], deps: Parameters<typeof main>[1]): Promise<unknown> {
  const write = process.stdout.write;
  process.stdout.write = ((chunk: unknown, ...rest: unknown[]) =>
    typeof chunk === "string"
      ? true
      : Reflect.apply(write, process.stdout, [chunk, ...rest])) as typeof write;
  try {
    await main(argv, deps);
    return null;
  } catch (error) {
    return error;
  } finally {
    process.stdout.write = write;
  }
}

/** Runs `run` with `stdin` standing in for process.stdin. */
async function withStdin<T>(stdin: unknown, run: () => Promise<T>): Promise<T> {
  const saved = Object.getOwnPropertyDescriptor(process, "stdin") as PropertyDescriptor;
  Object.defineProperty(process, "stdin", { value: stdin, configurable: true });
  try {
    return await run();
  } finally {
    Object.defineProperty(process, "stdin", saved);
  }
}

/** `error` is a refusal whose message contains each of `texts`. */
function refused(error: unknown, texts: string | string[], label = ""): void {
  assert.ok(error instanceof UserError, `${label}: ${String(error)}`);
  for (const text of [texts].flat()) {
    assert.ok(error.message.includes(text), `${label}: ${text} not in ${error.message}`);
  }
}

/** A node that answers nothing, recording what it was asked. */
function silentNode(): PoolNode & { calls: string[] } {
  const calls: string[] = [];
  const answer = async (method: string): Promise<never> => {
    calls.push(method);
    throw new Error(`${method} called`);
  };
  return { calls, call: answer, simulate: () => answer("simulate") };
}

const noKey = async (): Promise<Uint8Array> => assert.fail("the funded key was read");

test("this tree spends position-notes-v3, with the recorded deployment's formulas", () => {
  assert.equal(POOL_PROFILE, "position-notes-v3");
  // The record names this profile's testnet deployment.
  assert.equal(DEPLOYED.profile, POOL_PROFILE);
  assert.equal(domainScalar(CHAIN, POOL), BigInt(DEPLOYED.domain as string));
  // keccak(pool || epoch 0), written out rather than read from the client.
  const source = toHex(keccak(concat(toBytes(POOL, 20), new Uint8Array(32))));
  assert.equal(source, DEPLOYED.sourceIdEpoch0);
  assert.equal(toHex(sourceId(POOL, 0n)), source);
});

describe("command-line flags", () => {
  // A flag the CLI does not know stops it before any file or RPC, so a typo of --dry-run cannot
  // send a real transaction; abbreviations and underscore spellings are refused too.
  for (const typo of ["--dryrun", "--dry", "--dry_run", "--no-tails", "--action-gaas=1"]) {
    test(`${typo} exits 2 before reading the missing config`, async () => {
      const runs = await Promise.all(
        ["shield", "publish", "transfer", "withdraw"].map(async (op) => ({
          op,
          ...(await runPoolCli(["http://127.0.0.1:1", "missing-config.json", FIXTURE, op, typo])),
        })),
      );
      for (const { op, code, stderr } of runs) {
        assert.equal(code, 2, `${op}: ${stderr}`);
        assert.ok(
          stderr.endsWith(`: Unknown option '${typo.split("=")[0]}'\n`),
          `${op}: ${stderr}`,
        );
      }
    });
  }

  // Only the last value of an integer flag is used, but every value is checked.
  for (const first of ["-1", "007", "x"]) {
    test(`--epoch=${first} --epoch=5 exits 2 before reading the missing config`, async () => {
      const args = ["http://127.0.0.1:1", "missing-config.json", FIXTURE, "transfer"];
      const { code, stderr } = await runPoolCli([...args, `--epoch=${first}`, "--epoch=5"]);
      assert.equal(code, 2, stderr);
      assert.ok(stderr.includes("--epoch must be 0x hex or decimal without leading zeros"), stderr);
    });
  }

  /**
   * A spend of the smoke fixture, a transfer by default, that reaches the sender, which records
   * what it is given instead of sending: the node holds the spend's root at slot 5.
   */
  function recordedSpend(op = "transfer") {
    const config = writeTemp("config.json", { ...DEPLOYED, profile: POOL_PROFILE });
    const entry = readJson(FIXTURE)[op] as Json;
    const stored = recentRootEntry(sourceId(POOL, 0n), 5n, BigInt(entry.root as string));
    const node: PoolNode = {
      async call(method) {
        if (method === "eth_getBlockByNumber") return { slotNumber: "0x6" };
        if (method === "eth_getStorageAt") return toHex(stored);
        throw new Error(`${method} called`);
      },
      simulate: async () => assert.fail("simulated"),
    };
    const sent: Send[] = [];
    const options: unknown[] = [];
    const deps: Parameters<typeof main>[1] = {
      node,
      checkDeployedProfile: async () => {},
      buildAndSend: async (_node, _io, _key, _pool, send, given) => {
        sent.push(send);
        options.push(given);
        return null;
      },
      readFundedKey: noKey,
    };
    const argv = ["http://node", config, FIXTURE, op, "--root-slot", "5"];
    return { argv, deps, sent, options };
  }

  const target = "0x" + "ab".repeat(20);
  const tail = `--action-target ${target} --action-call 0x1234 --action-gas 300000 --action-state-gas 0`;

  test("--flag=value parses like --flag value, the custom tail included", async () => {
    const { argv, deps, sent } = recordedSpend();
    assert.equal(await runMain([...argv, ...tail.split(" ")], deps), null);
    const joined = tail.split(/ (?=--)/).map((pair) => pair.replace(" ", "="));
    assert.equal(await runMain([...argv, ...joined], deps), null);
    const data = Uint8Array.of(0x12, 0x34);
    const expected: Action = { target: BigInt(target), data, gasLimit: 300_000n, stateLimit: 0n };
    const actions = sent.map((send) => send.kind === "spend" && send.action);
    assert.deepEqual(actions, [expected, expected]);
  });

  test("an action flag given twice is refused", async () => {
    const { argv, deps, sent } = recordedSpend();
    const twice = [...argv, ...tail.split(" "), "--action-target", target];
    refused(await runMain(twice, deps), "--action-target must be supplied exactly once");
    assert.equal(sent.length, 0);
  });

  test("the fee flags reach a spend's sender, and are refused on shield and publish", async () => {
    const { argv, deps, options } = recordedSpend();
    const fees = ["--max-fee-per-gas=7", "--max-priority-fee-per-gas", "0x3"];
    assert.equal(await runMain([...argv, ...fees], deps), null);
    assert.deepEqual(options, [{ dryRun: false, maxFee: 7n, maxPriorityFee: 3n }]);
    for (const op of ["shield", "publish"]) {
      const node = silentNode();
      const config = writeTemp("config.json", { ...DEPLOYED, profile: POOL_PROFILE });
      const error = await runMain(["http://node", config, FIXTURE, op, fees[0]], {
        node,
        readFundedKey: noKey,
      });
      refused(error, "fee overrides are valid only for transfer or withdraw", op);
      assert.deepEqual(node.calls, [], `${op} called the node`);
    }
  });

  test("tail flags that do not fit the operation are refused before any RPC", async () => {
    const misfits: [op: string, flags: string[], refusal: string][] = [
      ["transfer", ["--no-tail", ...tail.split(" ")], "--no-tail cannot be combined with action"],
      ["shield", ["--no-tail"], "--no-tail are valid only for transfer or withdraw"],
      ["publish", ["--no-tail"], "--no-tail are valid only for transfer or withdraw"],
      ["transfer", ["--allow-failed-claim"], "--allow-failed-claim is only valid on withdraw"],
      ["withdraw", ["--allow-failed-claim", "--no-tail"], "cannot be combined with --no-tail"],
    ];
    const config = writeTemp("config.json", { ...DEPLOYED, profile: POOL_PROFILE });
    for (const [op, flags, refusal] of misfits) {
      const node = silentNode();
      const argv = ["http://node", config, FIXTURE, op, ...flags];
      refused(await runMain(argv, { node, readFundedKey: noKey }), refusal, argv.join(" "));
      assert.deepEqual(node.calls, [], `${op} called the node`);
    }
  });

  // The smoke fixture's withdraw_seed and withdraw entries spend from one root.
  test("--spend-key sends the fixture entry it names", async () => {
    const { argv, deps, sent } = recordedSpend("withdraw");
    assert.equal(await runMain([...argv, "--spend-key", "withdraw_seed"], deps), null);
    const nf1 = ((readJson(FIXTURE).withdraw_seed as Json).nf1 as string).slice(2);
    assert.ok(sent.length === 1 && sent[0].kind === "spend");
    assert.ok(toHex(sent[0].settle).includes(nf1), "the settle does not spend withdraw_seed");
  });

  test("a configured root slot must be a decimal integer", async () => {
    const { deps } = recordedSpend();
    const config = { ...DEPLOYED, profile: POOL_PROFILE, _slot_transfer: [5] };
    const argv = ["http://node", writeTemp("config.json", config), FIXTURE, "transfer"];
    refused(await runMain(argv, deps), "_slot_transfer must be a non-negative decimal integer");
  });

  test("publish sends the epoch --epoch names", async () => {
    const { argv, deps, sent } = recordedSpend();
    const publish = [...argv.slice(0, 3), "publish", "--epoch", "3"];
    const readFundedKey = async () => fromHex("0x" + FUNDED, "the funded key");
    assert.equal(await runMain(publish, { ...deps, readFundedKey }), null);
    // publishEpochRoot(uint64) for epoch 3
    const calldata = "0xd03870b3" + hex32(3n).slice(2);
    assert.deepEqual(
      sent.map((send) => send.kind === "call" && toHex(send.calldata)),
      [calldata],
    );
  });
});

// shield, transfer and withdraw refuse a config for another profile, or without one, before any
// RPC. publish does not check the label.
describe("profile labels", () => {
  async function refusedBeforeRpc(config: string, ops: string[], text: (op: string) => string) {
    for (const op of ops) {
      const node = silentNode();
      const argv = ["http://127.0.0.1:1", config, FIXTURE, op, "--dry-run"];
      refused(await runMain(argv, { node, readFundedKey: noKey }), text(op), op);
      assert.deepEqual(node.calls, [], `${op} called the node`);
    }
  }
  // JSON leaves out an undefined profile.
  const configFor = (profile: unknown) => writeTemp("config.json", { ...DEPLOYED, profile });
  const others = [PREVIOUS_POOL_PROFILE, "recipient-pull-v1", "eip8272-canonical-frame"];
  const requiresProfile = (op: string) => `${op} requires profile=${POOL_PROFILE}`;

  for (const profile of [...others, null, undefined]) {
    const name = profile === undefined ? "no profile" : JSON.stringify(profile);
    test(`${name} is refused by shield, transfer and withdraw`, () =>
      refusedBeforeRpc(configFor(profile), ["shield", "transfer", "withdraw"], requiresProfile));
  }

  // A spend's claim frame is signed at this profile's limits, so a config recording other claim
  // limits describes another deployment and is refused before any RPC.
  test("transfer and withdraw refuse a config with other claim limits", async () => {
    const limits = [{ claimGas: 99_999 }, { claimStateGas: 183_500 }, { claimGas: undefined }];
    const text = () => `spends require claimGas/claimStateGas matching ${POOL_PROFILE}`;
    for (const limit of limits) {
      const config = writeTemp("config.json", { ...DEPLOYED, profile: POOL_PROFILE, ...limit });
      await refusedBeforeRpc(config, ["transfer", "withdraw"], text);
    }
  });

  test("the CLI exits 1 with the refusal on stderr", async () => {
    const argv = ["http://127.0.0.1:1", configFor(null), FIXTURE, "shield", "--dry-run"];
    const { code, stderr } = await runPoolCli(argv);
    assert.equal(code, 1, stderr);
    assert.ok(stderr.includes(requiresProfile("shield")), stderr);
  });
});

// A key pasted where a path belongs passes the parser, and would come back in the refusal.
test("the CLI redacts a key-like path from its refusal", async () => {
  const key = "ab".repeat(32);
  writeFileSync(join(tmp, `${key}.json`), "x");
  const { code, stderr } = await runPoolCli([
    "http://127.0.0.1:1",
    `${key}.json`,
    FIXTURE,
    "shield",
  ]);
  assert.equal(code, 1, stderr);
  assert.ok(stderr.includes("<redacted>.json is not JSON") && !stderr.includes(key), stderr);
});

// The pool CLI reads the funded key from standard input. In the position where it once took the
// key it names the change (exit status 1); anywhere else the parser refuses the key (exit status
// 2, before any file is read); a key typed where a path belongs passes the parser and the failed
// read follows. None of them prints the key.
describe("the pool CLI never echoes a key", { concurrency: 8 }, () => {
  const key = "01".repeat(32);
  // A directory of its own, made once the file's temporary directory exists.
  let cwd = "";
  before(() => {
    cwd = mkdtempSync(join(tmp, "cli-"));
  });
  const cli = (...args: string[]) => runPoolCli(args, cwd);
  const head = ["http://127.0.0.1:1", "cfg.json", "fix.json"];
  /** The run exited with status `expected`, its stderr holds `text`, and it printed no key. */
  const refusedRun = ({ code, stdout, stderr }: CliResult, expected: number, text = "") => {
    assert.equal(code, expected, stderr);
    assert.ok(stderr.includes(text), stderr);
    assert.ok(!(stdout + stderr).includes(key), stderr);
  };
  const strays = [
    ["--dry-run", key],
    ["--", "0x" + key],
    ["--dry-run=" + key],
    ["--epoch", key],
    ["--sender", "0x" + key + "01"],
  ];
  for (const op of ["shield", "publish", "transfer", "withdraw"]) {
    test(`${op}: a key where the CLI once took it is refused`, async () => {
      refusedRun(await cli(...head, op, key), 1, "no longer takes a key argument");
    });
    for (const stray of strays) {
      test(`${op} ${stray.join(" ").replaceAll(key, "<key>")} is refused`, async () => {
        refusedRun(await cli(...head, op, ...stray), 2, "pool.ts: error:");
      });
    }
  }

  test("a key in place of the config path is not printed", async () => {
    refusedRun(await cli("http://127.0.0.1:1", key, "f.json", "transfer"), 1);
  });

  test("a key in place of the op is refused as an invalid choice", async () => {
    refusedRun(await cli(...head, key), 2, "op must be one of shield, publish, transfer, withdraw");
  });

  // A flag is never an option's value: here --dry-run would stop being a dry run.
  test("a flag where an option's value belongs is refused", async () => {
    const args = [...head, "transfer", "--spend-key", "--dry-run"];
    refusedRun(await cli(...args), 2, "Option '--spend-key' argument is ambiguous");
  });
});

// ---- the deployed-pool gate ----

/** The verifier call that a verifier for this profile's proving key accepts. */
const [GOOD_CALL] = referenceVerifierCalls();
const DOMAIN_CALL = "0x58f7ca61" + "00".repeat(32); // domain(uint64) for epoch 0
const INITCODE_FILE = path("core/artifacts/shielded_pool_dispatcher_init.hex");
const INITCODE = readFileSync(INITCODE_FILE, "utf8").trim();

/** A node's simulated deployment, stood in by a hash: different initcode, different code. */
const deployed = (initcode: string) => toHex(keccak(fromHex(initcode, "initcode")));
const linked = (logic: bigint, verifier: bigint, initcode = INITCODE) =>
  initcode + hex32(logic).slice(2) + hex32(verifier).slice(2);
const reverted = (message: string) => new RpcError("eth_call", { code: -32000, message });

const THIS_CODE = deployed(linked(LOGIC, VERIFIER));
/** The previous profile's dispatcher: the same logic, verifier and domain, different code. */
const PREVIOUS_INITCODE = INITCODE.slice(0, -1) + (INITCODE.endsWith("0") ? "1" : "0");
const PREVIOUS_CODE = deployed(linked(LOGIC, VERIFIER, PREVIOUS_INITCODE));
const GOOD_DOMAIN = DEPLOYED.domain as string;

interface Deployment {
  /** The code at POOL, or the error the node throws when asked to simulate the deployment. */
  code?: string | Error;
  domain?: string | Error;
  verifier?: "committed" | "previous-interface" | "other-key" | "accepts-any";
  /** What the node returns for the simulated deployment, otherwise a hash of the initcode. */
  simulation?: string;
}

/**
 * A node on chain CHAIN holding `code` at POOL and, at VERIFIER, a verifier that behaves as
 * named: the committed one, one with the previous ten-input interface (reverts), one for another
 * proving key (rejects all), or one that accepts any proof. The pool answers domain(uint64) and
 * the verifier answers verifyProof, each only at its own address, so a check that probes the
 * wrong contract fails the test, as does any other request.
 */
function deployedNode({
  code = THIS_CODE,
  domain = GOOD_DOMAIN,
  verifier = "committed",
  simulation,
}: Deployment = {}): PoolNode & { calls: string[] } {
  const calls: string[] = [];
  const at = (address: unknown, expected: bigint, what: string) =>
    assert.equal(BigInt(String(address)), expected, `${what} sent to ${String(address)}`);
  const call = async (method: string, params: readonly unknown[]): Promise<unknown> => {
    calls.push(method);
    const request = params[0] as { to?: string; data: string };
    if (method === "eth_chainId") return "0x" + CHAIN.toString(16);
    if (method === "eth_getCode") {
      at(params[0], POOL, "eth_getCode");
      return code;
    }
    if (method === "eth_call" && !("to" in request)) {
      if (code instanceof Error) throw code;
      return simulation ?? deployed(request.data);
    }
    if (method === "eth_call" && request.data.startsWith("0x11479fea")) {
      at(request.to, VERIFIER, "verifyProof");
      if (verifier === "previous-interface") throw reverted("execution reverted");
      if (verifier === "other-key") return hex32(0n);
      if (verifier === "accepts-any") return hex32(1n);
      return hex32(request.data === GOOD_CALL ? 1n : 0n);
    }
    if (method === "eth_call" && request.data === DOMAIN_CALL) {
      at(request.to, POOL, "domain(uint64)");
      if (domain instanceof Error) throw domain;
      return domain;
    }
    throw new Error(`${method} called before the deployed-pool check finished`);
  };
  return { calls, call, simulate: async () => assert.fail("simulated") };
}

describe("the deployed-pool gate", () => {
  const gate = (deployment: Deployment = {}, configuredChain = CHAIN) =>
    checkDeployedProfile(deployedNode(deployment), POOL, configuredChain, LOGIC, VERIFIER);

  test("the reference verifier call carries the committed fixture's transfer proof", () => {
    // test/reference.test.ts checks how the call is composed against the pinned vectors; here
    // it only has to be built from the committed fixture, whose proof Forge also verifies.
    const proof = (readJson(FIXTURE).transfer as Json).proof;
    const words = JSON.stringify(proof).match(/0x[0-9a-f]{64}/g)!;
    assert.equal(words.length, 8);
    assert.equal(GOOD_CALL.length, 714);
    for (const w of words) assert.ok(GOOD_CALL.includes(w.slice(2)), w);
  });

  test("accepts the genuine pool", () => gate());

  const notDispatcher = `is not the ${POOL_PROFILE} dispatcher`;
  const notVerifier = `does not verify ${POOL_PROFILE} proofs`;
  const relinked = (l: bigint, v: bigint) => ({ code: deployed(linked(l, v)) });
  const revert = reverted("execution reverted");
  const otherEpoch = hex32(domainScalar(CHAIN, POOL, 1n));
  const cases: [string, Deployment, string, bigint?][] = [
    // Its logic, verifier and domain match.
    ["the previous profile's dispatcher", { code: PREVIOUS_CODE }, notDispatcher],
    ["this dispatcher linked to other logic", relinked(LOGIC ^ 1n, VERIFIER), notDispatcher],
    ["this dispatcher linked to another verifier", relinked(LOGIC, VERIFIER ^ 1n), notDispatcher],
    ["an address without code", { code: "0x" }, notDispatcher],
    // A node that answers a failed deployment with empty output at a pool address without code:
    // the two empty strings agree, but nothing is deployed.
    ["an empty simulated deployment", { code: "0x", simulation: "0x" }, notDispatcher],
    ["a node that cannot simulate", { code: reverted("unsupported") }, "could not simulate"],
    ["a pool that reverts on domain(uint64)", { domain: revert }, "does not expose domain(uint64)"],
    ["a domain from another epoch", { domain: otherEpoch }, "domain(0) does not match"],
    // This dispatcher, linked to a verifier that behaves otherwise.
    ["the previous ten-input verifier", { verifier: "previous-interface" }, notVerifier],
    ["a verifier for another proving key", { verifier: "other-key" }, notVerifier],
    ["a verifier that accepts any proof", { verifier: "accepts-any" }, notVerifier],
    ["the genuine pool on a chain the config does not name", {}, "config names chain 1", 1n],
  ];
  for (const [label, deployment, expected, configuredChain] of cases) {
    test(`refuses ${label}`, () =>
      assert.rejects(gate(deployment, configuredChain), (error: unknown) => {
        assert.ok(error instanceof PoolError, String(error));
        assert.ok(error.message.includes(expected), error.message);
        return true;
      }));
  }

  // Only a JSON-RPC error reply is a verdict. A rate limit's 429 can carry a JSON-RPC error
  // body, but the verifier gave no answer, so the gate fails without refusing it.
  test("reports a verifier probe that failed over HTTP instead of refusing", async () => {
    const node = deployedNode();
    const server = await rpcServer(async ({ method, params }) => {
      const limited = method === "eth_call" && params[0].data.startsWith("0x11479fea");
      if (limited) return { status: 429, error: { code: -32005, message: "rate limited" } };
      return { result: await node.call(method, params) };
    });
    try {
      const gate = checkDeployedProfile(poolNode(server.url), POOL, CHAIN, LOGIC, VERIFIER);
      await assert.rejects(gate, (error: unknown) => {
        assert.ok(error instanceof RpcTransportError, String(error));
        assert.equal(error.message, "eth_call request failed: HTTP 429");
        return true;
      });
    } finally {
      await server.close();
    }
  });

  // shield, transfer and withdraw refuse the previous profile's pool, relabeled as this
  // profile, before anything is signed or sent.
  test("the CLI runs it before signing anything", async () => {
    const config = writeTemp("config.json", { ...DEPLOYED, profile: POOL_PROFILE });
    for (const op of ["shield", "transfer", "withdraw"]) {
      const node = deployedNode({ code: PREVIOUS_CODE });
      const argv = ["http://node", config, FIXTURE, op];
      refused(await runMain(argv, { node, readFundedKey: noKey }), notDispatcher, op);
      assert.ok(!node.calls.includes("eth_sendRawTransaction"), op);
    }
  });
});

// ---- shield binds the fixture and reads the funded key ----

describe("shield binds the fixture and reads the funded key", () => {
  const fixture = readJson(FIXTURE);
  const chainId = fixture.chain_id as number;
  const pool = BigInt(fixture.pool_address as string);
  const cfg: Json = {
    pool: fixture.pool_address,
    chainId,
    logic: "0x01",
    verifier: "0x02",
    profile: POOL_PROFILE,
  };
  // currentEpoch(), nextIndex() and currentRoot()
  const SELECTORS: Record<string, number> = { "76671808": 0, fc7e9c6f: 1, fdab463d: 2 };
  type State = [epoch: bigint, index: bigint, root: bigint];
  interface Shield {
    fix?: Json;
    state?: State;
    landed?: [bigint, bigint];
    config?: Json;
    extra?: string[];
    /** What is piped on standard input. */
    stdin?: string;
  }
  const leafLog = (address: unknown, epoch: bigint, index: bigint) => ({
    address,
    topics: [LEAF_APPENDED, "0x" + "11".repeat(32), hex32(epoch)],
    data: hex32(index) + "22".repeat(32),
  });

  /**
   * One shield in process: the deployed-code check passes, the node answers only the pool's
   * state, and a recording sender returns a receipt whose LeafAppended log puts the note at
   * `landed`. The funded key is piped on stdin. Returns the error and the keys sent with.
   */
  async function shield({
    fix = fixture,
    state = [0n, 0n, EMPTY_ROOT],
    landed = [0n, 0n],
    config = cfg,
    extra = [],
    stdin = FUNDED + "\n",
  }: Shield): Promise<{ error: unknown; keys: Uint8Array[] }> {
    const node: PoolNode = {
      async call(method, params) {
        const request = params[0] as { to: string; data: string };
        assert.equal(method, "eth_call");
        assert.equal(BigInt(request.to), pool);
        return hex32(state[SELECTORS[request.data.slice(2, 10)]]);
      },
      simulate: async () => assert.fail("simulated"),
    };
    const receipt = { logs: [leafLog(fixture.pool_address, ...landed)] };
    const keys: Uint8Array[] = [];
    const files = [writeTemp("config.json", config), writeTemp("fixture.json", fix)];
    const argv = ["http://node", ...files, "shield", ...extra];
    const deps: Parameters<typeof main>[1] = {
      node,
      checkDeployedProfile: async () => {},
      buildAndSend: async (_node, _io, key) => (keys.push(key), receipt),
    };
    const error = await withStdin(Readable.from([Buffer.from(stdin)]), () => runMain(argv, deps));
    return { error, keys };
  }

  const otherPool = "0x" + (pool ^ 1n).toString(16).padStart(40, "0");
  const { pool_address: _, ...unpooled } = fixture;
  const relabeled = { ...fixture, epoch: 1 };
  const epoch1 = { ...fixture, epoch: 1, domain: hex32(domainScalar(BigInt(chainId), pool, 1n)) };
  // The nonce-race fixture names each note's leaf and the root before it, so a foreign deposit
  // at an earlier leaf is refused although the next leaf matches.
  const unnoted = { inner: fixture.inner_a, value: "1", leaf: 3, prior_root: hex32(1234n) };
  const named = { ...unnoted, note: fixture.shield_note };
  const race = (entry: Json, state: State = [0n, 3n, 1234n]): Shield => ({
    fix: { ...fixture, shields: [entry] },
    state,
    landed: [0n, 3n],
    extra: ["--note", "0"],
  });

  const refusals: [string, Shield, string][] = [
    ["another chain", { config: { ...cfg, chainId: chainId + 1 } }, "not 0x"],
    ["another pool", { config: { ...cfg, pool: otherPool } }, "not 0x"],
    [
      "a domain for another epoch",
      { fix: relabeled, state: [1n, 0n, EMPTY_ROOT] },
      "fixture domain",
    ],
    ["no recorded pool", { fix: unpooled }, "record pool_address"],
    // No one can open these inners, so the pool would lock the deposit.
    ["inner 0", { fix: { ...fixture, inner_a: hex32(0n) } }, "which no one can spend"],
    ["a sink inner", { fix: { ...fixture, inner_a: hex32(2n) } }, "which no one can spend"],
    ["a pool that already holds a leaf", { state: [0n, 1n, 5n] }, "next leaf is epoch 0 leaf 1"],
    ["a pool in a later epoch", { state: [1n, 0n, EMPTY_ROOT] }, "next leaf is epoch 1 leaf 0"],
    // Its recipient could not find the note.
    ["a nonce-race shield without the wallet's note", race(unnoted), "has no `note`"],
    ["a nonce-race shield at another leaf", race(named, [0n, 2n, 1234n]), "leaf 3"],
    [
      "a nonce-race shield at the same leaf of another tree",
      race(named, [0n, 3n, 999n]),
      "another deposit took an earlier leaf",
    ],
    // One leaf short of full, the tree does not roll over yet.
    [
      "an epoch-1 fixture while epoch 0 has a leaf left",
      { fix: epoch1, state: [0n, TREE_CAPACITY - 1n, 7n] },
      `next leaf is epoch 0 leaf ${TREE_CAPACITY - 1n}`,
    ],
    // trim() would drop the mark as whitespace.
    [
      "a piped key line with a byte order mark",
      { stdin: "\uFEFF" + FUNDED + "\n" },
      "standard input did not hold a private key",
    ],
  ];
  for (const [label, options, expected] of refusals) {
    test(`refuses before sending: ${label}`, async () => {
      const { error, keys } = await shield(options);
      refused(error, expected, label);
      assert.equal(keys.length, 0);
    });
  }

  // A note that landed elsewhere is reported, with the fixture to keep.
  const sends: [string, Shield, string | null][] = [
    ["sends the fixture's shield with the key from standard input", {}, null],
    ["reports a note that a deposit landing first moved", { landed: [0n, 1n] }, "(0, 1)"],
    ["reports a note that landed at its leaf in another epoch", { landed: [1n, 0n] }, "(1, 0)"],
    [
      "a full tree rolls over first, so an epoch-1 fixture's note lands at leaf 0",
      { fix: epoch1, state: [0n, TREE_CAPACITY, 7n], landed: [1n, 0n] },
      null,
    ],
    ["sends a nonce-race fixture's named note at its leaf", race(named), null],
    ["reads only the first line of standard input", { stdin: FUNDED + "\nnext\n" }, null],
  ];
  for (const [label, options, landed] of sends) {
    test(label, async () => {
      const { error, keys } = await shield(options);
      if (landed === null) assert.equal(error, null);
      else refused(error, [`landed at (epoch, leaf) ${landed}`, "Keep this fixture"], label);
      // The funded key comes from standard input, never the command line.
      assert.deepEqual(keys.map(toHex), ["0x" + FUNDED]);
    });
  }

  // On a terminal the key is typed at a prompt on stderr, in raw mode, which turns echo off.
  test("a key typed on a terminal is not echoed", async () => {
    const modes: boolean[] = [];
    const terminal = new EventEmitter();
    Object.assign(terminal, {
      isTTY: true,
      isRaw: false,
      setRawMode: (raw: boolean) => modes.push(raw),
      resume: () => terminal.emit("data", Buffer.from("ab\r")),
      pause: () => {},
    });
    const write = process.stderr.write;
    let shown = "";
    process.stderr.write = ((text: string) => ((shown += text), true)) as typeof write;
    try {
      assert.equal(await withStdin(terminal, () => readSecretLine("key: ")), "ab");
    } finally {
      process.stderr.write = write;
    }
    assert.deepEqual(modes, [true, false]);
    assert.equal(shown, "key: \n");
  });

  // Another contract the shield touches could emit a LeafAppended log too; only the pool's says
  // where the note landed.
  test("reads where the note landed only from the pool's own log", () => {
    const [own, other] = [leafLog(fixture.pool_address, 0n, 1n), leafLog(otherPool, 0n, 0n)];
    assert.deepEqual(shieldLeaf({ logs: [other, own] }, pool), [0n, 1n]);
    assert.equal(shieldLeaf({ logs: [other] }, pool), null);
    // A frame transaction's logs may sit in its frame receipts instead.
    const frameReceipts = [{ logs: [other] }, { logs: [leafLog(fixture.pool_address, 2n, 5n)] }];
    assert.deepEqual(shieldLeaf({ frameReceipts }, pool), [2n, 5n]);
  });
});
