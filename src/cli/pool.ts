/**
 * The pool command: builds and submits the pool's frame transactions from a deployment config
 * and a fixture.
 *
 *   node src/cli/pool.ts <rpc> <config> <fixture> shield|publish|transfer|withdraw [--dry-run]
 *
 * shield and publish read the funded key from standard input, since any local user can read a
 * command line; a spend is signed by the authorizer its proof selects. Flags and the config are
 * checked before any RPC.
 */
import { fromHex, parseConfigAddress, parseDec, parseHex, uintFromText } from "../bytes.ts";
import {
  checkDeployedProfile,
  checkShieldFixture,
  recentRootReference,
  shieldLeaf,
} from "../deployment.ts";
import { InputError, PoolError } from "../errors.ts";
import { readJson } from "../files.ts";
import { parsePrivateKeyLine } from "../frametx.ts";
import * as gas from "../gas.ts";
import { asObject, isObject, stringify, type JsonObject } from "../json.ts";
import * as protocol from "../protocol.ts";
import { poolNode, type PoolNode } from "../rpc.ts";
import { buildAndSend, waitPublishedSlot, type SendIo } from "../send.ts";
import {
  authorizerKey,
  entryProofBytes,
  ownerSignature,
  parseRecentRoot,
  settleCalldata,
  shieldCalldata,
  type Action,
} from "../spend.ts";
import { parseArgs, runCli } from "./args.ts";
import { readSecretLine } from "./secret.ts";

const TAIL = "custom DEFAULT tail (all four together)";
const SPEC = {
  prog: "pool.ts",
  description: "Build and submit the minimal pool's frame transactions.",
  positionals: [
    { name: "rpc" },
    { name: "config", help: "deployment config, such as core/deploy_config.json" },
    { name: "fixture", help: "fixture from src/cli/smoke.ts or src/cli/nonce-race.ts" },
    { name: "op", choices: ["shield", "publish", "transfer", "withdraw"] },
  ],
  options: {
    "--dry-run": { kind: "flag", help: "simulate without submitting" },
    "--epoch": { kind: "int", help: "epoch to publish" },
    "--note": { kind: "int", help: "index into the fixture's shields" },
    "--spend-key": {
      kind: "string",
      help: "name of the fixture's spend entry (e.g. transfer_c), never a key",
    },
    "--root-slot": { kind: "int", help: "consensus slot that published the root" },
    "--no-tail": { kind: "flag", help: "send a spend without a fourth frame" },
    "--allow-failed-claim": {
      kind: "flag",
      help: "send a withdrawal whose default claim is expected to revert",
    },
    "--action-target": { kind: "append", help: TAIL },
    "--action-call": { kind: "append", help: TAIL },
    "--action-gas": { kind: "append", help: TAIL },
    "--action-state-gas": { kind: "append", help: TAIL },
    "--max-fee-per-gas": {
      kind: "int",
      help: "a spend's fee cap in wei (default: twice the base fee plus the tip)",
    },
    "--max-priority-fee-per-gas": { kind: "int", help: "a spend's tip in wei (default: 1 gwei)" },
  },
  // The CLI once took the funded key here. Refused before parsing, whose errors repeat values.
  refuseBeforeParsing: {
    index: 4,
    message:
      "the CLI no longer takes a key argument, which other local users could read: shield " +
      "and publish read the funded key from standard input",
  },
} as const;

const ACTION_OPTION_FLAGS = Object.keys(SPEC.options).filter((flag) =>
  flag.startsWith("--action-"),
);
// Whole hex bytes, after an optional 0x or 0X.
const CALL_FORM = /^(?:0[xX])?((?:[0-9a-fA-F]{2})*)$/;

/** One all-or-none custom tail from [flag, value, ...] pairs, or null without action flags. */
export function actionOptions(argv: readonly string[]): Action | null {
  const flags = ACTION_OPTION_FLAGS;
  const unknown = new Set(argv.filter((a) => a.startsWith("--action-") && !flags.includes(a)));
  if (unknown.size > 0) {
    throw new InputError(`unknown action option: ${[...unknown].sort().join(", ")}`);
  }
  const missing = flags.filter((flag) => !argv.includes(flag));
  if (missing.length === flags.length) return null;
  if (missing.length > 0) throw new InputError(`action requires ${missing.sort().join(", ")}`);
  const value = <T>(flag: string, read: (raw: string) => T | null): T => {
    if (argv.filter((arg) => arg === flag).length !== 1) {
      throw new InputError(`${flag} must be supplied exactly once`);
    }
    const raw = argv[argv.indexOf(flag) + 1];
    if (raw === undefined || raw.startsWith("--")) throw new InputError(`${flag} requires a value`);
    const parsed = read(raw);
    if (parsed === null) throw new InputError(`invalid ${flag} value: ${raw}`);
    return parsed;
  };
  const calldata = (raw: string) => {
    const digits = CALL_FORM.exec(raw)?.[1];
    return digits === undefined ? null : fromHex("0x" + digits, "--action-call");
  };
  return {
    target: value("--action-target", uintFromText),
    data: value("--action-call", calldata),
    gasLimit: value("--action-gas", uintFromText),
    stateLimit: value("--action-state-gas", uintFromText),
  };
}

/** What in-process tests replace: the node, the deployed-code check, the sender, the key. */
export interface Deps {
  readonly node?: PoolNode;
  readonly checkDeployedProfile?: typeof checkDeployedProfile;
  readonly buildAndSend?: typeof buildAndSend;
  readonly readFundedKey?: () => Promise<Uint8Array>;
}

/** The shield or publish payer's key: a hidden prompt on a terminal, one line from a pipe. */
async function fundedKey(): Promise<Uint8Array> {
  const line = await readSecretLine("funded private key: ");
  try {
    // trim() would drop a byte order mark as whitespace; a key line holding one is refused.
    if (!line.includes("\uFEFF")) return parsePrivateKeyLine(line, "the funded key");
  } catch (error) {
    if (!(error instanceof InputError)) throw error;
  }
  throw new InputError("standard input did not hold a private key");
}

/**
 * The shield to fund: a smoke fixture's note A, proved as the first leaf of an empty tree, or
 * --note N of a nonce-race fixture, whose shields share one tree (the second completes the root
 * both race transfers reference) and so record their leaf and prior root.
 */
function fixtureShield(fix: JsonObject, note: bigint | undefined) {
  if (!Object.hasOwn(fix, "shields")) {
    const value = parseDec(fix.shield_value, "the fixture's shield_value");
    const entry = Object.hasOwn(fix, "shield_note") ? { note: fix.shield_note } : {};
    return { value, inner: fix.inner_a, leaf: 0n, priorRoot: protocol.EMPTY_ROOT, entry };
  }
  if (note === undefined) {
    throw new PoolError("this fixture has a 'shields' array; pass --note N (0-based)");
  }
  const s: unknown = Array.isArray(fix.shields) ? fix.shields[Number(note)] : undefined;
  if (!isObject(s)) throw new PoolError(`the fixture's shields have no note ${note}`);
  if (!Object.hasOwn(s, "prior_root")) {
    throw new PoolError("this fixture's shields do not record prior_root; regenerate it");
  }
  const value = parseDec(s.value, "the shield's value");
  const leaf = parseDec(s.leaf, "the shield's leaf");
  const priorRoot = parseHex(s.prior_root, "the shield's prior_root");
  return { value, inner: s.inner, leaf, priorRoot, entry: s };
}

/**
 * Runs the command line `argv` (without node and the script), against the real node by default.
 * A config for another profile, and options that do not fit the operation, are refused before
 * any RPC; then the deployed pool is checked, except before a publication, and the shield,
 * publication or spend is built and sent.
 */
export async function main(argv: readonly string[], deps: Deps = {}): Promise<void> {
  const { positionals, options } = parseArgs(SPEC, argv);
  const { op } = positionals;
  const dryRun = options["--dry-run"];
  const omitTail = options["--no-tail"];
  const allowFailedClaim = options["--allow-failed-claim"];
  const maxFee = options["--max-fee-per-gas"];
  const maxPriorityFee = options["--max-priority-fee-per-gas"];
  // Flag-value pairs as the parser read them, so --flag=value forms obey the same tail rules.
  const given: Record<string, unknown> = options;
  const pairs = ACTION_OPTION_FLAGS.flatMap((flag) =>
    (given[flag] as string[]).flatMap((value) => [flag, value]),
  );
  const action = actionOptions(pairs);
  const config = readJson(positionals.config);
  const fix = readJson(positionals.fixture) as JsonObject;
  const cfg = asObject(config, positionals.config);
  const poolAddress = parseConfigAddress(cfg.pool, "the config's pool");
  const spend = op === "transfer" || op === "withdraw";
  // A config for another profile names a pool this tooling cannot spend from. The label is a
  // first check before any RPC; checkDeployedProfile compares the deployed code.
  if (op !== "publish") {
    if (cfg.profile !== gas.POOL_PROFILE) {
      throw new PoolError(
        `${op} requires profile=${gas.POOL_PROFILE}; this config names ` +
          `${stringify(cfg.profile ?? null)}. Use a fresh deployment of this profile`,
      );
    }
    const missing = ["chainId", "logic", "verifier"].filter((key) => !Object.hasOwn(cfg, key));
    if (missing.length > 0) {
      throw new PoolError(`${op} requires the config to record ${missing.join(", ")}`);
    }
  }
  // JSON numbers, which readJson gives for integers this small: 100000.0 matches, "100000" not.
  const claimLimits = [Number(gas.CLAIM_FRAME_GAS), Number(gas.CLAIM_FRAME_STATE_GAS)];
  if (spend && (cfg.claimGas !== claimLimits[0] || cfg.claimStateGas !== claimLimits[1])) {
    throw new PoolError(`spends require claimGas/claimStateGas matching ${gas.POOL_PROFILE}`);
  }
  if (omitTail && action !== null) {
    throw new PoolError("--no-tail cannot be combined with action options");
  }
  if ((action !== null || omitTail) && !spend) {
    throw new PoolError("action options and --no-tail are valid only for transfer or withdraw");
  }
  if (allowFailedClaim && op !== "withdraw") {
    throw new PoolError("--allow-failed-claim is only valid on withdraw");
  }
  if (allowFailedClaim && omitTail) {
    throw new PoolError("--allow-failed-claim cannot be combined with --no-tail");
  }
  if ((maxFee !== undefined || maxPriorityFee !== undefined) && !spend) {
    throw new PoolError("fee overrides are valid only for transfer or withdraw");
  }

  const node = deps.node ?? poolNode(positionals.rpc);
  const sendTx = deps.buildAndSend ?? buildAndSend;
  const io: SendIo = { log: (line) => process.stdout.write(line + "\n") };
  const sendCall = async (value: bigint, calldata: Uint8Array, fixedGas = false) => {
    const call = { kind: "call", value, calldata, fixedGas } as const;
    const key = await (deps.readFundedKey ?? fundedKey)();
    return sendTx(node, io, key, poolAddress, call, { dryRun });
  };
  if (op === "publish") {
    const epoch = options["--epoch"] ?? 0n;
    const calldata = protocol.encodePublish(epoch);
    io.log(`publishEpochRoot(${epoch}) via frame tx -> pool ${cfg.pool}`);
    const receipt = await sendCall(0n, calldata);
    if (receipt !== null) io.log(`ROOT_SLOT ${await waitPublishedSlot(node, io, receipt)}`);
    return;
  }

  const logic = parseConfigAddress(cfg.logic, "the config's logic");
  const verifier = parseConfigAddress(cfg.verifier, "the config's verifier");
  const chainId = parseDec(cfg.chainId, "the config's chainId");
  const checkDeployed = deps.checkDeployedProfile ?? checkDeployedProfile;
  await checkDeployed(node, poolAddress, chainId, logic, verifier);

  if (op === "shield") {
    const { value, inner, leaf, priorRoot, entry } = fixtureShield(fix, options["--note"]);
    // A missing inner is refused before the pool's tree is read; shieldCalldata checks its form.
    if (inner === undefined) throw new PoolError("the fixture does not record the shield's inner");
    await checkShieldFixture(node, poolAddress, chainId, fix, leaf, priorRoot);
    const calldata = shieldCalldata(inner, entry);
    io.log(`shield ${value} wei via frame tx -> pool ${cfg.pool}`);
    const receipt = await sendCall(value, calldata, true);
    if (receipt === null) return;
    const landed = shieldLeaf(receipt, poolAddress);
    const shown = landed === null ? "none" : `(${landed.join(", ")})`;
    io.log(`SHIELD_LEAF ${shown}`);
    const epoch = parseDec(fix.epoch, "the fixture's epoch");
    if (landed === null || landed[0] !== epoch || landed[1] !== leaf) {
      throw new PoolError(
        `  the note landed at (epoch, leaf) ${shown}, not (${fix.epoch}, ${leaf}), so the ` +
          "fixture's proofs cannot spend it. Keep this fixture: its spend entries' inputs hold " +
          "the note's opening, from which it can be proved again at the leaf it occupies.",
      );
    }
    return;
  }

  // A nonce-race fixture holds two transfers against one root (--spend-key picks one), both
  // using the slot in which its second shield completed the tree (--root-slot).
  const name = options["--spend-key"] ?? op;
  const source = Object.hasOwn(fix, name) ? fix[name] : undefined;
  if (!isObject(source)) throw new PoolError(`the fixture has no spend entry ${name}`);
  const configured = `_slot_${op}`;
  const slot = options["--root-slot"] ?? cfg[configured];
  if (slot === undefined) throw new PoolError(`the config has no ${configured}; pass --root-slot`);
  // --root-slot is already a bigint. A configured slot is a JSON integer or decimal digits; a
  // malformed string is reported as the spend entry's root_slot, anything else by its config key.
  const what =
    typeof slot === "string" ? "the spend entry's root_slot" : `the config's ${configured}`;
  const rootSlot = parseDec(slot, what);
  // The recent root is checked against the node first: its refusals say how to proceed, so they
  // come before a fault in any later field of the entry.
  const root = parseRecentRoot(source, rootSlot);
  const recentRoot = await recentRootReference(node, poolAddress, root);
  const key = authorizerKey(source);
  const owner = ownerSignature(source, chainId, poolAddress);
  const settle = settleCalldata(source, rootSlot);
  io.log(`join-split ${op} via frame tx (pool ${cfg.pool} self-pays)`);
  const proof = entryProofBytes(source);
  const fields = { settle, proof, recentRoot, owner, action, omitTail, allowFailedClaim };
  const sendOptions = { dryRun, maxFee, maxPriorityFee };
  await sendTx(node, io, key, poolAddress, { kind: "spend", ...fields }, sendOptions);
}

if (import.meta.main) await runCli(() => main(process.argv.slice(2)), { redactErrors: true });
