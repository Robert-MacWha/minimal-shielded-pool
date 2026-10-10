/**
 * Sends the pool's frame transactions and checks what was mined. A call (a shield or a
 * publication) goes from the funded account; a spend is paid by the pool. A spend whose SENDER
 * frame reverts still burns its notes, so spendVerdict lets one go only after a simulation in
 * which settlement succeeded. A call that reverts loses nothing (a shield's deposit stays with
 * the sender), so it may go unsimulated on a node that cannot simulate, and otherwise its SENDER
 * frame is sized from the simulated gas.
 */
import { setTimeout as delay } from "node:timers/promises";

import { hexPadded, maxBigint, parseHex, parseUint, toHex } from "./bytes.ts";
import { PoolError } from "./errors.ts";
import {
  addressOf,
  APPROVE,
  checksumAddress,
  maxCost,
  MODE,
  rawTx,
  sigHash,
  totalGasLimit,
  type FrameTx,
} from "./frametx.ts";
import * as gas from "./gas.ts";
import { isObject, printable, stringify, type JsonObject } from "./json.ts";
import type { PoolNode } from "./rpc.ts";
import {
  checkTxResourceLimits,
  signTransaction,
  spendFrames,
  spendNonceKeys,
  spendTailFrame,
  type Action,
} from "./spend.ts";

// The self-verify frame of a shield or publish, and the floor when its SENDER frame is resized.
const CALL_VERIFY_FRAME_GAS = 80_000n;
const MAX_PRIORITY_FEE = 10n ** 9n;

const get = (value: unknown, key: string): unknown => (isObject(value) ? value[key] : undefined);

/** What to send: an ordinary call from the funded account, or a spend the pool pays for. */
export type Send =
  | { readonly kind: "call"; readonly value: bigint; readonly calldata: Uint8Array }
  | {
      readonly kind: "spend";
      readonly settle: Uint8Array;
      readonly proof: Uint8Array;
      readonly recentRoot: Uint8Array;
      readonly action?: Action | null;
      readonly omitTail?: boolean;
      readonly allowFailedClaim?: boolean;
    };

/** Where the sender reports progress, and how it waits; sleep and now default to real time. */
export interface SendIo {
  readonly log: (line: string) => void;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly now?: () => number;
}

/** A spend's fourth frame: a custom action, a withdrawal's default claim, or none. */
export type TailKind = "action" | "claim" | null;

// A node value in a progress line: a string as it is, anything else as JSON, with control
// characters escaped either way.
const show = (value: unknown): string =>
  printable(typeof value === "string" ? value : stringify(value ?? null));
const grouped = (value: bigint | null): string =>
  value === null ? "null" : value.toLocaleString("en-US");

// ---- simulation ----

/** A simulation result as ethrex writes it, with its gas values and frame outcomes read. */
export interface Simulation {
  /** The node's answer. Its other fields only shape messages or are compared with "success". */
  readonly result: JsonObject;
  readonly valid: boolean;
  readonly frames: readonly { readonly gasUsed: bigint | null; readonly succeeded: boolean }[];
  readonly gasUsed: bigint | null;
}

/**
 * A simulation result, or null when the node lacks the method: an object whose gas values are
 * hex or null and whose frames are objects.
 */
function simulation(result: unknown): Simulation | null {
  if (result === null) return null;
  if (!isObject(result)) {
    throw new PoolError(
      `  simulate: ethrex_simulateFrameTransaction returned ${show(result)}, not an object`,
    );
  }
  const gasOf = (value: unknown, what: string) =>
    value == null ? null : parseHex(value, `the simulation's ${what}`);
  const frames = result.frames ?? [];
  if (!Array.isArray(frames) || !frames.every(isObject)) {
    throw new PoolError(`  simulate: frames ${show(frames)} is not a list of objects; not sending`);
  }
  return {
    result,
    valid: result.valid === true,
    frames: frames.map((f, i) => ({
      gasUsed: gasOf(f.gasUsed, `frame ${i} gasUsed`),
      // Only the JSON boolean true: an aggregate status cannot tell a failed tail from a
      // failed settlement.
      succeeded: f.succeeded === true,
    })),
    gasUsed: gasOf(result.gasUsed, "gasUsed"),
  };
}

const ACTION_REBUILD =
  "Fix the account calldata or limits and rebuild. The RPC has seen this signed spend, so " +
  "check that its nonce keys are unused before sending another.";

/**
 * Whether a simulated spend of `frameCount` frames may be sent: the progress lines to print
 * before acting on the verdict, and why the spend must not be sent, or null to send it. Every
 * frame must succeed, except a withdrawal's claim when `allowFailedClaim` is set: its credit
 * then stays in the pool for a later claim. A failed DEFAULT tail makes the node mark the
 * simulation invalid though nothing before it failed, so an invalid simulation gets through only
 * for such a claim, and only once settlement (frame 2) succeeded.
 */
export function spendVerdict(
  sim: Simulation,
  tailKind: TailKind,
  allowFailedClaim: boolean,
  frameCount: number,
): { notes: string[]; refusal: string | null } {
  const notes: string[] = [];
  const refuse = (refusal: string) => ({ notes, refusal });
  const { frames, result } = sim;
  const settled = frames[2]?.succeeded === true;
  const tailFailed = tailKind !== null && frames[3]?.succeeded !== true;
  if (!sim.valid) {
    if (settled && tailKind === "action") {
      return refuse(
        "  simulate: settlement would succeed but the gas-only action frame would fail; not " +
          `sending. ${ACTION_REBUILD}`,
      );
    }
    if (!(settled && tailKind === "claim" && allowFailedClaim)) {
      let message = `  simulate: INVALID (${show(result.violation)}); not sending`;
      if (show(result.violation).includes("Nonce mismatch")) {
        message +=
          "\n  a nullifier key is already consumed: this spend, or another spend of the" +
          "\n  same note or dummy, may already have settled. Check the notes before" +
          "\n  building another spend.";
      }
      return refuse(message);
    }
    notes.push(
      `  simulate: valid=${show(result.valid)} violation=${show(result.violation)}; settlement ` +
        "succeeded and failed claim is allowed",
    );
  }
  if (!settled) {
    return refuse("  simulate: settlement frame 2 did not explicitly succeed; not sending");
  }
  if (tailFailed && tailKind === "action") {
    return refuse(
      "  simulate: settlement succeeded but the gas-only action frame failed; not sending. " +
        ACTION_REBUILD,
    );
  }
  if (tailFailed && !allowFailedClaim) {
    return refuse(
      "  simulate: settlement succeeded but the claim frame failed; not sending. The credit " +
        "would remain and can be claimed later.",
    );
  }
  if (frames.length !== frameCount || frames.some((f, i) => i !== 3 && !f.succeeded)) {
    return refuse("  simulate: settlement succeeded but another frame failed; not sending");
  }
  if (tailFailed) {
    notes.push(
      "  simulate: settlement succeeded; claim frame failed (allowed); credit will remain for a later claim",
    );
  }
  return { notes, refusal: null };
}

// ---- sending ----

/**
 * Builds, simulates and sends a call or a spend and returns its receipt, or null after a dry
 * run. A spend keeps its SENDER limit: EIP-8037 state accounting varies too much for measured
 * gas plus 25% to be a safe margin.
 */
export async function buildAndSend(
  node: PoolNode,
  io: SendIo,
  key: Uint8Array,
  pool: bigint,
  send: Send,
  options: { dryRun?: boolean; maxFee?: bigint; maxPriorityFee?: bigint } = {},
): Promise<JsonObject | null> {
  const spend = send.kind === "spend" ? send : null;
  const value = send.kind === "call" ? send.value : 0n;
  const omit = spend?.omitTail;
  const tail = spend && spendTailFrame(pool, spend.settle, spend.action ?? null, { omit });
  const tailKind: TailKind = spend?.action ? "action" : tail ? "claim" : null;
  const signer = addressOf(key);
  const account = hexPadded(spend ? pool : signer, 40);
  const chainId = parseHex(await node.call("eth_chainId", []), "eth_chainId's result");
  // A spend's sequence is always 0, but its nonce is still read, keeping the RPC order.
  const count = await node.call("eth_getTransactionCount", [account, "latest"]);
  const nonce = parseHex(count, "eth_getTransactionCount's result");
  const block = await node.call("eth_getBlockByNumber", ["latest", false]);
  if (!isObject(block)) throw new PoolError("eth_getBlockByNumber returned no latest block");
  const { baseFeePerGas = "0x0" } = block;
  const baseFee = parseHex(baseFeePerGas, "the latest block's baseFeePerGas");
  // By default the fee cap is twice the base fee plus a 1 gwei tip. A spend's proof fixes a fee
  // that must cover the transaction's maximum cost, so the overrides let an existing proof fit
  // when base fees rise.
  const maxPriorityFee = options.maxPriorityFee ?? MAX_PRIORITY_FEE;
  const maxFee = options.maxFee ?? 2n * baseFee + maxPriorityFee;
  if (maxFee < baseFee || maxPriorityFee > maxFee) {
    throw new PoolError("fee overrides require max_fee >= base_fee and max_priority <= max_fee");
  }
  if (value > 0n) {
    const answer = await node.call("eth_getBalance", [account, "latest"]);
    const balance = parseHex(answer, "eth_getBalance's result");
    if (balance < value) {
      throw new PoolError(
        `  sender ${account} has ${balance} wei; this frame moves ${value} wei plus gas ` +
          "(deployer balance after contract creates is a common cause)",
      );
    }
  }
  const build = (senderGas = gas.SETTLE_FRAME_GAS): FrameTx => {
    const tx: FrameTx = {
      chainId,
      nonceKeys: spend ? spendNonceKeys(spend.settle) : [0n],
      nonceSeq: spend ? 0n : nonce,
      sender: spend ? pool : signer,
      frames:
        send.kind === "spend"
          ? spendFrames({ ...send, pool, tail, settleGas: senderGas })
          : [
              // The account's default code checks the signature and approves both.
              {
                mode: MODE.VERIFY,
                flags: APPROVE.EXECUTION_AND_PAYMENT,
                target: signer,
                gasLimit: CALL_VERIFY_FRAME_GAS,
                stateLimit: 0n,
                value: 0n,
                data: new Uint8Array(0),
              },
              {
                mode: MODE.SENDER,
                flags: APPROVE.NONE,
                target: pool,
                gasLimit: senderGas,
                stateLimit: gas.SETTLE_FRAME_STATE_GAS,
                value,
                data: send.calldata,
              },
            ],
      signatures: [],
      maxPriorityFee,
      maxFee,
      maxBlobFee: 0n,
      blobHashes: [],
    };
    checkTxResourceLimits(signTransaction(tx, key));
    return tx;
  };
  let tx = build();
  const sim = simulation(await node.simulate(toHex(rawTx(tx))));
  const r = sim?.result ?? {};
  const { prefixShape: shape, payer, executionStatus: status } = r;
  const report = `shape=${show(shape)}  payer=${show(payer)}  status=${show(status)}`;
  if (options.dryRun) {
    if (sim === null) {
      io.log("  dry-run: ethrex_simulateFrameTransaction unavailable on this endpoint");
      return null;
    }
    io.log(`  dry-run: valid=${show(r.valid)}  ${report}`);
    io.log(`           violation=${show(r.violation)}`);
    io.log(`           max_cost=${maxCost(tx)}  total_gas_limit=${totalGasLimit(tx)}`);
    const per = sim.frames.map((f, i) => `f${i}=${grouped(f.gasUsed)}`).join(", ");
    if (sim.gasUsed !== null) io.log(`           gas=${grouped(sim.gasUsed)}  (${per})`);
    return null;
  }
  if (sim?.valid) {
    const per = sim.frames.map((f, i) => `f${i}=${show(f.gasUsed)}`).join(", ");
    io.log(`  simulate: valid  ${report}  gas=${show(sim.gasUsed)}  (${per})`);
  }

  if (spend) {
    if (sim === null) {
      throw new PoolError(
        "  simulate: ethrex_simulateFrameTransaction unavailable here; refusing to send a " +
          "nullifier-consuming spend without a pre-send simulation (a mined tx whose SENDER " +
          "frame reverts burns the spent notes)",
      );
    }
    const allowFailedClaim = spend.allowFailedClaim === true;
    const verdict = spendVerdict(sim, tailKind, allowFailedClaim, tx.frames.length);
    for (const line of verdict.notes) io.log(line);
    if (verdict.refusal !== null) throw new PoolError(verdict.refusal);
  } else if (sim === null) {
    io.log("  simulate: ethrex_simulateFrameTransaction unavailable here; default gas limits");
  } else {
    if (!sim.valid) throw new PoolError(`  simulate: INVALID (${show(r.violation)}); not sending`);
    if ((status ?? "success") !== "success") {
      const hint =
        value > 0n
          ? `; this frame moves ${value} wei — if the sender is short after contract creates, ` +
            "top up and redeploy from scratch"
          : " (if root-not-recent, retry one block later)";
      const error = r.executionError;
      const cause = show(typeof error === "string" && error !== "" ? error : status);
      throw new PoolError(`  simulate: execution did not succeed (${cause}); not sending${hint}`);
    }
    // Only a reported success is a size; a call whose status is missing keeps the default limit.
    const used = sim.frames.at(-1)?.gasUsed ?? null;
    if (used !== null && status === "success") {
      const sized = maxBigint(used + used / 4n, CALL_VERIFY_FRAME_GAS);
      const resized = build(sized);
      const check = simulation(await node.simulate(toHex(rawTx(resized))));
      if (check?.valid && check.result.executionStatus === "success") {
        tx = resized;
        const measured = `measured ${grouped(used)} + 25%, floor 80k`;
        io.log(`  sized SENDER frame to ${grouped(sized)} gas (${measured})`);
      } else if (check?.valid) {
        const fallback = grouped(gas.SETTLE_FRAME_GAS);
        io.log(`  sized SENDER ${grouped(sized)} did not execute; keeping default ${fallback}`);
      }
    }
  }

  io.log(
    `  frame tx: sender=${account} signer=${checksumAddress(signer)} ` +
      `nonce_keys=[${tx.nonceKeys.join(", ")}] raw_len=${rawTx(tx).length} ` +
      `max_cost=${maxCost(tx)} sig_hash=${toHex(sigHash(tx)).slice(2, 20)}...`,
  );
  const hash = await node.call("eth_sendRawTransaction", [toHex(rawTx(tx))]);
  io.log(`  submitted: ${show(hash)}`);
  for (let poll = 0; poll < 30; poll++) {
    const receipt = await node.call("eth_getTransactionReceipt", [hash]);
    if (receipt !== null) return checkReceipt(io, receipt, spend, tailKind);
    await (io.sleep ?? delay)(2_000);
  }
  throw new PoolError("  not mined within timeout");
}

// ---- receipts ----

// Frame receipt statuses are compared as the literal strings, so "0x01" never passes for "0x1".
const FRAME_STATUSES: ReadonlySet<unknown> = new Set(["0x0", "0x1", "0x2"]);

/** Refuses a mined transaction whose settlement or tail did not do what was signed. */
function checkReceipt(
  io: SendIo,
  receipt: unknown,
  spend: { allowFailedClaim?: boolean } | null,
  tailKind: TailKind,
): JsonObject {
  if (!isObject(receipt)) {
    throw new PoolError(`  eth_getTransactionReceipt returned ${show(receipt)}, not a receipt`);
  }
  const { status = "0x0", gasUsed = "0x0" } = receipt;
  const reverted = parseHex(status, "the receipt's status") !== 1n;
  const block = parseHex(receipt.blockNumber, "the receipt's blockNumber");
  io.log(
    `  MINED block=${block} type=${show(receipt.type)} status=${show(receipt.status)} ` +
      `gasUsed=${parseHex(gasUsed, "the receipt's gasUsed")}`,
  );
  if (!spend) {
    if (reverted) throw new PoolError(`  tx reverted (status ${show(receipt.status)}); aborting`);
    return receipt;
  }
  const frames = Array.isArray(receipt.frameReceipts) ? receipt.frameReceipts : [];
  const [settlement, tailStatus] = [get(frames[2], "status"), get(frames[3], "status")];
  if (!FRAME_STATUSES.has(settlement)) {
    throw new PoolError("  settlement outcome unavailable; inspect frame receipts before retrying");
  }
  if (settlement !== "0x1") {
    throw new PoolError(
      "  settlement frame did not succeed; nullifiers may have been consumed without creating " +
        "outputs. Inspect frame receipts before retrying.",
    );
  }
  if (tailKind !== null && !FRAME_STATUSES.has(tailStatus)) {
    throw new PoolError(
      tailKind === "action"
        ? "  settlement succeeded, but the gas-only action outcome is unknown. The input notes " +
            "may already be consumed; inspect the nullifiers, outputs, and account state. Do not " +
            "retry or re-sign using those notes."
        : "  settlement succeeded, but the claim frame outcome is unknown. Inspect the pool " +
            "credit before taking any recovery action.",
    );
  }
  const tailReverted = tailKind !== null && tailStatus !== "0x1";
  if (tailReverted && tailKind === "action") {
    throw new PoolError(
      "  settlement succeeded, but the gas-only action frame failed. The input notes were " +
        "consumed and settlement outputs were created; inspect them and the account state. Do " +
        "not retry or re-sign using those notes.",
    );
  }
  const claimFailed = "  settlement succeeded, but the claim frame failed";
  if (tailReverted && !spend.allowFailedClaim) {
    throw new PoolError(`${claimFailed}. The settled credit remains recoverable.`);
  }
  if (tailReverted) io.log(`${claimFailed} (allowed). The settled credit remains recoverable.`);
  // Only an allowed claim revert may leave the whole transaction reverted.
  if (reverted && !tailReverted) {
    throw new PoolError(
      `  tx reverted (status ${show(receipt.status)}) after successful settlement; inspect frame receipts`,
    );
  }
  return receipt;
}

/** Waits for two blocks after the publication block, then returns its EIP-7843 slotNumber. */
export async function waitPublishedSlot(
  node: PoolNode,
  io: SendIo,
  receipt: unknown,
  timeoutMs = 180_000,
): Promise<bigint> {
  const published = parseHex(get(receipt, "blockNumber"), "the receipt's blockNumber");
  const hash = get(receipt, "blockHash");
  if (hash === undefined) throw new PoolError("  the publication receipt has no blockHash");
  const now = io.now ?? Date.now;
  const deadline = now() + timeoutMs;
  for (;;) {
    const head = parseHex(await node.call("eth_blockNumber", []), "eth_blockNumber's result");
    io.log(`  confirmations: head=${head} publish_block=${published} (need +2)`);
    if (head >= published + 2n) break;
    if (now() >= deadline) {
      throw new PoolError(
        `  timed out waiting for 2 blocks after publish at ${published} (head ${head})`,
      );
    }
    await (io.sleep ?? delay)(2_000);
  }
  const block = await node.call("eth_getBlockByHash", [hash, false]);
  if (!isObject(block)) throw new PoolError("  publication block is no longer on the chain");
  const slot = block.slotNumber;
  if ((slot ?? "") === "") throw new PoolError("  publication block has no slotNumber");
  return parseUint(slot, "the publication block's slotNumber");
}
