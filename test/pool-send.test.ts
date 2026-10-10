/**
 * The optional fourth DEFAULT frame of a spend (a withdrawal's claim or one custom action), its
 * option parser and resource checks, and the send gates that refuse to broadcast a spend whose
 * simulation does not show settlement succeeding. Mining such a spend would consume its keys
 * without creating the outputs. Then how a shield or publish call is sized, refused and sent.
 * Runs in about 0.3 s.
 *
 *   node --test test/pool-send.test.ts
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";

import { concat, fromHex, keccak, toBytes, toHex, word } from "../src/bytes.ts";
import { actionOptions } from "../src/cli/pool.ts";
import { InputError, PoolError } from "../src/errors.ts";
import {
  calldataFloorGas,
  encodeFrame,
  executionCapUsage,
  rawTx,
  rlpInt,
  rlpItems,
  rlpList,
  sigHash,
  stateGasLimit,
  totalGasLimit,
  type Frame,
  type FrameTx,
} from "../src/frametx.ts";
// The expected limits come from the wallet defaults in gas.ts, never from the client's frame
// builder, so a limit the client overrides cannot follow itself into the expectation.
import * as gas from "../src/gas.ts";
import { PRECOMPILES, UNCLAIMABLE_RECIPIENTS } from "../src/protocol.ts";
import { poolNode, type PoolNode } from "../src/rpc.ts";
import { buildAndSend, spendVerdict, type Simulation, type TailKind } from "../src/send.ts";
import { checkTxResourceLimits, spendTailFrame, type Action } from "../src/spend.ts";
import { rpcServer } from "./helpers.ts";

const POOL = 0xbeefn;
const ACCOUNT = 0xa11cen;
const ACTION_GAS = 300_000n;
const SETTLE_SIGNATURE =
  "settle((bytes32,uint64,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,address,address))";
const SETTLE = keccak(Buffer.from(SETTLE_SIGNATURE)).subarray(0, 4);

/**
 * settle(Spend) calldata: words root, root_slot, epoch, domain, nf1 = 3, nf2 = 4, out_cm1,
 * out_cm2, public_amount, fee, recipient, authorizer, then the notes (two by default).
 */
function settlement(publicAmount = 0n, recipient = 0n, notes = new Uint8Array(96).fill(0x5a)) {
  const words = [1n, 1n, 0n, 2n, 3n, 4n, 5n, 6n, publicAmount, 7n, recipient, 8n];
  return concat(SETTLE, ...words.map(word), notes);
}

const frame = (
  mode: bigint,
  flags: bigint,
  target: bigint,
  gasLimit: bigint,
  data: Uint8Array,
  stateLimit = 0n,
): Frame => ({ mode, flags, target, gasLimit, stateLimit, value: 0n, data });

/** The spend this file expects the client to build, written out from gas.ts's defaults. */
function spendTx(tail: Frame): FrameTx {
  return {
    chainId: 1n,
    nonceKeys: [3n, 4n],
    nonceSeq: 0n,
    sender: POOL,
    frames: [
      // EIP-8272's recent-root contract, which the first VERIFY frame calls.
      frame(1n, 0n, 0x8272n, gas.RECENT_ROOT_FRAME_GAS, new Uint8Array(72)),
      frame(1n, 3n, POOL, gas.VERIFY_FRAME_GAS, new Uint8Array(288), gas.VERIFY_FRAME_STATE_GAS),
      frame(2n, 0n, POOL, gas.SETTLE_FRAME_GAS, settlement(), gas.SETTLE_FRAME_STATE_GAS),
      tail,
    ],
    signatures: [
      { scheme: 1n, signer: ACCOUNT, msg: new Uint8Array(0), signature: new Uint8Array(65) },
    ],
    maxPriorityFee: 1n,
    maxFee: 10n,
    maxBlobFee: 0n,
    blobHashes: [],
  };
}

/** Throws InputError, whose message contains `text`. */
function rejects(fn: () => unknown, text: string): void {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof InputError, String(error));
    assert.ok(error.message.includes(text), `${JSON.stringify(text)} not in: ${error.message}`);
    return true;
  });
}

const ARGV = "--action-target 0xa11ce --action-call 0x --action-gas 300000 --action-state-gas 0";
const ACTION = actionOptions(ARGV.split(" ")) as Action;
const CUSTOM_TAIL = frame(0n, 0n, ACCOUNT, ACTION_GAS, new Uint8Array(0));

describe("action options", () => {
  test("no flags is no action; the four make one DEFAULT tail with zero value", () => {
    assert.equal(actionOptions([]), null);
    const { target, data, gasLimit, stateLimit } = CUSTOM_TAIL;
    assert.deepEqual(ACTION, { target, data, gasLimit, stateLimit });
    assert.deepEqual(spendTailFrame(POOL, settlement(), ACTION), CUSTOM_TAIL);
  });

  test("all four flags or none, each exactly once, each well formed", () => {
    const argv = ARGV.split(" ");
    for (let i = 0; i < argv.length; i += 2) {
      rejects(() => actionOptions(argv.toSpliced(i, 2)), argv[i]);
    }
    rejects(() => actionOptions([...argv, "--action-gas", "1"]), "exactly once");
    rejects(() => actionOptions(["--action-gaas", "1"]), "unknown");
    // A flag is never another flag's value, and the last flag needs one too.
    const valueless = ["--action-target", ...argv.slice(2)];
    rejects(() => actionOptions(valueless), "--action-target requires a value");
    rejects(() => actionOptions(argv.slice(0, -1)), "--action-state-gas requires a value");
    for (const call of ["0x0", "0xgg", "0x0X12"]) {
      rejects(() => actionOptions(argv.with(3, call)), "invalid --action-call");
    }
    // Calldata is bare hex or hex after one 0x or 0X.
    for (const call of ["1234", "0x1234", "0X1234"]) {
      assert.deepEqual(actionOptions(argv.with(3, call))?.data, Uint8Array.of(0x12, 0x34), call);
    }
  });
});

describe("the tail frame", () => {
  const withdrawal = settlement(1n, ACCOUNT);

  test("a transfer has no tail; a withdrawal claims its credit, or leaves it with omit", () => {
    assert.equal(spendTailFrame(POOL, settlement()), null);
    // DEFAULT(pool, claimWithdrawal(recipient)) at the wallet's claim limits.
    const claim = concat(Buffer.from("a3066aab", "hex"), word(ACCOUNT));
    const expected = frame(0n, 0n, POOL, gas.CLAIM_FRAME_GAS, claim, gas.CLAIM_FRAME_STATE_GAS);
    assert.deepEqual(spendTailFrame(POOL, withdrawal), expected);
    assert.equal(spendTailFrame(POOL, withdrawal, null, { omit: true }), null);
    rejects(() => spendTailFrame(POOL, withdrawal, ACTION, { omit: true }), "omit cannot");
  });

  test("a custom action replaces the claim, and may call the pool", () => {
    assert.deepEqual(spendTailFrame(POOL, withdrawal, ACTION), CUSTOM_TAIL);
    // The claim itself, and publishEpochRoot(0) to publish the root a transfer's outputs create.
    const claim = (spendTailFrame(POOL, withdrawal) as Frame).data;
    const publish = concat(Buffer.from("d03870b3", "hex"), new Uint8Array(32));
    for (const [settle, data, stateLimit] of [
      [withdrawal, claim, 183_600n],
      [settlement(), publish, 97_920n],
    ] as const) {
      const action = { target: POOL, data, gasLimit: 100_000n, stateLimit };
      const expected = frame(0n, 0n, POOL, 100_000n, data, stateLimit);
      assert.deepEqual(spendTailFrame(POOL, settle, action), expected);
    }
  });

  test("refuses a malformed action", () => {
    type Bad = [Partial<Action>, string];
    const invalid: Bad[] = [
      [{ target: 0n }, "nonzero"],
      [{ target: 1n << 160n }, "nonzero"],
      [{ gasLimit: 0n }, "execution gas"],
      [{ stateLimit: -1n }, "state gas"],
      ...[0x01n, 0x02n, 0x04n, 0x11n, 0x100n].map((t): Bad => [{ target: t }, "precompile"]),
    ];
    for (const [change, message] of invalid) {
      rejects(() => spendTailFrame(POOL, settlement(), { ...ACTION, ...change }), message);
    }
  });

  test("refuses settlement data of the wrong shape", () => {
    const range = "invalid pool, recipient, or public amount";
    const notes = "followed by its notes";
    const other = settlement();
    other[0] ^= 1; // calldata of the right length for another function
    const cases: [bigint, Uint8Array, Action | null, string][] = [
      [POOL, settlement(1n, 0n), null, "both be zero"],
      [POOL, settlement(0n, ACCOUNT), null, "both be zero"],
      // A public amount is a uint128 and a recipient an address, though their words are wider.
      [POOL, settlement(1n << 128n, ACCOUNT), null, range],
      [POOL, settlement(1n, 1n << 160n), null, range],
      [0n, settlement(), null, range],
      [POOL, other, ACTION, notes],
      [POOL, settlement().subarray(0, -1), ACTION, notes],
    ];
    for (const [pool, settle, action, text] of cases) {
      rejects(() => spendTailFrame(pool, settle, action), text);
    }
    // settle(Spend) is followed by two notes, optionally after an ML-KEM-768 ciphertext.
    for (const length of [0, 48, 95, 97, 1183, 1185]) {
      rejects(
        () => spendTailFrame(POOL, settlement(0n, 0n, new Uint8Array(length)), ACTION),
        notes,
      );
    }
    assert.notEqual(spendTailFrame(POOL, settlement((1n << 128n) - 1n, ACCOUNT)), null);
    assert.notEqual(spendTailFrame(POOL, settlement(0n, 0n, new Uint8Array(1184)), ACTION), null);
  });

  test("refuses a withdrawal to an address that can never claim, with or without a tail", () => {
    // Written out here, not read from the code under test, so dropping an address from the
    // client's refusal sets fails this test.
    const stranding = [
      ...[0xaan, 0x8141n, 0x8250n, 0x8272n, 0x100n],
      ...Array.from({ length: 0x11 }, (_, i) => BigInt(i + 1)),
      0x000f3df6d732807ef1319fb7b8bb8522d0beac02n, // EIP-4788 beacon roots
      0x0000f90827f1c53a10cb7a02335b175320002935n, // EIP-2935 history
      0x00000961ef480eb55e80d19ad83579a64c007002n, // EIP-7002 withdrawal requests
      0x0000bbddc7ce488642fb579f8b00f3a590007251n, // EIP-7251 consolidation requests
      0x00000000219ab540356cbb839cbe05303d7705fan, // beacon deposit contract
      0x0000bff46984e3725691fa540a8c7589300d8282n, // EIP-8282 builder deposits
      0x000064d678505ad48f8ccb093bc65613800e8282n, // EIP-8282 builder exits
    ];
    assert.equal(stranding.length, 29);
    const missing = stranding.filter((a) => !UNCLAIMABLE_RECIPIENTS.has(a) && !PRECOMPILES.has(a));
    assert.deepEqual(missing, []);
    for (const stranded of [POOL, ...stranding]) {
      const stuck = settlement(1n, stranded);
      rejects(() => spendTailFrame(POOL, stuck), "would strand the credit");
      rejects(() => spendTailFrame(POOL, stuck, null, { omit: true }), "would strand the credit");
      rejects(() => spendTailFrame(POOL, stuck, ACTION), "would strand the credit");
    }
  });
});

describe("transaction resource limits", () => {
  const withAction = (change: Partial<Action> = {}) =>
    spendTx(spendTailFrame(POOL, settlement(), { ...ACTION, ...change }) as Frame);

  // Computed by the Python client (test_gas_only_action._spend_tx at commit 2386147).
  test("a modest action fits, and its encoding and gas match the pinned values", () => {
    const tx = withAction();
    checkTxResourceLimits(tx);
    assert.equal(
      createHash("sha256").update(rawTx(tx)).digest("hex"),
      "f8d9bf393e6b5cc1ce9656d4dd5db47e69899804d397f4e29bae294d79a9377d",
    );
    assert.equal(
      toHex(sigHash(tx)),
      "0xce7bf7c77ba6b60340864c3f2ae4aecb79d9f46e0d86f36c1c0eb2708d38247e",
    );
    assert.deepEqual(
      [executionCapUsage(tx), totalGasLimit(tx), calldataFloorGas(tx), stateGasLimit(tx)],
      [2_554_824n, 3_300_664n, 76_412n, 745_840n],
    );
  });

  test("an action at the EIP-7825 cap does not, nor one past the ethrex mempool size", () => {
    rejects(
      () => checkTxResourceLimits(withAction({ gasLimit: gas.EIP7825_TX_GAS_CAP })),
      "EIP-7825",
    );
    // Its execution fits; only its size does not.
    const data = new Uint8Array(gas.ETHREX_MEMPOOL_MAX_BYTES + 1).fill(0xff);
    rejects(() => checkTxResourceLimits(withAction({ data })), "mempool");
  });

  test("state gas is a separate dimension the EIP-7825 cap does not count", () => {
    const tx = withAction({ stateLimit: gas.EIP7825_TX_GAS_CAP });
    assert.ok(totalGasLimit(tx) > gas.EIP7825_TX_GAS_CAP, "max_gas counts state gas");
    checkTxResourceLimits(tx);
  });
});

// ---- the send gates ----

// A simulation's or receipt's frame outcomes are written "+" for success and "-" for failure.
// Each simulated frame reports 0x100000 gas, which sizes a call's SENDER frame but never a
// spend's.
const simulated = (outcomes: string, valid = true, violation?: string) => ({
  simulation: {
    valid,
    ...(violation && { violation }),
    executionStatus: outcomes.includes("-") ? "reverted" : "success",
    frames: [...outcomes].map((c) => ({ succeeded: c === "+", gasUsed: "0x100000" })),
  },
});
const mined = (status: string, outcomes?: string) => ({
  receipt: {
    blockNumber: "0x2",
    type: "0x6",
    status,
    gasUsed: "0x100",
    ...(outcomes && {
      frameReceipts: [...outcomes].map((c) => ({ status: c === "+" ? "0x1" : "0x0" })),
    }),
  },
});

const CALLDATA = Uint8Array.of(1, 2, 3, 4);
interface SendCase {
  simulation?: unknown;
  /** The answer when a call resized from the first simulation is simulated again. */
  resized?: unknown;
  receipt?: unknown;
  action?: Action | null;
  settle?: Uint8Array;
  allowFailedClaim?: boolean;
  fees?: { maxFee?: bigint; maxPriorityFee?: bigint };
  /** A call moving 5 wei to the pool from key 1's account, in place of the spend. */
  call?: boolean;
  /** The call keeps the default SENDER limit, as a shield does. */
  fixedGas?: boolean;
  balance?: string;
  dryRun?: boolean;
}
/** A withdrawal with its default claim. */
const CLAIM: SendCase = { action: null, settle: settlement(5n, ACCOUNT) };

/**
 * Runs the real send path with private key 1 against a node that answers only what a spend or
 * call needs (by default, a spend with ACTION whose simulation succeeds), and returns the error
 * and the raw transactions broadcast.
 */
async function sendCase(options: SendCase): Promise<{ error: unknown; sent: Uint8Array[] }> {
  const o = {
    ...simulated(options.call ? "++" : "++++"),
    action: ACTION,
    settle: settlement(),
    ...options,
  };
  const sent: Uint8Array[] = [];
  const answers: Record<string, unknown> = {
    eth_chainId: "0x1",
    // A spend is at sequence 0 whatever the pool's nonce (a contract's starts at 1); a call is
    // at its account's nonce.
    eth_getTransactionCount: "0x1",
    eth_getBlockByNumber: { baseFeePerGas: "0x1" },
    eth_getBalance: o.balance ?? "0x5",
    eth_sendRawTransaction: "0x" + "12".repeat(32),
    eth_getTransactionReceipt: o.receipt ?? null,
  };
  const simulations = [o.simulation, o.resized ?? o.simulation];
  const node: PoolNode = {
    async call(method, params) {
      if (!(method in answers)) throw new Error(`unexpected ${method}`);
      if (method === "eth_sendRawTransaction") sent.push(fromHex(params[0], "the raw transaction"));
      return answers[method];
    },
    // Only a call resized from the first simulation is simulated again.
    simulate: async () => simulations.shift(),
  };
  const send = o.call
    ? ({ kind: "call", value: 5n, calldata: CALLDATA, fixedGas: o.fixedGas } as const)
    : ({
        kind: "spend",
        settle: o.settle,
        proof: new Uint8Array(288),
        recentRoot: new Uint8Array(72),
        action: o.action,
        allowFailedClaim: o.allowFailedClaim,
      } as const);
  const io = { log: () => {}, sleep: async () => {} };
  const sendOptions = { ...o.fees, dryRun: o.dryRun };
  const error = await buildAndSend(node, io, toBytes(1n, 32), POOL, send, sendOptions).then(
    () => null,
    (e: unknown) => e,
  );
  return { error, sent };
}

function refused(error: unknown, text: string): void {
  assert.ok(error instanceof PoolError, String(error));
  assert.ok(error.message.includes(text), `${JSON.stringify(text)} not in: ${error.message}`);
}

describe("send gates", () => {
  // A spend whose simulation does not show every frame doing what was signed is never
  // broadcast. A simulation that reports another number of frames simulated something else.
  const settlementFailed = "settlement frame 2 did not explicitly succeed";
  const otherFailed = "another frame failed";
  const gates: [string, SendCase, string][] = [
    [
      "an action that simulation shows failing, even with a claim allowance",
      { ...simulated("+++-", false, "frame 3 reverted"), allowFailedClaim: true },
      "gas-only action frame would fail",
    ],
    ["no simulation", { simulation: null }, "without a pre-send simulation"],
    ["settlement failed", simulated("++-+"), settlementFailed],
    ["outcomes missing", simulated("++"), settlementFailed],
    ["an action outcome the simulation leaves out", simulated("+++"), "action frame failed"],
    ["another frame failed", simulated("+-++"), otherFailed],
    ["invalid prefix", simulated("", false, "prefix"), "INVALID"],
    ["claim failed", { ...CLAIM, ...simulated("+++-") }, "claim frame failed; not sending"],
    ["a fifth frame the spend does not have", simulated("+++++"), otherFailed],
    [
      "an allowed claim the simulation leaves out",
      { ...CLAIM, ...simulated("+++"), allowFailedClaim: true },
      otherFailed,
    ],
  ];
  for (const [label, options, text] of gates) {
    test(`refused before sending: ${label}`, async () => {
      const { error, sent } = await sendCase(options);
      refused(error, text);
      assert.equal(sent.length, 0);
    });
  }

  // A mined spend whose receipt does not show what was signed is reported after its one send.
  const receipts: [string, SendCase, string | null][] = [
    ["no frame receipts", mined("0x1"), "settlement outcome unavailable"],
    [
      "an action outcome the receipt omits",
      mined("0x1", "+++"),
      "gas-only action outcome is unknown",
    ],
    [
      "an action that failed, though a claim failure is allowed",
      { ...mined("0x0", "+++-"), allowFailedClaim: true },
      "notes were consumed",
    ],
    ["settlement failed", mined("0x0", "++-+"), "settlement frame did not succeed"],
    [
      "the transaction reverted, though every frame succeeded",
      mined("0x0", "++++"),
      "reverted (status 0x0) after successful settlement",
    ],
    [
      "the claim failed",
      { ...CLAIM, ...mined("0x0", "+++-") },
      "claim frame failed. The settled credit remains recoverable",
    ],
    [
      "nothing, when an allowed claim failure reverts the whole transaction",
      { ...CLAIM, ...mined("0x0", "+++-"), allowFailedClaim: true },
      null,
    ],
  ];
  for (const [label, options, text] of receipts) {
    test(`reported after one send: ${label}`, async () => {
      const { error, sent } = await sendCase(options);
      if (text === null) assert.equal(error, null);
      else refused(error, text);
      assert.equal(sent.length, 1);
    });
  }

  test("an action that fails on chain is reported, after exactly one send", async () => {
    const { error, sent } = await sendCase(mined("0x0", "+++-"));
    refused(error, "notes were consumed");
    assert.equal(sent.length, 1);
    // Its frames are the ones spendTx writes out from gas.ts, though the simulation reported gas.
    const frames = rlpItems(sent[0].subarray(1))[4];
    assert.deepEqual(frames, rlpList(spendTx(CUSTOM_TAIL).frames.map(encodeFrame)));
    // The whole signed transaction (default fees for base fee 1, RFC 6979 signature with key 1),
    // as the Python client broadcast it in the same case (commit 2386147).
    assert.equal(
      toHex(keccak(sent[0])),
      "0x298483c6c4fedbd0403db74fd320d0182a0bbb71357da5d27422647cb34595f5",
    );
  });

  // A proof fixes the fee that must cover the transaction's maximum cost, so a lower cap can
  // let an existing proof be sent. The base fee here is 1 wei and the default tip 1 gwei.
  test("fee overrides are signed as given; a cap below the base fee or the tip is refused", async () => {
    // Field 6 of the envelope is [max_priority_fee, max_fee, max_blob_fee].
    const signed: [SendCase["fees"], bigint[]][] = [
      [{ maxFee: 3n, maxPriorityFee: 2n }, [2n, 3n, 0n]],
      [{ maxPriorityFee: 5n }, [5n, 7n, 0n]],
    ];
    for (const [fees, expected] of signed) {
      const { error, sent } = await sendCase({ ...mined("0x1", "++++"), fees });
      assert.equal(error, null);
      assert.deepEqual(rlpItems(sent[0].subarray(1))[6], rlpList(expected.map(rlpInt)));
    }
    const low = [
      { maxFee: 0n, maxPriorityFee: 0n },
      { maxFee: 2n },
      { maxFee: 5n, maxPriorityFee: 6n },
    ];
    for (const fees of low) {
      const { error, sent } = await sendCase({ fees });
      refused(error, "fee overrides require max_fee >= base_fee and max_priority <= max_fee");
      assert.equal(sent.length, 0);
    }
  });
});

// spendVerdict alone, for what the send gates cannot show: the progress lines it returns, and
// an allowed claim failure in a simulation the node marks invalid.
describe("the spend verdict", () => {
  /** A simulation whose frame outcomes are written "+" for success and "-" for failure. */
  const sim = (outcomes: string, valid = true, violation?: string): Simulation => ({
    result: { valid, ...(violation && { violation }) },
    valid,
    frames: [...outcomes].map((c) => ({ gasUsed: null, succeeded: c === "+" })),
    gasUsed: null,
  });
  const allowedInvalid =
    "  simulate: valid=false violation=frame 3 reverted; settlement succeeded and failed claim " +
    "is allowed";
  const claimLeft =
    "  simulate: settlement succeeded; claim frame failed (allowed); credit will remain for a " +
    "later claim";
  type Case = [
    label: string,
    simulation: Simulation,
    tailKind: TailKind,
    allowFailedClaim: boolean,
    notes: string[],
    refusal: string | null,
  ];
  const reverted = (outcomes: string) => sim(outcomes, false, "frame 3 reverted");
  const cases: Case[] = [
    ["a transfer whose frames all succeed", sim("+++"), null, false, [], null],
    ["a withdrawal whose claim succeeds", sim("++++"), "claim", false, [], null],
    ["an allowed claim failure", sim("+++-"), "claim", true, [claimLeft], null],
    [
      "an allowed claim failure the node marks invalid",
      reverted("+++-"),
      "claim",
      true,
      [allowedInvalid, claimLeft],
      null,
    ],
    [
      "an allowed claim failure the node marks invalid, beside another failed frame",
      reverted("+-+-"),
      "claim",
      true,
      [allowedInvalid],
      "another frame failed",
    ],
    ["a claim failure not allowed", reverted("+++-"), "claim", false, [], "INVALID (frame 3"],
    ["a failed action", reverted("+++-"), "action", true, [], "action frame would fail"],
    ["an invalid transfer", reverted("+++"), null, false, [], "INVALID (frame 3 reverted)"],
    [
      "a consumed nullifier key",
      sim("", false, "Nonce mismatch"),
      null,
      false,
      [],
      "a nullifier key is already consumed",
    ],
    ["a failed settlement", sim("++-+"), "claim", true, [], "frame 2 did not explicitly succeed"],
  ];
  for (const [label, simulation, tailKind, allow, notes, refusal] of cases) {
    test(label, () => {
      const frameCount = tailKind === null ? 3 : 4;
      const verdict = spendVerdict(simulation, tailKind, allow, frameCount);
      assert.deepEqual(verdict.notes, notes);
      if (refusal === null) assert.equal(verdict.refusal, null);
      else assert.ok(verdict.refusal?.includes(refusal), `${refusal} not in ${verdict.refusal}`);
    });
  }
});

describe("calls", () => {
  // A shield or publish loses nothing when it reverts, so it may go without a simulation.
  const CALL: SendCase = { call: true, ...mined("0x1") };
  // Key 1's account, whose default code checks the signature in the VERIFY frame.
  const SIGNER = 0x7e5f4552091a69125d5dfcb7b8c2659029395bdfn;
  const callFrames = (senderGas: bigint) =>
    rlpList(
      [
        frame(1n, 3n, SIGNER, 80_000n, new Uint8Array(0)),
        { ...frame(2n, 0n, POOL, senderGas, CALLDATA, gas.SETTLE_FRAME_STATE_GAS), value: 5n },
      ].map(encodeFrame),
    );

  test("a call goes under nonce key 0 at its account's nonce", async () => {
    const { error, sent } = await sendCase({ ...CALL, simulation: null });
    assert.equal(error, null);
    const fields = rlpItems(sent[0].subarray(1));
    assert.deepEqual(fields.slice(1, 3), [rlpList([rlpInt(0n)]), rlpInt(1n)]);
  });

  test("a call's SENDER limit is measured gas plus 25%, or the default for a shield or if that fails", async () => {
    const sized: [SendCase, bigint][] = [
      [{}, 1_310_720n], // 0x100000 plus 25%
      [{ resized: simulated("+-").simulation }, gas.SETTLE_FRAME_GAS],
      [{ simulation: null }, gas.SETTLE_FRAME_GAS],
      [{ fixedGas: true }, gas.SETTLE_FRAME_GAS],
    ];
    for (const [change, senderGas] of sized) {
      const { error, sent } = await sendCase({ ...CALL, ...change });
      assert.equal(error, null);
      assert.deepEqual(rlpItems(sent[0].subarray(1))[4], callFrames(senderGas));
    }
  });

  const gates: [string, SendCase, string][] = [
    ["an account short of the value", { balance: "0x4" }, "has 4 wei"],
    ["a simulation that reverted", simulated("+-"), "execution did not succeed (reverted)"],
  ];
  for (const [label, options, text] of gates) {
    test(`refused before sending: ${label}`, async () => {
      const { error, sent } = await sendCase({ ...CALL, ...options });
      refused(error, text);
      assert.equal(sent.length, 0);
    });
  }

  test("a dry run sends nothing, even on a node that cannot simulate", async () => {
    const { error, sent } = await sendCase({ ...CALL, simulation: null, dryRun: true });
    assert.equal(error, null);
    assert.equal(sent.length, 0);
  });

  test("a call that reverts on chain is reported after its one send", async () => {
    const { error, sent } = await sendCase({ ...CALL, ...mined("0x0") });
    refused(error, "tx reverted (status 0x0)");
    assert.equal(sent.length, 1);
  });

  test("a missing simulate method means no simulation; any other node error refuses", async () => {
    // The local node answers each raw transaction with the error code it names.
    const server = await rpcServer(({ params }) => ({
      error: { code: Number(params[0]), message: "refused" },
    }));
    try {
      const node = poolNode(server.url);
      assert.equal(await node.simulate("-32601"), null);
      refused(await node.simulate("-32000").catch((e: unknown) => e), "simulate RPC error");
    } finally {
      await server.close();
    }
  });
});
