/**
 * Checks the EIP-8141 gas profile: two declared dimensions per frame.
 *
 *   node tools/check-gas-profile.ts
 *
 * The frozen profile declared one number per frame and split it into execution and state at
 * runtime. The current spec has each frame declare `limits = [execution, state]`, and the two
 * pools never lend to each other. The settlement's state growth therefore leaves its execution
 * budget, which drops by exactly that charge, and the state budget becomes a separate declared
 * number. The transaction's maximum cost includes every declared state budget and the pool
 * pays it, so the dispatcher approves payment only when the proof's fee covers that cost.
 * Settlement's state budget stays pinned, because running out after approval burns notes.
 *
 * The execution check adds a conservative write/call margin to the maximum measured native
 * case. MMR operation counts are checked at every size; the finite VM measurements are not a
 * formal gas proof for arbitrary forks.
 */
import { resolve } from "node:path";

import { runCli } from "../src/cli/args.ts";
import { CheckError } from "../src/errors.ts";
import * as gas from "../src/gas.ts";
import { canonical, isObject, parse } from "../src/json.ts";
import { MAX_TREES, TREE_CAPACITY } from "../src/protocol.ts";
import { check, readText, ROOT } from "./check.ts";

export const PRE_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS = 294_401n;
const PRE_PR_12279_KEYED_NONCE_EXECUTION_GAS = 2n * 20_000n;
// Measured on a devnet running EIP-8250 at f3079a09e8 and EIP-8272 at 824cbc0b0e, the
// ten-input verifier's proof frame used up to 255,011; the drop from the pre-12279 figure is
// the keyed-nonce first use leaving the execution dimension for the state one. Hybrid
// compression cuts the verifier to three public inputs. With the owner's intent digest and the
// MMR's frontier in the statement, which the dispatcher also opens against the root, on native
// ethrex 247e2dd2 the proof frame uses 217,491, plus 90 with a fourth frame, 27 when nf1 > nf2
// (the dispatcher sorts the nonce keys) and up to 1,098 for a deep frontier, so at most 218,706.
export const POST_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS = 218_706n;
// The proof frame needs a larger limit than it uses. Each nested call keeps back 1/64 of the
// gas it could forward (EIP-150), once from the dispatcher to the verifier and once from the
// verifier to the pairing precompile. On native ethrex 247e2dd2 the heaviest spend (a fourth
// frame, nf1 > nf2 and a first payment's notes) needs a limit of 224,681; 224,680 fails. Below
// that the verifier runs out of gas and the dispatcher reports an invalid proof.
const MIN_WORKING_VERIFY_FRAME_GAS = 224_681n;
// The pool grammar permits exactly one 72-byte recent-root tuple, pinned by the dispatcher's
// `frameParam(0, 0x04) == 72`; that shape's verifier frame measured 5,579 gas, under the
// 8,000-gas wallet default. The figure says nothing about the sixteen tuples EIP-8272 allows:
// sixteen distinct roots are sixteen cold SLOADs, 33,600 gas before the rest of the verifier
// runs. (An earlier measurement repeated one tuple, so its identical storage keys paid one cold
// SLOAD and fifteen warm ones.)
export const MAX_OBSERVED_RECENT_ROOT_FRAME_GAS = 5_579n;
const CONSERVATIVE_VERIFY_STATE_BOUND =
  gas.SPEND_NONCE_KEY_COUNT * gas.KEYED_NONCE_FIRST_USE_STATE_GAS;

// A rollover writes the final root, the epoch and the MMR's packed ranks, depth and count, and
// each append a root, a chain, the packed ranks and the depth and count (treeShapes).
// New slots: each of two appends may start a tree at a depth no epoch has reached, a new root
// and chain, and a credit may be new; a rollover writes fewer.
const MAX_SSTORE_OPERATIONS = 13n;
const MAX_NEW_STORAGE_SLOTS = 5n;

// Pinned ethrex 247e2dd2, two outputs that each merge two trees and a new credit, carrying a
// first payment's 1,184 note bytes. See test/native/native-report.json.
const NATIVE_MAX_OBSERVED_SETTLEMENT_GAS = 217_126n;
// EIP-8038: cold access (2,100) + STORAGE_WRITE (10,000).
const EIP_8038_COLD_WRITE_GAS = 12_100n;

// The execution dimension no longer carries state growth. Two nested call levels (dispatcher
// -> logic -> Poseidon) each keep back 1/64, and the full write margin is charged again even
// though the measured path already contains writes: the ceiling of margin * (64/63)^2.
const WITH_WRITE_MARGIN =
  NATIVE_MAX_OBSERVED_SETTLEMENT_GAS + MAX_SSTORE_OPERATIONS * EIP_8038_COLD_WRITE_GAS;
export const CONSERVATIVE_SETTLEMENT_EXECUTION_BOUND =
  (WITH_WRITE_MARGIN * 64n * 64n + 63n * 63n - 1n) / (63n * 63n);
// EIP-8037 charges the same state gas for any new storage slot.
export const CONSERVATIVE_SETTLEMENT_STATE_BOUND =
  MAX_NEW_STORAGE_SLOTS * gas.KEYED_NONCE_FIRST_USE_STATE_GAS;

// What the frozen profile had to declare for the same work, as one number.
const FROZEN_VERIFY_FRAME_GAS = 320_000n;
const FROZEN_SETTLE_FRAME_GAS = 2_000_000n;

/**
 * The most hashes and storage writes one settlement's appends make at any MMR size: 2 and 9
 * without a rollover, 0 and 13 with one. An append merges the two smallest trees, with one hash,
 * when their ranks are equal (LibSkewMmr); a settlement also writes a credit.
 * The MMR never holds more than MAX_TREES trees below TREE_CAPACITY notes.
 */
function treeShapes() {
  const capacity = Number(TREE_CAPACITY);
  const shapes = { no_rollover: [0, 0], rollover: [0, 0] };
  /** Appends to an MMR's ranks, smallest last; returns the hashes it took. */
  const append = (ranks: number[]) => {
    const merges = ranks.length >= 2 && ranks.at(-1) === ranks.at(-2);
    if (!merges) {
      ranks.push(0);
      return 0;
    }
    ranks.pop();
    ranks.push(ranks.pop()! + 1);
    return 1;
  };
  const ranks: number[] = [];
  for (let start = 0; start <= capacity; start++) {
    check(ranks.length <= MAX_TREES, `the MMR holds ${ranks.length} trees at ${start} notes`);
    for (const count of [1, 2]) {
      const rolled = count > capacity - start;
      // Two appends read at most the three smallest trees.
      const after = rolled ? [] : ranks.slice(-3);
      let hashes = 0;
      for (let i = 0; i < count; i++) hashes += append(after);
      const shape = rolled ? shapes.rollover : shapes.no_rollover;
      shape[0] = Math.max(shape[0], hashes);
      shape[1] = Math.max(shape[1], (rolled ? 4 : 0) + 4 * count + 1);
    }
    if (start < capacity) append(ranks);
  }
  return shapes;
}

/** Checks the gas profile against the dispatcher and the deployment record; returns the report. */
export function checkGasProfile(root = ROOT): string {
  const shapes = treeShapes();
  // The settlement's write margin counts MAX_SSTORE_OPERATIONS writes, which must cover every
  // append.
  const writes = Math.max(shapes.no_rollover[1], shapes.rollover[1]);
  check(BigInt(writes) <= MAX_SSTORE_OPERATIONS, `an append can write ${writes} slots`);
  // The pre-PR 12279 figure charged keyed-nonce creation as execution gas and no longer
  // applies. The measured figures must fit the wallet defaults, or a spend that simulates
  // fine halts mid-frame on a chain with slightly different costs.
  if (POST_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS >= gas.VERIFY_FRAME_GAS) {
    throw new CheckError("the measured VERIFY execution exceeds VERIFY_FRAME_GAS");
  }
  if (MIN_WORKING_VERIFY_FRAME_GAS >= gas.VERIFY_FRAME_GAS) {
    throw new CheckError("the minimum working VERIFY limit exceeds VERIFY_FRAME_GAS");
  }
  if (MAX_OBSERVED_RECENT_ROOT_FRAME_GAS >= gas.RECENT_ROOT_FRAME_GAS) {
    throw new CheckError("the measured recent-root execution exceeds RECENT_ROOT_FRAME_GAS");
  }
  if (CONSERVATIVE_SETTLEMENT_EXECUTION_BOUND >= gas.SETTLE_FRAME_GAS) {
    throw new CheckError("the conservative settlement bound exceeds SETTLE_FRAME_GAS");
  }
  if (CONSERVATIVE_SETTLEMENT_STATE_BOUND >= gas.SETTLE_FRAME_STATE_GAS) {
    throw new CheckError("the conservative settlement state bound exceeds SETTLE_FRAME_STATE_GAS");
  }
  // The depth-20 tree's long carry at 262,143 and 524,287 leaves ran out of gas at 1.4M after
  // VERIFY and approval succeeded, which set the dispatcher's 2M pin. The MMR's settlements
  // need far less, and the pin stays: it is part of the immutable dispatcher profile. 2M is
  // not a proof of every settlement shape.
  check(gas.SETTLE_FRAME_GAS === FROZEN_SETTLE_FRAME_GAS, "SETTLE_FRAME_GAS is not 2,000,000");
  // The proof itself writes nothing. This exact budget exists only because its payment
  // APPROVE creates the two EIP-8250 keyed-nonce slots.
  if (gas.VERIFY_FRAME_STATE_GAS !== CONSERVATIVE_VERIFY_STATE_BOUND) {
    throw new CheckError("VERIFY_FRAME_STATE_GAS is not the two keyed-nonce slots");
  }
  // EIP-8272: the recent-root verifier frame joins the public mempool's verify budget and the
  // prefix's state budgets stay under EIP-8141's MAX_VERIFY_STATE_GAS. One tuple costs the
  // predeploy's cold entry plus two keccaks and a cold SLOAD, under the wallet default. Each of
  // the two secp256k1 signatures, the authorizer's and the owner's, costs 2,800.
  const frames = gas.RECENT_ROOT_FRAME_GAS + gas.VERIFY_FRAME_GAS;
  if (gas.SPEND_SIGNATURES !== 2n || gas.REQUIRED_VERIFY_BUDGET !== frames + 2n * 2_800n) {
    throw new CheckError("REQUIRED_VERIFY_BUDGET is not the two prefix frames plus two signatures");
  }
  if (gas.REQUIRED_VERIFY_BUDGET > gas.HEGOTA_TESTNET_MAX_VERIFY_GAS) {
    throw new CheckError("REQUIRED_VERIFY_BUDGET exceeds the testnet's verify budget");
  }
  if (gas.VERIFY_FRAME_STATE_GAS > gas.MAX_VERIFY_STATE_GAS) {
    throw new CheckError("VERIFY_FRAME_STATE_GAS exceeds MAX_VERIFY_STATE_GAS");
  }

  const declaredSplit =
    gas.VERIFY_FRAME_GAS +
    gas.VERIFY_FRAME_STATE_GAS +
    gas.SETTLE_FRAME_GAS +
    gas.SETTLE_FRAME_STATE_GAS;
  const declaredSingle = FROZEN_VERIFY_FRAME_GAS + FROZEN_SETTLE_FRAME_GAS;
  check(gas.EIP7825_TX_GAS_CAP === 16_777_216n, "EIP7825_TX_GAS_CAP is not 2^24");

  // The dispatcher must enforce the same settlement pins the wallet emits. Yul cannot import
  // the TypeScript module, so check its unavoidable literals here.
  const read = (path: string) => readText(resolve(root, path));
  const dispatcher = read("core/dispatcher/ShieldedPoolDispatcher.yul");
  // The validation frames' limits are wallet defaults, not dispatcher pins.
  for (const unpinned of ["frameParam(0, 0x01)", "frameParam(1, 0x01)", "frameParam(1, 0x09)"]) {
    check(!dispatcher.includes(unpinned), `dispatcher pins ${unpinned}`);
  }
  const shapeError = "{ fail(errShape()) }";
  const pins = [
    `if iszero(eq(frameParam(2, 0x01), ${gas.SETTLE_FRAME_GAS})) ${shapeError}`,
    `if iszero(eq(frameParam(2, 0x09), ${gas.SETTLE_FRAME_STATE_GAS})) ${shapeError}`,
  ];
  if (!pins.every((pin) => dispatcher.includes(pin))) {
    throw new CheckError("dispatcher gas limits differ from src/gas.ts");
  }
  const signatures = `if iszero(eq(txParam(0x0B), ${gas.SPEND_SIGNATURES})) ${shapeError}`;
  check(dispatcher.includes(signatures), "dispatcher signature count differs from src/gas.ts");
  // The settlement frame admits exactly settle(Spend) plus either note length, and the gas
  // bound above charges the larger.
  const [short, long] = gas.SETTLE_FRAME_DATA_BYTES;
  check(
    gas.SPEND_NOTES_BYTES.join() === "96,1184" &&
      gas.SETTLE_FRAME_DATA_BYTES.join() === "1220,2308",
    "the note and settlement lengths changed",
  );
  const lengths = `or(eq(settleLength, ${short}), eq(settleLength, ${long}))`;
  const lengthPin = `if iszero(${lengths}) ${shapeError}`;
  check(dispatcher.includes(lengthPin), "dispatcher settlement lengths differ from src/gas.ts");
  // The optional DEFAULT tail has no pool-specific gas or calldata ceiling.
  for (const param of ["0x01", "0x09", "0x04"]) {
    if (dispatcher.includes(`if gt(frameParam(3, ${param}),`)) {
      throw new CheckError(`dispatcher caps the tail frame's ${param}`);
    }
  }

  // The deployment record describes a deployment of this profile, or the previous one between
  // a profile change and its first deployment; the spend CLI refuses the latter.
  const record = parse(read("core/deploy_config.json"));
  const recorded = (key: string) => {
    check(isObject(record) && Object.hasOwn(record, key), `core/deploy_config.json has no ${key}`);
    return record[key];
  };
  const profile = recorded("profile");
  if (profile !== gas.PREVIOUS_POOL_PROFILE) {
    check(profile === gas.POOL_PROFILE, `core/deploy_config.json names profile ${profile}`);
    const limits = {
      recentRootGas: gas.RECENT_ROOT_FRAME_GAS,
      verifyGas: gas.VERIFY_FRAME_GAS,
      verifyStateGas: gas.VERIFY_FRAME_STATE_GAS,
      settleGas: gas.SETTLE_FRAME_GAS,
      settleStateGas: gas.SETTLE_FRAME_STATE_GAS,
      claimGas: gas.CLAIM_FRAME_GAS,
      claimStateGas: gas.CLAIM_FRAME_STATE_GAS,
    };
    for (const [key, value] of Object.entries(limits)) {
      // Compared as numbers: 8000 and 8000.0 agree, and a string never matches.
      const actual = recorded(key);
      const number = typeof actual === "number" || typeof actual === "bigint";
      check(number && actual == value, `core/deploy_config.json ${key} differs from src/gas.ts`);
    }
  }

  return canonical({
    verify: {
      execution_cap: gas.VERIFY_FRAME_GAS,
      state_cap: gas.VERIFY_FRAME_STATE_GAS,
      pre_pr_12279_observed_execution: PRE_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS,
      pre_pr_12279_keyed_nonce_execution_gas: PRE_PR_12279_KEYED_NONCE_EXECUTION_GAS,
      post_pr_12279_observed_execution: POST_PR_12279_MAX_OBSERVED_VERIFY_EXECUTION_GAS,
      min_working_execution_limit: MIN_WORKING_VERIFY_FRAME_GAS,
      keyed_nonce_state_bound: CONSERVATIVE_VERIFY_STATE_BOUND,
    },
    recent_root: {
      execution_cap: gas.RECENT_ROOT_FRAME_GAS,
      observed_execution_one_tuple: MAX_OBSERVED_RECENT_ROOT_FRAME_GAS,
    },
    settlement: {
      native_max_observed_execution: NATIVE_MAX_OBSERVED_SETTLEMENT_GAS,
      tree_hash_and_write_maxima: shapes,
      execution_cap: gas.SETTLE_FRAME_GAS,
      state_cap: gas.SETTLE_FRAME_STATE_GAS,
      conservative_execution_bound: CONSERVATIVE_SETTLEMENT_EXECUTION_BOUND,
      conservative_state_bound: CONSERVATIVE_SETTLEMENT_STATE_BOUND,
      execution_margin: gas.SETTLE_FRAME_GAS - CONSERVATIVE_SETTLEMENT_EXECUTION_BOUND,
      state_margin: gas.SETTLE_FRAME_STATE_GAS - CONSERVATIVE_SETTLEMENT_STATE_BOUND,
    },
    declared_total: {
      frozen_single_dimension: declaredSingle,
      spec_two_dimensions: declaredSplit,
      // The two state dimensions, less what the proof frame's lower wallet default saves.
      extra_over_frozen: declaredSplit - declaredSingle,
    },
  });
}

if (import.meta.main) {
  await runCli(() => {
    process.stdout.write(checkGasProfile() + "\n");
  });
}
