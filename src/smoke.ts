/**
 * The smoke fixture: a native-ETH join-split story with real Groth16 proofs, which the Forge
 * verifier test, the pool CLI and the note tests run against. All values are in wei.
 *
 *   1. Alice shields 1.0 ether into note A.
 *   2. Alice's transfer spends (A, dummy) into Bob's 0.6 and her 0.35 change, with a 0.05 fee
 *      kept by the self-paying pool. Its two nullifiers are consumed as one EIP-8250 key set.
 *   3. Bob's withdrawal spends (B, dummy) into the two zero sinks: 0.55 to the recipient and
 *      0.05 to the sender. Alice's change gets a withdrawal of its own (withdraw_seed) against
 *      the same root, which can leave a credit on the recipient without invalidating Bob's.
 *
 * Each wallet's notes belong to an owner set held by a software owner, which stands in for its
 * device and signs each of its spends with a fresh leaf. Alice's notes are sealed under her own
 * secret and Bob's payment through his public address; random notes fill the withdrawals' unused
 * places, and the fixture records each wallet's seed and its owner's seed. Every proof is
 * verified before it lands here, and nine witnesses that each break one circuit rule must fail
 * to compute.
 */
import assert from "node:assert/strict";

import { hex32, hexFromText, hexPadded, keccak, parseAddress, toHex } from "./bytes.ts";
import { GeneratorError, InputError } from "./errors.ts";
import * as fixtures from "./fixtures.ts";
import * as notes from "./notes.ts";
import { SoftwareOwner } from "./owner.ts";
import {
  commitment,
  domainScalar,
  inner,
  outputCommitments,
  OWNER_DEPTH,
  P,
  sinkOutputs,
} from "./protocol.ts";
import { secureRng, seededRng } from "./random.ts";
import { Tree, buildWitness, dummyInput, newAuthorizer } from "./wallet.ts";

/** The test placeholder recipient, refused off the test chain and pool. */
const PLACEHOLDER_RECIPIENT = "0x00000000000000000000000000000000cafebabe";
const SEED = 20260702n;
const EPOCH = 0n;
const SHIELD = 10n ** 18n;
const PAYMENT = (SHIELD * 60n) / 100n;
const FEE = (SHIELD * 5n) / 100n;
const CHANGE = SHIELD - PAYMENT - FEE;

interface SmokeOptions {
  /** Fresh seeds and secrets, required off the test chain and pool. */
  random: boolean;
  chainId: bigint;
  /** "0x" and 40 hex digits, recorded in the fixture as given. */
  poolAddress: string;
  /** The withdrawals' recipient; "0x" is optional. */
  recipient?: string;
  /** As given on the command line; by default defaultOutput(chainId, pool). */
  output?: string;
}

/**
 * Refuses anything that would put live notes at risk, then proves the story and writes the
 * fixture owner-only. The refusals come before any proving: the public fixed seed off the test
 * chain and pool, the placeholder recipient there, a recipient that would strand its credit,
 * and an output that may hold another chain's secrets.
 */
export async function generateSmoke(options: SmokeOptions, deps: fixtures.GeneratorDeps) {
  const { chainId, poolAddress } = options;
  const { prover, log } = deps;
  const rng = options.random ? secureRng : seededRng(SEED);
  let recipient = PLACEHOLDER_RECIPIENT;
  if (options.recipient !== undefined) {
    const text = options.recipient.startsWith("0x") ? options.recipient : "0x" + options.recipient;
    const value = hexFromText(text) ?? 0n;
    if (value === 0n || value >= 1n << 160n) {
      throw new GeneratorError(`invalid --recipient: ${text}`);
    }
    recipient = hexPadded(value, 40);
  }
  // Any 0x hex reads as the pool here, so the refusals below, which protect live notes, come
  // before parseAddress refuses a pool of the wrong length. Other text stops here.
  const pool = hexFromText(poolAddress);
  if (pool === null) throw new InputError("--pool-address must be 0x and 40 hex digits");
  // Anyone could rebuild notes made from the public seed and spend them, so it and the
  // placeholder recipient are kept for the committed fixture's chain and pool.
  if (chainId !== fixtures.TEST_CHAIN_ID || pool !== BigInt(fixtures.TEST_POOL)) {
    if (!options.random) {
      throw new GeneratorError(
        "the fixed seed is public, so anyone could spend these notes; pass --random for " +
          "another chain or pool",
      );
    }
    if (recipient === PLACEHOLDER_RECIPIENT) {
      throw new GeneratorError(
        `pass --recipient for another chain or pool; the default ${PLACEHOLDER_RECIPIENT} is a ` +
          "test placeholder",
      );
    }
  }
  fixtures.refuseRecipient(BigInt(recipient), pool);
  const output = fixtures.outputPath(options.output, fixtures.defaultOutput(chainId, pool));
  const previous = fixtures.refuseOverwrite(output);
  const domain = domainScalar(chainId, parseAddress(poolAddress, "--pool-address"), EPOCH);

  const label = (name: string) =>
    keccak(new TextEncoder().encode(`minimal-shielded-pool:smoke:${name}:v1`));
  const names = ["alice", "bob", "alice-owner", "bob-owner"];
  const seeds = names.map((name) => (options.random ? rng.bytes(32) : label(name)));
  const [aliceSeed, bobSeed, aliceOwnerSeed, bobOwnerSeed] = seeds;
  const aliceOwner = new SoftwareOwner(aliceOwnerSeed, fixtures.OWNER_LEAVES);
  const bobOwner = new SoftwareOwner(bobOwnerSeed, fixtures.OWNER_LEAVES);
  const alice = new notes.WalletKeys(aliceSeed, aliceOwner.set.root);
  const bob = new notes.WalletKeys(bobSeed, bobOwner.set.root);
  const aliceSelf = notes.directChannel(alice.ownerPk, alice.selfSecret);

  // Alice's deposit, Bob's payment and Alice's change.
  const a = notes.reserve(aliceSelf, SHIELD);
  const b = notes.reserve(notes.openChannel(bob.address()), PAYMENT);
  const a2 = notes.reserve(aliceSelf, CHANGE);
  const cmA = commitment(alice.ownerPk, a.rho, SHIELD);

  // Each spend's terms, with a fresh one-time authorizer and the spender's next owner leaf. The
  // draws happen in a fixed order, so the fixed seed gives the same keys, notes and statements
  // on every run.
  const terms = (device: SoftwareOwner, publicAmount: bigint, recipient: bigint) => {
    const [authorizerKey, authorizer] = newAuthorizer(rng);
    const signing = { owner: device.nextLeaf(), device, chainId, pool, authorizerKey };
    return { epoch: EPOCH, fee: FEE, publicAmount, recipient, authorizer, ...signing };
  };

  // 1 and 2. Alice's transfer: (A, dummy) -> (Bob 0.6, change 0.35), fee 0.05.
  const t1 = new Tree();
  t1.append(cmA);
  const insT = [{ nk: alice.nk, rho: a.rho, value: SHIELD, idx: 0n }, dummyInput(rng)];
  const outsT = [
    [inner(bob.ownerPk, b.rho), PAYMENT] as const,
    [inner(alice.ownerPk, a2.rho), CHANGE] as const,
  ];
  const termsT = terms(aliceOwner, 0n, 0n);
  const wt = buildWitness(t1, insT, outsT, domain, termsT);
  const provedT = await prover.prove(wt, "transfer");

  // 3. Bob's withdrawal: (B, dummy) -> the sinks, 0.55 to the recipient, fee 0.05.
  const t2 = new Tree();
  for (const cm of [cmA, ...outputCommitments(outsT)]) t2.append(cm);
  assert(t2.leaves[1] === commitment(bob.ownerPk, b.rho, PAYMENT), "Bob's note is leaf 1");
  const insW = [{ nk: bob.nk, rho: b.rho, value: PAYMENT, idx: 1n }, dummyInput(rng)];
  const termsW = terms(bobOwner, PAYMENT - FEE, BigInt(recipient));
  const ww = buildWitness(t2, insW, sinkOutputs(), domain, termsW);
  const provedW = await prover.prove(ww, "withdraw");

  // Alice's change at leaf 2, against the same root.
  assert(t2.leaves[2] === commitment(alice.ownerPk, a2.rho, CHANGE), "Alice's change is leaf 2");
  const insS = [{ nk: alice.nk, rho: a2.rho, value: CHANGE, idx: 2n }, dummyInput(rng)];
  const termsS = terms(aliceOwner, CHANGE - FEE, BigInt(recipient));
  const ws = buildWitness(t2, insS, sinkOutputs(), domain, termsS);
  const provedS = await prover.prove(ws, "withdraw_seed");

  // The circuit itself refuses each of these witnesses. The old circuit accepted one note in
  // both inputs and relied on the envelope's duplicate-key rule, and counted a positive
  // duplicate output twice in conservation but inserted it once. The last two give Bob's
  // withdrawal an owner outside Bob's owner set: an address of Alice's, and the empty leaf after
  // his addresses, whose value 0 no signature can come from.
  const randomInner = () => inner(rng.below(P), rng.below(P));
  const fresh = () => [randomInner(), SHIELD] as const;
  const same = buildWitness(t1, [{ ...insT[0] }, { ...insT[0] }], [fresh(), fresh()], domain, {
    authorizer: newAuthorizer(rng)[1],
    owner: termsT.owner,
  });
  await prover.assertUnprovable(same, "same_note");
  const half = String((SHIELD - FEE) / 2n);
  const twice = String(randomInner());
  const duplicate = { ...wt, out_inner: [twice, twice], out_value: [half, half] };
  duplicate.authorizer = String(newAuthorizer(rng)[1]);
  await prover.assertUnprovable(duplicate, "duplicate_positive_output");
  const noRealInputs = { in_value: ["0", "0"], out_inner: ["1", "2"], out_value: ["0", "0"] };
  const zeroReal = { ...wt, ...noRealInputs, public_amount: "0", fee: "0" };
  await prover.assertUnprovable(zeroReal, "zero_real_inputs");
  await prover.assertUnprovable({ ...ww, out_inner: ["2", "1"] }, "wrong_sink_positions");
  await prover.assertUnprovable({ ...wt, authorizer: "0" }, "zero_authorizer");
  const positiveSink = { ...wt, out_inner: ["1", wt.out_inner[1]] };
  await prover.assertUnprovable(positiveSink, "positive_output_uses_sink");
  await prover.assertUnprovable({ ...ww, recipient: "0" }, "withdrawal_without_recipient");
  const outside = aliceOwner.set.leaf(fixtures.OWNER_LEAVES - 1).address;
  await prover.assertUnprovable({ ...ww, owner: String(outside) }, "owner_outside_the_set");
  const bobSet = new Tree(OWNER_DEPTH);
  for (const address of bobOwner.set.addresses) bobSet.append(address);
  const emptyPath = bobSet.authPath(BigInt(fixtures.OWNER_LEAVES));
  const emptyLeaf = {
    owner: "0",
    owner_siblings: emptyPath.siblings.map(String),
    owner_bits: emptyPath.bits.map(String),
  };
  await prover.assertUnprovable({ ...ww, ...emptyLeaf }, "empty_owner_leaf");

  const randomNote = () => notes.dummyNote(secureRng);
  const randomNotes = () => toHex(notes.spendNotes(randomNote(), randomNote()));
  const wallet = (keys: notes.WalletKeys, seed: Uint8Array, owner: Uint8Array) => ({
    seed: toHex(seed),
    owner_seed: toHex(owner),
    owner_leaves: fixtures.OWNER_LEAVES,
    owner_root: hex32(keys.ownerRoot),
    address: keys.address().hex(),
  });
  const fixture = {
    chain_id: chainId,
    pool_address: poolAddress,
    epoch: EPOCH,
    domain: hex32(domain),
    inner_a: hex32(inner(alice.ownerPk, a.rho)),
    cm_a: hex32(cmA),
    shield_value: String(SHIELD),
    shield_note: toHex(notes.shieldNotes(a.note)),
    recipient,
    wallets: {
      alice: wallet(alice, aliceSeed, aliceOwnerSeed),
      bob: wallet(bob, bobSeed, bobOwnerSeed),
    },
    transfer: fixtures.spendEntry(t1, domain, insT, outsT, termsT, provedT, {
      notes: toHex(notes.spendNotes(b.note, a2.note, b.ciphertext)),
      // Bob's opening, for the withdrawal.
      out_inner1: hex32(outsT[0][0]),
      out_value1: String(outsT[0][1]),
    }),
    withdraw_seed: fixtures.spendEntry(t2, domain, insS, sinkOutputs(), termsS, provedS, {
      notes: randomNotes(),
    }),
    withdraw: fixtures.spendEntry(t2, domain, insW, sinkOutputs(), termsW, provedW, {
      notes: randomNotes(),
    }),
  };
  fixtures.writeFixture(output, fixture, previous);
  const { nf1, nf2 } = fixture.transfer;
  log(
    "real join-split proofs generated and verified off-chain; compressed public signals bind " +
      "the wallet statement",
  );
  log(`wrote ${output}`);
  log(`  transfer  nf1 ${nf1.slice(0, 18)}... nf2 ${nf2.slice(0, 18)}... fee ${FEE}`);
  log(`  withdraw_seed publicAmount ${termsS.publicAmount} fee ${FEE}`);
  log(`  withdraw  publicAmount ${termsW.publicAmount} fee ${FEE}`);
  log(`  domain   ${fixture.domain} (chain ${chainId}, pool ${poolAddress})`);
  log("  same-note witness rejected in-circuit (nf1 != nf2)");
  return { output, fixture };
}
