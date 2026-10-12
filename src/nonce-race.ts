/**
 * The shared-sender nonce-race fixture. Notes A and C are shielded into one tree, so after both
 * inserts the pool publishes a single root R, and two independent transfers prove membership
 * against that same R:
 *
 *   transfer:   spend A -> (Bob 0.6, change 0.35), fee 0.05
 *   transfer_c: spend C -> (Dave 0.6, change 0.35), fee 0.05
 *
 * The transfers consume disjoint nullifiers, so under EIP-8250 keyed nonces they share the
 * pool's sender address without any ordering between them: both are admissible in the same
 * block, in either order. That is the property under test.
 *
 * Alice pays Bob through his public address and Carol pays Dave with a secret Dave handed her
 * out of band. Each wallet's owner set is held by a software owner, whose seed the fixture
 * records. Against a live pool (--rpc), the tree is first rebuilt from the pool's leaves, so the
 * fixture's root is the one the pool will hold after both shields land.
 */
import assert from "node:assert/strict";
import { join } from "node:path";

import { hex32, hexPadded, keccak, parseAddress, parseHex, toHex } from "./bytes.ts";
import { GeneratorError } from "./errors.ts";
import * as fixtures from "./fixtures.ts";
import * as notes from "./notes.ts";
import { SoftwareOwner } from "./owner.ts";
import * as protocol from "./protocol.ts";
import { secureRng, seededRng } from "./random.ts";
import { rpc } from "./rpc.ts";
import { Tree, buildWitness, dummyInput, newAuthorizer } from "./wallet.ts";

/** Always under the ignored artifacts/, even on the test chain. */
export const NONCE_RACE_OUTPUT = join(fixtures.ARTIFACTS, "nonce_race_fixture.json");
const SEED = 20260712n;
const NAMES = ["alice", "bob", "carol", "dave"] as const;

type Reserved = ReturnType<typeof notes.reserve>;

interface NonceRaceOptions {
  /** Fresh seeds and secrets, required off the test chain or with rpc. */
  random: boolean;
  chainId: bigint;
  /** "0x" and 40 hex digits, recorded in the fixture as given. */
  poolAddress?: string;
  epoch: bigint;
  noteWei: bigint;
  /** A node whose pool at poolAddress seeds the tree. */
  rpc?: string;
  /** As given on the command line; by default NONCE_RACE_OUTPUT. */
  output?: string;
}

/** One JSON-RPC call, as seededTree makes it; tests pass a fake. */
export type Call = (method: string, params: unknown[]) => Promise<unknown>;

/**
 * The pool's current tree, rebuilt from its LeafAppended logs in index order, refused unless its
 * root equals the pool's currentRoot(). Without it the fixture's proofs would bind an empty
 * tree's root, which no live pool with earlier leaves holds.
 */
export async function seededTree(call: Call, pool: string, expectedEpoch: bigint): Promise<Tree> {
  const read = (signature: string) =>
    call("eth_call", [{ to: pool, data: toHex(protocol.selector(signature)) }, "latest"]);
  const logs = await call("eth_getLogs", [
    { address: pool, topics: [protocol.LEAF_APPENDED], fromBlock: "0x0", toBlock: "latest" },
  ]);
  const epoch = parseHex(await read("currentEpoch()"), "currentEpoch()");
  if (epoch !== expectedEpoch) {
    throw new GeneratorError(
      `--epoch=${expectedEpoch} does not match the live tree epoch ${epoch}`,
    );
  }
  // The node filtered the logs by the pool's address. A later log for an index replaces an
  // earlier one, and an older epoch's leaves are not this tree's.
  if (!Array.isArray(logs)) throw new GeneratorError("eth_getLogs did not return a list of logs");
  const leaves = new Map<bigint, bigint>();
  for (const log of logs) {
    const leaf = protocol.parseLeafAppended(log);
    if (leaf !== null && leaf.epoch === epoch) leaves.set(leaf.index, leaf.cm);
  }
  const tree = new Tree();
  for (let i = 0n; i < BigInt(leaves.size); i++) {
    const cm = leaves.get(i);
    if (cm === undefined) throw new GeneratorError(`the pool's LeafAppended logs skip leaf ${i}`);
    tree.append(cm);
  }
  const rebuilt = hex32(tree.root());
  const onchain = hexPadded(parseHex(await read("currentRoot()"), "currentRoot()"), 64);
  if (rebuilt !== onchain) {
    throw new GeneratorError(
      `tree reconstruction mismatch: rebuilt ${rebuilt} != on-chain ${onchain}; the pool's ` +
        "leaf set changed or DEPTH/hash params differ",
    );
  }
  return tree;
}

/**
 * Refuses the public fixed seed off the test chain or against a live tree, and an output that
 * may hold another chain's secrets, then proves both transfers and writes the fixture
 * owner-only.
 */
export async function generateNonceRace(options: NonceRaceOptions, deps: fixtures.GeneratorDeps) {
  const { chainId, poolAddress, epoch, noteWei: v } = options;
  const { prover, log } = deps;
  const output = fixtures.outputPath(options.output, NONCE_RACE_OUTPUT);
  if (poolAddress === undefined) throw new GeneratorError("--pool-address=0x... is required");
  // Anyone could rebuild notes made from the public seed and spend them.
  if (!options.random && (chainId !== fixtures.TEST_CHAIN_ID || options.rpc !== undefined)) {
    throw new GeneratorError(
      "the fixed seed is public, so anyone could spend these notes; pass --random for " +
        "another chain or a live tree",
    );
  }
  const rng = options.random ? secureRng : seededRng(SEED);
  const previous = fixtures.refuseOverwrite(output);
  const url = options.rpc;
  const call: Call = (method, params) => rpc(url!, method, params, { timeoutMs: 30_000 });
  if (url !== undefined && parseHex(await call("eth_chainId", []), "eth_chainId") !== chainId) {
    throw new GeneratorError("--chain-id does not match the chain --rpc reads");
  }
  const pool = parseAddress(poolAddress, "--pool-address");
  const domain = protocol.domainScalar(chainId, pool, epoch);

  const label = (name: string) =>
    keccak(new TextEncoder().encode(`minimal-shielded-pool:nonce-race:${name}:v1`));
  const seed = (name: string) => (options.random ? rng.bytes(32) : label(name));
  const seeds = NAMES.map(seed);
  const ownerSeeds = NAMES.map((name) => seed(`${name}-owner`));
  const owners = ownerSeeds.map((s) => new SoftwareOwner(s, fixtures.OWNER_LEAVES));
  const keys = seeds.map((s, i) => new notes.WalletKeys(s, owners[i].set.root));
  const [alice, bob, carol, dave] = keys;
  const aliceSelf = notes.directChannel(alice.ownerPk, alice.selfSecret);
  const carolSelf = notes.directChannel(carol.ownerPk, carol.selfSecret);

  // Two deposits into one tree, whose root R is fixed once both are in.
  const a = notes.reserve(aliceSelf, v);
  const c = notes.reserve(carolSelf, v);
  const cmA = protocol.commitment(alice.ownerPk, a.rho, v);
  const cmC = protocol.commitment(carol.ownerPk, c.rho, v);
  let tree = new Tree();
  if (url !== undefined) {
    tree = await seededTree(call, poolAddress, epoch);
    const root = hex32(tree.root()).slice(0, 18);
    log(`  seeded tree from ${tree.leaves.length} on-chain leaves, root ${root}... verified`);
  }
  // The root before each note lands, which the pool CLI checks before shielding it.
  const priorA = tree.root();
  const idxA = tree.append(cmA);
  const priorC = tree.root();
  const idxC = tree.append(cmC);
  const rootR = tree.root();

  const vBob = (v * 60n) / 100n;
  const vFee = (v * 5n) / 100n;
  const vChange = v - vBob - vFee;
  // The sender's deposit and a dummy, into the payee's note and the sender's change.
  const transfer = async (
    sender: notes.WalletKeys,
    device: SoftwareOwner,
    deposit: Reserved,
    index: bigint,
    payee: notes.WalletKeys,
    paid: Reserved,
    change: Reserved,
    tag: string,
  ) => {
    const inputs = [{ nk: sender.nk, rho: deposit.rho, value: v, idx: index }, dummyInput(rng)];
    const outputs = [
      [protocol.inner(payee.ownerPk, paid.rho), vBob] as const,
      [protocol.inner(sender.ownerPk, change.rho), vChange] as const,
    ];
    const [key, authorizer] = newAuthorizer(rng);
    const signing = { owner: device.nextLeaf(), device, chainId, pool };
    const terms = { epoch, authorizer, authorizerKey: key, fee: vFee, ...signing };
    const proved = await prover.prove(buildWitness(tree, inputs, outputs, domain, terms), tag);
    // No later spend records these outputs, so their openings go with the transfer.
    const opening = (owner: notes.WalletKeys, rho: bigint, value: bigint) => ({
      owner_root: hex32(owner.ownerRoot),
      nk: hex32(owner.nk),
      rho: hex32(rho),
      value: String(value),
    });
    const openings = [opening(payee, paid.rho, vBob), opening(sender, change.rho, vChange)];
    return fixtures.spendEntry(tree, domain, inputs, outputs, terms, proved, {
      output_openings: openings,
      notes: toHex(notes.spendNotes(paid.note, change.note, paid.ciphertext)),
    });
  };

  // Transfer A pays Bob's public address; transfer C, against the same root, pays Dave with
  // the secret he handed Carol.
  const toBob = notes.reserve(notes.openChannel(bob.address()), vBob);
  const changeA = notes.reserve(aliceSelf, vChange);
  const ea = await transfer(alice, owners[0], a, idxA, bob, toBob, changeA, "race_a");
  const toDave = notes.reserve(notes.directChannel(dave.ownerPk, dave.directSecret(0n)), vBob);
  const changeC = notes.reserve(carolSelf, vChange);
  const ec = await transfer(carol, owners[2], c, idxC, dave, toDave, changeC, "race_c");
  const disjoint = ![ea.nf1, ea.nf2].some((nf) => nf === ec.nf1 || nf === ec.nf2);
  assert(disjoint, "transfers must consume disjoint nullifiers");
  assert(ea.root === hex32(rootR) && ec.root === ea.root, "both transfers bind the same root");

  const shield = (cm: bigint, pk: bigint, note: Reserved, leaf: bigint, prior: bigint) => ({
    inner: hex32(protocol.inner(pk, note.rho)),
    cm: hex32(cm),
    value: String(v),
    leaf,
    prior_root: hex32(prior),
    note: toHex(notes.shieldNotes(note.note)),
  });
  const fixture = {
    chain_id: chainId,
    pool_address: poolAddress,
    epoch,
    domain: hex32(domain),
    root: hex32(rootR),
    shields: [
      shield(cmA, alice.ownerPk, a, idxA, priorA),
      shield(cmC, carol.ownerPk, c, idxC, priorC),
    ],
    wallets: Object.fromEntries(
      NAMES.map((name, i) => [
        name,
        {
          seed: toHex(seeds[i]),
          owner_seed: toHex(ownerSeeds[i]),
          owner_leaves: fixtures.OWNER_LEAVES,
          owner_root: hex32(keys[i].ownerRoot),
          address: keys[i].address().hex(),
        },
      ]),
    ),
    // The pool CLI reads a spend entry by its key; both are transfers.
    transfer: ea,
    transfer_c: ec,
  };
  fixtures.writeFixture(output, fixture, previous);
  log("two independent transfers proven against one root, disjoint nullifiers");
  log(`  root R      ${fixture.root.slice(0, 18)}...`);
  log(`  transfer A  nf ${ea.nf1.slice(0, 14)}.. ${ea.nf2.slice(0, 14)}..`);
  log(`  transfer C  nf ${ec.nf1.slice(0, 14)}.. ${ec.nf2.slice(0, 14)}..`);
  log("  disjoint: true   same root: true");
  log(`wrote ${output}`);
  return { output, fixture };
}
