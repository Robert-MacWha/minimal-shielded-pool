/**
 * The pool client's checks against the node, made before anything is signed: that the pool is
 * this profile's dispatcher, linked to the configured logic and a verifier for this proving
 * key; that a shield fixture's proofs can spend the note it funds; and that a spend's recent
 * root is inside the EIP-8272 window and held by the recent-root contract. Also where a shield's
 * note landed, read from its receipt.
 */
import { readFileSync } from "node:fs";

import {
  concat,
  hexPadded,
  parseAddress,
  parseDec,
  parseHex,
  toBigint,
  toHex,
  word,
} from "./bytes.ts";
import { PoolError } from "./errors.ts";
import * as gas from "./gas.ts";
import { isObject, parse, type JsonObject } from "./json.ts";
import * as protocol from "./protocol.ts";
import { RpcError, type PoolNode } from "./rpc.ts";
import { parseSpend, parseSpendProof, type RecentRoot } from "./spend.ts";

const INITCODE = new URL("../core/artifacts/shielded_pool_dispatcher_init.hex", import.meta.url);
// A proof from the committed proving key, used to check the verifier a pool is linked to.
const REFERENCE_FIXTURE = new URL("../test/fixtures/smoke_fixture.json", import.meta.url);

const get = (value: unknown, key: string): unknown => (isObject(value) ? value[key] : undefined);

// ---- the deployed pool ----

/**
 * Calldata for the reference transfer proof with its compressed signals [beta, gamma, alpha],
 * and the same call with gamma changed. A verifier for this circuit accepts only the first.
 */
export function referenceVerifierCalls(): [good: string, changed: string] {
  const transfer = get(parse(readFileSync(REFERENCE_FIXTURE, "utf8")), "transfer");
  const owner = parseAddress(get(transfer, "owner"), "the reference transfer's owner");
  const stmt = protocol.statement({ ...parseSpend(transfer, 0n), owner });
  const alpha = protocol.compressionAlpha(stmt);
  const { proof, beta } = parseSpendProof(transfer);
  const gamma = protocol.fingerprint((alpha + beta) % protocol.P, stmt);
  const call = (g: bigint) => toHex(protocol.verifyProofCall(proof, [beta, g, alpha]));
  return [call(gamma), call((gamma + 1n) % protocol.P)];
}

/** An eth_call's one-word answer, or null for a JSON-RPC error or an answer of another length. */
async function callWord(node: PoolNode, to: string, data: string): Promise<bigint | null> {
  const result = await node.call("eth_call", [{ to, data }, "latest"]).catch((error) => {
    if (error instanceof RpcError) return null;
    throw error;
  });
  const isWord = typeof result === "string" && result.length === 66;
  return isWord ? parseHex(result, "eth_call's result") : null;
}

/**
 * Refuses a pool that is not this profile's dispatcher, linked to the configured logic and
 * verifier on the configured chain, so no deposit lands where VERIFY rejects every spend. This
 * catches a stale config, not a malicious deployer; only a JSON-RPC error reply is a verdict.
 */
export async function checkDeployedProfile(
  node: PoolNode,
  pool: bigint,
  configuredChain: bigint,
  logic: bigint,
  verifier: bigint,
): Promise<void> {
  const profile = gas.POOL_PROFILE;
  const chainId = parseHex(await node.call("eth_chainId", []), "eth_chainId's result");
  if (chainId !== configuredChain) {
    throw new PoolError(
      `RPC is on chain ${chainId}, but the config names chain ${configuredChain}`,
    );
  }
  // The previous profile shares this one's domain formula, so the code itself is compared.
  const links = toHex(concat(word(logic), word(verifier))).slice(2);
  const initcode = readFileSync(INITCODE, "utf8").trim() + links;
  const expected = await node.call("eth_call", [{ data: initcode }, "latest"]).catch((error) => {
    if (!(error instanceof RpcError)) throw error;
    throw new PoolError(
      `could not simulate the ${profile} dispatcher deployment: ${error.message}`,
    );
  });
  const [address, verifierAddress] = [hexPadded(pool, 40), hexPadded(verifier, 40)];
  const code = await node.call("eth_getCode", [address, "latest"]);
  const deployed = typeof expected === "string" && expected.length > 2 && typeof code === "string";
  if (!deployed || code.toLowerCase() !== expected.toLowerCase()) {
    throw new PoolError(
      `pool ${address} is not the ${profile} dispatcher linked to the configured logic ` +
        `${hexPadded(logic, 40)} and verifier ${verifierAddress}`,
    );
  }
  // The dispatcher's code does not cover the verifier it calls.
  const [good, changed] = referenceVerifierCalls();
  for (const [data, verdict] of [[good, 1n] as const, [changed, 0n] as const]) {
    if ((await callWord(node, verifierAddress, data)) !== verdict) {
      throw new PoolError(`verifier ${verifierAddress} does not verify ${profile} proofs`);
    }
  }
  const domain = await callWord(node, address, toHex(protocol.encodeDomainCall(0n)));
  if (domain === null) {
    throw new PoolError(
      `pool ${address} does not expose domain(uint64); it is not a ${profile} deployment`,
    );
  }
  if (domain !== protocol.domainScalar(chainId, pool)) {
    throw new PoolError(`pool ${address} domain(0) does not match ${profile} on chain ${chainId}`);
  }
}

// ---- shields ----

/**
 * Refuses to fund a note this fixture's proofs cannot spend: their domain names a chain, pool
 * and epoch, and their paths assume the note lands at `leaf` of the tree with root `priorRoot`.
 * Another deposit can still take the leaf first, so callers also check shieldLeaf.
 */
export async function checkShieldFixture(
  node: PoolNode,
  pool: bigint,
  chainId: bigint,
  fixture: unknown,
  leaf: bigint,
  priorRoot: bigint,
): Promise<void> {
  const field = (key: string) => get(fixture, key);
  const recorded = ["chain_id", "pool_address", "epoch", "domain"];
  const missing = recorded.filter((key) => field(key) === undefined);
  if (missing.length > 0) {
    throw new PoolError(`shield requires the fixture to record ${missing.join(", ")}`);
  }
  const epoch = parseDec(field("epoch"), "the fixture's epoch");
  if (
    parseDec(field("chain_id"), "the fixture's chain_id") !== chainId ||
    parseAddress(field("pool_address"), "the fixture's pool_address") !== pool
  ) {
    throw new PoolError(
      `fixture was made for pool ${field("pool_address")} on chain ${field("chain_id")}, ` +
        `not ${hexPadded(pool, 40)} on chain ${chainId}`,
    );
  }
  const domain = parseHex(field("domain"), "the fixture's domain");
  if (domain !== protocol.domainScalar(chainId, pool, epoch)) {
    throw new PoolError("fixture domain does not match its chain, pool and epoch");
  }
  const state: bigint[] = [];
  for (const signature of ["currentEpoch()", "nextIndex()", "currentRoot()"]) {
    const call = { to: hexPadded(pool, 40), data: toHex(protocol.selector(signature)) };
    const answer = await node.call("eth_call", [call, "latest"]).catch((error) => {
      if (!(error instanceof RpcError)) throw error;
      throw new PoolError(`could not read the pool's next leaf: ${error.message}`);
    });
    state.push(parseHex(answer, `the pool's ${signature}`));
  }
  // A full tree rolls to a new, empty epoch before this deposit.
  const full = state[1] === protocol.TREE_CAPACITY;
  const [nowEpoch, nowIndex, nowRoot] = full ? [state[0] + 1n, 0n, protocol.EMPTY_ROOT] : state;
  if (nowEpoch !== epoch || nowIndex !== leaf) {
    throw new PoolError(
      `fixture expects the note at epoch ${epoch} leaf ${leaf}, but the pool's next leaf is ` +
        `epoch ${nowEpoch} leaf ${nowIndex}`,
    );
  }
  if (nowRoot !== priorRoot) {
    throw new PoolError(
      "the pool's tree is not the one this fixture's proofs assume: another deposit took an earlier leaf",
    );
  }
}

/**
 * (epoch, index) from the pool's LeafAppended log in a shield receipt, or null. Addresses are
 * checked before parsing, so another contract's malformed log is ignored; the node writes the
 * address, so one that is not an address is refused on any log.
 */
export function shieldLeaf(receipt: unknown, pool: bigint): [epoch: bigint, index: bigint] | null {
  const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
  const frames = list(get(receipt, "frameReceipts")).map((f) => get(f, "logs"));
  for (const log of [get(receipt, "logs"), ...frames].flatMap(list)) {
    const address = get(log, "address");
    if (address === undefined) continue;
    if (parseAddress(address, "a receipt log's address") !== pool) continue;
    const leaf = protocol.parseLeafAppended(log as JsonObject);
    if (leaf !== null) return [leaf.epoch, leaf.index];
  }
  return null;
}

// ---- recent roots ----

/**
 * Why the node would refuse a root published in `slot`, or null. EIP-8272 judges a
 * transaction against the earliest block that could carry it, so the current slot is the
 * head's plus one; comparing against the head would sign a transaction one slot too late.
 */
export function recentRootWindowError(slot: bigint, latestSlot: bigint, epoch = 0n): string | null {
  const current = latestSlot + 1n;
  if (slot >= current) {
    return (
      `  recent-root ref is not yet referenceable: publication slot ${slot} is not earlier than ` +
      `current slot ${current}. A root written in slot S is only usable from S+1 on; wait one ` +
      "slot and re-sign."
    );
  }
  if (current - slot >= protocol.RECENT_ROOT_LENGTH) {
    return (
      `  recent-root ref expired: publication slot ${slot} is outside the ` +
      `${protocol.RECENT_ROOT_LENGTH}-slot window at current slot ${current}. If the tree has ` +
      `not changed since the proof's root, call publishEpochRoot(${epoch}), read that block's ` +
      "slotNumber, and re-sign with --root-slot set to that consensus slot."
    );
  }
  return null;
}

/**
 * Frame 0's tuple, source_id || uint64 slot || root, once the slot (EIP-7843's slotNumber, never
 * derived from timestamps) is in the window and the recent-root contract holds this root there.
 */
export async function recentRootReference(
  node: PoolNode,
  pool: bigint,
  recent: RecentRoot,
): Promise<Uint8Array> {
  const { root, rootSlot: slot, epoch } = recent;
  const source = protocol.sourceId(pool, epoch);
  const latest = get(await node.call("eth_getBlockByNumber", ["latest", false]), "slotNumber");
  if (latest === undefined) {
    throw new PoolError("latest block has no EIP-7843 slotNumber; refusing timestamp derivation");
  }
  const what = "the latest block's slotNumber";
  const problem = recentRootWindowError(slot, parseHex(latest, what), epoch);
  if (problem) throw new PoolError(problem);
  const at = toHex(protocol.recentRootStorageKey(source, slot));
  const contract = hexPadded(protocol.RECENT_ROOT_ADDRESS, 40);
  const stored = await node.call("eth_getStorageAt", [contract, at, "latest"]);
  const entryHash = toBigint(protocol.recentRootEntry(source, slot, root));
  // A storage word has at most 64 digits; a longer answer is not this entry.
  const found = parseHex(stored, "eth_getStorageAt's result");
  if (found !== entryHash || (stored as string).length > 66) {
    throw new PoolError(
      `  recent-root ref self-check failed at consensus slot ${slot}. The fixture root differs ` +
        "from the root committed at that slot, or the wrong epoch/slot was supplied. Either " +
        "would be rejected as FrameTxRecentRootNotCommitted. If another deposit changed the " +
        "tree, the notes are safe but this proof is not: prove again against a published root, " +
        "at the leaves the notes occupy, from the openings in the fixture entries' `inputs`, " +
        "dummy included, so that the owner's signature still holds, and keep this fixture: it " +
        "holds the only copy of those secrets.",
    );
  }
  return protocol.recentRootTuple(source, slot, root);
}
