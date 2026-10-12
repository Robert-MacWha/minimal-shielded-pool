/**
 * A fixture's shield and spend entries as the pool's calldata, and the frame transaction that
 * carries a spend. A spend is VERIFY(0x…8272, recent-root tuple) -> VERIFY(pool, proof) ->
 * SENDER(pool, settle(Spend) || notes), plus at most one DEFAULT tail; the pool pays, and its
 * nonce keys are the nullifiers. It carries two signatures, in this order: the authorizer's, which
 * the proof selects, over the whole transaction with the owner's signature bytes; then the
 * owner's, over the spend's EIP-712 intent, which the fixture records before the authorizer signs.
 * Nothing here asks the node: src/deployment.ts checks a spend's recent root against it, and
 * src/send.ts sends the spend.
 */
import {
  concat,
  fromHex,
  parseAddress,
  parseDec,
  parseHex,
  parseUint,
  toBigint,
  word,
} from "./bytes.ts";
import { InputError, PoolError } from "./errors.ts";
import {
  addressOf,
  APPROVE,
  executionCapUsage,
  MODE,
  parsePrivateKey,
  rawTx,
  recoverSigner,
  SCHEME,
  SECP256K1_N,
  sigHash,
  signHash,
  type Frame,
  type FrameSig,
  type FrameTx,
} from "./frametx.ts";
import * as gas from "./gas.ts";
import { isObject } from "./json.ts";
import * as protocol from "./protocol.ts";

const get = (value: unknown, key: string): unknown => (isObject(value) ? value[key] : undefined);

// ---- fixture entries ----

type Parser = (value: unknown, what: string) => bigint;
const word32: Parser = (value, what) => toBigint(fromHex(value, what, 32));

/** The note bytes a wallet stored in a fixture entry; the protocol encoders check the length. */
function notesField(entry: unknown, key: string, what: string): Uint8Array {
  const notes = get(entry, key);
  if (notes === undefined) {
    throw new PoolError(
      `the fixture's ${what} has no \`${key}\`: regenerate it with src/cli/smoke.ts or ` +
        "src/cli/nonce-race.ts so its recipients can find their notes",
    );
  }
  return fromHex(notes, `the ${what}'s ${key}`);
}

/** The root a spend references, the slot that published it, and the epoch that names its source. */
export type RecentRoot = Pick<protocol.Spend, "root" | "rootSlot" | "epoch">;

/** The recent root of a fixture spend entry whose root was published in `rootSlot`. */
export function parseRecentRoot(entry: unknown, rootSlot: bigint): RecentRoot {
  // Fixtures write the epoch in decimal, the only form read here; parseSpend reads the entry's
  // integers with parseUint (0x hex, or decimal without leading zeros).
  const epoch = parseDec(get(entry, "epoch"), "the spend entry's epoch");
  return { rootSlot, epoch, root: word32(get(entry, "root"), "the spend entry's root") };
}

/** The Spend of a fixture spend entry whose root was published in `rootSlot`. */
export function parseSpend(entry: unknown, rootSlot: unknown): protocol.Spend {
  const at = (parse: Parser, key: string) => parse(get(entry, key), `the spend entry's ${key}`);
  return {
    root: at(word32, "root"),
    rootSlot: parseUint(rootSlot, "the spend entry's root_slot"),
    epoch: at(parseUint, "epoch"),
    domain: at(word32, "domain"),
    nf1: at(word32, "nf1"),
    nf2: at(word32, "nf2"),
    outCm1: at(word32, "out_cm1"),
    outCm2: at(word32, "out_cm2"),
    publicAmount: at(parseUint, "public_amount"),
    fee: at(parseUint, "fee"),
    recipient: at(parseAddress, "recipient"),
    authorizer: at(parseAddress, "authorizer"),
    count: at(parseUint, "count"),
    packedRanks: at(parseUint, "packed_ranks"),
    depth: at(parseUint, "depth"),
    frontier: frontierField(entry),
  };
}

/** The frontier's roots of a fixture spend entry, padded to MAX_TREES as settle takes them. */
function frontierField(entry: unknown): bigint[] {
  const frontier = get(entry, "frontier");
  if (!Array.isArray(frontier) || frontier.length !== protocol.MAX_TREES) {
    throw new InputError(`the spend entry's frontier must list ${protocol.MAX_TREES} roots`);
  }
  return frontier.map((root, i) => word32(root, `the spend entry's frontier[${i}]`));
}

/** settle(Spend) calldata followed by the notes, from a fixture spend entry and its root slot. */
export function settleCalldata(entry: unknown, rootSlot: unknown): Uint8Array {
  return protocol.encodeSettle(parseSpend(entry, rootSlot), notesField(entry, "notes", "spend"));
}

/** shield(inner, note) calldata with the note the wallet made for the new leaf. */
export function shieldCalldata(inner: unknown, entry: unknown): Uint8Array {
  const note = notesField(entry, "note", "shield");
  const value = word32(inner, "the shield's inner");
  const calldata = protocol.encodeShield(value, note);
  // The pool accepts any inner below p, but no one can open 0 or a sink inner, so a deposit to
  // one is locked for good.
  if (value === 0n || protocol.SINK_INNERS.includes(value)) {
    throw new PoolError("the shield's inner is 0 or a sink inner, which no one can spend");
  }
  return calldata;
}

/** A fixture spend entry's Groth16 proof and hybrid compression's beta. */
export function parseSpendProof(entry: unknown): { proof: protocol.Proof; beta: bigint } {
  // Rows must be arrays: an object keyed "0" and "1" is not read as one.
  const row = (value: unknown, i: number) => (Array.isArray(value) ? value[i] : undefined);
  const at = (key: string, ...path: number[]) =>
    parseHex(path.reduce(row, get(get(entry, "proof"), key)), `the spend entry's proof ${key}`);
  const proof: protocol.Proof = {
    pA: [at("pA", 0), at("pA", 1)],
    pB: [
      [at("pB", 0, 0), at("pB", 0, 1)],
      [at("pB", 1, 0), at("pB", 1, 1)],
    ],
    pC: [at("pC", 0), at("pC", 1)],
  };
  return { proof, beta: parseHex(get(entry, "beta"), "the spend entry's beta") };
}

/** The proof frame's 288 bytes: the Groth16 proof in snarkjs calldata word order, then beta. */
export function entryProofBytes(entry: unknown): Uint8Array {
  const { proof, beta } = parseSpendProof(entry);
  return protocol.proofBytes(proof, beta);
}

/**
 * The owner's signature entry for a fixture spend entry from the pool at `pool` on chain
 * `chainId`: its recorded signature over the spend's EIP-712 intent, refused unless it recovers
 * to the entry's owner. The proof binds that owner, and the pool reads it from this entry.
 */
export function ownerSignature(entry: unknown, chainId: bigint, pool: bigint): FrameSig {
  const owner = parseAddress(get(entry, "owner"), "the spend entry's owner");
  const signature = fromHex(get(entry, "owner_signature"), "the spend entry's owner_signature", 65);
  const msg = protocol.intentDigest(chainId, pool, parseSpend(entry, 0n));
  // EIP-8141 takes v as 0 or 1 and only low s, so each signature has one encoding.
  const lowS = toBigint(signature.subarray(33)) <= SECP256K1_N / 2n;
  let signer: bigint | null = null;
  try {
    signer = lowS ? recoverSigner(msg, signature) : null;
  } catch {
    // v above 1, or r or s out of range: refused below, like a signature by another key
  }
  if (signer !== owner) {
    throw new PoolError(
      "the fixture's owner signature does not sign this spend's intent for this chain and pool",
    );
  }
  return { scheme: SCHEME.SECP256K1, signer: owner, msg, signature };
}

/** The entry's authorizer key, refused unless it is the key of the authorizer the proof binds. */
export function authorizerKey(entry: unknown): Uint8Array {
  const what = "the spend entry's authorizer_private_key";
  const key = parsePrivateKey(get(entry, "authorizer_private_key"), what);
  const authorizer = parseAddress(get(entry, "authorizer"), "the spend entry's authorizer");
  if (addressOf(key) !== authorizer) {
    throw new PoolError("fixture authorizer private key does not match the proof public");
  }
  return key;
}

// ---- the optional fourth frame ----

/** A custom DEFAULT tail. Its calldata already holds whatever authorization the target needs. */
export interface Action {
  readonly target: bigint;
  readonly data: Uint8Array;
  readonly gasLimit: bigint;
  readonly stateLimit: bigint;
}

/**
 * DEFAULT(pool, claimWithdrawal(recipient)) at the claim frame's wallet limits, unchecked: the
 * native generator signs claims for deliberately invalid settlements.
 */
export function defaultClaimTail(pool: bigint, recipient: bigint): Frame {
  const data = concat(protocol.CLAIM_SELECTOR, word(recipient));
  return {
    mode: MODE.DEFAULT,
    flags: APPROVE.NONE,
    target: pool,
    gasLimit: gas.CLAIM_FRAME_GAS,
    stateLimit: gas.CLAIM_FRAME_STATE_GAS,
    value: 0n,
    data,
  };
}

/**
 * A spend's optional fourth DEFAULT frame: a withdrawal's claim by default, none when `omit`
 * leaves withdrawalCredit, or one custom action. Resource limits are checked on the whole tx.
 */
export function spendTailFrame(
  pool: bigint,
  settle: Uint8Array,
  action: Action | null = null,
  options: { omit?: boolean } = {},
): Frame | null {
  const decoded = protocol.decodeSettle(settle);
  if (decoded === null) {
    throw new InputError("tail frame requires settle(Spend) calldata followed by its notes");
  }
  const { publicAmount: amount, recipient } = decoded.spend;
  if (pool <= 0n || pool >= 1n << 160n || recipient >= 1n << 160n || amount >= 1n << 128n) {
    throw new InputError("invalid pool, recipient, or public amount");
  }
  if ((amount === 0n) !== (recipient === 0n)) {
    throw new InputError("public amount and recipient must both be zero or both nonzero");
  }
  // Checked before omit, so leaving out the tail cannot launder a credit nobody can claim.
  const unclaimable = protocol.PRECOMPILES.has(recipient)
    ? "a precompile, which no one controls"
    : protocol.UNCLAIMABLE_RECIPIENTS.get(recipient);
  if (amount !== 0n && (unclaimable || recipient === pool)) {
    const what = unclaimable ?? "the pool itself";
    throw new InputError(`withdrawal recipient would strand the credit: ${what}`);
  }
  if (options.omit) {
    if (action !== null) throw new InputError("omit cannot be combined with a custom action");
    return null;
  }
  if (action === null) return amount === 0n ? null : defaultClaimTail(pool, recipient);
  const { target, data, gasLimit, stateLimit } = action;
  if (target <= 0n || target >= 1n << 160n) {
    throw new InputError("action target must be a nonzero address");
  }
  // ethrex 247e2dd2 panics executing a top-level frame to a precompile after an earlier frame
  // emitted logs, as settlement does. The testnet's 64b8fc09 has the fix; other nodes may not.
  if (protocol.PRECOMPILES.has(target)) {
    throw new InputError("action target must not be a precompile");
  }
  if (gasLimit <= 0n) throw new InputError("action execution gas must be positive");
  if (stateLimit < 0n) throw new InputError("action state gas must be nonnegative");
  return { mode: MODE.DEFAULT, flags: APPROVE.NONE, target, gasLimit, stateLimit, value: 0n, data };
}

// ---- building ----

/**
 * A spend's frames, unchecked, so the native generator can sign deliberately invalid spends.
 * The recent-root frame approves nothing. The proof frame reads the tuple back from frame 0,
 * and once the proof verifies the pool approves itself as sender and payer. The SENDER frame
 * starts at the limit the activation profile proves: an out-of-gas after payment approval
 * burns the notes.
 */
export function spendFrames(spend: {
  pool: bigint;
  recentRoot: Uint8Array;
  proof: Uint8Array;
  settle: Uint8Array;
  tail?: Frame | null;
  settleGas?: bigint;
}): Frame[] {
  const { pool, recentRoot, proof, settle, tail, settleGas = gas.SETTLE_FRAME_GAS } = spend;
  return [
    {
      mode: MODE.VERIFY,
      flags: APPROVE.NONE,
      target: protocol.RECENT_ROOT_ADDRESS,
      gasLimit: gas.RECENT_ROOT_FRAME_GAS,
      stateLimit: 0n,
      value: 0n,
      data: recentRoot,
    },
    {
      mode: MODE.VERIFY,
      flags: APPROVE.EXECUTION_AND_PAYMENT,
      target: pool,
      gasLimit: gas.VERIFY_FRAME_GAS,
      stateLimit: gas.VERIFY_FRAME_STATE_GAS,
      value: 0n,
      data: proof,
    },
    {
      mode: MODE.SENDER,
      flags: APPROVE.NONE,
      target: pool,
      gasLimit: settleGas,
      stateLimit: gas.SETTLE_FRAME_STATE_GAS,
      value: 0n,
      data: settle,
    },
    ...(tail ? [tail] : []),
  ];
}

/** A spend's EIP-8250 nonce keys: its two nullifiers in ascending numeric order. */
export function spendNonceKeys(settle: Uint8Array): bigint[] {
  const [a, b] = [4, 5].map((i) => toBigint(settle.subarray(4 + 32 * i, 36 + 32 * i)));
  return a <= b ? [a, b] : [b, a];
}

/**
 * Signs the transaction with `key` over its signature hash, in place, as its first signature,
 * followed by `after`: the owner's signature for a spend, none for a call. The hash elides the
 * first signature's bytes but covers the owner's, whose msg is an explicit digest.
 */
export function signTransaction(tx: FrameTx, key: Uint8Array, ...after: FrameSig[]): FrameTx {
  const unsigned = { scheme: SCHEME.SECP256K1, signer: addressOf(key), msg: new Uint8Array(0) };
  tx.signatures = [{ ...unsigned, signature: new Uint8Array(0) }, ...after];
  tx.signatures = [{ ...unsigned, signature: signHash(sigHash(tx), key) }, ...after];
  return tx;
}

/**
 * Refuses a transaction over chain-wide limits: execution (intrinsic cost plus frame budgets,
 * against the EIP-7976 calldata floor; EIP-7825's cap does not count state gas) and size.
 */
export function checkTxResourceLimits(tx: FrameTx): void {
  const [used, cap] = [executionCapUsage(tx), gas.EIP7825_TX_GAS_CAP];
  if (used > cap) throw new InputError(`declared execution ${used} exceeds EIP-7825 cap ${cap}`);
  const [size, limit] = [rawTx(tx).length, gas.ETHREX_MEMPOOL_MAX_BYTES];
  if (size > limit) {
    throw new InputError(
      `encoded transaction ${size} bytes exceeds ethrex ${limit}-byte mempool limit`,
    );
  }
}
