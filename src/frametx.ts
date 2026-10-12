/**
 * EIP-8141 frame transactions (type 0x06) as published at ethereum/EIPs 7d1c8bfb94 and
 * implemented by ethrex:
 *
 *   raw       = 0x06 || rlp([chain_id, nonce_keys, nonce_seq, sender, frames, signatures,
 *                            fees, blob_hashes])
 *   fees      = [max_priority_fee, max_fee, max_blob_fee]
 *   frame     = [mode, flags, target or empty, [execution, state], value, data]
 *   signature = [scheme, signer, msg, signature bytes]
 *   sig_hash  = keccak256(0x06 || rlp(envelope with empty-msg signatures' bytes elided))
 *
 * The pre-relaunch chain-8141 dialect is archived under the repository's evidence-archive tag
 * (evidence/vectors/2026-09-01-hegota-final-profile/); the two envelopes cannot read each
 * other. Transactions are plain mutable objects, so tests can change a field after building one.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";

import {
  concat,
  equalBytes,
  fromHex,
  keccak,
  maxBigint,
  toBigint,
  toBytes,
  toHex,
} from "./bytes.ts";
import { InputError } from "./errors.ts";

// ---------- RLP ----------

/** RLP of a byte string. A single byte below 0x80 is its own encoding. */
export function rlpBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 1 && bytes[0] < 0x80) return Uint8Array.of(bytes[0]);
  return concat(header(0x80, bytes.length), bytes);
}

/** RLP of a list whose items are already RLP-encoded. */
export function rlpList(items: Uint8Array[]): Uint8Array {
  const body = concat(...items);
  return concat(header(0xc0, body.length), body);
}

/** RLP of a non-negative integer: big-endian without leading zeros, so 0 is 0x80. */
export function rlpInt(value: bigint): Uint8Array {
  return rlpBytes(minimal(value));
}

function minimal(value: bigint): Uint8Array {
  if (value < 0n) throw new RangeError(`cannot RLP-encode the negative integer ${value}`);
  return value === 0n ? new Uint8Array(0) : toBytes(value, (value.toString(16).length + 1) >> 1);
}

function header(offset: number, length: number): Uint8Array {
  if (length < 56) return Uint8Array.of(offset + length);
  const size = minimal(BigInt(length));
  return concat(Uint8Array.of(offset + 55 + size.length), size);
}

/**
 * Splits one RLP list into its top-level items, each still encoded: enough to count an
 * envelope's fields and look one level in without a full decoder.
 */
export function rlpItems(encoded: Uint8Array): Uint8Array[] {
  if (encoded.length === 0 || encoded[0] < 0xc0) throw new Error("not an RLP list");
  const body = encoded.subarray(...payload(encoded, 0));
  const items: Uint8Array[] = [];
  for (let at = 0; at < body.length;) {
    const end = payload(body, at)[1];
    items.push(body.subarray(at, end));
    at = end;
  }
  return items;
}

/** Where the payload of the RLP item at `at` starts and ends. */
function payload(bytes: Uint8Array, at: number): [start: number, end: number] {
  const prefix = bytes[at];
  let [start, length] = prefix < 0x80 ? [at, 1] : [at + 1, prefix - (prefix < 0xc0 ? 0x80 : 0xc0)];
  // Past 55, the prefix counts the bytes of a big-endian length that follows it.
  if (length > 55) {
    start = at + 1 + length - 55;
    length = Number(toBigint(bytes.subarray(at + 1, start)));
  }
  if (start + length > bytes.length) throw new Error("truncated RLP");
  return [start, start + length];
}

// ---------- frame-tx model ----------

export interface Frame {
  mode: bigint;
  flags: bigint;
  /** null is a targetless frame, encoded as the empty string. */
  target: bigint | null;
  /** limits.execution */
  gasLimit: bigint;
  /** limits.state: the EIP-8037 state budget, which can never borrow from gasLimit. */
  stateLimit: bigint;
  value: bigint;
  data: Uint8Array;
}

export interface FrameSig {
  scheme: bigint;
  signer: bigint;
  msg: Uint8Array;
  /** For secp256k1, v (0 or 1) || r || s; empty before signing. */
  signature: Uint8Array;
}

export interface FrameTx {
  chainId: bigint;
  nonceKeys: bigint[];
  nonceSeq: bigint;
  sender: bigint;
  frames: Frame[];
  signatures: FrameSig[];
  maxPriorityFee: bigint;
  maxFee: bigint;
  maxBlobFee: bigint;
  blobHashes: Uint8Array[];
}

/** Frame modes: DEFAULT runs as the entry point, VERIFY validates, SENDER runs as the sender. */
export const MODE = { DEFAULT: 0n, VERIFY: 1n, SENDER: 2n } as const;

/**
 * The approval scope in bits 0 and 1 of a frame's flags: what APPROVE may grant in that frame.
 * EXECUTION lets later frames act as the sender, and PAYMENT makes the frame's target pay for
 * the whole transaction. A VERIFY frame flagged EXECUTION_AND_PAYMENT (0x03) may grant both, so
 * its target becomes the sender's authority and its payer: the pool once a spend's proof
 * verifies, or a funded account whose signature checks.
 */
export const APPROVE = { NONE: 0n, PAYMENT: 1n, EXECUTION: 2n, EXECUTION_AND_PAYMENT: 3n } as const;

/** Bit 2 of a frame's flags, the atomic-batch flag. The pool's transactions never set it. */
export const ATOMIC_BATCH = 4n;

export const SCHEME = { ARBITRARY: 0n, SECP256K1: 1n, P256: 2n } as const;
const VERIFICATION_COST = [100n, 2_800n, 6_700n]; // by scheme

const address20 = (address: bigint) => toBytes(address, 20);

/** One frame's RLP, the item the envelope's frame list holds. */
export function encodeFrame(frame: Frame): Uint8Array {
  return rlpList([
    rlpInt(frame.mode),
    rlpInt(frame.flags),
    rlpBytes(frame.target === null ? new Uint8Array(0) : address20(frame.target)),
    rlpList([rlpInt(frame.gasLimit), rlpInt(frame.stateLimit)]),
    rlpInt(frame.value),
    rlpBytes(frame.data),
  ]);
}

/**
 * The envelope's RLP. With `elide`, an empty-msg signature encodes empty signature bytes, since
 * the signature hash cannot cover the signature it is about to receive.
 */
function envelope(tx: FrameTx, elide: boolean): Uint8Array {
  const signature = (sig: FrameSig) =>
    rlpList([
      rlpInt(sig.scheme),
      rlpBytes(address20(sig.signer)),
      rlpBytes(sig.msg),
      rlpBytes(elide && sig.msg.length === 0 ? new Uint8Array(0) : sig.signature),
    ]);
  return rlpList([
    rlpInt(tx.chainId),
    rlpList(tx.nonceKeys.map(rlpInt)),
    rlpInt(tx.nonceSeq),
    rlpBytes(address20(tx.sender)),
    rlpList(tx.frames.map(encodeFrame)),
    rlpList(tx.signatures.map(signature)),
    rlpList([rlpInt(tx.maxPriorityFee), rlpInt(tx.maxFee), rlpInt(tx.maxBlobFee)]),
    rlpList(tx.blobHashes.map(rlpBytes)),
  ]);
}

/** The envelope's RLP with every signature in place, without the type byte. */
export function encodeTx(tx: FrameTx): Uint8Array {
  return envelope(tx, false);
}

/** The bytes eth_sendRawTransaction takes: 0x06 || encodeTx(tx). */
export function rawTx(tx: FrameTx): Uint8Array {
  return concat(Uint8Array.of(0x06), envelope(tx, false));
}

/** What every signer signs: keccak256 of the raw transaction with empty-msg signatures elided. */
export function sigHash(tx: FrameTx): Uint8Array {
  return keccak(concat(Uint8Array.of(0x06), envelope(tx, true)));
}

// ---------- gas (a client-side mirror of EIP-8141 max_gas) ----------

const sum = <T>(items: readonly T[], f: (item: T) => bigint) =>
  items.reduce((total, item) => total + f(item), 0n);

/**
 * The fields EIP-8141 prices as data: each frame's data, each signature's signer, msg and
 * stored bytes (never elided), and the RLP of the nonce keys followed by the nonce sequence.
 */
function dataFields(tx: FrameTx): Uint8Array[] {
  return [
    ...tx.frames.map((frame) => frame.data),
    ...tx.signatures.flatMap((sig) => [address20(sig.signer), sig.msg, sig.signature]),
    concat(rlpList(tx.nonceKeys.map(rlpInt)), rlpInt(tx.nonceSeq)),
  ];
}

/** Standard calldata gas of the data fields: 4 per zero byte, 16 per other byte. */
function calldataGas(tx: FrameTx): bigint {
  return sum(dataFields(tx), (field) => field.reduce((gas, byte) => gas + (byte ? 16n : 4n), 0n));
}

/** What EIP-8141 charges to verify the signatures. */
export function signatureVerificationCost(tx: FrameTx): bigint {
  return sum(tx.signatures, (sig) => {
    const cost = VERIFICATION_COST[Number(sig.scheme)];
    if (cost === undefined) throw new RangeError(`unknown signature scheme ${sig.scheme}`);
    return cost;
  });
}

/**
 * TX_VALUE_COST (6,000) per frame that moves value to another account, as EIP-2780 prices a
 * top-level transfer. A frame with no target, or one targeting the sender, moves nothing.
 */
export function valueTransferCost(tx: FrameTx): bigint {
  const moves = (frame: Frame) =>
    frame.value > 0n &&
    frame.target !== null &&
    !equalBytes(address20(frame.target), address20(tx.sender));
  return 6_000n * BigInt(tx.frames.filter(moves).length);
}

/**
 * The intrinsic (12,000), 475 per frame, signature verification and value transfers: the terms
 * both sides of the max_gas comparison share, so none is dropped when the floor binds.
 */
export function mandatoryGas(tx: FrameTx): bigint {
  const frames = 475n * BigInt(tx.frames.length);
  return 12_000n + frames + signatureVerificationCost(tx) + valueTransferCost(tx);
}

/** The declared EIP-8037 state budgets of all frames. */
export function stateGasLimit(tx: FrameTx): bigint {
  return sum(tx.frames, (frame) => frame.stateLimit);
}

/** Mandatory gas, standard calldata gas and every frame's execution and state budget. */
export function standardGasLimit(tx: FrameTx): bigint {
  return executionGas(tx) + stateGasLimit(tx);
}

function executionGas(tx: FrameTx): bigint {
  return mandatoryGas(tx) + calldataGas(tx) + sum(tx.frames, (frame) => frame.gasLimit);
}

/** Mandatory gas plus the EIP-7976 floor: 16 gas per token, 4 tokens per byte, zero or not. */
export function calldataFloorGas(tx: FrameTx): bigint {
  return mandatoryGas(tx) + 64n * sum(dataFields(tx), (field) => BigInt(field.length));
}

/** Declared execution against the EIP-7825 cap. State is a separate dimension. */
export function executionCapUsage(tx: FrameTx): bigint {
  return maxBigint(executionGas(tx), calldataFloorGas(tx));
}

/**
 * EIP-8141 max_gas = max(standard_gas_limit, calldata_floor_gas + sum(limits.state)): state
 * gas is added on top of the floor, so state growth never rides free under it.
 */
export function totalGasLimit(tx: FrameTx): bigint {
  return maxBigint(standardGasLimit(tx), calldataFloorGas(tx) + stateGasLimit(tx));
}

/** The most the transaction can cost its payer at the given blob base fee (131,072 per blob). */
export function maxCost(tx: FrameTx, blobBaseFee = 0n): bigint {
  return tx.maxFee * totalGasLimit(tx) + BigInt(tx.blobHashes.length) * 131_072n * blobBaseFee;
}

// ---------- secp256k1 ----------

/** The order n of secp256k1's group: private keys are in [1, n), and EIP-8141 takes s <= n/2. */
export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * A secp256k1 private key: 64 hex digits, with or without "0x", whose value is in [1, n). The
 * message never repeats the text, which is a secret.
 */
export function parsePrivateKey(text: unknown, what: string): Uint8Array {
  if (typeof text === "string" && /^(0x)?[0-9a-fA-F]{64}$/.test(text)) {
    const key = fromHex("0x" + text.slice(-64), what, 32);
    if (secp256k1.utils.isValidSecretKey(key)) return key;
  }
  throw new InputError(`${what} is not a secp256k1 private key`);
}

/** A key typed at a prompt or piped as one line; surrounding whitespace is ignored. */
export function parsePrivateKeyLine(line: string, what: string): Uint8Array {
  return parsePrivateKey(line.trim(), what);
}

/**
 * Signs a 32-byte hash as given (noble would otherwise prehash with SHA-256): v (0 or 1) || r
 * || s with the RFC 6979 nonce and low s. EIP-8141 takes the bare recovery id, not 27/28.
 */
export function signHash(hash: Uint8Array, privateKey: Uint8Array): Uint8Array {
  if (hash.length !== 32) throw new RangeError(`a message hash is 32 bytes, got ${hash.length}`);
  return secp256k1.sign(hash, privateKey, { prehash: false, lowS: true, format: "recovered" });
}

/** The address that produced a v || r || s signature over a 32-byte hash. */
export function recoverSigner(hash: Uint8Array, signature: Uint8Array): bigint {
  if (hash.length !== 32) throw new RangeError(`a message hash is 32 bytes, got ${hash.length}`);
  if (signature.length !== 65 || signature[0] > 1) {
    throw new RangeError("a secp256k1 signature is v (0 or 1), r and s in 65 bytes");
  }
  const signer = secp256k1.Signature.fromBytes(signature, "recovered").recoverPublicKey(hash);
  return publicKeyAddress(signer.toBytes(false));
}

/** The Ethereum address of a private key, as an integer. */
export function addressOf(privateKey: Uint8Array): bigint {
  return publicKeyAddress(secp256k1.getPublicKey(privateKey, false));
}

function publicKeyAddress(uncompressed: Uint8Array): bigint {
  return toBigint(keccak(uncompressed.subarray(1)).subarray(12));
}

/** EIP-55 mixed case: a letter is uppercase when its nibble of the hash is 8 or more. */
export function checksumAddress(address: bigint): string {
  const digits = toHex(address20(address)).slice(2);
  const hash = toHex(keccak(new TextEncoder().encode(digits))).slice(2);
  return "0x" + [...digits].map((d, i) => (hash[i] >= "8" ? d.toUpperCase() : d)).join("");
}
