/**
 * Note delivery: a secret per sender and recipient, and 48-byte notes on chain. This module holds
 * the note format, the wallet's keys and addresses, and the sender's channels; src/scan.ts finds
 * a wallet's notes on chain, and src/cli/notes.ts runs both from the command line.
 *
 * A recipient needs each note's amount and rho to spend it. The pool publishes notes and never
 * reads them (core/contracts/src/ShieldedPoolLogic.sol): settlement carries two notes, one per
 * output, and a shield carries one. A sender's first payment to a public address puts its
 * ML-KEM-768 ciphertext before the notes.
 *
 *   note = tag (16) || ChaCha20-Poly1305(value as 16 bytes) (16 + 16 tag)
 *   tag  = PRF(K, "tag", i)[:16]
 *   key  = PRF(K, "key", i)              each key seals one note, so the nonce is zero
 *   rho  = PRF64(K, "rho", i) mod r       the recipient recomputes the commitment
 *   cm   = Poseidon(2, Poseidon2(owner_pk, rho), value)
 *
 * PRF is HMAC-SHA256 and PRF64 joins two outputs into 512 bits before reducing. `i` counts the
 * notes sent under K. Reusing an index repeats the tag, the key and rho, which links two
 * payments and reveals the XOR of their amounts, so a sender reserves each index in its saved
 * state before using it. The recipient watches LOOKAHEAD indices past the last one it found,
 * so a sender keeps fewer than LOOKAHEAD payments past the last one it has seen final.
 *
 * K, the secret a sender and recipient share, comes from the recipient's public address (a
 * version byte, owner_pk and an ML-KEM-768 encapsulation key): the payment that opens the
 * channel carries its 1,088-byte ciphertext, and no other transaction does, since two carrying
 * it would be linked. Version 2 names an owner key over an owner set, so a sender refuses a
 * version 1 address, whose notes no owner set could spend. Or the recipient issues K =
 * PRF(root, "direct", n), for the next number n, to one sender over a post-quantum channel; n
 * stays within GAP of the highest number paid, which is how far a scan from the seed looks.
 * Change and shields from one's own funds use K = PRF(root, "self"), and a withdrawal puts a
 * random dummy in the payee note.
 *
 * A recipient rebuilds every incoming note, and every change note, from its seed and its owner
 * set's root. A sender cannot recompute a secret it encapsulated, so after a restore it opens a
 * new channel with each recipient, and resumes its self channel with selfChannel(). Direct
 * secrets and the self channel do not depend on the deployment, so a seed is used with one pool
 * only.
 *
 * An address's owner key commits to its device's owner set and to a nullifier key nk the seed
 * derives (protocol.ownerPk), so the seed finds and proves the address's notes, but only the
 * device can authorize their spends. Every secret of an address, nk and its ML-KEM key included,
 * comes from root = PRF(seed, "account", account, owner set's root). An address under another
 * owner set therefore shares no secret with it: a scan of one cannot see the direct numbers and
 * change indices the other used, so shared secrets would go to a second sender or repeat a key.
 * All notes paid to one address share its nk. A disclosure receipt for one of them reveals
 * Poseidon2(D, nk), which identifies every spend of that address in epoch D, so src/disclosure.ts
 * refuses such a receipt unless asked for it explicitly.
 */
import * as crypto from "node:crypto";

import {
  concat,
  fromHex,
  hex32,
  maxBigint,
  parseDec,
  parseHex,
  toBigint,
  toBytes,
  toHex,
  word,
} from "./bytes.ts";
import { NotesError } from "./errors.ts";
import { NOTE_BYTES, SHIELD_NOTE_BYTES, SPEND_NOTES_BYTES } from "./gas.ts";
import { asObject } from "./json.ts";
import * as protocol from "./protocol.ts";
import { P } from "./protocol.ts";
import type { Rng } from "./random.ts";

const LABEL = "minimal-shielded-pool:note:v1:";
export const TAG_BYTES = 16;
const VALUE_BYTES = 16;
export const SECRET_BYTES = 32;
const EK_BYTES = 1184;
const ADDRESS_VERSION = 2;
export const ADDRESS_BYTES = 1 + 32 + EK_BYTES;
export const MIN_SEED_BYTES = 32;
export const GAP = 20;
export const LOOKAHEAD = 20;
export const RESTORE_SKIP = LOOKAHEAD / 2;
const EMPTY: Uint8Array = new Uint8Array();

// ---- primitives ----

/** HMAC-SHA256 under a domain-separated label; an integer part is one 32-byte word. */
export function prf(key: Uint8Array, label: string, ...parts: (bigint | Uint8Array)[]): Uint8Array {
  const hmac = crypto.createHmac("sha256", key).update(LABEL + label);
  for (const part of parts) hmac.update("|").update(typeof part === "bigint" ? word(part) : part);
  return new Uint8Array(hmac.digest());
}

/** A field element from 512 PRF bits, so the reduction mod P has no useful bias. */
export function prfField(key: Uint8Array, label: string, ...parts: (bigint | Uint8Array)[]) {
  return toBigint(concat(prf(key, `${label}:0`, ...parts), prf(key, `${label}:1`, ...parts))) % P;
}

export function noteTag(secret: Uint8Array, index: bigint): Uint8Array {
  return prf(secret, "tag", index).subarray(0, TAG_BYTES);
}

export function noteRho(secret: Uint8Array, index: bigint): bigint {
  return prfField(secret, "rho", index);
}

const NONCE = new Uint8Array(12);
const AAD = { plaintextLength: VALUE_BYTES };

/** The 48-byte note for the index-th payment under `secret`, and its rho. */
export function sealNote(secret: Uint8Array, index: bigint, value: bigint) {
  if (!(value > 0n && value < protocol.MAX_VALUE)) {
    throw new NotesError("a note's value must be positive and fit 128 bits");
  }
  const tag = noteTag(secret, index);
  const cipher = crypto.createCipheriv("chacha20-poly1305", prf(secret, "key", index), NONCE);
  cipher.setAAD(tag, AAD);
  const sealed = concat(cipher.update(toBytes(value, VALUE_BYTES)), cipher.final());
  return { note: concat(tag, sealed, cipher.getAuthTag()), rho: noteRho(secret, index) };
}

/** The note's value, or null if it was not sealed with (secret, index). */
export function openNote(secret: Uint8Array, index: bigint, note: Uint8Array): bigint | null {
  const tag = note.subarray(0, TAG_BYTES);
  if (note.length !== NOTE_BYTES || !crypto.timingSafeEqual(tag, noteTag(secret, index))) {
    return null;
  }
  const decipher = crypto.createDecipheriv("chacha20-poly1305", prf(secret, "key", index), NONCE);
  decipher.setAAD(tag, AAD).setAuthTag(note.subarray(TAG_BYTES + VALUE_BYTES));
  const value = toBigint(decipher.update(note.subarray(TAG_BYTES, TAG_BYTES + VALUE_BYTES)));
  try {
    decipher.final();
  } catch {
    return null;
  }
  return value > 0n ? value : null;
}

/** Random bytes in a note's place, for a withdrawal's payee: they open for no one. */
export function dummyNote(rng: Rng): Uint8Array {
  return rng.bytes(NOTE_BYTES);
}

/** Settlement's notes: an optional ciphertext, then the payee and change notes. */
export function spendNotes(payee: Uint8Array, change: Uint8Array, ciphertext = EMPTY) {
  const data = concat(ciphertext, payee, change);
  const notes = payee.length === NOTE_BYTES && change.length === NOTE_BYTES;
  if (!notes || !SPEND_NOTES_BYTES.includes(data.length)) {
    throw new NotesError(
      "a spend carries two 48-byte notes, optionally after a 1,088-byte ciphertext",
    );
  }
  return data;
}

/** A shield's note, optionally after a ciphertext. */
export function shieldNotes(note: Uint8Array, ciphertext = EMPTY): Uint8Array {
  const data = concat(ciphertext, note);
  if (note.length !== NOTE_BYTES || !SHIELD_NOTE_BYTES.includes(data.length)) {
    throw new NotesError(
      "a shield carries one 48-byte note, optionally after a 1,088-byte ciphertext",
    );
  }
  return data;
}

// ---- keys and addresses ----

/** The bytes of hex with or without "0x", as a person pastes a seed or an address. */
export function pastedHex(text: string, what: string): Uint8Array {
  const digits = text.replace(/^0x/, "");
  if (digits.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(digits)) {
    throw new NotesError(`${what} is hex`);
  }
  return fromHex("0x" + digits, what);
}

// Node imports ML-KEM-768 keys (OID 2.16.840.1.101.3.4.4.2) only as DER: PKCS#8 holding the
// FIPS 203 seed d || z, and SPKI holding the 1,184-byte encapsulation key.
const PKCS8_SEED = Buffer.from("3054020100300b060960864801650304040204428040", "hex");
const SPKI = Buffer.from("308204b2300b0609608648016503040402038204a100", "hex");
const NO_MLKEM =
  "this Node cannot load ML-KEM-768 keys: note delivery needs Node 24.7 or later built with " +
  "OpenSSL 3.5 or later";

const spki = (ek: Uint8Array) =>
  crypto.createPublicKey({ key: Buffer.concat([SPKI, ek]), format: "der", type: "spki" });

function publicKey(ek: Uint8Array): crypto.KeyObject {
  try {
    return spki(ek);
  } catch {
    // An all-zero key passes FIPS 203's check that every 12-bit coefficient is below 3329, so if
    // it fails too, this Node has no ML-KEM.
    try {
      spki(new Uint8Array(EK_BYTES));
    } catch {
      throw new NotesError(NO_MLKEM);
    }
    throw new NotesError("the address's ML-KEM-768 key is invalid");
  }
}

/** A public address: owner_pk and an ML-KEM-768 encapsulation key. */
export class Address {
  readonly ownerPk: bigint;
  readonly ek: Uint8Array;

  constructor(ownerPk: bigint, ek: Uint8Array) {
    this.ownerPk = ownerPk;
    this.ek = ek;
  }

  encode(): Uint8Array {
    return concat(Uint8Array.of(ADDRESS_VERSION), word(this.ownerPk), this.ek);
  }

  hex(): string {
    return toHex(this.encode());
  }

  /** An address from its bytes or hex, with its owner key and ek checked. */
  static decode(data: string | Uint8Array): Address {
    if (typeof data === "string") data = pastedHex(data, "an address");
    if (!(data instanceof Uint8Array)) throw new NotesError("an address is hex or bytes");
    if (data.length === ADDRESS_BYTES && data[0] === 1) {
      throw new NotesError(
        "a version 1 address predates owner sets, so no one could spend a payment to it; ask " +
          "the recipient for a new address",
      );
    }
    if (data.length !== ADDRESS_BYTES || data[0] !== ADDRESS_VERSION) {
      throw new NotesError(
        `an address is ${ADDRESS_BYTES} bytes starting with version ${ADDRESS_VERSION}`,
      );
    }
    const owner = toBigint(data.subarray(1, 33));
    if (!(owner > 0n && owner < P)) {
      throw new NotesError("the address's owner key is not a nonzero field element");
    }
    const ek = data.slice(33);
    publicKey(ek);
    return new Address(owner, ek);
  }
}

/**
 * One address's keys: its secrets, derived from the wallet seed, the account number and the root
 * of the owner set whose device authorizes its spends.
 */
export class WalletKeys {
  readonly account: bigint;
  readonly root: Uint8Array;
  readonly ownerRoot: bigint;
  readonly nk: bigint;
  readonly ownerPk: bigint;
  readonly selfSecret: Uint8Array;
  readonly #kem: crypto.KeyObject;

  constructor(seed: Uint8Array, ownerRoot: bigint, account = 0n) {
    if (seed.length < MIN_SEED_BYTES) {
      throw new NotesError(`a seed has at least ${MIN_SEED_BYTES} bytes`);
    }
    if (!(ownerRoot > 0n && ownerRoot < P)) {
      throw new NotesError("an owner set's root is a nonzero field element");
    }
    if (account < 0n) throw new NotesError("an account number is nonnegative");
    this.account = account;
    this.root = prf(seed, "account", account, ownerRoot);
    this.ownerRoot = ownerRoot;
    this.nk = prfField(this.root, "nullifier");
    if (this.nk === 0n) throw new NotesError("degenerate nullifier key");
    this.ownerPk = protocol.ownerPk(ownerRoot, this.nk);
    // FIPS 203's 64-byte seed (d || z) regenerates the same key pair in any library.
    const key = Buffer.concat([PKCS8_SEED, prf(this.root, "kem-d"), prf(this.root, "kem-z")]);
    try {
      this.#kem = crypto.createPrivateKey({ key, format: "der", type: "pkcs8" });
    } catch {
      throw new NotesError(NO_MLKEM);
    }
    this.selfSecret = prf(this.root, "self");
  }

  address(): Address {
    const der = crypto.createPublicKey(this.#kem).export({ format: "der", type: "spki" });
    return new Address(this.ownerPk, new Uint8Array(der.subarray(SPKI.length)));
  }

  /** The secret this wallet hands its number-th out-of-band sender. */
  directSecret(number: bigint): Uint8Array {
    if (number < 0n) throw new NotesError("a direct secret number is nonnegative");
    return prf(this.root, "direct", number);
  }

  decapsulate(ciphertext: Uint8Array): Uint8Array {
    return new Uint8Array(crypto.decapsulate(this.#kem, ciphertext));
  }
}

// ---- sending ----

/** A sender's secret with one recipient, and the next index it may use. */
export interface Outgoing {
  ownerPk: bigint;
  secret: Uint8Array;
  nextIndex: bigint;
  ciphertext: Uint8Array; // the opening payment's, until that payment is final
  ciphertextSent: boolean; // the opening payment is reserved but not final
  confirmed: bigint; // one past the highest index seen final
}

function outgoing(ownerPk: bigint, secret: Uint8Array, rest: Partial<Outgoing> = {}): Outgoing {
  const fresh = { nextIndex: 0n, ciphertext: EMPTY, ciphertextSent: false, confirmed: 0n };
  return { ownerPk, secret, ...fresh, ...rest };
}

export function outgoingToJson(channel: Outgoing) {
  return {
    owner_pk: hex32(channel.ownerPk),
    secret: toHex(channel.secret),
    next_index: channel.nextIndex,
    ciphertext: toHex(channel.ciphertext),
    ciphertext_sent: channel.ciphertextSent,
    confirmed: channel.confirmed,
  };
}

export function outgoingFromJson(data: unknown): Outgoing {
  const d = asObject(data, "a channel");
  const sent = d.ciphertext_sent;
  if (typeof sent !== "boolean") throw new NotesError("ciphertext_sent is not true or false");
  return outgoing(parseHex(d.owner_pk, "owner_pk"), fromHex(d.secret, "secret"), {
    nextIndex: parseDec(d.next_index, "next_index"),
    ciphertext: fromHex(d.ciphertext, "ciphertext"),
    ciphertextSent: sent,
    confirmed: parseDec(d.confirmed, "confirmed"),
  });
}

/** ML-KEM-768 encapsulation to an encapsulation key; tests replay recorded pairs instead. */
export type Encapsulate = (ek: Uint8Array) => { secret: Uint8Array; ciphertext: Uint8Array };

const encapsulateMlKem: Encapsulate = (ek) => {
  const { sharedKey, ciphertext } = crypto.encapsulate(publicKey(ek));
  return { secret: new Uint8Array(sharedKey), ciphertext: new Uint8Array(ciphertext) };
};

/** A new secret with the owner of a public address, and the ciphertext that carries it. */
export function openChannel(
  address: Address | string | Uint8Array,
  encapsulate: Encapsulate = encapsulateMlKem,
): Outgoing {
  const to = address instanceof Address ? address : Address.decode(address);
  const { secret, ciphertext } = encapsulate(to.ek);
  return outgoing(to.ownerPk, secret, { ciphertext });
}

/** The sender's side of a secret the recipient handed over out of band. */
export function directChannel(owner: bigint, secret: Uint8Array): Outgoing {
  if (secret.length !== SECRET_BYTES || !(owner > 0n && owner < P)) {
    throw new NotesError("a direct secret is 32 bytes for a nonzero owner key");
  }
  return outgoing(owner, secret.slice());
}

/** What selfChannel reads from a Scanner, named here since src/scan.ts imports this module. */
type ScanResult = {
  readonly keys: WalletKeys;
  readonly incoming: readonly { readonly kind: string; readonly nextIndex: bigint }[];
};

/**
 * The self channel of a wallet restored from its seed, or of a device taking over sending (one
 * device sends from an account at a time, and a saved channel is stale once another has sent),
 * after a scan to the finalized head. It skips the RESTORE_SKIP indices after the highest self
 * index found, which is safe only while every self payment that is not final yet, but may still
 * land, has a lower index than the one it resumes at. Until one of its self payments is final, a
 * device that resumed this way sends from the index the next call returns, so before taking over
 * from it, wait until its self payments are final or can no longer land (a spend once its recent
 * root has left the window, a shield once its sender's nonce is used).
 */
export function selfChannel(scanner: ScanResult): Outgoing {
  const found = scanner.incoming.find((i) => i.kind === "self");
  if (found === undefined) throw new NotesError("the wallet state has no self channel");
  const nextIndex = found.nextIndex + BigInt(RESTORE_SKIP);
  const { ownerPk, selfSecret } = scanner.keys;
  return outgoing(ownerPk, selfSecret, { nextIndex, confirmed: found.nextIndex });
}

/** Records that the payment carrying `index` is final and succeeded, so the channel is open. */
export function finalized(channel: Outgoing, index: bigint): void {
  if (!(index >= 0n && index < channel.nextIndex)) {
    throw new NotesError("that index was never reserved on this channel");
  }
  channel.ciphertext = EMPTY;
  channel.ciphertextSent = false;
  channel.confirmed = maxBigint(channel.confirmed, index + 1n);
}

/**
 * Seals the channel's next note and advances its index. Save the state before broadcasting the
 * note: an index used twice repeats its tag, key and rho. Retry a payment that did not land with
 * its existing note, so that both attempts carry the same bytes and spend the same inputs, and at
 * most one lands; two transactions with one ciphertext would also be linked.
 */
export function reserve(channel: Outgoing, value: bigint) {
  if (channel.ciphertextSent) {
    throw new NotesError(
      "this channel's opening payment is not final yet: retry that payment with its note, or " +
        "open a new channel, since two transactions with one ciphertext are linked",
    );
  }
  if (channel.nextIndex >= channel.confirmed + BigInt(LOOKAHEAD)) {
    throw new NotesError(
      `${channel.nextIndex - channel.confirmed} payments on this channel are past the last ` +
        `final one, and the recipient watches only ${LOOKAHEAD} ahead: wait until one is ` +
        "final, or retry a payment with its existing note",
    );
  }
  const index = channel.nextIndex;
  const { note, rho } = sealNote(channel.secret, index, value);
  channel.nextIndex += 1n;
  channel.ciphertextSent = channel.ciphertext.length > 0;
  return { note, rho, index, ciphertext: channel.ciphertext };
}
