/**
 * Owner sets. A note belongs to the owner set its owner key names (protocol.ownerPk): a
 * depth-16 Poseidon tree of one-time secp256k1 addresses whose keys a signing device holds, with
 * 0 in unused leaves. A spend reveals one unused address, the owner, and carries the owner's
 * EIP-8141 signature over the spend's EIP-712 intent (protocol.intentDigest), which the pool
 * requires. The wallet that proves needs the set's addresses, never their keys.
 *
 * Each address signs one spend: the pool publishes it, so a second spend from it would be linked
 * to the first. Notes of two owner sets cannot be spent together, since both inputs share one
 * set, and a set allows at most 2^16 spends over its life.
 *
 * SoftwareOwner stands in for the device in fixtures and tests. Its keys come from a seed the
 * fixture records, so it keeps no key apart from the wallet that proves.
 */
import * as crypto from "node:crypto";

import { concat, toBigint, word } from "./bytes.ts";
import { addressOf, SECP256K1_N, signHash } from "./frametx.ts";
import { OWNER_DEPTH } from "./protocol.ts";
import { Tree, type OwnerLeaf } from "./wallet.ts";

const LABEL = "minimal-shielded-pool:owner:v1:";
export const OWNER_SET_CAPACITY = 2 ** OWNER_DEPTH;

/** A leaf of an owner set, with its index. */
export type IndexedLeaf = OwnerLeaf & { index: number };

/** What holds an owner set's keys: it signs a 32-byte digest with leaf `index`'s key. */
export interface OwnerSigner {
  sign(index: number, digest: Uint8Array): Uint8Array;
}

/** An owner set built from its addresses in leaf order; leaves past them are empty. */
export class OwnerSet {
  readonly addresses: readonly bigint[];
  readonly root: bigint;
  readonly #tree = new Tree(OWNER_DEPTH);

  constructor(addresses: readonly bigint[]) {
    if (addresses.length === 0 || addresses.length > OWNER_SET_CAPACITY) {
      throw new RangeError(`an owner set holds 1 to ${OWNER_SET_CAPACITY} addresses`);
    }
    // An empty leaf is 0, which the circuit refuses as an owner, so no address may be 0.
    if (!addresses.every((a) => a > 0n && a < 1n << 160n)) {
      throw new RangeError("an owner set's addresses are nonzero 160-bit integers");
    }
    if (new Set(addresses).size !== addresses.length) {
      throw new RangeError("an owner set's addresses are distinct");
    }
    for (const address of addresses) this.#tree.append(address);
    this.addresses = Object.freeze([...addresses]);
    this.root = this.#tree.root();
  }

  /** The leaf at `index`, as a witness takes it. */
  leaf(index: number): IndexedLeaf {
    const address = this.addresses[index];
    if (address === undefined) throw new RangeError(`the owner set has no leaf ${index}`);
    return { root: this.root, address, index, path: this.#tree.authPath(BigInt(index)) };
  }
}

/** Leaf `index`'s key: 512 HMAC-SHA256 bits of the seed, reduced into [1, n). */
function ownerKey(seed: Uint8Array, index: number): Uint8Array {
  const half = (part: number) =>
    crypto.createHmac("sha256", seed).update(`${LABEL}key|${index}|${part}`).digest();
  return word(1n + (toBigint(concat(half(0), half(1))) % (SECP256K1_N - 1n)));
}

/** A device's stand-in for fixtures: `size` one-time keys from a seed, used in leaf order. */
export class SoftwareOwner implements OwnerSigner {
  readonly set: OwnerSet;
  readonly #keys: readonly Uint8Array[];
  #used = 0;

  constructor(seed: Uint8Array, size: number) {
    if (seed.length < 32) throw new RangeError("an owner seed has at least 32 bytes");
    if (!Number.isSafeInteger(size) || size < 1 || size > OWNER_SET_CAPACITY) {
      throw new RangeError(`an owner set holds 1 to ${OWNER_SET_CAPACITY} addresses`);
    }
    this.#keys = Array.from({ length: size }, (_, i) => ownerKey(seed, i));
    this.set = new OwnerSet(this.#keys.map(addressOf));
  }

  /** The next leaf no spend has revealed; each signs one spend. */
  nextLeaf(): IndexedLeaf {
    if (this.#used === this.#keys.length) {
      throw new RangeError("every address of this owner set has signed a spend");
    }
    return this.set.leaf(this.#used++);
  }

  /** Leaf `index`'s signature over a 32-byte digest: v || r || s with low s, as EIP-8141 takes. */
  sign(index: number, digest: Uint8Array): Uint8Array {
    const key = this.#keys[index];
    if (key === undefined) throw new RangeError(`the owner set has no leaf ${index}`);
    return signHash(digest, key);
  }
}
