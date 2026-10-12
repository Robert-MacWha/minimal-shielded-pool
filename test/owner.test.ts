/**
 * Owner sets and the owner's spend intent. An owner set's root and paths follow from its
 * addresses, and its constructor refuses an address the circuit could not use. A software
 * owner's keys follow from its seed, each leaf is handed out once, and its signatures recover to
 * the leaf's address with low s. The intent digest is EIP-712's: Foundry's cast, an independent
 * implementation, signs the same typed data to the signature SoftwareOwner's signHash gives
 * the digest, and the dispatcher holds the same type hashes. Needs cast on PATH. Runtime: about 1 s.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { hex32, keccak, toBigint, toHex } from "../src/bytes.ts";
import {
  addressOf,
  checksumAddress,
  recoverSigner,
  SECP256K1_N,
  signHash,
} from "../src/frametx.ts";
import { OwnerSet, SoftwareOwner } from "../src/owner.ts";
import * as protocol from "../src/protocol.ts";
import { OwnerTree } from "../src/wallet.ts";

const utf8 = (text: string) => new TextEncoder().encode(text);
const SEED = keccak(utf8("owner test seed"));

test("an owner set's root and paths follow from its addresses in leaf order", () => {
  const addresses = [5n, 7n, (1n << 160n) - 1n];
  const set = new OwnerSet(addresses);
  const tree = new OwnerTree(protocol.OWNER_DEPTH);
  for (const address of addresses) tree.append(address);
  assert.equal(set.root, tree.root());
  assert.notEqual(new OwnerSet([7n, 5n, (1n << 160n) - 1n]).root, set.root);
  addresses.forEach((address, index) => {
    const leaf = set.leaf(index);
    assert.deepEqual(leaf, { root: set.root, address, index, path: tree.authPath(BigInt(index)) });
    let node = address;
    leaf.path.bits.forEach((bit, d) => {
      const sibling = leaf.path.siblings[d];
      node = bit === 0 ? protocol.p2(node, sibling) : protocol.p2(sibling, node);
    });
    assert.equal(node, set.root, `leaf ${index}`);
  });
  for (const index of [-1, 3, 1.5]) assert.throws(() => set.leaf(index), /has no leaf/);
});

test("an owner set refuses what no signature could come from, or what would repeat", () => {
  // 0 is an empty leaf, which the circuit refuses as an owner.
  for (const addresses of [[], [0n], [1n << 160n], [-1n], [3n, 3n]]) {
    assert.throws(() => new OwnerSet(addresses), RangeError, `${addresses}`);
  }
});

test("a software owner's keys follow from its seed, and each leaf is handed out once", () => {
  const owner = new SoftwareOwner(SEED, 3);
  assert.equal(new SoftwareOwner(SEED, 3).set.root, owner.set.root);
  assert.notEqual(new SoftwareOwner(keccak(SEED), 3).set.root, owner.set.root);
  // A larger set from the same seed starts with the same addresses.
  assert.deepEqual(new SoftwareOwner(SEED, 4).set.addresses.slice(0, 3), owner.set.addresses);
  assert.deepEqual(
    [0, 1, 2].map(() => owner.nextLeaf().index),
    [0, 1, 2],
  );
  assert.throws(() => owner.nextLeaf(), /every address of this owner set has signed/);
  assert.throws(() => new SoftwareOwner(SEED.slice(1), 1), /at least 32 bytes/);
  for (const size of [0, 2 ** protocol.OWNER_DEPTH + 1, 1.5]) {
    assert.throws(() => new SoftwareOwner(SEED, size), RangeError, `${size}`);
  }
});

test("a software owner signs with the leaf's key, low s and v 0 or 1", () => {
  const owner = new SoftwareOwner(SEED, 2);
  for (const index of [0, 1]) {
    for (const message of ["a", "b", "c", "d"]) {
      const digest = keccak(utf8(`${message}${index}`));
      const signature = owner.sign(index, digest);
      assert.equal(signature.length, 65);
      assert.ok(signature[0] <= 1);
      assert.ok(toBigint(signature.subarray(33)) <= SECP256K1_N / 2n);
      assert.equal(recoverSigner(digest, signature), owner.set.addresses[index]);
    }
  }
  assert.throws(() => owner.sign(2, keccak(SEED)), /has no leaf 2/);
});

/** eth_signTypedData_v4's JSON for an intent, written here from EIP-712, not from src/. */
function typedData(chainId: bigint, pool: bigint, intent: protocol.Intent) {
  const field = (name: string, type: string) => ({ name, type });
  return {
    types: {
      EIP712Domain: [
        field("name", "string"),
        field("chainId", "uint256"),
        field("verifyingContract", "address"),
      ],
      Spend: [
        field("nullifier1", "bytes32"),
        field("nullifier2", "bytes32"),
        field("output1", "bytes32"),
        field("output2", "bytes32"),
        field("amount", "uint256"),
        field("recipient", "address"),
        field("fee", "uint256"),
      ],
    },
    primaryType: "Spend",
    domain: {
      name: "Minimal Shielded Pool",
      chainId: String(chainId),
      verifyingContract: checksumAddress(pool),
    },
    message: {
      nullifier1: hex32(intent.nf1),
      nullifier2: hex32(intent.nf2),
      output1: hex32(intent.outCm1),
      output2: hex32(intent.outCm2),
      amount: String(intent.publicAmount),
      recipient: checksumAddress(intent.recipient),
      fee: String(intent.fee),
    },
  };
}

test("cast signs the intent's typed data to the signature of the intent digest", () => {
  const key = keccak(utf8("owner test key"));
  const field = (label: string) => toBigint(keccak(utf8(label))) % protocol.P;
  const intents: [bigint, bigint, protocol.Intent][] = [
    [
      8141n,
      0x5ec4723ba24043065b30aef3c3b71a6030b3de09n,
      {
        ...{ nf1: field("nf1"), nf2: field("nf2"), outCm1: field("o1"), outCm2: field("o2") },
        ...{ publicAmount: 55n * 10n ** 16n, recipient: 0xcafebaben, fee: 5n * 10n ** 16n },
      },
    ],
    [
      1n,
      1n,
      { nf1: 1n, nf2: 2n, outCm1: 3n, outCm2: 4n, publicAmount: 0n, recipient: 0n, fee: 0n },
    ],
  ];
  for (const [chainId, pool, intent] of intents) {
    const digest = protocol.intentDigest(chainId, pool, intent);
    const json = JSON.stringify(typedData(chainId, pool, intent));
    const args = ["wallet", "sign", "--data", json, "--private-key", toHex(key)];
    // cast writes r || s || v with v as 27 or 28; EIP-8141 takes v || r || s with v as 0 or 1.
    const cast = execFileSync("cast", args, { encoding: "utf8" }).trim();
    const v = parseInt(cast.slice(-2), 16) - 27;
    const signature = signHash(digest, key);
    assert.equal(toHex(signature), "0x0" + v + cast.slice(2, -2), `chain ${chainId}`);
    assert.equal(recoverSigner(digest, signature), addressOf(key));
  }
});

test("the dispatcher holds the intent's type hashes and domain name hash", () => {
  const yul = readFileSync(
    new URL("../core/dispatcher/ShieldedPoolDispatcher.yul", import.meta.url),
    "utf8",
  );
  for (const text of [
    protocol.INTENT_TYPE,
    protocol.INTENT_DOMAIN_TYPE,
    protocol.INTENT_DOMAIN_NAME,
  ]) {
    assert.ok(yul.includes(toHex(keccak(utf8(text)))), text);
  }
  assert.ok(yul.includes("mstore(0, shl(240, 0x1901))"));
});
