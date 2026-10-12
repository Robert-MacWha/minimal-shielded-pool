/**
 * The one-time authorizer's signature binds the complete intent of a spend: every envelope
 * field, every proof word, every settlement word and note, the recent-root tuple, the optional
 * fourth frame and the owner's signature. Each mutation below must change the signature hash,
 * and the original signature must not authorize the mutated transaction. The owner's signature
 * a fixture records is sent only for the chain, pool and intent it signs. Runs in about 0.6 s.
 *
 *   node --test test/pool-envelope-binding.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { compareBigint, concat, fromHex, keccak, toBigint, toBytes, toHex } from "../src/bytes.ts";
import {
  parsePrivateKey,
  rawTx,
  recoverSigner,
  SCHEME,
  SECP256K1_N,
  sigHash,
  signHash,
  type FrameTx,
} from "../src/frametx.ts";
import { parse } from "../src/json.ts";
import { InputError, PoolError } from "../src/errors.ts";
import { intentDigest, recentRootTuple, sourceId } from "../src/protocol.ts";
import {
  authorizerKey,
  entryProofBytes,
  ownerSignature,
  parseSpend,
  settleCalldata,
  signTransaction,
  spendFrames,
  spendNonceKeys,
  spendTailFrame,
  type Action,
} from "../src/spend.ts";

type Entry = Record<string, unknown>;
const fixture = parse(
  readFileSync(new URL("vectors/reference/smoke_fixture.json", import.meta.url), "utf8"),
) as Record<string, unknown>;
const POOL = BigInt(fixture.pool_address as string);
const hex = (bytes: Uint8Array) => toHex(bytes).slice(2);

/** One fixture spend with root_slot 1, signed by the authorizer its proof selects. */
function signed(key: string, action: Action | null = null, omit = false): FrameTx {
  const entry: Entry = { ...structuredClone(fixture[key] as Entry), root_slot: "1" };
  const settle = settleCalldata(entry, entry.root_slot);
  const source = sourceId(POOL, BigInt(entry.epoch as number));
  const recentRoot = recentRootTuple(source, 1n, BigInt(entry.root as string));
  const tail = spendTailFrame(POOL, settle, action, { omit });
  const tx = signTransaction(
    {
      chainId: BigInt(fixture.chain_id as number),
      nonceKeys: spendNonceKeys(settle),
      nonceSeq: 0n,
      sender: POOL,
      frames: spendFrames({ pool: POOL, recentRoot, proof: entryProofBytes(entry), settle, tail }),
      signatures: [],
      maxPriorityFee: 1n,
      maxFee: 10n,
      maxBlobFee: 0n,
      blobHashes: [],
    },
    parsePrivateKey(entry.authorizer_private_key, "the fixture key"),
  );
  const nullifiers = [BigInt(entry.nf1 as string), BigInt(entry.nf2 as string)];
  assert.deepEqual(tx.nonceKeys, nullifiers.sort(compareBigint));
  assert.equal(tx.signatures[0].signer, BigInt(entry.authorizer as string));
  return tx;
}

type Mutation = [name: string, mutate: (tx: FrameTx) => void];

/** Flips the lowest bit of the byte at `at` in frame `f`'s data. */
const flip = (f: number, at: number) => (x: FrameTx) => void (x.frames[f].data[at] ^= 1);

/** Moves each field of frame `i` but its data to another value. */
const frameMutations = (name: string, i: number): Mutation[] =>
  (["mode", "flags", "target", "gasLimit", "stateLimit", "value"] as const).map((field) => [
    `${name}_${field}`,
    (x) => void (x.frames[i][field] = (x.frames[i][field] as bigint) ^ 1n),
  ]);

function commonMutations(tx: FrameTx): Mutation[] {
  const strides = Math.ceil((tx.frames[2].data.length - (4 + 12 * 32)) / 48);
  return [
    ["chain_id", (x) => void (x.chainId += 1n)],
    ["nonce_key", (x) => void (x.nonceKeys[0] ^= 1n)],
    ["nonce_seq", (x) => void (x.nonceSeq = 1n)],
    ["sender", (x) => void (x.sender ^= 1n)],
    ...frameMutations("root_frame", 0),
    // One byte inside each field of the tuple source_id (32) || slot (8) || root (32), so
    // each mutation changes only the field it names.
    ["root_source", flip(0, 0)],
    ["root_slot", flip(0, 32)],
    ["root_value", flip(0, 40)],
    ...frameMutations("verify", 1),
    // Eight proof words, then hybrid compression's beta.
    ...Array.from({ length: 9 }, (_, w): Mutation => [`proof_word_${w}`, flip(1, w * 32)]),
    ...frameMutations("settle", 2),
    ...Array.from({ length: 12 }, (_, w): Mutation => [`settle_word_${w}`, flip(2, 4 + w * 32)]),
    // After the twelve words come the notes, in the transfer a 1088-byte ML-KEM ciphertext and
    // then two 48-byte notes. Flip one byte in every 48 of those bytes.
    ...Array.from({ length: strides }, (_, i): Mutation => [
      `notes_byte_${48 * i}`,
      flip(2, 388 + 48 * i),
    ]),
    ["signature_scheme", (x) => void (x.signatures[0].scheme = SCHEME.P256)],
    ["signature_signer", (x) => void (x.signatures[0].signer ^= 1n)],
    ["signature_message", (x) => void (x.signatures[0].msg = new Uint8Array(32).fill(1))],
    ["priority_fee", (x) => void (x.maxPriorityFee = 2n)],
    ["max_fee", (x) => void (x.maxFee = 11n)],
    ["blob_fee", (x) => void (x.maxBlobFee = 1n)],
    ["blob_hashes", (x) => void x.blobHashes.push(new Uint8Array(32).fill(1))],
  ];
}

const claimMutations: Mutation[] = [
  ...frameMutations("claim", 3),
  ["claim_selector", flip(3, 0)],
  ["claim_recipient", (x) => flip(3, x.frames[3].data.length - 1)(x)],
];

const actionMutations: Mutation[] = [
  ...frameMutations("action", 3),
  ["action_calldata", (x) => void (x.frames[3].data = Uint8Array.of(...x.frames[3].data, 0))],
  ["action_removed", (x) => void x.frames.pop()],
  ["action_duplicated", (x) => void x.frames.push(structuredClone(x.frames[3]))],
];

const ACTION: Action = {
  target: 0xa11cen,
  data: new Uint8Array([0x12, 0x34, 0x56, 0x78, ...Buffer.from("owner-authorized-action")]),
  gasLimit: 300_000n,
  stateLimit: 100_000n,
};

// Each spend's signature hash and whole signed transaction are also the Python client's
// (test_pool_envelope_binding._signed at commit 2386147, with cast's settle calldata and
// eth-keys 0.7.0's RFC 6979 signatures), so the bound transaction is the one it signed.
const spends: [
  name: string,
  build: () => FrameTx,
  tail: Mutation[],
  bound: number,
  sigHash: string,
  rawKeccak: string,
][] = [
  [
    "transfer: three frames",
    () => signed("transfer"),
    [],
    78,
    "50bff46fdd226f3b3a008968f82e75341daa51af2b3b137236b8dd2ddeec63c7",
    "a112871a6a09e3dfef2748758c3ed964f697c8a61b617eb050c89d7e3eb690fd",
  ],
  [
    "transfer with a gas-only action: four frames",
    () => signed("transfer", ACTION),
    actionMutations,
    87,
    "da502e7538ad333fa99d267bff2ace16af330bdfccff0a6235d3c5c451233ce2",
    "d5ed41e89bc63b9dfd74848975614b068d513f0da8d2e9329ecc9792f96f2f2f",
  ],
  [
    "withdraw with the default claim: four frames",
    () => signed("withdraw"),
    claimMutations,
    63,
    "c996c0fb2e0756bd4362d26af47946c8d3d126f0302ec11144a1f0246633901a",
    "b64ec2261387e24e4734bcdb47814aaa98487c6c673f03cffb2f65b9ec6da40e",
  ],
  [
    "withdraw without a tail: three frames",
    () => signed("withdraw", null, true),
    [],
    55,
    "400cc451e05a9be87ee9acf7cbecdc46ed7943271a6713c02da036302af65ba9",
    "6889b7676ea78afd035295e848f076467bc8736b2a11fef388741a9603347c5c",
  ],
  [
    "withdraw with a custom action: four frames",
    () => signed("withdraw", ACTION),
    actionMutations,
    64,
    "b38d3a7b271d034ff03fc195fc334d0421b15c7d19cc674d10d2242b87827207",
    "4fd5c92d9a2b9d1163e751df9287f637e64a8c13ffa07e7072ad3f053eb8835f",
  ],
];

for (const [name, build, tail, bound, pinnedSigHash, pinnedRawKeccak] of spends) {
  test(`${name}, ${bound} bound fields`, () => {
    const tx = build();
    const original = sigHash(tx);
    assert.equal(hex(original), pinnedSigHash);
    assert.equal(hex(keccak(rawTx(tx))), pinnedRawKeccak);
    const authorizer = tx.signatures[0].signer;
    const sig = tx.signatures[0].signature;
    assert.equal(recoverSigner(original, sig), authorizer);
    const mutations = [...commonMutations(tx), ...tail];
    assert.equal(mutations.length, bound);
    for (const [field, mutate] of mutations) {
      const candidate = structuredClone(tx);
      mutate(candidate);
      const hash = sigHash(candidate);
      assert.notEqual(hex(hash), hex(original), `signature hash did not bind ${field}`);
      assert.notEqual(recoverSigner(hash, sig), authorizer, `old signature authorized ${field}`);
    }
    // The hash cannot cover the signature it is about to receive, so the bytes of an empty-msg
    // signature are left out of it.
    const resigned = structuredClone(tx);
    resigned.signatures[0].signature[1] ^= 1;
    assert.equal(hex(sigHash(resigned)), hex(original));
  });
}

test("refuses an authorizer key that does not match the proof's authorizer", () => {
  const entry = structuredClone(fixture.transfer as Entry);
  const other = fixture.withdraw as Entry;
  assert.notEqual(entry.authorizer, other.authorizer);
  entry.authorizer_private_key = other.authorizer_private_key;
  assert.throws(
    () => authorizerKey(entry),
    (error) => error instanceof PoolError && /does not match the proof public/.test(error.message),
  );
});

// A field read loosely would sign a spend the entry does not state, so each loose form is refused.
test("refuses spend entry fields written in a loose form", () => {
  const entry: Entry = { ...(fixture.transfer as Entry), root_slot: "1" };
  for (const [field, value, text] of [
    ["root", "0x01", "root must be 32 bytes"],
    ["fee", "0b1", "fee must be 0x hex or decimal without leading zeros"],
    ["fee", " 5", "fee must be 0x hex or decimal without leading zeros"],
    ["fee", "05", "fee must be 0x hex or decimal without leading zeros"],
    ["root_slot", -1, "root_slot must be a non-negative decimal integer"],
  ] as const) {
    const refused = (error: unknown) => error instanceof InputError && error.message.includes(text);
    const changed: Entry = { ...entry, [field]: value };
    assert.throws(() => settleCalldata(changed, changed.root_slot), refused, `${field} ${value}`);
  }
  // Proof rows are arrays; an object keyed "0" and "1" is not read as one.
  const [x, y] = (entry.proof as Entry).pA as string[];
  const proof = { ...(entry.proof as Entry), pA: { 0: x, 1: y } };
  assert.throws(() => entryProofBytes({ ...entry, proof }), /proof pA must be 0x-prefixed hex/);
});

// The committed fixture's spends carry the owner's signature, after the authorizer's.
const smoke = parse(
  readFileSync(new URL("fixtures/smoke_fixture.json", import.meta.url), "utf8"),
) as Record<string, unknown>;
const SMOKE_CHAIN = BigInt(smoke.chain_id as number);
const SMOKE_POOL = BigInt(smoke.pool_address as string);

/** The committed fixture's transfer with root_slot 1, signed by its authorizer and its owner. */
function ownerSigned(): FrameTx {
  const entry: Entry = { ...structuredClone(smoke.transfer as Entry), root_slot: "1" };
  const settle = settleCalldata(entry, entry.root_slot);
  const source = sourceId(SMOKE_POOL, BigInt(entry.epoch as number));
  const recentRoot = recentRootTuple(source, 1n, BigInt(entry.root as string));
  const frames = spendFrames({
    pool: SMOKE_POOL,
    recentRoot,
    proof: entryProofBytes(entry),
    settle,
  });
  const tx: FrameTx = {
    chainId: SMOKE_CHAIN,
    nonceKeys: spendNonceKeys(settle),
    nonceSeq: 0n,
    sender: SMOKE_POOL,
    frames,
    signatures: [],
    maxPriorityFee: 1n,
    maxFee: 10n,
    maxBlobFee: 0n,
    blobHashes: [],
  };
  const owner = ownerSignature(entry, SMOKE_CHAIN, SMOKE_POOL);
  return signTransaction(tx, authorizerKey(entry), owner);
}

test("the authorizer's signature binds the owner's signature, which comes second", () => {
  const tx = ownerSigned();
  const [authorizer, owner] = tx.signatures;
  const original = sigHash(tx);
  assert.equal(recoverSigner(original, authorizer.signature), authorizer.signer);
  // The owner signs the intent digest it carries, not the transaction hash.
  assert.equal(recoverSigner(owner.msg, owner.signature), owner.signer);
  const ownerMutations: Mutation[] = [
    ["owner_scheme", (x) => void (x.signatures[1].scheme = SCHEME.P256)],
    ["owner_signer", (x) => void (x.signatures[1].signer ^= 1n)],
    ["owner_message", (x) => void (x.signatures[1].msg[31] ^= 1)],
    ["owner_signature", (x) => void (x.signatures[1].signature[64] ^= 1)],
    ["owner_removed", (x) => void x.signatures.pop()],
    ["owner_repeated", (x) => void x.signatures.push(structuredClone(x.signatures[1]))],
  ];
  for (const [field, mutate] of ownerMutations) {
    const candidate = structuredClone(tx);
    mutate(candidate);
    const hash = sigHash(candidate);
    assert.notEqual(hex(hash), hex(original), `signature hash did not bind ${field}`);
    assert.notEqual(recoverSigner(hash, authorizer.signature), authorizer.signer, field);
  }
  // Only the authorizer's own bytes, which sign the hash, are left out of it.
  const resigned = structuredClone(tx);
  resigned.signatures[0].signature[1] ^= 1;
  assert.equal(hex(sigHash(resigned)), hex(original));
});

test("an owner signature is sent only for the chain, pool and intent it signs", () => {
  const entry = smoke.transfer as Entry;
  const owner = ownerSignature(entry, SMOKE_CHAIN, SMOKE_POOL);
  const spend = parseSpend(entry, 0n);
  assert.deepEqual(owner.msg, intentDigest(SMOKE_CHAIN, SMOKE_POOL, spend));
  assert.equal(owner.signer, BigInt(entry.owner as string));
  const signature = fromHex(entry.owner_signature, "the owner signature");
  const n = SECP256K1_N;
  // The same signature with s mirrored and v flipped recovers the same key, but EIP-8141 takes
  // only low s.
  const s = toBigint(signature.subarray(33));
  const mirrored = concat(
    Uint8Array.of(signature[0] ^ 1),
    signature.subarray(1, 33),
    toBytes(n - s, 32),
  );
  assert.equal(recoverSigner(owner.msg, mirrored), owner.signer);
  const other = signHash(owner.msg, new Uint8Array(32).fill(7));
  const refusals: [string, unknown, bigint, bigint][] = [
    ["another chain", entry, SMOKE_CHAIN + 1n, SMOKE_POOL],
    ["another pool", entry, SMOKE_CHAIN, SMOKE_POOL ^ 1n],
    ["another fee", { ...entry, fee: String(spend.fee + 1n) }, SMOKE_CHAIN, SMOKE_POOL],
    ["another key", { ...entry, owner_signature: toHex(other) }, SMOKE_CHAIN, SMOKE_POOL],
    ["high s", { ...entry, owner_signature: toHex(mirrored) }, SMOKE_CHAIN, SMOKE_POOL],
    [
      "v = 2",
      { ...entry, owner_signature: toHex(Uint8Array.of(2, ...signature.subarray(1))) },
      SMOKE_CHAIN,
      SMOKE_POOL,
    ],
  ];
  for (const [label, changed, chain, pool] of refusals) {
    assert.throws(
      () => ownerSignature(changed, chain, pool),
      (error) =>
        error instanceof PoolError && /does not sign this spend's intent/.test(error.message),
      label,
    );
  }
  const short = { ...entry, owner_signature: toHex(signature.subarray(1)) };
  assert.throws(() => ownerSignature(short, SMOKE_CHAIN, SMOKE_POOL), InputError);
});
