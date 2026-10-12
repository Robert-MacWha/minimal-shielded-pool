// Checks the TypeScript client against the pinned reference vectors in test/vectors/reference/.
// An earlier implementation, the Python client this one replaced (commit 2386147), computed them,
// so they are never regenerated from the code under test: a deliberate encoding change updates the
// affected vectors by hand, in the same commit, with the reason (see the README there). Every
// expected value comes from those files; nothing here asks the code under test for its own
// answer. Runtime: about 0.4 s.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { keccak_256 } from "@noble/hashes/sha3.js";

import { InputError, NotesError, UserError } from "../src/errors.ts";
import * as ft from "../src/frametx.ts";
import * as gas from "../src/gas.ts";
import * as notes from "../src/notes.ts";
import { OwnerSet } from "../src/owner.ts";
import { poseidon } from "../src/poseidon.ts";
import * as pr from "../src/protocol.ts";
import * as spend from "../src/spend.ts";
import { RepeatedTree, Tree, buildWitness, type MerkleTree } from "../src/wallet.ts";

type Json = any; // the vector files are untyped JSON

const load = (name: string): Json =>
  JSON.parse(readFileSync(new URL(`./vectors/reference/${name}`, import.meta.url), "utf8"));

// Hex and keccak here are Node's and noble's, not the client's bytes.ts.
const bytes = (text: string): Uint8Array => new Uint8Array(Buffer.from(text.slice(2), "hex"));
const hex = (data: Uint8Array): string => "0x" + Buffer.from(data).toString("hex");
const big = (text: string): bigint => BigInt(text);

/** A vector's integers as bigints, through arrays and objects. */
function bigs(x: Json): Json {
  if (typeof x === "string") return BigInt(x);
  if (x === null || typeof x !== "object") return x;
  if (Array.isArray(x)) return x.map(bigs);
  return Object.fromEntries(Object.entries(x).map(([k, y]) => [k, bigs(y)]));
}

/** The bytes a vector's data stands for: hex, or a prefix then a pattern repeated to a length. */
function expand(data: Json): Uint8Array {
  if (typeof data === "string") return bytes(data);
  const [prefix, pattern] = [bytes(data.prefix ?? "0x"), bytes(data.pattern)];
  return Uint8Array.from({ length: data.length }, (_, i) =>
    i < prefix.length ? prefix[i] : pattern[(i - prefix.length) % pattern.length],
  );
}

/** A value as the vectors write it: integers in decimal, bytes in hex, sets sorted, maps as pairs. */
function plain(value: unknown): Json {
  const json = JSON.stringify(value, (_, v) => {
    if (typeof v === "bigint" || typeof v === "number") return String(v);
    if (v instanceof Uint8Array) return hex(v);
    if (v instanceof Set) return [...v].map(String).sort();
    return v instanceof Map ? [...v] : v;
  });
  return JSON.parse(json);
}
const same = (got: unknown, want: unknown, message?: string) =>
  assert.deepEqual(plain(got), plain(want), message);

/** Runs `check` on every case of a non-empty vector group, naming the case in any failure. */
function each(cases: Json[], check: (c: Json) => void): void {
  assert.ok(cases.length > 0, "a vector group is empty");
  cases.forEach((c, i) => {
    try {
      check(c);
    } catch (error) {
      if (error instanceof Error) error.message = `${c.name ?? c.source ?? i}: ${error.message}`;
      throw error;
    }
  });
}

/**
 * The vector records a refusal of this input: the client must refuse it too, with an error of
 * `kind`. "bug" is a broken caller invariant (recorded as an assertion failure), any error but a
 * UserError; "own" is one the function checks itself and throws as a plain Error, so a TypeError
 * or a helper's RangeError further down does not count.
 */
type Kind = (new (...args: never[]) => Error) | "bug" | "own";
function refuses(fn: () => unknown, kind: Kind): void {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof Error, `threw a non-Error: ${String(error)}`);
    const ok =
      kind === "bug"
        ? !(error instanceof UserError)
        : kind === "own"
          ? error.constructor === Error
          : error instanceof kind;
    const want = typeof kind === "string" ? kind : kind.name;
    assert.ok(ok, `expected ${want}, got ${error.name}: ${error.message}`);
    return true;
  });
}

/**
 * A vector's `error` names the exception class the reference implementation raised, which is a
 * Python class name; this map translates it to the client's error kind. NotesError stays
 * NotesError, OverflowError (an integer past its 32-byte word) becomes RangeError, and any other
 * class may be any Error.
 */
const REFERENCE_ERROR_KINDS: Record<string, Kind> = { NotesError, OverflowError: RangeError };

/**
 * {out} must equal what `run` returns and {error} must throw `kind`, by default the kind
 * REFERENCE_ERROR_KINDS gives the recorded class.
 */
function outcome(c: Json, run: () => unknown, kind?: Kind): void {
  if ("error" in c) refuses(run, kind ?? REFERENCE_ERROR_KINDS[c.error] ?? Error);
  else same(run(), c.out);
}
const outcomes = (cases: Json[], run: (c: Json) => unknown, kind?: Kind) =>
  each(cases, (c) => outcome(c, () => run(c), kind));

/** One test per named vector group (or single case), each case checked by `outcome`. */
function groups(v: Json, rows: Record<string, [(c: Json) => unknown, Kind?]>): void {
  for (const [name, [run, kind]] of Object.entries(rows)) {
    test(name, () => outcomes([v[name]].flat(), run, kind));
  }
}

// ===================================================================== protocol.json

describe("protocol hashes (protocol.json)", () => {
  const v = load("protocol.json");
  const beta = (c: Json) => pr.compressionBeta(bigs(c.in));

  groups(v, {
    poseidon: [(c) => poseidon(bigs(c.in)), RangeError],
    // The Python client's owner key, Poseidon(1, spend_key, 0), is the owner key of the owner
    // set with root spend_key under the nullifier key 0, so these cases still pin its hashes.
    notes: [
      (c) => {
        const { sk, rho, value } = bigs(c.in);
        const ownerPk = pr.ownerPk(sk, 0n);
        const commitment = pr.commitment(ownerPk, rho, value);
        return { ownerPk, inner: pr.inner(ownerPk, rho), commitment };
      },
    ],
    // The Python client derived the nullifier from the spend key as this one does from nk.
    nullifiers: [
      (c) => {
        const { domain, sk: nk, cm, index } = bigs(c.in);
        if ("error" in c) return pr.nullifier(domain, nk, cm, index);
        const key = pr.domainKey(domain, nk);
        const fromKey = pr.nullifierFromKey(key, cm, index);
        return { key, nullifier: pr.nullifier(domain, nk, cm, index), fromKey };
      },
      InputError,
    ],
    // Pools as integers and as 0x + 40 hex digits.
    domains: [
      ({ in: d }) => {
        const poolArg = typeof d.pool === "string" ? d.pool : big(d.pool.int);
        return pr.domainScalar(big(d.chain), poolArg, big(d.epoch));
      },
      InputError,
    ],
    statements: [
      (c) => {
        const stmt = pr.statement(bigs(c.in));
        const [alpha, beta] = [pr.compressionAlpha(stmt), pr.compressionBeta(stmt)];
        const gamma = pr.fingerprint((alpha + beta) % pr.P, stmt);
        return { statement: stmt, alpha, beta, gamma };
      },
    ],
    alphaErrors: [(c) => pr.compressionAlpha(bigs(c.in)), "bug"],
    betaErrors: [beta, "bug"],
    betaAliased: [beta],
    fingerprints: [(c) => pr.fingerprint(big(c.in.sigma), bigs(c.in.stmt))],
    spendHashes: [
      ({ in: s }) => ({
        nullifiers: pr.inputNullifiers(big(s.domain), big(s.owner_root), bigs(s.inputs)),
        commitments: pr.outputCommitments(bigs(s.outputs)),
      }),
    ],
    // EIP-8272 source ids, tuples, entries and storage keys.
    recentRoots: [
      (c) => {
        const { pool, epoch, slot, root } = bigs(c.in);
        const source = pr.sourceId(pool, epoch);
        return {
          sourceId: source,
          tuple: pr.recentRootTuple(source, slot, root),
          entry: pr.recentRootEntry(source, slot, root),
          storageKey: pr.recentRootStorageKey(source, slot),
        };
      },
    ],
  });

  test("sink outputs and commitments", () =>
    same({ outputs: pr.sinkOutputs(), commitments: pr.sinkCommitments() }, v.sinks));

  test("constants, selectors, topics and the gas profile", () => {
    const { EMPTY_TREE_ROOT, gas: profile, ...constants } = v.constants;
    same(new Tree().root(), EMPTY_TREE_ROOT);
    for (const [name, want] of Object.entries(constants)) same((pr as Json)[name], want, name);
    // The vectors spell ETHREX as ETHEX, and pin CLAIM_WITHDRAWAL_CALLDATA, the claim's
    // calldata length, which the client has no constant for since its encoder fixes it.
    for (const [name, want] of Object.entries(profile)) {
      const ours = (gas as Json)[name.replace("ETHEX", "ETHREX")];
      same(name === "CLAIM_WITHDRAWAL_CALLDATA" ? pr.encodeClaim(1n).length : ours, want, name);
    }
  });
});

// ===================================================================== wallet.json

describe("trees and witnesses (wallet.json)", () => {
  const v = load("wallet.json");

  /** A vector path: null is the empty subtree of that height, "u" the repeated one. */
  function expectPaths(tree: MerkleTree, paths: Json[]): void {
    for (const p of paths) {
      const siblings = p.siblings.map((s: string | null, height: number) =>
        s === null ? v.zeros[height] : s === "u" ? v.uniform[height] : s,
      );
      same(tree.authPath(big(p.index)), { siblings, bits: p.bits }, `path of ${p.index}`);
    }
  }

  test("roots and authentication paths of trees of 0 to 40 leaves", () =>
    each(v.trees, (c) => {
      const tree = new Tree();
      c.leaves.forEach((leaf: string, i: number) =>
        assert.equal(tree.append(big(leaf)), BigInt(i)),
      );
      same(tree.root(), c.root);
      expectPaths(tree, c.paths);
    }));

  test("repeated-leaf trees up to 2^20 leaves, with extras past the boundary", () =>
    each(v.repeated, (c) => {
      const tree = new RepeatedTree(big(c.cm), big(c.count), bigs(c.extras));
      same([tree.uniform, tree.root()], [v.uniform, c.root]);
      expectPaths(tree, c.paths);
    }));

  test("a tree takes 2^20 leaves and refuses one more", () => {
    const { leaf, lastIndex } = v.fullTree;
    const tree = new Tree();
    let last = -1n;
    for (let i = 0; i <= Number(lastIndex); i++) last = tree.append(big(leaf));
    same(last, lastIndex);
    outcome(v.fullTree, () => tree.append(big(leaf)), "own");
  });

  /** A witness from a case; the owner set and its leaf come from `owner`, the first case's. */
  const witness = (c: Json, { leaves, domain, owner } = c) => {
    const tree = new Tree();
    for (const leaf of leaves) tree.append(big(leaf));
    const terms = {
      ...bigs(c.terms),
      owner: new OwnerSet(bigs(owner.addresses)).leaf(owner.index),
    };
    // The Python client's error cases name each input's nullifier key spend_key.
    const inputs = c.inputs.map(({ sk, ...input }: Json) => bigs({ nk: input.nk ?? sk, ...input }));
    return buildWitness(tree, inputs, bigs(c.outputs), big(domain), terms);
  };

  test("full circuit witnesses", () => each(v.witnesses, (c) => same(witness(c), c.witness)));

  // Each refusal must come from buildWitness's own checks, as each recorded one came from the
  // witness builder's: a later step refusing the same input (compressionAlpha on a negative
  // word) does not count.
  test("witnesses the circuit would refuse", () => {
    outcomes(v.witnessErrors, (c) => witness(c, v.witnesses[0]), "own");
  });
});

// ===================================================================== frametx.json

/** A FrameTx from a vector: every field not bytes is an integer. */
function txOf({ frames, signatures, blobHashes, ...ints }: Json): ft.FrameTx {
  return {
    ...bigs(ints),
    frames: frames.map(({ data, ...f }: Json) => ({ ...bigs(f), data: expand(data) })),
    signatures: signatures.map(({ msg, signature, ...s }: Json) => ({
      ...bigs(s),
      msg: bytes(msg),
      signature: bytes(signature),
    })),
    blobHashes: blobHashes.map(bytes),
  };
}

const TX_GAS = [
  "signatureVerificationCost",
  "valueTransferCost",
  "mandatoryGas",
  "stateGasLimit",
  "standardGasLimit",
  "calldataFloorGas",
  "executionCapUsage",
  "totalGasLimit",
  "maxCost",
] as const;

/** Every encoding and gas figure the vector records for a transaction. */
function expectTx(tx: ft.FrameTx, out: Json): void {
  const raw = ft.rawTx(tx);
  assert.deepEqual(raw.subarray(1), ft.encodeTx(tx));
  const { blobBaseFee, ...want } = out;
  const got = {
    ...("raw" in out ? { raw } : { rawLength: raw.length, rawKeccak: keccak_256(raw) }),
    ...Object.fromEntries(TX_GAS.map((name) => [name, ft[name](tx)])),
    sigHash: ft.sigHash(tx),
    maxCostAtBlobBaseFee: ft.maxCost(tx, big(blobBaseFee)),
  };
  same(got, want);
}

describe("frame transactions (frametx.json)", () => {
  const v = load("frametx.json");

  // RLP of integers, byte strings and lists, and the one-level splitter.
  groups(v.rlp, {
    ints: [(c) => ft.rlpInt(big(c.in))],
    negativeInt: [() => ft.rlpInt(-1n)],
    strings: [(c) => ft.rlpBytes(bytes(c.in))],
    notList: [(c) => ft.rlpItems(bytes(c.in))],
  });

  test("long RLP strings and lists", () => {
    each(v.rlp.longStrings, (c) => {
      const encoded = ft.rlpBytes(expand(c.in));
      const header = encoded.subarray(0, 4);
      same([encoded.length, keccak_256(encoded), header], [c.outLength, c.outKeccak, c.header]);
    });
    each(v.rlp.lists, (c) => {
      const encoded = ft.rlpList(c.in.map(bytes));
      same([encoded, ft.rlpItems(encoded)], [c.out, c.items]);
    });
  });

  // The variants of `base` show that a declared state budget reaches max_gas exactly, that
  // TX_VALUE_COST applies only to a frame moving value to another account, and that the floor
  // prices zero and nonzero bytes alike. `frozen`, the old 11-field dialect's goldens for base,
  // is skipped here because test/frametx.test.ts pins the same goldens.
  test("the self-test transactions: a base and its variants", () => {
    const { shape, frozen: _, ...named } = v.selftest;
    for (const c of Object.values<Json>(named)) expectTx(txOf(c.tx), c.out);
    const fields = ft.rlpItems(ft.encodeTx(txOf(named.base.tx)));
    const frame0 = ft.rlpItems(ft.rlpItems(fields[4])[0]);
    const fees = ft.rlpItems(fields[6]).length;
    const limits = ft.rlpItems(frame0[3]).length;
    same({ fields: fields.length, fees, frameFields: frame0.length, limits }, shape);
  });

  test("encodings, signature hashes and gas of random transactions", () =>
    each(v.transactions, (c) => expectTx(txOf(c.tx), c.out)));

  test("values outside their types and an unknown scheme are refused", () =>
    each(v.invalid, ({ name: _, tx, ...results }) => {
      const t = txOf(tx);
      for (const [fn, result] of Object.entries(results)) {
        outcome(result, () => (fn === "raw" ? ft.rawTx : (ft as Json)[fn])(t), RangeError);
      }
    }));

  test("the signed smoke spends of the pool client", () => {
    const s = v.spends;
    const poolAddress = big(s.pool);
    const { data, ...limits } = s.action;
    const action = { ...bigs(limits), data: bytes(data) };
    each(s.cases, (c) => {
      const entry = { ...s.entries[c.entry], root_slot: s.rootSlot };
      const settle = spend.settleCalldata(entry, entry.root_slot);
      const proof = spend.entryProofBytes(entry);
      const source = pr.sourceId(poolAddress, big(entry.epoch));
      const recentRoot = pr.recentRootTuple(source, big(s.rootSlot), big(entry.root));
      const tail = spend.spendTailFrame(poolAddress, settle, c.action ? action : null, {
        omit: c.omit,
      });
      const tx: ft.FrameTx = {
        chainId: big(s.chainId),
        nonceKeys: spend.spendNonceKeys(settle),
        nonceSeq: 0n,
        sender: poolAddress,
        frames: spend.spendFrames({ pool: poolAddress, recentRoot, proof, settle, tail }),
        signatures: [],
        maxPriorityFee: big(s.maxPriorityFee),
        maxFee: big(s.maxFee),
        maxBlobFee: 0n,
        blobHashes: [],
      };
      const key = spend.authorizerKey(entry);
      spend.signTransaction(tx, key);
      const raw = ft.rawTx(tx);
      const { signature } = tx.signatures[0];
      assert.equal(ft.recoverSigner(ft.sigHash(tx), signature), big(c.out.authorizer));
      const got = {
        authorizer: ft.addressOf(key),
        settleLength: settle.length,
        settleKeccak: keccak_256(settle),
        proofKeccak: keccak_256(proof),
        recentRootTuple: recentRoot,
        frames: tx.frames.length,
        tail: tx.frames[3]?.data ?? null,
        nonceKeys: tx.nonceKeys,
        sigHash: ft.sigHash(tx),
        signature,
        rawLength: raw.length,
        rawKeccak: keccak_256(raw),
        totalGasLimit: ft.totalGasLimit(tx),
        executionCapUsage: ft.executionCapUsage(tx),
      };
      same(got, c.out);
    });
  });
});

// ===================================================================== signing.json

describe("secp256k1 (signing.json)", () => {
  const v = load("signing.json");

  test("signatures over edge and random hashes, addresses and recovery", () =>
    each(v.signatures, (c) => {
      const key = ft.parsePrivateKey(c.key, "key");
      const signature = ft.signHash(bytes(c.hash), key);
      const address = ft.addressOf(key);
      same(
        [
          signature,
          address,
          ft.checksumAddress(address),
          ft.recoverSigner(bytes(c.hash), signature),
          ft.recoverSigner(bytes(c.other), signature),
        ],
        [c.signature, c.address, c.checksum, c.recovered, c.recoveredOther],
      );
    }));

  test("EIP-55 checksums", () =>
    each(v.checksums, (c) => assert.equal(ft.checksumAddress(big(c.address)), c.checksum)));

  groups(v, {
    // Recovery takes v of 0 or 1 only.
    recover: [(c) => ft.recoverSigner(bytes(c.hash), bytes(c.signature)), RangeError],
    privateKeys: [(c) => ft.parsePrivateKey(c.text, "key"), InputError],
  });
});

// ===================================================================== abi.json

describe("pool calldata (abi.json)", () => {
  const v = load("abi.json");
  /** Calldata as a vector records it: in full, or by length and keccak. */
  const calldata = (got: Uint8Array, want: Json) =>
    "hex" in want ? { hex: got } : { length: got.length, keccak: keccak_256(got) };
  const entries: Json[] = [];

  groups(v, {
    // settle(Spend) followed by the notes, including aliased words. A case is an entry, or an
    // earlier case's entry with fields set or removed.
    settle: [
      (c) => {
        const entry = "base" in c ? { ...entries[c.base], ...c.set } : c.entry;
        for (const key of c.unset ?? []) delete entry[key];
        entries.push(entry);
        return calldata(spend.settleCalldata(entry, entry.root_slot), c.out);
      },
      UserError,
    ],
    shield: [
      (c) => calldata(spend.shieldCalldata(c.inner, { note: hex(expand(c.entry.note)) }), c.out),
      UserError,
    ],
    publish: [(c) => pr.encodePublish(big(c.epoch)), InputError],
    domainCall: [(c) => pr.encodeDomainCall(big(c.epoch)), InputError],
    claim: [(c) => pr.encodeClaim(big(c.recipient)), InputError],
    proofBytes: [(c) => spend.entryProofBytes(c.entry), InputError],
    // The compressed signals [beta, gamma, alpha], with the right gamma and one off by one. The
    // Python client's statement had ten values, so alpha is computed here as it computed it.
    verifierCalls: [
      ({ transfer: t }) => {
        const keys = "nf1 nf2 out_cm1 out_cm2 root domain public_amount fee recipient authorizer";
        const stmt = keys.split(" ").map((key) => big(t[key]));
        const words = Buffer.from(
          stmt.map((x) => x.toString(16).padStart(64, "0")).join(""),
          "hex",
        );
        const alpha = BigInt(hex(keccak_256(words))) % pr.P;
        const beta = big(t.beta);
        const gamma = pr.fingerprint((alpha + beta) % pr.P, stmt);
        const call = (g: bigint) => pr.verifyProofCall(bigs(t.proof), [beta, g, alpha]);
        return [call(gamma), call((gamma + 1n) % pr.P)];
      },
    ],
    decodeSettle: [
      (c) => {
        const decoded = pr.decodeSettle(expand(c.data));
        return decoded && decoded.spend;
      },
    ],
  });
});

// ===================================================================== notes.json

describe("note delivery primitives (notes.json)", () => {
  const v = load("notes.json");
  const keysOf = (w: Json) =>
    new notes.WalletKeys(bytes(w.seed), big(w.owner_root), big(w.account));
  const walletOf = (name: string) => keysOf(v.wallets.find((w: Json) => w.name === name));
  const partsOf = (parts: Json[]) => parts.map((p) => ("int" in p ? big(p.int) : bytes(p.bytes)));
  const prf = (c: Json) => {
    const [key, parts] = [bytes(c.key), partsOf(c.parts)];
    const out = notes.prf(key, c.label, ...parts);
    return { prf: out, field: notes.prfField(key, c.label, ...parts) };
  };
  const decoded = (data: string | Uint8Array) => {
    const address = notes.Address.decode(data);
    return { ownerPk: address.ownerPk, addressKeccak: keccak_256(address.encode()) };
  };
  const alice = () => walletOf("alice").address().encode();

  test("keys, addresses and direct secrets from a seed", () =>
    each(v.wallets, (c) => {
      const keys = keysOf(c);
      const { root, nk, ownerPk, selfSecret } = keys;
      const address = keys.address().encode();
      const numbers = Object.keys(c.out.directSecrets);
      const directSecrets = Object.fromEntries(numbers.map((n) => [n, keys.directSecret(big(n))]));
      const addressKeccak = keccak_256(address);
      const got: Json = { root, nk, ownerPk, selfSecret, addressKeccak, directSecrets };
      if ("address" in c.out) got.address = address;
      same(got, c.out);
    }));

  groups(v, {
    walletErrors: [keysOf],
    directErrors: [(c) => walletOf(c.wallet).directSecret(big(c.number))],
    decapsulateErrors: [(c) => walletOf(c.wallet).decapsulate(expand(c.ciphertext))],
    prf: [prf],
    prfErrors: [prf],
    sealErrors: [(c) => notes.sealNote(bytes(c.secret), big(c.index), big(c.value))],
    open: [(c) => notes.openNote(bytes(c.secret), big(c.index), bytes(c.note))],
    // Alice's address truncated or extended, then bytes overwritten.
    addresses: [
      ({ edit }) => {
        const good = alice();
        const data = new Uint8Array(edit.length ?? good.length);
        data.set(good.subarray(0, data.length));
        for (const [offset, text] of edit.set ?? []) data.set(bytes(text), offset);
        return decoded(data);
      },
      NotesError,
    ],
    addressStrings: [
      (c) => {
        if (!("form" in c)) return decoded(c.text);
        const digits = Buffer.from(alice()).toString("hex");
        const text = c.form.prefix + (c.form.upper ? digits.toUpperCase() : digits);
        return decoded(text.slice(0, text.length - (c.form.drop ?? 0)));
      },
      NotesError,
    ],
    directChannelErrors: [(c) => notes.directChannel(big(c.ownerPk), bytes(c.secret))],
  });

  test("decapsulating recorded ML-KEM-768 ciphertexts, and implicit rejection", () => {
    for (const group of [v.encapsulations, v.implicitRejection]) {
      each(group, (c) => {
        const { ciphertext } = "encapsulation" in c ? v.encapsulations[c.encapsulation] : c;
        same(walletOf(c.to ?? c.wallet).decapsulate(expand(ciphertext)), c.secret);
      });
    }
  });

  test("sealing and opening notes", () => {
    const { ownerPk } = walletOf("alice");
    each(v.seal, (c) => {
      const [secret, index, value] = [bytes(c.secret), big(c.index), big(c.value)];
      const { note, rho } = notes.sealNote(secret, index, value);
      const open = (n: Uint8Array = note, s: Uint8Array = secret, i = index) =>
        notes.openNote(s, i, n);
      const tampered = bytes(c.out.tampered.note);
      const got = {
        note,
        rho,
        tag: notes.noteTag(secret, index),
        outputCommitment: pr.commitment(ownerPk, rho, value),
        opened: open(),
        wrongIndex: open(note, secret, (index + 1n) % 2n ** 256n),
        wrongSecret: open(note, Uint8Array.of(secret[0] ^ 1, ...secret.subarray(1))),
        tampered: { note: tampered, opened: open(tampered) },
        short: open(note.subarray(0, 47)),
        long: open(Uint8Array.of(...note, 0)),
      };
      same(got, c.out);
      same(notes.noteRho(secret, index), c.out.rho);
    });
  });

  /** Replays a channel's recorded steps, reserve and finalized, in the recorded order. */
  function replay(channel: notes.Outgoing, [open, ...steps]: Json[]): void {
    same([open.op, notes.outgoingToJson(channel)], ["open", open.out]);
    each(steps, (step) => {
      const run =
        step.op === "reserve"
          ? () => {
              const reserved = notes.reserve(channel, big(step.value));
              return { ...reserved, state: notes.outgoingToJson(channel) };
            }
          : () => notes.finalized(channel, big(step.index)) ?? null;
      outcome(step, run, NotesError);
    });
  }

  test("a channel opened with a recorded encapsulation, as sender and recipient", () => {
    const c = v.kemChannel;
    const wallet = walletOf(c.to);
    const { secret, ciphertext } = v.encapsulations[c.encapsulation];
    const channel = notes.openChannel(wallet.address().hex(), (ek) => {
      assert.deepEqual(ek, wallet.address().ek);
      return { secret: bytes(secret), ciphertext: bytes(ciphertext) };
    });
    replay(channel, c.steps);
    // The recipient decapsulates the opening ciphertext and opens each note it was sent.
    const shared = wallet.decapsulate(bytes(ciphertext));
    const sent = c.steps.filter((s: Json) => s.op === "reserve" && "out" in s);
    const opened = sent.map((s: Json) =>
      notes.openNote(shared, big(s.out.index), bytes(s.out.note)),
    );
    same(opened, c.recipientOpens);
  });

  test("a direct channel from a number the recipient handed out", () => {
    const { to, number, steps } = v.directChannel;
    const bob = walletOf(to);
    replay(notes.directChannel(bob.ownerPk, bob.directSecret(big(number))), steps);
  });
});
