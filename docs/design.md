# Design

This note explains why the pool is built the way it is, so that a change does
not break a rule something else depends on. [README.md](../README.md) says what
the pool does, and [SECURITY.md](../SECURITY.md) lists its trust and failure
boundaries.

## The rule behind most others

A spend has a validation frame, which checks the proof and approves the
transaction, and a later frame that settles it. Approval consumes the spent
notes' nullifiers, the tags that mark a note as spent. Anything that makes
settlement fail after approval therefore burns the notes. That is why
validation re-checks everything settlement could refuse, and why settlement's
gas limits are pinned.

## The pool is the sender

EIP-8250 nonce keys belong to a transaction's sender. With the pool as the
sender of every spend, a spend's two nullifiers are its nonce keys at sequence
zero, and the dispatcher requires exactly those keys. The protocol then rejects
a second spend of either note without the pool keeping its own record of spent
notes. The pool also pays the gas, out of note value, through the proof's
`fee`.

Validation needs EIP-8141's new opcodes, which Solidity cannot emit, so the
dispatcher (`core/dispatcher/ShieldedPoolDispatcher.yul`) is written in Yul
with `verbatim`. It checks the frame layout, the nonce keys, the recent-root
tuple, and the transaction's two signatures: the first from the proof's
one-time `authorizer` over the whole transaction, the second from the owner
over the spend's intent. It calls the verifier directly rather than through the
logic, which an earlier ethrex mempool policy required and which keeps the
logic's code out of validation, and then approves. Every other call is
delegatecalled to `ShieldedPoolLogic`, which shares the dispatcher's storage
and refuses direct state-changing calls.

## Owners sign, the prover proves

A note's owner key is `Poseidon3(1, Q, nk)`: `Q` is the root of a depth-16 tree
of one-time secp256k1 addresses whose keys a signing device holds, and `nk` is
a nullifier key the wallet derives. The prover therefore needs `Q`, the
addresses and `nk`, but never a key that can spend, as long as `Q` was built
from the device's addresses. A spend reveals one address
of the set, the owner, and the pool requires the owner's EIP-8141 signature
over the spend's EIP-712 intent, which EIP-8141 validates before any frame
runs. The pool reads the owner from that signature, the proof shows it is a
leaf of the inputs' owner set, and the circuit refuses an owner of 0, the value
of an empty leaf. The tree's path bits must be 0 or 1, as in the note MMR:
otherwise a prover who knows a node's children could place any address under
it, and so spend with a key of its own.

The protocol, not the circuit, checks the signature, so the circuit stays free
of curve arithmetic and any wallet that signs EIP-712 typed data can hold the
keys. The price is that the owner is public, so each address signs one spend,
and the transaction carries a second signature. The intent omits the root, the
epoch and the authorizer, so a stale proof can be proved again, beside the
same dummy input, without the device. Checking an EdDSA signature over
BabyJubJub in the circuit would also keep the key off the prover, at about the
same circuit cost and with reusable keys, but only sideloaded device apps sign
it, while stock hardware wallets and threshold signers sign EIP-712.

## Nullifiers bind the position

The nullifier binds a note's epoch and its index, its position in the epoch's
MMR in insertion order:

```text
nf = Poseidon3(4, Poseidon2(D, nk), Poseidon2(cm, index))
```

Here `D` hashes the chain ID, the pool and the epoch of the root the spend
proves against. `SkewMmrInclusion` derives the index from the note's opening,
from the sizes of the older trees and the path's turns, so the prover cannot
choose it, and it stays fixed as later appends merge trees. Two insertions of
the same commitment are therefore separate notes, each spendable once, and a
sender who repeats a commitment by mistake loses nothing. Settlement appends a
duplicate output rather than refusing it: a refusal after approval would burn
the spend's inputs, the reason PR 14 removed the commitment registry. A
zero-value dummy input, whose membership is not checked, takes index 0, and
the commitment carries the value, so a dummy cannot copy a funded note's
nullifier. A new nullifier formula needs a fresh deployment.

The tree is a skew-MMR from the `@skew-mmr` packages: a frontier of at most
`MAX_TREES` perfect trees, where every node holds a note and an append takes at
most one Poseidon hash. The circuit opens a note without its index, so the
nullifier cannot bind it.

## The statement is compressed

A spend's statement is `12 + MAX_TREES` values (`nf1, nf2, outCm1, outCm2,
domain, publicAmount, fee, recipient, authorizer, owner, packedRanks, depth`
and the frontier's roots): all but the owner in the settlement calldata, and
the owner as the owner signature's signer.
Groth16 verification costs gas per public input, so the proof exposes only
three, using the hybrid compression of
[eprint 2025/1500](https://eprint.iacr.org/2025/1500). With `r` the BN254
scalar field order, the pool computes `alpha = keccak256(statement) mod r`, the
circuit computes `beta`, the statement chained through
Poseidon of two, and both evaluate `gamma`, the statement as a polynomial at
`alpha + beta`. This saved about 44,100 gas per spend (PR 19).

The verifier no longer sees the values, so the dispatcher range-checks each
one, except the owner, which the protocol gives as a 20-byte address, and
requires the frontier to open the spend's root exactly. Without that, a note
owner could re-prove a spend with a value plus `r`.
The proof would still verify, so the pool would approve and pay the gas, and
settlement, which re-checks the values, would then revert. An aliased
nullifier gives fresh nonce keys, so the pool would pay each time, and an
aliased output, amount or fee spends the owner's notes without creating
anything. The wallet, the dispatcher and the circuit must agree on the order and
encoding of the values, and a mismatch shows up only as an invalid proof.

## Roots come from EIP-8272

The first frame runs EIP-8272's recent-root check on a `(source_id, slot,
root)` tuple, and the dispatcher requires that tuple to name the spend's root
and `source_id = keccak256(pool || epoch)`. The root is the MMR's keccak
commitment to its frontier, which the dispatcher recomputes from the frontier
the statement carries. Validation therefore never reads
pool storage. This matters because every spend has the same sender, and ethrex
lets several of one sender's frame transactions wait in the mempool only when
their nonce keys are disjoint and their validation reads no sender storage. The
tuple also keeps a proof valid for EIP-8272's window while new deposits change
the tree. Anyone can publish a root with `publishEpochRoot`, outside
settlement, so a failed publication never consumes note keys. When the
epoch's MMR lacks room for the notes being inserted, the pool starts a new
epoch first, so settlement never fails for lack of room.

## Settlement gas is pinned

The dispatcher pins the settlement frame's execution and state gas (the
README's [frame table](../README.md#transactions)), because running out after
approval burns the notes. The limits sit above the highest settlement the
[native suite](../test/native/README.md) measures, which carries a first
payment's notes, so they are a measurement with margin, not a proof. The
validation limits are wallet defaults in `src/gas.ts`, because a validation
limit that is too low only makes the transaction invalid before any key is
consumed. A repricing that makes settlement more expensive needs a new pool. A
repricing of validation needs only new defaults and a regenerated manifest, as
long as the proof check still fits the fixed gas the dispatcher forwards to the
verifier.

## The client and its cross-checks

The client in `src/` is TypeScript, run by Node without a build step. It proves
with snarkjs as a library, encodes calls itself in `src/protocol.ts`, signs with
@noble/curves and encrypts notes with ML-KEM-768 and ChaCha20-Poly1305 from
`node:crypto`, so it starts no other program. The tools and the node:test suites
are TypeScript too, apart from the setup and deployment shell scripts; the Forge
tests are Solidity and the native harness is Rust. Because the client
reimplements Poseidon, the statement and the transaction encoding, and builds
the tree with `@skew-mmr/core`, which its own repository tests, the tests check
it against independent sources: Poseidon against circomlibjs vectors
(`test/poseidon.test.ts`), witnesses and statements against the committed R1CS
and a real proof (`test/circuit.test.ts`), the smoke fixture's proof against
the Solidity verifier in Forge, and the whole pool with real proofs and signed
transactions in the pinned ethrex VM (`test/native/`).

The client replaced a Python one, and the reference vectors in
`test/vectors/reference/` pin the Python client's behaviour. The Python client
at commit `2386147` computed them, and `test/reference.test.ts` checks the
TypeScript against every case: hashes, witnesses, encodings and gas
figures, signatures, and note delivery. The vectors are never regenerated from
the TypeScript: a deliberate change to an encoding or hash updates the affected
vectors in the same commit and says why. The fixture generators draw by default
from a seeded stream (`src/random.ts`) rather than Python's generator, so the
committed smoke fixture's random values differ from the Python's;
`test/random.test.ts` pins that stream, and the Python's own fixture stays in
the reference vectors.

## Changing the tree or the statement

A change to the tree or the statement touches all of these:

- the circuit, then the artifacts and the verifier (`tools/setup.sh` runs a
  test setup, not a ceremony, and `tools/patch-verifier.ts` patches the
  verifier it exports);
- the dispatcher's statement handling, its frame data length pins (in the
  README's [frame table](../README.md#transactions)), the `settle` selector,
  the owner's intent and the constructor's empty root;
- `ShieldedPoolLogic`'s tree constants, `Spend` struct, storage layout,
  insertion and epoch roll, and the Forge tests;
- the client's shared definitions in `src/protocol.ts`: the note hashes,
  nullifier, statement and compression, the owner's intent, the `Spend` fields,
  selectors, events, ABI encoders and empty root, with the frame data sizes in
  `src/gas.ts`;
- the client code built on them: `src/wallet.ts` (trees and witness),
  `src/owner.ts` (owner sets),
  `src/spend.ts` (calldata and frames), `src/deployment.ts` (the
  deployed-profile checks), `src/notes.ts` (output commitments), `src/scan.ts`,
  whose scanner rebuilds positions from `LeafAppended` and tracks spends by
  nullifier, and `src/disclosure.ts`, which decodes `settle` calls and
  recomputes nullifiers from disclosed keys;
- `src/poseidon.ts`, `tools/export-vectors.ts` and `test/vectors/`, if the
  change needs a new hash arity, and new Poseidon libraries from
  `tools/poseidon-sol.ts` if the contracts need it too;
- the fixture generators (`src/smoke.ts`, `src/nonce-race.ts` and
  `test/native/scripts/generate-fixtures.ts`), the committed smoke fixture and
  the TypeScript tests;
- the reference vectors whose values the change alters, updated as described
  above;
- gas: re-measure the worst settlement in the native suite, then update the
  pins, `src/gas.ts` and `tools/check-gas-profile.ts`;
- the activation manifest, the activation check's profiles, a new pool profile
  and a fresh deployment. The formal proofs cover commit `8835be7` and do not
  cover a changed file until the proofs and their pins are updated;
  `node tools/check-formal-pins.ts` lists the pinned files that already
  differ, among them the dispatcher and the logic.
