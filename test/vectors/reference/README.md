# Reference vectors

These are pinned reference vectors: an earlier implementation, the Python client this one
replaced (commit 2386147, since deleted), computed them, and `test/reference.test.ts` checks the
TypeScript client against every case. Because they come from outside the code under test, they
are never regenerated from it. A deliberate change to an encoding or hash updates the affected
vectors by hand, in the same commit, and the commit message gives the reason.

| File | What it pins |
|---|---|
| `protocol.json` | Poseidon, owner key, inner, commitment, nullifier key and nullifier, domain, statement, alpha, beta, gamma, fingerprint, sinks, EIP-8272 recent-root keys, selectors, topics and the gas profile |
| `wallet.json` | Witnesses the circuit would refuse, built on the leaves and domain of the first of two witness cases |
| `frametx.json` | RLP; frame transaction encodings, signature hashes and every gas figure for a set of self-test transactions, random transactions and refused ones; the signed smoke spends of the pool client |
| `signing.json` | secp256k1 signatures over edge and random hashes, addresses, recovery, EIP-55 checksums and stored private keys |
| `abi.json` | `settle`, `shield`, `publishEpochRoot`, `domain`, `claimWithdrawal` and proof-frame bytes, including statement words aliased to x + P; verifier calls; settle decoding |
| `smoke_fixture.json` | The smoke fixture the earlier implementation generated, which `test/pool-envelope-binding.test.ts` signs; the committed `test/fixtures/smoke_fixture.json` now comes from the TypeScript generator's seeded stream |
| `notes.json` | Note-delivery keys, addresses and direct secrets, the PRF, sealing and opening notes, address decoding, and channels replayed from recorded ML-KEM-768 encapsulations |

Integers are decimal strings and byte strings `0x` hex. A case with `error` is an input the
earlier implementation refused, and the client must refuse it too. `error` holds the exception
class it raised, a Python class name such as `OverflowError`; `REFERENCE_ERROR_KINDS` in the
test translates it to the client's error kind. Inputs that only the earlier implementation's
lenient parsers accepted, such as hex without `0x`, are left out, since the client refuses them
on purpose. A long byte string appears as `{"prefix", "pattern", "length"}`: the prefix, then the
pattern repeated up to `length` bytes.
