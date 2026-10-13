# Native occurrence tests

These tests execute real Groth16 proofs and signed frame transactions in the
native LEVM from ethrex `247e2dd2c4d4c526dcc64ac1c025bd2319e7a10e`. They deploy
the contracts from this checkout and check frame results, nonce keys, tree
storage, withdrawal credits, recipient balances and gas payments.

They need Node 24.7 or later with `npm ci` run at the repository root,
[Foundry](https://getfoundry.sh) (CI uses 1.7.1), Rust (CI uses 1.93.0) and a
checkout of lambdaclass/ethrex at that commit. The dispatcher is compiled with
solc 0.8.30, which `forge build` installs; `SOLC` can name another copy of that
version. Then run:

```sh
node test/native/run.ts --ethrex-source /path/to/pinned/ethrex
```

`ETHREX_SOURCE` can name the checkout instead, and `just native PATH` runs the
same command. `run.ts` first checks the checkout against the pinned hashes in
`ethrex-source-sha256.json`. A normal run then rebuilds the contracts with
Forge, in the default and `libsmall` profiles, and writes the vectors under
`test/native/fixtures/` with `node test/native/scripts/generate-fixtures.ts`.
`--skip-generate` reuses the vectors already there, and `--offline` passes
`--offline` to Cargo when its dependencies are cached.

Each proof is cached beside the vectors as `fixtures/NAME-proof.json`, keyed by
its witness, proving key and circuit WASM, so a run proves only what changed.
Groth16 proving is randomized, so the cache is committed: only these proofs
reproduce the committed transactions byte for byte. `run.ts --cache-only`
passes `--cache-only` to `generate-fixtures.ts`, which then fails on a proof
missing from the cache instead of proving it. The generator checks each cached
proof against the committed verification key before using it and stops on one
that does not verify, because a case that expects a rejection would otherwise
pass on an invalid proof. `test/native-proofs.test.ts` checks every committed
proof the same way. No setup ceremony runs here, and the repository's proving
key is test-only. The vectors themselves are ignored by Git. The two reports,
`native-report.json` and `policy-report.json`, are tracked, so a run changes
them by design.

The recorded run passes 87 native scenarios and two client-policy tests, using
34 real Groth16 proofs. The highest measured settlement execution cost is
1,435,539 gas (long carry plus withdrawal credit, with a first payment's
notes). The conservative five-slot state test uses 489,600 state gas, below the
pinned state limit. The reports contain each transaction hash and per-frame
results. This suite, not Forge, bounds settlement gas, because it deploys the
`libsmall` Poseidon builds a real pool uses, while the Forge suite runs the
via-IR builds, about 10% cheaper per hash.

The recorded reports come from a run on the TypeScript generator's fixtures,
built from the committed proofs. CI regenerates the fixtures with
`run.ts --cache-only`, reruns both suites, and checks with `compare-reports.ts`
that the fresh reports are identical to the committed ones, every transaction
hash, fee, payer and gas figure included. A change to a spend's witness, the
circuit or the proving key therefore fails CI until a run without
`--cache-only` proves the affected spends again and their proofs are committed
with the new reports.

The native job never proves. Proving from scratch is tested by the TypeScript
suites: `real-groth16-proof` in `test/circuit.test.ts` proves a witness, and
the nonce-race run in `test/generators.test.ts` proves two transfers, each
checked by `prove()` against the committed verification key. Those checks run
in snarkjs; only committed proofs reach the EVM verifier, here and in the Forge
tests.

The scenarios cover both copies of identical funded deposits being withdrawn
in one history, an identical private output and its original both being spent,
replay against a later root and slot, epoch/domain changes, and failed recipient
calls retaining their credit. Rejected transactions must leave the complete
EVM account state unchanged, including nonce keys and balances.

Fifteen scenarios cover the optional fourth frame. A withdrawal without a
tail keeps its credit, and a withdrawal or transfer may end with a generic
call to another account. A transfer may also call the pool. In one scenario it
publishes its own root, and the note it created is withdrawn against that root
in the next slot. When that publication fails, the settlement stands, and a
separate publication makes the note spendable. After a rollover, the tail must
publish the new epoch: doing so lets the output be withdrawn in the next slot,
while publishing the old epoch succeeds without the output until the new epoch
is published separately. Two tails call the pool to repeat the settlement or
the proof check, with enough gas to finish either; both revert, and the
settlement stands with each key consumed once. Each rejected case breaks one
rule of an otherwise valid spend and must fail in the pool's `VERIFY` frame: a
`SENDER` tail repeating the settlement, a zero target, an approval flag on the
tail, an atomic batch joining settlement and tail, and a fifth frame. A tail
carrying value is rejected statically by the client, as EIP-8141 requires,
before the dispatcher's own value check runs. Removing the dispatcher's mode
check lets the repeated settlement through with twice the proven credit, which
this suite then reports as a failure.

Seven scenarios cover the validation frames' limits, which the dispatcher no
longer pins. A withdrawal declaring far more than the defaults is accepted.
Declaring less than the recent-root frame's execution, the proof frame's
execution or the proof frame's state gas needs makes the transaction invalid in
that frame, with state unchanged. At a price where the default limits just fit
the proof's fee, the same withdrawal is accepted; raising the recent-root
frame's execution limit or the proof frame's state limit then pushes the
maximum cost past the fee, and the pool refuses it before approval, again with
state unchanged.

Nineteen scenarios cover hybrid compression, and each leaves state unchanged.
Twelve change one thing in a withdrawal: its `beta`, or one of the ten statement
values in the settlement calldata. The owner signs each changed intent again.
For `nf1` and `nf2` the nonce keys follow, and the authorizer case re-signs
someone else's proof with an attacker's key, so these reach the proof check
along with the output, amount, fee and recipient cases. The root and domain
changes are refused earlier by the exact tuple and domain checks, and a `beta`
outside the field by both the dispatcher and the verifier. Seven more prove an
honest withdrawal against `alpha` over one value plus the field modulus, and the
owner signs the aliased intent, so the proof, `gamma` and the owner check pass
and only the dispatcher's range checks can refuse it. Deleting those checks
makes exactly these seven fail.

Nine scenarios cover the owner's signature. Seven change only the signatures
of a valid withdrawal: no owner signature, the owner's signature twice, the
owner's key signing another intent, the same intent for another pool, or the
transaction hash, a key outside the owner set signing the right intent, and the
owner signing first. One spends a note whose owner set holds a P-256 address,
signed with P-256, which EIP-8141 validates but the pool refuses, so every
spend has one shape. The pool refuses each in its `VERIFY` frame with state
unchanged. The ninth proves a withdrawal again against a later root, under a
new authorizer, beside the same dummy input and with the same owner leaf, and
the owner's original signature authorizes it.

Fourteen scenarios cover dispatcher checks that no other scenario reaches,
each breaking one check in an otherwise valid spend. A spent key set replayed at
`nonce_seq` 1, or a spent note settled again under fresh nonce keys, would pay
out twice. The victim's signature re-sent as an explicit message, or the
attacker's own signature over the victim's proof, would let anyone choose the
fourth frame. A `DEFAULT` settlement frame, or settlement limits below the
profile's, could fail after approval and leave the inputs spent; each limit is
tested one below its pin and at a value that does run out. A root the
attacker published under their own source, a genuine tuple for the pool's real
root beside a proof over another, or the identity precompile in place of the
recent-root frame would let a note nobody deposited withdraw other users'
funds. A valid proof over another epoch's domain would pass the proof check and
revert in settlement at the pool's expense. The pool refuses each in its
`VERIFY` frame, and deleting any one of these checks makes exactly its
scenarios fail. Deleting the settlement execution pin stops the fixture
generator itself, because the old-limit regression patches that literal, so no
scenario runs.

One scenario covers a rule of EIP-8141 that the dispatcher relies on instead of
a check of its own: the authorizer signs an explicit all-zero `msg`, beside
another fourth frame. `SIGPARAM` would report that `msg` as 0, as for a
signature over the transaction hash, so the protocol must refuse the
transaction before any frame runs; the pinned ethrex does, with state
unchanged.

Two more scenarios cover checks that back each other up, so each survives
deleting one of them and fails only when both go. A recent-root frame in
`DEFAULT` mode whose validation reverts would be trusted on its bytes without
both the mode and the status check. A settlement frame to another account
carrying the pool's balance would pay that account without both the target
and the value check.

The reorg scenario checkpoints the EVM database, executes and spends on one
branch, restores the checkpoint, and reverses two deposit transactions. The
old proof fails both with its old root and when rebound to the new root. A
rebuilt proof for the new position succeeds. This tests application recovery
under database rollback, not consensus fork choice or network reorganization.

Large-tree tests seed the exact frontier and balance of repeated funded
deposits, then execute proof verification and settlement normally. They cover
the longest carry, nearly full and full tree rollover, and spending a newly
created output from the rolled epoch. They do not execute a million deposit
transactions. Two additional tests inject conservative storage-bound states
(an empty active epoch and a zero frontier); those states are not claimed to
have been reached by deposits.

The settlement limits are in the README's
[frame table](../../README.md#transactions). `run.ts` refuses an ethrex source
that does not match the pinned `247e2dd2` hashes. To run the same fixtures on
another revision, such as `bdfc5d8f`, generate them with
`run.ts`, then run `cargo test` with a
`Cargo.toml` made from `Cargo.toml.in` whose `@ETHREX@` names that source and
with `ETHREX_SOURCE` set to it. The report names the revision it ran on, with
`-dirty` if that source has local changes. On `bdfc5d8f`, 88 commits older,
the same scenarios gave identical results, gas included, before notes were
added.

The old-limit regression deploys a separate dispatcher with only the pinned
settlement limit changed back to 1.4 million. It requires settlement to fail
after the nonce keys are consumed. The same long carry must settle successfully
under the new profile. Every accepted transaction's frame statuses are
asserted, so a frame that runs out of gas fails its case. The per-frame
comparison with declared limits is only a consistency check: a frame that runs
out still reports usage within its limit, so margin is tracked by the measured
maxima above, not by an assertion.

`policy/` runs the real validation observer, Profile 2 checks and direct client
mempool insertion with two independently signed, disjoint spends. It requires
zero sender-storage reads and both transactions to remain pending, and includes
storage-read and overlapping-key negative controls. It inserts with MATCHA's
charge disabled, so it tests keyed concurrency and the Profile 2 checks, not
the width budget, which on a default node refuses the second spend until the
pool has earned width. This is not a test of full
blockchain admission, inclusion-list omission processing, block import or
networking. The declared validation budget still exceeds EIP-8141's
public-mempool default ([README](../../README.md#deployment)) and needs the
testnet's policy.
