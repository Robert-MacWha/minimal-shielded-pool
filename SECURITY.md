# Security

This is unaudited research software for the ethrex Hegotá testnet. Do not use
it, its proving key or its testnet pools for real value. Production use stays
blocked on a real setup ceremony, an independent audit, evidence from other
clients and a proof that settlement fits each fork's gas schedule.
[docs/design.md](docs/design.md) explains why the pool is built this way.

## Five ways to lose funds or keys

1. **The proving key is a test key.** It comes from a local single-party setup
   (`tools/setup.sh`) whose phase 2 records one contribution and whose phase 1
   is not recorded. Whoever produced either phase could have kept the toxic
   waste and could forge spends that drain any pool using this key. Hold no
   real value in such a pool; a real one needs the setup under
   [Assumptions](#assumptions).
2. **Secrets live in files that nothing backs up.** A fixture holds the only
   openings of its notes and the authorizer keys of its spends, and a wallet
   seed derives the spend key of every address it makes. Losing a fixture
   loses its unspent notes, and anyone who reads a fixture or seed can spend
   them. Back them up, keep them readable by their owner only, and keep a
   fixture until its notes are spent. The generators' fixed seed is public, so
   the smoke generator refuses it off the local test chain and pool, and the
   nonce-race generator off that chain or with `--rpc`.
3. **A fork can break the pool.** Approval consumes a spend's notes before
   settlement runs, so a settlement that fails afterwards burns them
   ([design](docs/design.md#the-rule-behind-most-others)). Settlement's
   gas limits are fixed in the pool and were measured under the current gas
   schedule, so a fork that makes settlement cost more can make spends fail
   after approval, first those that insert outputs. A full withdrawal to two
   sinks keeps fitting unless the state gas per new storage slot rises more
   than fivefold. A chain that keeps the pool's state but changes its chain
   ID, as the minority side of a contentious fork might, gives every spent note
   a fresh nullifier, so its copy of the pool can be drained. The pool cannot
   be upgraded: withdraw before either kind of fork.
4. **A withdrawal can strand its credit.** `claimWithdrawal(recipient)` pays a
   withdrawal's credit with a plain ETH transfer that nothing can redirect, so
   a recipient that rejects plain ETH leaves it in the pool for good. The CLI
   and the generators refuse the pool, precompiles and the protocol contracts
   listed in `src/protocol.ts`, but no other contract. Withdraw to an account
   that accepts plain ETH, such as an externally owned account. Credits to one
   recipient add up and anyone can pay them out, so an account shared by
   several users must not attribute a claimed amount to one withdrawal.
5. **The client trusts its RPC and its config.** Before sending, and also with
   `--dry-run`, the CLI gives the RPC the fully signed transaction to simulate,
   and the RPC could broadcast it. The CLI's deployment checks
   ([README](README.md#deployment)) catch a stale or mislabeled config, not a
   malicious deployer: they trust the logic and verifier the config names and
   cannot see what the pool's constructor stored. Use an RPC you trust and your
   own copy of the config, and check the deployment transactions of a pool
   someone else deployed before depositing.

## Trust boundaries

The pool stays solvent, holding the ETH that its unspent notes and unclaimed
credits are worth, and lets only a note's owner spend it, once. Both rest on
the circuit, contracts and dispatcher in `core/` and on a deployment that links
the pool to the logic, verifier and Poseidon libraries built from them. They
also rest on the setup behind the proving key and on a chain that keeps its
chain ID (item 3) and implements EIP-8141, EIP-8250, EIP-8272 and EIP-7843
correctly, under the [assumptions](#assumptions) below. Neither property rests
on a client: the pool checks every spend itself, so a spend from a faulty or
hostile client faces the same checks as any other. A client can lose only what
its user trusts it with: the user's keys and seed, the privacy of the payments
the user takes part in, and the user's funds, for example through a lost
fixture, a wrong recipient or amount, a fee above the transaction's cost (the
unused part stays in the pool) or a stranded credit. It can still delay other
users' spends ([Liveness](#liveness)).

`tools/run_live_dispatcher.sh` compares the deployed code of the verifier, both
Poseidon libraries and the logic with a local build, and the pool with the
committed dispatcher initcode, before it writes `core/deploy_config.json`. A
spend's proof names a one-time authorizer whose signature covers the whole
transaction, so a copied or rerandomized proof is useless without that
authorizer's key. The dispatcher takes that signature only with an empty
`msg`, which `SIGPARAM(0, 0x02)` reports as 0, because a signature with an
empty `msg` covers `compute_sig_hash(tx)` and with it every frame. This rests
on EIP-8141 making an explicit 32-byte zero `msg` invalid, which reserves 0 for
the empty case: a client that admitted one would let a signature over that
fixed digest pass as one over the transaction.

The client encrypts notes with ML-KEM-768 and ChaCha20-Poly1305 from
`node:crypto`, which needs Node 24.7 or later built against OpenSSL 3.5 or
later; without ML-KEM, note delivery stops with an error. ML-KEM keys derive
from the seed through FIPS 203's 64-byte seed form, and encapsulation uses
OpenSSL's randomness. Signing uses @noble/curves (RFC 6979 nonces, low `s`),
and proving uses snarkjs in process.

## The fourth frame

A spend may end with one `DEFAULT` call that its authorizer chooses and signs
([README](README.md#transactions)). An account it calls sees EIP-8141's entry
point (`0xaa`) as its caller. Trusting that caller would let any frame
transaction operate the account, so the account must authenticate its owner
and prevent replay itself; supporting EIP-8141, EIP-7702 or ERC-4337 does not
do this by itself. An owner's signature sent separately may run before the
pool transaction unless it binds the intended context, and the tail does not
make a spend atomic, so an account that needs settlement to have succeeded
must check it.

The native suite pins ethrex `247e2dd2`, and the testnet's RPC node runs
`64b8fc09`, which is `bdfc5d8f` with eight testnet fixes. `247e2dd2` panics
when a top-level frame calls a precompile after an earlier frame emitted logs,
as settlement always does, so one such pending transaction from any wallet
stops a node from producing blocks until it leaves the mempool. `64b8fc09`
carries the fix (`bf42186d`). The CLI still refuses precompile targets, since
other nodes may lack it.

## Liveness

Every spend has the pool as sender, so per-sender mempool limits apply to all
users at once. EIP-8141's conservative rule keeps one pending frame transaction
per sender; both ethrex revisions relax it for spends with disjoint nonce keys.
`247e2dd2`'s MATCHA, on by default, charges each pending spend beyond the first
to one width budget for the pool, at admission and again at every
forkchoiceUpdated, and evicts spends it can no longer pay for. The budget
refills only from the pool's finalized gas, so a few concurrent spends, or one
note holder replacing a spend while another is pending, can delay everyone
else's.

Both revisions recheck every pending spend, its pairing check included, on each
forkchoiceUpdated. A recheck takes an estimated 1.1 to 1.3 ms on fast hardware,
from a measurement not recorded in this repository, so on `64b8fc09`, which has
no width budget, about 6,000 to 7,000 pending spends, fewer on slower nodes,
would exceed the Engine API's 8-second limit. Raising a pending spend's fee
past its proof's fee needs a new proof with the same dummy input: a new dummy
changes the key set, which the mempool refuses while the first spend is
pending.

## Privacy limits

The proof hides which notes a spend consumes. The rest of the statement is
public, and these patterns can still link a spend to a deposit or another spend:

- Two sink outputs reveal the inputs' total, so a full withdrawal of an unusual
  amount links to its deposit. A change output hides it.
- Anyone who knows an `inner` can test amounts against its commitment, so each
  payment needs a fresh `inner`, which note delivery derives per note.
- A spend names its root's slot, so publishing that root from the depositor's
  account, or from a spend's fourth frame, links the later spend to that
  account or spend. Prove against a root someone else published, or publish
  from an unrelated account.
- Reusing an authorizer, or using one tied to the depositor, links spends.
- A spend reveals its input epoch, so notes in different epochs never share an
  anonymity set. Anyone can force a new epoch by filling the tree: `2^20`
  deposits at about 0.8 million gas each, roughly 800 ETH at 1 gwei and almost
  nothing at the testnet's base fee.
- Fees, gas limits and fourth frames differ between wallets and mark their
  spends.
- A payment that opens a channel to a public address carries a 1,088-byte
  ML-KEM ciphertext, which shows that someone opened one. A sender opens a
  channel on its first payment to an address, after a restore, and when it
  pays again before the opening payment is final.
- The recipient sees which channel each payment arrives on, so it links every
  payment on one channel to one sender, and to the sender's account when a
  shield opened the channel.
- A disclosure receipt shows its links and amounts to whoever holds it, and
  disclosing both inputs and one output of a spend reveals the other output's
  value. If that output is later withdrawn in full, the amount links the
  withdrawal to it, even when the output belongs to someone else. A receipt
  also reveals each note's `inner`, which links any other note paid to the
  same `inner`. A nullifier
  key covers every note of its spend key in the epoch, which includes every
  note paid to one address, so export refuses such a key unless
  `--address-wide` accepts it.
- Export matches the pool's logs locally, with one exception. When the node's
  logs do not show the spend or creation of a disclosed note that the fixture
  spends, export reads that note's nullifier slot in the EIP-8250 nonce
  manager. The slot is a hash of the pool and the nullifier, so once a spend
  publishes the nullifier, the node can tell which spend the export looked up.
  Export with a node you control.

## Note delivery

The pool does not check what a note says, so a wrong note only hides a payment
from its recipient, and the sender can deliver the opening another way. A
public address has no checksum: a mistyped `owner_pk` is a valid key nobody
holds, so a payment to it is lost, and a mistyped ML-KEM key usually still
loads and hides the payment. Copy an address whole; never retype it. A
repeated index links two payments and reveals the XOR of their amounts, so a
wallet must save each reservation before broadcasting
([README](README.md#note-delivery)). One device sends from an account at a
time. A restored wallet, or a device taking over sending, resumes its change
channel with `selfChannel`, skipping the 10 indices after the highest change
index in finalized blocks. That is safe only while every change payment that
is not final yet, but may still land, has a lower index than the one it
resumes at. Until one of its change payments is final, a device that itself
resumed with `selfChannel` sends from the very index the next takeover picks,
so a single pending change payment from it makes a second takeover, or a
second restore, repeat that index. Before taking over from such a device, wait
until its change payments are final or can no longer land: a spend once its
recent root has left the 8192-slot window, a shield once its sender's nonce is
used.

Anyone who knows a public address can make its wallet keep more state, one
pool call at a time. A shield that opens a channel to the address makes the
wallet watch that channel's secret for good once its note starts with one of
the channel's first 20 tags, even if the note pays nothing, and a 1-wei
payment at the far end of a channel's window moves that window 20 indices
ahead. Each adds up to a few hundred bytes to the state file and 20 tags that
every later `scan` derives again, so the state and the scan time grow with
what the sender spends on shields. Requiring the opening note to pay something
would not raise this price, since a 1-wei payment does.

Use a seed with one pool only, since direct secrets and change indices do not
yet depend on the deployment. Only the state file that issued a direct number
records it, so issue direct secrets from one state file. A wallet restored from
its seed or from an older copy of its state, or a second device with a state of
its own, may hand out again a number already handed out but not yet paid, and
two senders with one secret link their payments and can read each other's
amounts. A direct secret cannot spend, but anyone who learns it, including from
a recorded channel that is broken later, sees which outputs paid the recipient
on it and their amounts. Send it over a post-quantum channel and never show it
in a public QR code.

`notes scan` rebuilds calls that ethrex `247e2dd2` leaves out of `eth_getLogs`
(`64b8fc09` returns them), but a full withdrawal that such a node leaves out
appends no leaf, so it leaves no gap: its note shows as unspent, and spending
it fails. A node that also leaves a call out of its receipts makes `scan` stop,
except for a call in an epoch's last leaf when a two-leaf settlement began the
next epoch: the pool also closes an epoch one leaf short before such a
settlement, so nothing shows the gap. The client refuses any node reply over 16
MiB before parsing it. When one `eth_getLogs` range holds more than about 5,000
ML-KEM shields, `scan` needs a smaller `--chunk`. Receipts are read one block
per call, so when `scan` reads them, as it does after a gap in the leaves or an
epoch seen one leaf short, it stops at any block whose receipts pass 16 MiB,
which anyone can cause by filling a block with logs. A node can also alter the
logs it returns instead of leaving them out, and `scan` cannot detect that: a
changed opening ciphertext hides every payment on that channel, and a later
scan of the same state with another node does not read those blocks again. Scan
with a node you trust; to check one, scan into a new state file with another
node. The new file does not record the direct numbers the old one handed out,
so issue direct secrets from it only once each of those numbers has been paid.
Earlier versions of `scan` read no receipts when a new epoch began, so a state
file they saved can lack a payment in an epoch's last leaves. When such a file
shows an epoch that closed short of full, the next `scan` rescans from the
deployment block and keeps the direct numbers handed out, and `direct-secret`
issues nothing until then. Notes older than client history (EIP-4444) need an
archive, which nobody guarantees to keep.

## Assumptions

- Groth16 knowledge soundness, BN254 pairing security, Poseidon and Keccak
  collision resistance, and secp256k1 unforgeability.
- Joint UHF hardness of Keccak mod p and circomlib's Poseidon(10), under which
  [eprint 2025/1500](https://eprint.iacr.org/2025/1500) binds the statement to
  three public signals ([design](docs/design.md#the-statement-is-compressed)).
- ML-KEM-768 ciphertexts that hide the key they were made for, proven for
  round-3 Kyber (PKC 2023) and not checked separately for FIPS 203.
- A public multi-party phase 1 and a multi-party phase 2 with destroyed
  contributions and verified transcripts. The activation gate checks the whole
  key only when given the phase 1 file (`--ptau`), whose SHA-256 the manifest
  pins as `ceremony.phase1_ptau_sha256`, so it refuses a manifest marked
  `production: true` unless `--ptau` names that file and the proving key
  verifies against it. The gate checks that file only against the pinned hash
  and counts only phase 2 contributions, so the origin of phase 1 must be
  checked by hand. The committed key's phase 1 is not recorded, so it cannot
  be checked in full ([README](README.md#what-the-tests-cover)).
- Correct ethrex implementations of EIP-8141, EIP-8250, EIP-8272 and EIP-7843.
  The activation manifest records the EIP-8250 and EIP-8272 revisions, and the
  native suite pins ethrex `247e2dd2`.
- A fork-scoped proof that settlement's gas limits cover every path. The
  [native suite](test/native/README.md) measures them; it does not prove them.
- A mempool policy that admits the declared validation budget
  ([README](README.md#deployment)). EIP-8369's per-IL budget is provisional.
- Independent review of the circuit, contracts, dispatcher, client and
  deployment, repeated for any circuit toolchain upgrade.

What the tests check is in the header of each TypeScript test file,
[docs/design.md](docs/design.md#the-client-and-its-cross-checks) and
[test/native/README.md](test/native/README.md). The September and October 2026
testnet runs are in the [README](README.md#deployment), and earlier dated runs
are under the [`evidence-archive`](https://github.com/soispoke/minimal-shielded-pool/tree/evidence-archive/evidence) tag. The tests and runs show compatibility
with one testnet configuration, not production readiness.

## Reporting

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/soispoke/minimal-shielded-pool/security/advisories/new)
before opening a public issue. Include the affected commit, a minimal
reproduction, impact, and proposed mitigation. Do not test public deployments
without permission.
