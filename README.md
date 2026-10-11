# Minimal shielded pool

An immutable shielded pool for native ETH on the ethrex Hegotá testnet. It uses
EIP-8141 frame transactions, EIP-8250 keyed nonces and EIP-8272 recent roots.
It has no ERC-20 support, admin, governance or external paymaster.

> [!CAUTION]
> **For research and prototyping only.** This is not production software. Do
> not deploy it on mainnet or use it with real funds. See
> [SECURITY.md](SECURITY.md).

## Where to look

The code that guards the pool's funds is about 1,700 lines in `core/`:

- `core/circuits/spend.circom`: the relation every spend proves. The spender
  owns its input notes, each input with value is in the tree, the nullifiers
  follow from the notes, and value is conserved.
- `core/dispatcher/ShieldedPoolDispatcher.yul`: the pool's account code. Before
  approving a spend it checks the frame layout, the recent-root tuple, the
  nonce keys, the authorizer's signature, the proof and that the fee covers
  the maximum cost. It passes every other call to the logic.
- `core/contracts/src/ShieldedPoolLogic.sol`: the pool's state. Shields and
  settlement append notes to the tree, settlement records withdrawal credits
  that `claimWithdrawal` pays out, and `publishEpochRoot` publishes roots to
  EIP-8272.
- `core/contracts/src/Groth16Verifier.sol`: the verifier snarkjs generated for
  the setup's verification key, hardened by `tools/patch-verifier.ts`.
- `core/contracts/src/PoseidonT3.sol` and `PoseidonT4.sol`: circomlib's
  Poseidon with two and three inputs, which the logic calls for the tree and a
  shield's commitment. `PoseidonBN254.sol` wraps them for the tests.

Pool solvency, meaning that nobody can take out more than their own notes hold,
rests on these files and the artifacts built from them, on the trusted setup
behind the proving key, and on correct implementations of the EIPs in the node
software ([SECURITY.md](SECURITY.md#assumptions) lists the assumptions). It
does not rest on the client in `src/`. A faulty or malicious client can lose or
expose only what its own user holds, sends or discloses, and its transactions
can hold up other users' ([SECURITY.md](SECURITY.md) says how), but it cannot
take out more than its user's notes hold. [What the tests
cover](#what-the-tests-cover) says how these files are checked and which of
them the formal proofs still cover.

The client in `src/` is a fixture generator, not a production wallet:
`smoke.ts` and `nonce-race.ts` prove deposits and spends in advance and save
them, with their notes' secrets, in a fixture file that the pool commands send
from. `src/` falls into four groups, and each module's header says what it
does:

- **Protocol mirror:** `protocol.ts`, `poseidon.ts`, `wallet.ts` (the tree and
  the circuit's inputs), `frametx.ts` and `gas.ts`. They must agree with what
  the circuit, the contracts and the EIPs compute, or the client builds
  transactions the chain rejects or notes its user cannot spend, so
  `test/reference.test.ts` checks them against reference vectors.
- **Features:** `spend.ts` turns a fixture's shield and spend entries into
  calldata and a spend's signed frames, `deployment.ts` checks the deployed
  pool and a spend's recent root, and `send.ts` simulates, sends and checks
  transactions. `notes.ts` seals notes and keeps a sender's channels, and
  `scan.ts` finds a wallet's notes on chain. `disclosure.ts` writes and checks
  receipts.
- **Fixture generators:** `smoke.ts` and `nonce-race.ts`, what they share in
  `fixtures.ts`, and `prover.ts`, which proves with snarkjs.
- **Plumbing:** `bytes.ts`, `json.ts`, `errors.ts`, `files.ts`, `random.ts`,
  `rpc.ts`, and `cli/`, the command-line tools with their argument parser and
  secret reader (`cli/notes.ts` also keeps the wallet's state file under a
  lock).

```text
core/          the files above, the activation manifest and the deployment record
  artifacts/   R1CS, WASM, proving key, verification key, dispatcher initcode
src/           the TypeScript client; cli/ holds pool, notes, disclosure, smoke
               and nonce-race
tools/         setup and deployment scripts, the activation, gas, compiler-settings
               and formal-pin checks, and the dispatcher, verifier, Poseidon and
               vector generators
test/          node:test suites, fixtures, reference vectors and the native
               ethrex suite
docs/          design notes
```

[docs/design.md](docs/design.md) explains why the pool is built this way and
what a change to the tree or the statement has to touch.

## Quickstart

The client, tests and tools are TypeScript, which Node runs directly, with no
build step. They need Node 24.7 or later, the first release with ML-KEM-768 in
`node:crypto`, and that Node must be built against OpenSSL 3.5 or later, or
note delivery stops with an error. The checks and tests also need
[Foundry](https://getfoundry.sh) (CI uses 1.7.1), and the recipes need
[just](https://just.systems). `package.json` at the root pins the npm
packages, including the circuit toolchain (circom2 and snarkjs).

```sh
npm ci                  # install the pinned npm packages (or: just install)
just test               # what CI's test job runs: the four recipes below
just check-artifacts    # rebuild the circuit, dispatcher and verifier, compare with the repo
just check              # type, format, gas, activation and compiler-settings checks
just test-ts            # the TypeScript tests: node --test test/*.test.ts
just test-contracts     # format, lint and test the contracts with Forge
```

`just --list` shows the other recipes: the native suite, the formal-pin
report, Poseidon regeneration and deployment.

The command-line tools are under [Use](#use), after the sections that explain
what they send.

## How it works

A note commits to its owner, a random `rho` and its value:

```text
owner_pk = Poseidon3(1, spend_key, 0)
inner    = Poseidon2(owner_pk, rho)
cm       = Poseidon3(2, inner, value)
```

`PoseidonN` is circomlib's Poseidon over BN254 with N inputs, not the separate
Poseidon2 hash.

A spend proves a join-split with two inputs and two outputs. Its statement is
ten values: `[nf1, nf2, outCm1, outCm2, root, domain, publicAmount, fee,
recipient, authorizer]`. To save verification gas, the proof exposes three
public signals instead, using the hybrid compression of
[eprint 2025/1500](https://eprint.iacr.org/2025/1500): the pool computes
`alpha = keccak256(statement) mod r`, the circuit computes
`beta = Poseidon(statement)`, and both evaluate `gamma`, the statement as a
polynomial at `alpha + beta`. The ten values stay public in the settlement
data. The pool recomputes `alpha` and `gamma` from them and range-checks each
value itself, since the verifier no longer sees them. The circuit derives each nullifier from its input note and checks that
every positive input is in the tree, that value is conserved over 128-bit
amounts, and that at least one input carries value. It also requires distinct
nullifiers and outputs, a nonzero authorizer address, and a recipient exactly
when `publicAmount` is positive. A zero-value output must use a fixed "sink"
commitment for its position, which the pool never inserts.

Every note is identified by its tree epoch and leaf index. The nullifier binds
that position, so two notes with the same commitment are spent independently and no uniqueness registry is needed:

```text
D  = keccak256(domain_tag || chain_id || pool || epoch) mod r
nf = Poseidon3(4, Poseidon2(D, spend_key), Poseidon2(cm, leaf_index))
```

Here `domain_tag = keccak256("minimal-shielded-pool:occurrence-domain:v1")`,
each field is 32 bytes and `r` is the BN254 scalar field order. The pool
checks that `D` uses the epoch of the root the spend proves against, so each
note has exactly one nullifier. Wallets must track notes
by position and rebuild positions after a reorg.

## Transactions

The pool is the sender and payer of every spend. The two nullifiers are the
transaction's EIP-8250 nonce keys at sequence zero, so the protocol rejects a
second spend of either note. A spend has three frames and an optional fourth:

1. `VERIFY(0x…8272, tuple)`: EIP-8272's recent-root check of the
   `(source_id, slot, root)` tuple for the root the proof uses. The slot is the
   EIP-7843 `slotNumber` of the block that published the root.
2. `VERIFY(pool, proof)`: the pool checks the proof, binds it to that tuple,
   and checks the frame layout and the settlement frame's gas limits. It then
   approves execution and payment.
3. `SENDER(pool, settle(Spend) || notes)`: settlement inserts the outputs,
   records any withdrawal as a credit for `recipient` and emits the notes (see
   [Note delivery](#note-delivery)). It never publishes a root or
   calls the recipient, and the pool's `VERIFY` rejects anything settlement
   would refuse. Its gas limits must cover the worst tree shape, because running
   out after approval burns the notes. The pinned limits come from
   measurement, not a proof.
4. Optional `DEFAULT` call: any nonzero target, including the pool, and any
   calldata, with zero value and flags. A withdrawal usually calls
   `claimWithdrawal(recipient)`. A transfer can call `publishEpochRoot` so the
   notes it creates can be spent from the next slot, though a spend against
   that root is then easy to link to the transfer. It must name the epoch its
   outputs land in, which is a new epoch if settlement starts a new tree.
   Naming the old epoch succeeds but leaves them unpublished. A call to the
   pool can do only what any caller can: `settle` accepts only the pool itself
   as caller, `shield` needs ETH and the pool's `VERIFY` entry works only as
   the second frame, so a fourth frame that repeats settlement or the proof
   check reverts and settlement stands.

The dispatcher pins the data length of the first three frames and the
settlement frame's gas limits. The validation frames' gas limits are wallet
defaults, except the recent-root frame's state limit, which EIP-8272 requires
to be zero. A limit that is too low only makes the transaction invalid, and
the proof's fee covers whatever is declared. Wallets can therefore raise these
limits after a gas repricing without a new pool, as long as the proof check
still fits the 500,000 gas the pool forwards to the verifier. Settlement's
limits are pinned, so a repricing that makes settlement more expensive needs a
new pool. Wallets should keep the defaults, since a spend with different limits
stands out.

| Frame | Execution gas | State gas | Data |
|---|---:|---:|---:|
| Recent root | 8,000 default (uses 5,579) | 0 pinned | 72 bytes |
| Proof | 225,000 default (uses about 210,000) | 195,840 default | 288 bytes |
| Settlement | 2,000,000 pinned | 550,000 pinned | 484 or 1,572 bytes |

The settlement frame's data is the 388-byte `settle(Spend)` call followed by
96 note bytes, or 1,184 on a sender's first payment to a public address.
The proof frame's data is the 256-byte proof followed by `beta`. It needs a
limit of about 216,000, although it uses about 210,000, because each nested
call keeps back 1/64 of its gas (EIP-150). Below
that, the verifier runs out of gas and the pool reports an invalid proof. The
proof frame's state gas pays for creating the two nullifier keys.

The proof names a secp256k1 authorizer, which the wallet makes fresh for each
spend. Its signature covers the
whole transaction, including the proof, the recent-root tuple and the fourth
frame. The proof's `fee` must cover the transaction's maximum cost; any unused
part stays in the pool for good, and the October 2026 testnet spends used only
14% to 44% of their maximum cost at the default limits.

The wallet chooses the fourth frame's limits. Intrinsic gas plus every frame's
execution limit, or the calldata floor when larger, must fit EIP-7825's `2^24`
cap, of which the pool's own frames use 2.23M by default; state gas is
budgeted separately. The encoded transaction must also fit ethrex's 128 KiB
mempool limit.

If the fourth frame fails or is left out, settlement still stands, and a
withdrawal remains as a credit that anyone can pay out later with
`claimWithdrawal(recipient)`. A failed fourth frame makes the receipt's overall
status 0 even though settlement succeeded, so check each frame's status. The
claim pays `recipient` with a plain ETH transfer and cannot redirect it, so a
recipient that rejects plain ETH transfers strands the credit.

An account called by the fourth frame sees EIP-8141's entry point as its caller, so it must
authenticate its own owner. This is a direct account call, not an ERC-4337
adapter. See [SECURITY.md](SECURITY.md#the-fourth-frame).

When the current tree lacks room for the notes being inserted, the pool starts
a new epoch first, for shields and settlements alike. Sinks take no space, so a
full tree never blocks a full withdrawal. `publishEpochRoot(epoch)` takes no
root from its caller and reads the epoch's root from pool state, so anyone may
publish the pool's current or final epoch root to EIP-8272. A failed
publication consumes no notes. If a transfer's own publication fails or names
the old epoch, retry only the publication, because the transfer has already
settled. A later publication of the same epoch in the same slot replaces the
stored root, so proofs must use the root stored last.

## Note delivery

A recipient needs each note's amount and `rho` to spend it. Notes carry them on
chain, encrypted under a 32-byte secret `K` that the sender and recipient share,
so a payment can go to a reusable address and the recipient can recover
everything from its seed. `src/notes.ts` implements the format with
ML-KEM-768 and ChaCha20-Poly1305 from `node:crypto`:

```text
note = tag (16) || ChaCha20-Poly1305(value) (16 + 16)
tag  = PRF(K, "tag", i)[:16]    rho = PRF64(K, "rho", i) mod r
```

PRF is HMAC-SHA256; PRF64 joins two PRF outputs into 512 bits so the reduction
has no useful bias.

`i` counts the notes a sender has sent with `K`. A sender sets up `K` in one of
two ways, and later payments look the same whichever it used:

- **Public address** (a version byte, `owner_pk` and an ML-KEM-768 key,
  1,217 bytes, shared by ENS or QR): no prior contact. The payment that opens
  the channel carries the 1,088-byte ML-KEM ciphertext, which the recipient
  decapsulates. Two transactions carrying the same ciphertext would be linked,
  so until that payment is final, another payment to the same recipient opens
  a new channel.
- **Out of band:** the recipient issues the next numbered secret from its seed
  with `direct-secret` and sends it to the sender over Signal or another
  post-quantum channel. The wallet state records each number, so that it goes
  to one sender. Nothing extra goes on chain.

Every spend carries two notes, one for the payee and one for the change (a
withdrawal's payee note is random). A shield carries one. The pool only
checks their length and emits them in a `Notes` event; the one-time
authorizer's signature covers them. The CLI refuses a spend or shield whose
fixture lacks the wallet's notes.

Wallets download every event and look for the tags they expect, so no server
learns which notes are theirs. From its seed alone a wallet rebuilds its
incoming and change notes: it re-derives its secrets, decapsulates every
ciphertext and matches tags, and it tracks their spends by nullifier. A sender
cannot recompute an outgoing secret, so after a restore it opens a new channel
with each recipient. The change channel cannot be reopened, so a restored
wallet, or a device taking over sending from the account, rebuilds it with
`selfChannel` in `src/notes.ts`, 10 indices past the change notes in finalized
blocks ([SECURITY.md](SECURITY.md#note-delivery) says when that is safe). A sender
reserves an index in its saved state before broadcasting a new payment, because
a repeated index repeats the tag, key and `rho`, and retries a payment that did
not land with the same note. It also keeps fewer than 20 payments per channel
past the last one it has seen final, since the recipient watches 20 indices
ahead.

The `notes` commands under [Use](#use) give a wallet its address, its notes and
its direct secrets. `scan` and `direct-secret` need the config of a
`position-notes-v3` pool, such as the testnet deployment that
`core/deploy_config.json` records.

`scan` reads finalized blocks only and keeps its state in an owner-only file.
It reads every shield and settlement apart, even several in one transaction. A
node may leave a call's logs out of `eth_getLogs`, as ethrex `247e2dd2` does for
every log of a frame transaction whose fourth frame failed. Once a later leaf
shows the gap, or begins a new epoch before the last one was seen full, `scan`
rebuilds the call from block receipts, and it stops if leaves are still missing
rather than hide notes ([one exception](SECURITY.md#note-delivery)). `direct-secret`
needs a state that has been scanned, and hands out numbers only within 20 of
the highest one paid, which is how far a scan from the seed looks. History
older than Ethereum's retention window (EIP-4444) comes from archives, as it
already does for the tree leaves.

A normal spend grows by 96 bytes and about 4,000 gas, and an inclusion list
still holds four spends. A first payment to a public address grows by
1,184 bytes and is visibly larger. See [SECURITY.md](SECURITY.md#privacy-limits).

## Disclosure receipts

`src/disclosure.ts` lets a user show, after the fact, where funds in the
pool came from and where they went, like Tornado Cash's compliance tool but
without giving anyone the power to spend. For each note you spent, a receipt
gives its nullifier key `nk = Poseidon2(D, spend_key)`. With `nk` and the
note's position, anyone can confirm on chain which spend used up the note,
but `nk` cannot spend anything. A receipt can follow notes from a public
deposit through private transfers to a withdrawal, and fully explains a
spend when both of its inputs are disclosed. The `disclosure` commands are
under [Use](#use).

Export discloses only the notes you name, and gives a nullifier key only for
notes you spent. Notes paid to one address share its spend key, so their
nullifier key shows when any of that address's notes in the epoch is spent.
Export cannot tell such a key from one a single note uses, so it refuses every
nullifier key unless you pass `--address-wide`. Export reads the
pool's logs from the node and matches them locally. When those logs show no
spend of a note the fixture spends, or no transaction that created it, export
reads that note's nullifier slot in the EIP-8250 nonce manager to catch a spend
whose logs the node left out. The slot is a hash of the pool and the nullifier,
so once a spend publishes the nullifier, the node can tell which spend the
export looked up. Verify checks the receipt against finalized blocks and the
pool's deployed code. Both
commands trust their config and their node, so use your own copy of the config
and a node you control; a public node also learns which transactions you look
up. A receipt proves links and amounts, not who presents it or where the funds
came from before the deposit. See [SECURITY.md](SECURITY.md#privacy-limits)
for what a receipt reveals.

## Use

The command-line tools are in `src/cli/`, and each lists its options with
`--help`. None takes a key or seed as an argument, because other local users
can read a command line. `shield` and `publish` read the funded account's key
as one line on standard input, or at a hidden prompt on a terminal. The `notes`
commands read the seed the same way, unless `--seed-file` names a file readable
by its owner only.

The pool commands send only what a fixture holds: deposits and spends that
`smoke.ts` or `nonce-race.ts` proved in advance against the tree they expected.
Another deposit landing first leaves those proofs unusable, so each spend entry
keeps its inputs' openings, from which the notes can be proved again where
they landed. `notes scan` finds a wallet's notes, but no command spends them
yet.

```sh
# Deposit one of a fixture's notes, paid by the funded account, whose key it prompts for.
node src/cli/pool.ts RPC CONFIG FIXTURE shield [--note N]
# Publish an epoch's root to EIP-8272, so that spends can prove against it.
node src/cli/pool.ts RPC CONFIG FIXTURE publish [--epoch N]
# Send a fixture's transfer against the root that slot N published.
node src/cli/pool.ts RPC CONFIG FIXTURE transfer [--spend-key NAME] [--root-slot N]
# Send a fixture's withdrawal; its fourth frame claims the credit unless --no-tail.
node src/cli/pool.ts RPC CONFIG FIXTURE withdraw [--spend-key NAME] [--root-slot N] [--no-tail]

# Print the wallet's public address, which senders use to pay it.
node src/cli/notes.ts address [--account N] [--seed-file PATH]
# Find the wallet's notes in finalized blocks and print the unspent ones.
node src/cli/notes.ts scan --config CONFIG --state PATH [--rpc URL] [--seed-file PATH]
# Issue the next numbered secret, for one sender to receive out of band.
node src/cli/notes.ts direct-secret --config CONFIG --state PATH [--seed-file PATH]

# Write a receipt that discloses the named notes of a fixture.
node src/cli/disclosure.ts export --rpc URL --config CONFIG --fixture FIXTURE \
  (--only CM[,CM...] | --all) [--address-wide] --output PATH
# Check a receipt against finalized blocks and the pool's deployed code.
node src/cli/disclosure.ts verify --rpc URL --config CONFIG --receipt PATH

# Generate a fixture of a shield, a transfer and two withdrawals, with real proofs.
node src/cli/smoke.ts [--random --chain-id=N --pool-address=0x... --recipient=0x...] \
  [--output=PATH]
# Generate a fixture of two transfers against one root, which share the pool as sender.
node src/cli/nonce-race.ts --pool-address=0x... [--random] [--rpc=URL] [--output=PATH]
```

`--spend-key` takes the name of a fixture's spend entry, such as `withdraw_seed`
or a nonce-race fixture's `transfer_c`, never the `spend_key` value inside one.
Every pool command accepts `--dry-run`, which signs the transaction and asks
the RPC to simulate it without sending it.
The RPC still sees the signed transaction and could broadcast it. A transfer or
withdrawal without `--root-slot` uses the slot the config records for it. The
four `--action-*` options replace a spend's fourth frame with a custom call
(see [Transactions](#transactions)). A spend's proof fixes its `fee`, which must
cover the transaction's maximum cost. By default the fee cap per gas is twice
the base fee plus a 1 gwei tip; on a transfer or withdrawal,
`--max-fee-per-gas` and `--max-priority-fee-per-gas` set the cap and tip in
wei, so a proof whose fee no longer covers the default cap can still be sent.

With no options, `smoke.ts` rewrites the committed
`test/fixtures/smoke_fixture.json` from a public fixed seed. Any other chain or
pool needs `--random` and a `--recipient`, and the fixture then goes by default
under the ignored `artifacts/`, as the nonce-race fixture does, unless
`--output` names another path. `just deploy` deploys a fresh testbed pool,
records it in `core/deploy_config.json`, and shields, transfers and withdraws
through it with these commands.

## Deployment

This is pool profile `position-notes-v3`. It follows EIP-8141 at
`7d1c8bfb94`, EIP-8250 at `f3079a09e8` and EIP-8272 at `824cbc0b0e`: an eight-field envelope
with separate execution and state gas limits for each frame. Because the EIPs
are drafts, each supported combination is a separate profile, and profiles are
not wire compatible. The format chain 8141 used before its relaunch is archived
byte for byte, with the earlier devnet runs and reviews, under the
[`evidence-archive`](https://github.com/soispoke/minimal-shielded-pool/tree/evidence-archive/evidence) tag (commit `bfea6ff`).

Each profile needs its own deployment, because a deployed pool cannot be
upgraded. A `position-notes-v2` pool rejects this profile's settlement and
shield calldata, which carry notes. `core/deploy_config.json` records this
profile's testnet deployment on chain 8141: pool `0x5ec4…de09`, built from
commit `6af7a9b` and deployed at block 332781. On October 9, 2026 it completed
a shield, two root publications, a transfer, a withdrawal whose fourth-frame
claim failed and left its credit, and a withdrawal whose claim paid the
recipient both credits. A replay of the spent transfer was refused before it
was sent, both wallets' scans found every note from their seeds alone, one of
them received over note delivery's ML-KEM channel, and a disclosure receipt of
all six notes verified against the chain.

The earlier pools stay on chain: `position-notes-v2` (`0xcb83…0e86`, commit
`08bb034`, deployed at block 143402), which on September 25, 2026 completed the
same sequence without note delivery, and `position-notes-v1` (`0xac01…b100`,
commit `c26b8e4`), which on September 22, 2026 completed a shield, a transfer,
a root refresh, a withdrawal and claim, a fourth-frame claim and call, a
deliberate tail revert whose credit was claimed later, and a rejected replay.
The CLI refuses to shield into or spend from either.

Before shielding or spending, the CLI requires the config to name this profile
and checks the pool itself: the RPC must be on the configured chain, the pool's
code must be exactly what this profile's dispatcher deploys when linked to the
logic and verifier the config records, and its `domain(uint64)` must match the
profile's formula. The code check matters because both profiles share the
domain formula. The linked verifier must also accept a reference proof and
reject it with `gamma` changed. These checks catch a stale or mislabeled config,
not a malicious deployer: they trust the config's logic and verifier, which the
deployment script verified, and cannot see what a pool's constructor wrote to
storage. Before depositing into a pool someone else deployed, check its
deployment transactions.

A shield also refuses a fixture made for another chain, pool or epoch, or one
whose note would not land at the leaf and on the tree its proofs expect.
Before sending, and with `--dry-run`, the CLI gives the RPC the fully signed
transaction for simulation, and the RPC could broadcast it. Use an RPC you
trust.

The public mempool counts the two validation frames' declared limits plus
2,800 gas for the signature: 235,800 by default, while a spend uses about
218,500. That is well above EIP-8141's published default of 100,000. The chain
8141 testnet admits it; other networks need a policy that does.
[EIP-8369](https://eips.ethereum.org/EIPS/eip-8369) has not settled a
per-transaction budget.

## What the tests cover

The [justfile](justfile) lists every command the recipes under
[Quickstart](#quickstart) run, and the header of each TypeScript test file says
what it checks.
[docs/design.md](docs/design.md#the-client-and-its-cross-checks) names the
independent sources the client is checked against. `test/circuit.test.ts`
checks every deliberately broken witness against the committed R1CS, not only
the witness generator, and fails if `core/circuits/spend.circom` gains a `<--`
or `-->` assignment, which sets a signal without constraining it. That check
reads only `spend.circom`'s own source, so it does not catch every
unconstrained signal.

The tests rebuild the circuit and require byte-identical R1CS and WASM, and
regenerate the verifier from the proving key and require the committed file. The
committed artifacts come from circom2 0.2.8; 0.2.23 does not reproduce them
byte for byte, so a compiler upgrade means a new reviewed artifact set.
circom's optimizer removes the private `fee` input, which conservation
determines, yet the R1CS header still counts 96 private inputs. A tool that
reads private inputs by position (wires 4 to 99) therefore takes wire 99, the
first nullifier, for one of them. Map wires by name through a `--sym` build, as
`test/circuit.test.ts` does.
`tools/setup.sh` runs a new single-party test setup, not a ceremony. Run it
only to replace the test setup on purpose, then rebuild the activation manifest
and proof fixtures. The activation gate checks that the proving key's A and B
terms come from the committed R1CS and that the verifier's constants are the
key's verification key; the rest of the key needs the phase-1 file (`--ptau`, see
[SECURITY.md](SECURITY.md#assumptions)), without which the gate refuses a
manifest marked `production: true`.

The Forge tests in `core/contracts/test/` run the contracts with the committed
verifier and Poseidon libraries. They check that settlement fits the 2,000,000
gas pin through an epoch rollover and the longest carries (262,143 and 524,287
leaves), full-tree exits, sink positions, root publication apart from
settlement, a failed claim keeping its credit, a reentrant recipient paid once,
the refusal of direct calls to the implementation, and that the verifier
refuses non-canonical and infinity points and binds each statement value,
`beta` and `gamma`.

The native tests in [`test/native/`](test/native/README.md) run real proofs
through the pinned ethrex VM. They cover duplicate notes, replay, a reorg
simulated by database rollback, settlement gas and the fourth-frame rules, but
not networking, other clients or FOCIL.

A Lean formal verification of the `position-notes-v2` pool at `8835be7` lives
in [verified-shielded-pool](https://github.com/soispoke/verified-shielded-pool),
with its own CI. Its SPEC.md says which claims are proved and which are still
open, and pins twelve files by hash. Of those, the circuit's R1CS, the proving
and verification keys, the verifier and the Poseidon libraries still match. The
circuit source differs only in its comments. The dispatcher and the logic differ
in what they do: for note delivery, the dispatcher admits settlement frame data
of 484 or 1,572 bytes instead of exactly 388, and shield and settlement check
the length of the notes they carry and emit them. The dispatcher initcode,
`foundry.toml` and the activation manifest differ too. The proofs do not cover
these changes. The formal repository is checked out as
`formal/` inside a pool checkout, which git ignores here. CI's `formal-pins`
job lists every pinned file that differs, as warnings that do not fail the
build (`node tools/check-formal-pins.ts`, or `just formal-pins`).

See [SECURITY.md](SECURITY.md) for trust and failure boundaries.
