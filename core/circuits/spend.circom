pragma circom 2.0.8;

// The spend relation of the minimal shielded pool: a join-split over native ETH
// with two input notes, two output notes, a public withdrawal amount and a fee,
// all in wei. There are no tokens. The pool is the sender and payer of every
// spend: the fee leaves the notes and stays in the pool, which pays the gas.
//
// Owners. A note belongs to an owner set: a depth-16 Poseidon tree whose leaves
// are one-time secp256k1 addresses held by the owner's signing device, with 0
// in any unused leaf. A spend reveals one of these addresses, the owner, and
// the pool requires the owner's signature over the spend (see the end of this
// comment). The prover holds the set's root Q and the note's nullifier key nk,
// which open and prove the owner's notes but cannot authorize a spend, so the
// device's keys never reach the prover.
//
// Notes. The first input of each three-input hash is a tag (1 owner key,
// 2 commitment, 4 nullifier) that keeps the three hashes apart:
//     owner_pk = Poseidon(1, Q, nk)
//     inner    = Poseidon(owner_pk, rho)     what a recipient gives a sender
//     cm       = Poseidon(2, inner, value)   shield hashes msg.value in on chain
//     nf       = Poseidon(4, Poseidon(domain, nk), cm)
// The spender proves it knows Q, each input's nk, rho, value and the opening
// of cm in the epoch's skew-MMR (@skew-mmr/circuits' SkewMmrInclusion): the
// tree that holds it, its children and the path from it to that tree's root,
// and the owner's path in Q. The domain is
// keccak256(DOMAIN_TAG || chain_id || pool || epoch) mod p, and the pool
// requires the epoch whose frontier the spend proves against. Each epoch has
// its own MMR of at most MAX_TREES trees, and the pool starts the next epoch
// when it lacks room. A commitment has one nullifier per epoch, so two
// insertions of the same commitment in an epoch can be spent only once
// between them. A fresh rho for each note keeps commitments distinct. A
// circuit with another nullifier formula needs a fresh pool: under an existing
// one, its spent notes would get new nullifiers and could be spent again.
//
// Statement. 12 + MAX_TREES values, in this order:
//     [nf1, nf2, out_cm1, out_cm2, domain, public_amount, fee, recipient,
//      authorizer, owner, packed_ranks, depth, roots[0], ...,
//      roots[MAX_TREES - 1]]
// roots, packed_ranks and depth are the MMR's frontier as LibSkewMmr holds it,
// with roots above depth zero. The pool publishes a keccak commitment to the
// frontier rather than the frontier itself, and the dispatcher checks the
// frontier against it. The values are private signals here. All but the owner
// are public in the settlement calldata, and the pool reads owner from the
// owner's signature entry. Hybrid compression (eprint 2025/1500) exposes three
// public signals instead of all of them, which saves the verifier a scalar
// multiplication per value:
//     alpha = keccak256(the values as 32-byte words) mod p, computed by the
//             pool and passed in as the one public input;
//     beta  = the values chained into Poseidon(2), from zero (see
//             StatementDigest), an output;
//     gamma = x[0] + x[1]*s + ... + x[n-1]*s^(n-1) at s = alpha + beta, an
//             output that the pool recomputes from its own copy of the values.
// circom puts outputs first, so the verifier's order is [beta, gamma, alpha].
// The verifier never sees the values, so the pool range-checks each one itself
// (see verifyProof in the dispatcher). The client (src/protocol.ts), the
// dispatcher and this circuit must agree on the order and encoding of the
// values, and a mismatch shows up only as an invalid proof.
//
// The rules, beyond each nullifier following from its note:
//   - Both inputs share Q. An input with value must open in the frontier. A
//     zero-value input is not checked, so a single note can be spent beside a
//     fabricated dummy, which adds no value.
//   - The owner is a nonzero leaf of Q. Unused leaves are 0, which no
//     signature can come from.
//   - Every amount is below 2^128, and value is conserved.
//   - At least one input carries value.
//   - nf1 != nf2, so one note cannot be both inputs. EIP-8250 refuses a
//     repeated nonce key too, as defense in depth.
//   - A zero-value output k must use inner k + 1, which makes its commitment
//     Poseidon(2, k + 1, 0), ShieldedPoolLogic's SINK_k. Settlement does not
//     insert sinks, so a spend can leave an output empty without using MMR
//     capacity, and a full MMR never blocks a full withdrawal. A positive
//     output may use neither sink inner, so sink inners only ever carry zero.
//   - out_cm1 != out_cm2. Settlement refuses two equal outputs, and a sink
//     in the other position. The dispatcher checks neither before approving,
//     so the proof must, or an approved spend would fail in settlement and
//     burn its inputs.
//   - recipient and authorizer are addresses, the authorizer is nonzero, and
//     a recipient is named exactly when public_amount is positive. The
//     dispatcher and settlement require the same. The owner needs no range
//     check: the pool takes it from a signature entry's 20-byte signer.
//
// The proof does not cover the rest of the transaction. Instead it names a
// fresh one-time secp256k1 authorizer and the owner, and the dispatcher
// (core/dispatcher/ShieldedPoolDispatcher.yul) requires exactly two
// signatures. The first comes from the authorizer and covers the whole frame
// transaction, including the recent-root tuple, the gas and fee fields, any
// fourth frame and the owner's signature. The second comes from the owner and
// covers an EIP-712 digest of the spend's nullifiers, outputs, withdrawal and
// fee, which a stock hardware wallet can sign. The dispatcher also binds the
// domain and the root to the recent-root tuple, checks the fee against the
// transaction's maximum cost, and requires the transaction's EIP-8250 nonce
// keys to be exactly {nf1, nf2} at sequence zero, so the protocol refuses a
// second spend of either note.
//
// A change to the relation needs new artifacts, a new verifier and a fresh
// pool; docs/design.md lists everything else it touches. A change to comments
// alone must keep every line of code on its line: circom builds line numbers
// into spend.wasm, which check-artifacts in the justfile rebuilds and compares
// byte for byte with core/artifacts/.

// circomlib and @skew-mmr/circuits, found through circom2's -l node_modules.
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@skew-mmr/circuits/inclusion.circom";

// The root of a depth-DEPTH Poseidon tree from a leaf and its path: each height's
// sibling and the leaf index's bit there, low bit first. The bits must be 0 or 1:
// any other value lets a prover pick both children of a node, and so place any leaf
// under a root whose children it knows.
template MerkleRoot(DEPTH) {
    signal input leaf;
    signal input siblings[DEPTH];
    signal input bits[DEPTH];
    signal output root;

    component node[DEPTH];
    signal left[DEPTH];
    signal right[DEPTH];
    signal cur[DEPTH + 1];
    cur[0] <== leaf;
    for (var i = 0; i < DEPTH; i++) {
        bits[i] * (bits[i] - 1) === 0;
        left[i] <== cur[i] + bits[i] * (siblings[i] - cur[i]);  // bits[i] = 1: sibling on the left
        right[i] <== siblings[i] + bits[i] * (cur[i] - siblings[i]);
        node[i] = Poseidon(2);
        node[i].inputs[0] <== left[i];
        node[i].inputs[1] <== right[i];
        cur[i + 1] <== node[i].out;
    }
    root <== cur[DEPTH];
}

// One input note: its nullifier, and its opening in the frontier when it has value.
template InputNote(MAX_TREES) {
    var MAX_RANK = MAX_TREES - 1;

    signal input roots[MAX_TREES];
    signal input packed_ranks;
    signal input depth;
    signal input domain;
    signal input owner_root;
    signal input nk;
    signal input rho;
    signal input value;
    signal input tree;
    signal input children[2];
    signal input path_len;
    signal input path_elements[MAX_RANK];
    signal input path_siblings[MAX_RANK];
    signal input path_right[MAX_RANK];
    signal output nf;

    component pk = Poseidon(3);
    pk.inputs[0] <== 1;
    pk.inputs[1] <== owner_root;
    pk.inputs[2] <== nk;
    component inner = Poseidon(2);
    inner.inputs[0] <== pk.out;
    inner.inputs[1] <== rho;
    component leaf = Poseidon(3);
    leaf.inputs[0] <== 2;
    leaf.inputs[1] <== inner.out;
    leaf.inputs[2] <== value;

    component member = SkewMmrInclusion(MAX_TREES);
    for (var i = 0; i < MAX_TREES; i++) {
        member.roots[i] <== roots[i];
    }
    member.packedRanks <== packed_ranks;
    member.depth <== depth;
    member.element <== leaf.out;
    member.tree <== tree;
    member.children[0] <== children[0];
    member.children[1] <== children[1];
    member.pathLen <== path_len;
    for (var i = 0; i < MAX_RANK; i++) {
        member.pathElements[i] <== path_elements[i];
        member.pathSiblings[i] <== path_siblings[i];
        member.pathRight[i] <== path_right[i];
    }
    // Membership only for a note with value: a zero-value input may be a dummy.
    (1 - member.valid) * value === 0;

    // The domain carries the input's epoch. cm carries the value, so a zero-value dummy,
    // whose membership is not checked, cannot copy a funded note's nullifier with its key.
    component domainKey = Poseidon(2);
    domainKey.inputs[0] <== domain;
    domainKey.inputs[1] <== nk;
    component null = Poseidon(3);
    null.inputs[0] <== 4;
    null.inputs[1] <== domainKey.out;
    null.inputs[2] <== leaf.out;
    nf <== null.out;
}

template Spend(MAX_TREES, OWNER_DEPTH) {
    var MAX_RANK = MAX_TREES - 1;

    signal input roots[MAX_TREES];
    signal input packed_ranks;
    signal input depth;
    signal input domain;
    signal input owner_root;     // Q, the owner set both inputs belong to
    signal input owner;          // the owner set's address that signs this spend
    signal input owner_siblings[OWNER_DEPTH];
    signal input owner_bits[OWNER_DEPTH];
    signal input in_nk[2];
    signal input in_rho[2];
    signal input in_value[2];
    signal input in_tree[2];
    signal input in_children[2][2];
    signal input in_path_len[2];
    signal input in_path_elements[2][MAX_RANK];
    signal input in_path_siblings[2][MAX_RANK];
    signal input in_path_right[2][MAX_RANK];
    signal input out_inner[2];   // a recipient reveals inner, never its secrets
    signal input out_value[2];
    signal input public_amount;  // credited to recipient as a withdrawal
    signal input fee;            // kept by the pool, which pays the gas
    signal input recipient;      // zero for a transfer, the withdrawal address otherwise
    signal input authorizer;     // the fresh secp256k1 address that signs this spend
    signal output nf1;
    signal output nf2;
    signal output out_cm1;
    signal output out_cm2;

    // inputs, both in the owner set Q
    component note[2];
    for (var k = 0; k < 2; k++) {
        note[k] = InputNote(MAX_TREES);
        for (var i = 0; i < MAX_TREES; i++) {
            note[k].roots[i] <== roots[i];
        }
        note[k].packed_ranks <== packed_ranks;
        note[k].depth <== depth;
        note[k].domain <== domain;
        note[k].owner_root <== owner_root;
        note[k].nk <== in_nk[k];
        note[k].rho <== in_rho[k];
        note[k].value <== in_value[k];
        note[k].tree <== in_tree[k];
        note[k].children[0] <== in_children[k][0];
        note[k].children[1] <== in_children[k][1];
        note[k].path_len <== in_path_len[k];
        for (var i = 0; i < MAX_RANK; i++) {
            note[k].path_elements[i] <== in_path_elements[k][i];
            note[k].path_siblings[i] <== in_path_siblings[k][i];
            note[k].path_right[i] <== in_path_right[k][i];
        }
    }

    // the owner: a nonzero leaf of Q (the header says why it needs no range check)
    component ownerPath = MerkleRoot(OWNER_DEPTH);
    ownerPath.leaf <== owner;
    for (var i = 0; i < OWNER_DEPTH; i++) {
        ownerPath.siblings[i] <== owner_siblings[i];
        ownerPath.bits[i] <== owner_bits[i];
    }
    ownerPath.root === owner_root;
    component ownerIsZero = IsZero();
    ownerIsZero.in <== owner;
    ownerIsZero.out === 0;

    // outputs: cm = Poseidon(2, inner, value), as shield computes it. A zero-value
    // output k is SINK_k (inner k + 1), a positive output uses neither sink inner, and
    // the two commitments differ (the header says why).
    var SINK_INNER_0 = 1;
    var SINK_INNER_1 = 2;
    component outCm[2];
    component outIsZero[2];
    component outEqSink0[2];
    component outEqSink1[2];
    for (var k = 0; k < 2; k++) {
        outCm[k] = Poseidon(3);
        outCm[k].inputs[0] <== 2;
        outCm[k].inputs[1] <== out_inner[k];
        outCm[k].inputs[2] <== out_value[k];

        outIsZero[k] = IsZero();
        outIsZero[k].in <== out_value[k];
        if (k == 0) {
            (out_inner[k] - SINK_INNER_0) * outIsZero[k].out === 0;
        } else {
            (out_inner[k] - SINK_INNER_1) * outIsZero[k].out === 0;
        }
        outEqSink0[k] = IsEqual();
        outEqSink0[k].in[0] <== out_inner[k];
        outEqSink0[k].in[1] <== SINK_INNER_0;
        outEqSink0[k].out * (1 - outIsZero[k].out) === 0;
        outEqSink1[k] = IsEqual();
        outEqSink1[k].in[0] <== out_inner[k];
        outEqSink1[k].in[1] <== SINK_INNER_1;
        outEqSink1[k].out * (1 - outIsZero[k].out) === 0;
    }

    // Amounts below 2^128 keep both sides below 2^130, so the sum cannot wrap mod p.
    component rc[6];
    var vals[6] = [in_value[0], in_value[1], out_value[0], out_value[1], public_amount, fee];
    for (var k = 0; k < 6; k++) {
        rc[k] = Num2Bits(128);
        rc[k].in <== vals[k];
    }
    in_value[0] + in_value[1] === out_value[0] + out_value[1] + public_amount + fee;

    // A spend must consume value. Two fabricated zero-value inputs would otherwise make
    // a valid spend that stores two new nonce keys, free on a chain with zero base fee.
    component noRealInput = IsZero();
    noRealInput.in <== in_value[0] + in_value[1];
    noRealInput.out === 0;

    // recipient and authorizer are addresses and the authorizer is nonzero. A
    // recipient is named exactly when public_amount is positive, as the dispatcher
    // and settlement also require.
    component recipientBits = Num2Bits(160);
    recipientBits.in <== recipient;
    component authorizerBits = Num2Bits(160);
    authorizerBits.in <== authorizer;
    component authorizerIsZero = IsZero();
    authorizerIsZero.in <== authorizer;
    authorizerIsZero.out === 0;
    component publicIsZero = IsZero();
    publicIsZero.in <== public_amount;
    component recipientIsZero = IsZero();
    recipientIsZero.in <== recipient;
    publicIsZero.out === recipientIsZero.out;

    nf1 <== note[0].nf;
    nf2 <== note[1].nf;
    component sameNullifier = IsEqual();  // one note cannot be both inputs
    sameNullifier.in[0] <== nf1;
    sameNullifier.in[1] <== nf2;
    sameNullifier.out === 0;
    out_cm1 <== outCm[0].out;
    out_cm2 <== outCm[1].out;
    component sameOutput = IsEqual();  // settlement refuses equal outputs
    sameOutput.in[0] <== out_cm1;
    sameOutput.in[1] <== out_cm2;
    sameOutput.out === 0;
}

// The spend with its statement compressed to (beta, gamma, alpha).
template CompressedSpend(MAX_TREES, OWNER_DEPTH) {
    var MAX_RANK = MAX_TREES - 1;
    var N = 12 + MAX_TREES;

    signal input alpha;
    signal input roots[MAX_TREES];
    signal input packed_ranks;
    signal input depth;
    signal input domain;
    signal input owner_root;
    signal input owner;
    signal input owner_siblings[OWNER_DEPTH];
    signal input owner_bits[OWNER_DEPTH];
    signal input in_nk[2];
    signal input in_rho[2];
    signal input in_value[2];
    signal input in_tree[2];
    signal input in_children[2][2];
    signal input in_path_len[2];
    signal input in_path_elements[2][MAX_RANK];
    signal input in_path_siblings[2][MAX_RANK];
    signal input in_path_right[2][MAX_RANK];
    signal input out_inner[2];
    signal input out_value[2];
    signal input public_amount;
    signal input fee;
    signal input recipient;
    signal input authorizer;
    signal output beta;
    signal output gamma;

    component spend = Spend(MAX_TREES, OWNER_DEPTH);
    for (var i = 0; i < MAX_TREES; i++) {
        spend.roots[i] <== roots[i];
    }
    spend.packed_ranks <== packed_ranks;
    spend.depth <== depth;
    spend.domain <== domain;
    spend.owner_root <== owner_root;
    spend.owner <== owner;
    for (var i = 0; i < OWNER_DEPTH; i++) {
        spend.owner_siblings[i] <== owner_siblings[i];
        spend.owner_bits[i] <== owner_bits[i];
    }
    for (var k = 0; k < 2; k++) {
        spend.in_nk[k] <== in_nk[k];
        spend.in_rho[k] <== in_rho[k];
        spend.in_value[k] <== in_value[k];
        spend.in_tree[k] <== in_tree[k];
        spend.in_children[k][0] <== in_children[k][0];
        spend.in_children[k][1] <== in_children[k][1];
        spend.in_path_len[k] <== in_path_len[k];
        for (var i = 0; i < MAX_RANK; i++) {
            spend.in_path_elements[k][i] <== in_path_elements[k][i];
            spend.in_path_siblings[k][i] <== in_path_siblings[k][i];
            spend.in_path_right[k][i] <== in_path_right[k][i];
        }
        spend.out_inner[k] <== out_inner[k];
        spend.out_value[k] <== out_value[k];
    }
    spend.public_amount <== public_amount;
    spend.fee <== fee;
    spend.recipient <== recipient;
    spend.authorizer <== authorizer;

    signal stmt[N];
    stmt[0] <== spend.nf1;
    stmt[1] <== spend.nf2;
    stmt[2] <== spend.out_cm1;
    stmt[3] <== spend.out_cm2;
    stmt[4] <== domain;
    stmt[5] <== public_amount;
    stmt[6] <== fee;
    stmt[7] <== recipient;
    stmt[8] <== authorizer;
    stmt[9] <== owner;
    stmt[10] <== packed_ranks;
    stmt[11] <== depth;
    for (var i = 0; i < MAX_TREES; i++) {
        stmt[12 + i] <== roots[i];
    }

    component digest = StatementDigest(N);
    for (var i = 0; i < N; i++) {
        digest.stmt[i] <== stmt[i];
    }
    beta <== digest.out;

    // Horner's rule, highest coefficient first.
    signal sigma;
    sigma <== alpha + beta;
    signal acc[N];
    acc[N - 1] <== stmt[N - 1];
    for (var i = N - 1; i > 0; i--) {
        acc[i - 1] <== acc[i] * sigma + stmt[i - 1];
    }
    gamma <== acc[0];
}

// beta: the statement chained into Poseidon(2), starting from zero.
template StatementDigest(N) {
    signal input stmt[N];
    signal output out;

    component link[N];
    for (var i = 0; i < N; i++) {
        link[i] = Poseidon(2);
        link[i].inputs[0] <== i == 0 ? 0 : link[i - 1].out;
        link[i].inputs[1] <== stmt[i];
    }
    out <== link[N - 1].out;
}

component main {public [alpha]} = CompressedSpend(20, 16);
