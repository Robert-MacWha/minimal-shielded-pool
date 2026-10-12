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
//     index    = sum(bits[i] * 2^i)          the note's leaf in its epoch's tree
//     nf       = Poseidon(4, Poseidon(domain, nk), Poseidon(cm, index))
// The spender proves it knows Q, each input's nk, rho, value and Merkle path
// (siblings, and the index bits, low bit first), and the owner's path in Q.
// The domain is keccak256(DOMAIN_TAG || chain_id || pool || epoch) mod p, and
// the pool requires the epoch whose root the spend proves against. Each epoch
// has its own depth-20 tree, and the pool starts the next epoch when a tree
// lacks room. Each leaf is therefore a separate note with exactly one
// nullifier, even when two leaves hold the same commitment. A circuit with
// another nullifier formula needs a fresh pool: under an existing one, its
// spent notes would get new nullifiers and could be spent again.
//
// Statement. Eleven values, in this order:
//     [nf1, nf2, out_cm1, out_cm2, root, domain, public_amount, fee,
//      recipient, authorizer, owner]
// They are private signals here. The first ten are public in the settlement
// calldata, and the pool reads owner from the owner's signature entry. Hybrid
// compression (eprint 2025/1500) exposes three public signals instead of
// eleven, which saves the verifier eight scalar multiplications:
//     alpha = keccak256(the eleven values as 32-byte words) mod p, computed
//             by the pool and passed in as the one public input;
//     beta  = Poseidon(the eleven values), an output;
//     gamma = x[0] + x[1]*s + ... + x[10]*s^10 at s = alpha + beta, an output
//             that the pool recomputes from its own copy of the values.
// circom puts outputs first, so the verifier's order is [beta, gamma, alpha].
// The verifier never sees the eleven values, so the pool range-checks each one
// itself (see verifyProof in the dispatcher). The client (src/protocol.ts),
// the dispatcher and this circuit must agree on the order and encoding of the
// values, and a mismatch shows up only as an invalid proof.
//
// The rules, beyond each nullifier following from its note:
//   - Both inputs share Q. An input with value must open at root. A
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
//     insert sinks, so a spend can leave an output empty without using tree
//     capacity, and a full tree never blocks a full withdrawal. A positive
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

// circomlib, found through circom2's -l node_modules.
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

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

// One input note: its nullifier, and its membership at root when it has value.
template InputNote(DEPTH) {
    signal input root;
    signal input domain;
    signal input owner_root;
    signal input nk;
    signal input rho;
    signal input value;
    signal input siblings[DEPTH];
    signal input bits[DEPTH];
    signal output nf;

    var index = 0;
    for (var i = 0; i < DEPTH; i++) {
        index += bits[i] * (2 ** i);
    }

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

    component path = MerkleRoot(DEPTH);
    path.leaf <== leaf.out;
    for (var i = 0; i < DEPTH; i++) {
        path.siblings[i] <== siblings[i];
        path.bits[i] <== bits[i];
    }
    // Membership only for a note with value: a zero-value input may be a dummy.
    (path.root - root) * value === 0;

    // The domain carries the input's epoch and the index its leaf, so each funded
    // leaf has one nullifier. cm stays in so that a zero-value dummy, whose path is
    // not checked, cannot copy a funded note's nullifier with its key and index.
    component domainKey = Poseidon(2);
    domainKey.inputs[0] <== domain;
    domainKey.inputs[1] <== nk;
    component occurrence = Poseidon(2);
    occurrence.inputs[0] <== leaf.out;
    occurrence.inputs[1] <== index;
    component null = Poseidon(3);
    null.inputs[0] <== 4;
    null.inputs[1] <== domainKey.out;
    null.inputs[2] <== occurrence.out;
    nf <== null.out;
}

template Spend(DEPTH, OWNER_DEPTH) {
    signal input root;
    signal input domain;
    signal input owner_root;     // Q, the owner set both inputs belong to
    signal input owner;          // the owner set's address that signs this spend
    signal input owner_siblings[OWNER_DEPTH];
    signal input owner_bits[OWNER_DEPTH];
    signal input in_nk[2];
    signal input in_rho[2];
    signal input in_value[2];
    signal input in_siblings[2][DEPTH];
    signal input in_bits[2][DEPTH];
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
        note[k] = InputNote(DEPTH);
        note[k].root <== root;
        note[k].domain <== domain;
        note[k].owner_root <== owner_root;
        note[k].nk <== in_nk[k];
        note[k].rho <== in_rho[k];
        note[k].value <== in_value[k];
        for (var i = 0; i < DEPTH; i++) {
            note[k].siblings[i] <== in_siblings[k][i];
            note[k].bits[i] <== in_bits[k][i];
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

// The spend with its eleven-value statement compressed to (beta, gamma, alpha).
template CompressedSpend(DEPTH, OWNER_DEPTH) {
    signal input alpha;
    signal input root;
    signal input domain;
    signal input owner_root;
    signal input owner;
    signal input owner_siblings[OWNER_DEPTH];
    signal input owner_bits[OWNER_DEPTH];
    signal input in_nk[2];
    signal input in_rho[2];
    signal input in_value[2];
    signal input in_siblings[2][DEPTH];
    signal input in_bits[2][DEPTH];
    signal input out_inner[2];
    signal input out_value[2];
    signal input public_amount;
    signal input fee;
    signal input recipient;
    signal input authorizer;
    signal output beta;
    signal output gamma;

    component spend = Spend(DEPTH, OWNER_DEPTH);
    spend.root <== root;
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
        for (var i = 0; i < DEPTH; i++) {
            spend.in_siblings[k][i] <== in_siblings[k][i];
            spend.in_bits[k][i] <== in_bits[k][i];
        }
        spend.out_inner[k] <== out_inner[k];
        spend.out_value[k] <== out_value[k];
    }
    spend.public_amount <== public_amount;
    spend.fee <== fee;
    spend.recipient <== recipient;
    spend.authorizer <== authorizer;

    signal stmt[11];
    stmt[0] <== spend.nf1;
    stmt[1] <== spend.nf2;
    stmt[2] <== spend.out_cm1;
    stmt[3] <== spend.out_cm2;
    stmt[4] <== root;
    stmt[5] <== domain;
    stmt[6] <== public_amount;
    stmt[7] <== fee;
    stmt[8] <== recipient;
    stmt[9] <== authorizer;
    stmt[10] <== owner;

    component digest = Poseidon(11);
    for (var i = 0; i < 11; i++) {
        digest.inputs[i] <== stmt[i];
    }
    beta <== digest.out;

    // Horner's rule, highest coefficient first.
    signal sigma;
    sigma <== alpha + beta;
    signal acc[11];
    acc[10] <== stmt[10];
    for (var i = 10; i > 0; i--) {
        acc[i - 1] <== acc[i] * sigma + stmt[i - 1];
    }
    gamma <== acc[0];
}

component main {public [alpha]} = CompressedSpend(20, 16);
