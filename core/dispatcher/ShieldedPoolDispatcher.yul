/// @title ShieldedPoolDispatcher
/// @notice The pool's account code, an immutable EIP-8141 validation shell. A call with
/// exactly 288 bytes of calldata is the VERIFY entry: it checks a spend's frames, recent
/// root, nonce keys, signatures, proof and fee, then approves execution and payment. Every
/// other call is delegated to ShieldedPoolLogic, which keeps the pool's state in this
/// account's storage.
/// @dev Runtime layout: this code, then the ShieldedPoolLogic address and the Groth16
/// verifier address as two 32-byte words. The proof check calls the verifier directly,
/// not through the logic, because ethrex refuses a delegatecall inside a VERIFY frame.
/// The dispatcher deployed before the testnet's relaunch is archived byte-exact under the
/// evidence-archive tag, in evidence/vectors/2026-09-01-hegota-final-profile/. It reads
/// an older transaction encoding: flat fee fields, one gas limit per frame, EIP-8250's
/// TXPARAM indices one lower, and the recent root in an envelope field rather than
/// EIP-8272's canonical verifier frame (824cbc0b0e). Neither dispatcher can read the
/// other's transactions, so deploy the one that matches the chain.
object "ShieldedPoolDispatcher" {
    code {
        // ShieldedPoolLogic.currentRoot (storage slot 22) starts as EMPTY_ROOT, the root
        // of the empty depth-20 tree.
        sstore(22, 0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e)

        // The deployer appends the logic and verifier addresses to this initcode as two
        // 32-byte words, as tools/dispatcher.ts --initcode does; copy them after the runtime.
        let rsize := datasize("runtime")
        codecopy(rsize, sub(codesize(), 64), 64)
        datacopy(0, dataoffset("runtime"), rsize)
        return(0, add(rsize, 64))
    }

    object "runtime" {
        code {
            // EIP-8141's opcodes, which solc cannot emit. verbatim puts its first argument on
            // top of the stack, where EIP-8141 puts offset for FRAMEDATALOAD and APPROVE,
            // frameIndex for FRAMEPARAM and signatureIndex for SIGPARAM.
            function txParam(param) -> value { value := verbatim_1i_1o(hex"B0", param) }
            function frameParam(frameIndex, param) -> value {
                value := verbatim_2i_1o(hex"B3", frameIndex, param)
            }
            function frameDataLoad(frameIndex, offset) -> value {
                value := verbatim_2i_1o(hex"B1", offset, frameIndex)
            }
            function sigParam(signatureIndex, param) -> value {
                value := verbatim_2i_1o(hex"B4", signatureIndex, param)
            }
            // EIP-8272's RECENT_ROOT_ADDRESS.
            function recentRootAddress() -> a { a := 0x0000000000000000000000000000000000008272 }
            // APPROVE with an empty return region and scope 3, APPROVE_EXECUTION_AND_PAYMENT.
            function approveExecutionAndPayment() { verbatim_3i_0o(hex"AA", 0, 0, 3) }

            // Refusals revert with a 4-byte error selector. errCanonical, errValue, errDomain
            // and errNullifier are ShieldedPoolLogic's NotCanonical(), ValueTooLarge(),
            // InvalidDomain() and ZeroNullifier(), and errOwner is InvalidOwnerSignature().
            function fail(sel) {
                mstore(0, shl(224, sel))
                revert(0, 4)
            }
            function errShape() -> s { s := 0xe6d22e28 }
            function errRoot() -> s { s := 0xaf501e1c }
            function errProof() -> s { s := 0x7fcdd1f4 }
            function errKeys() -> s { s := 0x586e51ed }
            function errCanonical() -> s { s := 0xd7c7beeb }
            function errValue() -> s { s := 0x2ad907fb }
            function errFee() -> s { s := 0x315cb54e }
            function errDomain() -> s { s := 0xeb127982 }
            function errNullifier() -> s { s := 0xcbbbbfe1 }
            function errAuthorizer() -> s { s := 0xb4683784 }
            function errOwner() -> s { s := 0x38a85a8d }

            // BN254's scalar field order p, the circuit's field.
            function scalarField() -> v {
                v := 21888242871839275222246405745257275088548364400416034343698204186575808495617
            }
            // BN254's base field order q, the field of the proof's point coordinates.
            function baseField() -> v {
                v := 21888242871839275222246405745257275088696311157297823662689037894645226208583
            }
            // Amounts are below 2^128, the circuit's range check.
            function maxValue() -> v { v := 0x100000000000000000000000000000000 }
            // ShieldedPoolLogic.DOMAIN_TAG.
            function domainTag() -> v {
                v := 0xa9d03fa1cd97bcf3294dc8e3bb024f555393c98967b356967fa502abab366ed3
            }

            // The EIP-8272 source_id that publishEpochRoot(epoch) writes under:
            // keccak256(address20(pool) || bytes32(epoch)).
            function sourceId(epoch) -> id {
                mstore(0, shl(96, address()))
                mstore(0x14, epoch)
                id := keccak256(0, 0x34)
            }

            // The nullifier domain, as ShieldedPoolLogic.domainFor computes it. It takes the
            // epoch whose source_id the recent-root frame names, so a spender cannot choose
            // another epoch's domain and give one note a second nullifier.
            function domainVal(epoch) -> d {
                mstore(0, domainTag())
                mstore(0x20, chainid())
                mstore(0x40, address())
                mstore(0x60, epoch)
                d := mod(keccak256(0, 0x80), scalarField())
            }

            // The EIP-712 digest of the spend's intent, which the owner signs (intentDigest in
            // src/protocol.ts): keccak256(0x1901 || domainSeparator || structHash), with the
            // struct's fields read from frame settleIndex's settle(Spend) call. The domain names
            // this pool and chain, so an intent signed for one pool authorizes nothing in another.
            function intentDigest(settleIndex) -> digest {
                // keccak256 of the struct's type, src/protocol.ts's INTENT_TYPE: "Spend(bytes32
                // nullifier1,bytes32 nullifier2,bytes32 output1,bytes32 output2,uint256 amount,
                // address recipient,uint256 fee)" without the line breaks.
                mstore(0, 0x5bc3d836b6452533ad63082131baa2545301df9b0e2a93c17ac714eec4c28758)
                mstore(0x20, frameDataLoad(settleIndex, 132)) // nf1
                mstore(0x40, frameDataLoad(settleIndex, 164)) // nf2
                mstore(0x60, frameDataLoad(settleIndex, 196)) // out1
                mstore(0x80, frameDataLoad(settleIndex, 228)) // out2
                mstore(0xa0, frameDataLoad(settleIndex, 260)) // publicAmount
                mstore(0xc0, frameDataLoad(settleIndex, 324)) // recipient
                mstore(0xe0, frameDataLoad(settleIndex, 292)) // fee
                let structHash := keccak256(0, 0x100)
                // keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)")
                // and keccak256("Minimal Shielded Pool")
                mstore(0, 0x8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a866)
                mstore(0x20, 0xc8951252be791158e1407343b9bdb1d51f9b4c1f34bb5b3dcfe7f863af63cf17)
                mstore(0x40, chainid())
                mstore(0x60, address())
                let separator := keccak256(0, 0x80)
                mstore(0, shl(240, 0x1901))
                mstore(0x02, separator)
                mstore(0x22, structHash)
                digest := keccak256(0, 0x42)
            }

            function impl() -> a {
                codecopy(0, sub(codesize(), 64), 32)
                a := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            }
            function verifierAddr() -> a {
                codecopy(0, sub(codesize(), 32), 32)
                a := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            }

            // Checks the proof in this frame's calldata against the statement: frame
            // settleIndex's settle(Spend) values, then the owner from its signature.
            function verifyProof(settleIndex, owner) {
                // settle((root,rootSlot,epoch,domain,nf1,nf2,out1,out2,
                //         publicAmount,fee,recipient,authorizer)), one word each after the
                // 4-byte selector.
                let root := frameDataLoad(settleIndex, 4)
                let rootSlot := frameDataLoad(settleIndex, 36)
                let epoch := frameDataLoad(settleIndex, 68)
                let dom := frameDataLoad(settleIndex, 100)
                let nf1 := frameDataLoad(settleIndex, 132)
                let nf2 := frameDataLoad(settleIndex, 164)
                let out1 := frameDataLoad(settleIndex, 196)
                let out2 := frameDataLoad(settleIndex, 228)
                let pub := frameDataLoad(settleIndex, 260)
                let fee := frameDataLoad(settleIndex, 292)
                let recipient := frameDataLoad(settleIndex, 324)
                let authorizer := frameDataLoad(settleIndex, 356)

                // A settlement that fails after approval burns the notes, so every value
                // settlement refuses or cannot decode is refused before approval. EIP-8250
                // also asks applications that derive nonce keys to refuse a key of zero.
                if iszero(nf1) { fail(errNullifier()) }
                if iszero(nf2) { fail(errNullifier()) }
                if or(shr(64, rootSlot), shr(64, epoch)) { fail(errCanonical()) }
                if or(iszero(authorizer), shr(160, authorizer)) { fail(errAuthorizer()) }
                if shr(160, recipient) { fail(errCanonical()) }
                if iszero(eq(iszero(pub), iszero(recipient))) { fail(errShape()) }
                if iszero(eq(dom, domainVal(epoch))) { fail(errDomain()) }

                // The verifier sees only (beta, gamma, alpha), and gamma reduces each word
                // mod p, so a word must be the canonical encoding of the circuit's field
                // element. Otherwise a note owner could re-prove a spend with a value plus
                // p: the proof would verify, the pool would approve and pay the gas, and
                // settlement would revert. An aliased nullifier is a fresh nonce key, so
                // the pool would pay again on every alias.
                let p := scalarField()
                if iszero(lt(root, p)) { fail(errCanonical()) }
                if iszero(lt(dom, p)) { fail(errCanonical()) }
                if iszero(lt(nf1, p)) { fail(errCanonical()) }
                if iszero(lt(nf2, p)) { fail(errCanonical()) }
                if iszero(lt(out1, p)) { fail(errCanonical()) }
                if iszero(lt(out2, p)) { fail(errCanonical()) }
                if iszero(lt(pub, maxValue())) { fail(errValue()) }
                if iszero(lt(fee, maxValue())) { fail(errValue()) }

                // Calldata is the 256-byte proof (A, then B, then C), then beta, which must
                // be a field element; the verifier also checks it.
                let beta := calldataload(256)
                if iszero(lt(beta, p)) { fail(errProof()) }

                // Refuse non-canonical coordinates (q or more) and points at infinity before
                // calling the verifier. The patched verifier refuses them too
                // (VerifierCanonical.t.sol), so this is defense in depth.
                let q := baseField()
                for { let o := 0 } lt(o, 256) { o := add(o, 32) } {
                    if iszero(lt(calldataload(o), q)) { fail(errProof()) }
                }
                if iszero(or(calldataload(0), calldataload(32))) { fail(errProof()) }
                if iszero(or(or(calldataload(64), calldataload(96)), or(calldataload(128), calldataload(160)))) {
                    fail(errProof())
                }
                if iszero(or(calldataload(192), calldataload(224))) { fail(errProof()) }

                // Hybrid compression (eprint 2025/1500): alpha = keccak256(statement) mod p,
                // and gamma is the statement evaluated as a polynomial at alpha + beta,
                // highest term first. The statement is written at 0x200, past the verifier
                // call built at 0x80 below, which ends at 0x1e4. The owner is a 20-byte
                // signer, so it needs no range check.
                let st := 0x200
                mstore(st, nf1)
                mstore(add(st, 0x20), nf2)
                mstore(add(st, 0x40), out1)
                mstore(add(st, 0x60), out2)
                mstore(add(st, 0x80), root)
                mstore(add(st, 0xa0), dom)
                mstore(add(st, 0xc0), pub)
                mstore(add(st, 0xe0), fee)
                mstore(add(st, 0x100), recipient)
                mstore(add(st, 0x120), authorizer)
                mstore(add(st, 0x140), owner)
                let alpha := mod(keccak256(st, 0x160), p)
                let sigma := addmod(alpha, beta, p)
                let gamma := 0
                for { let o := 0x160 } o { o := sub(o, 0x20) } {
                    gamma := addmod(mulmod(gamma, sigma, p), mload(add(st, sub(o, 0x20))), p)
                }

                // verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3]) with the
                // public signals in circom's order, [beta, gamma, alpha].
                let m := 0x80
                mstore(m, shl(224, 0x11479fea))
                calldatacopy(add(m, 4), 0, 256)
                mstore(add(m, 0x104), beta)
                mstore(add(m, 0x124), gamma)
                mstore(add(m, 0x144), alpha)

                let ok := staticcall(500000, verifierAddr(), m, 0x164, 0, 32)
                if iszero(ok) { fail(errProof()) }
                if iszero(eq(returndatasize(), 32)) { fail(errProof()) }
                if iszero(eq(mload(0), 1)) { fail(errProof()) }
            }

            function verifyFrameApprove() {
                // The pool is the sender. Three frames, or four with one generic DEFAULT
                // tail; publicAmount does not force the fourth frame, since a withdrawal
                // without one leaves withdrawalCredit for a later claim. This entry runs as
                // frame 1, with two signatures and no blobs.
                if iszero(eq(txParam(0x02), address())) { fail(errShape()) }
                let frames := txParam(0x09)
                if iszero(or(eq(frames, 3), eq(frames, 4))) { fail(errShape()) }
                if iszero(eq(txParam(0x0A), 1)) { fail(errShape()) }
                if iszero(eq(txParam(0x0B), 2)) { fail(errShape()) }
                if txParam(0x07) { fail(errShape()) }
                // Two EIP-8250 nonce keys at sequence zero, which EIP-8250 requires a
                // single-use key to authenticate: a key at sequence zero can be consumed
                // once, so a second spend of either note is invalid.
                if iszero(eq(txParam(0x0E), 2)) { fail(errKeys()) }
                if txParam(0x01) { fail(errKeys()) }

                // The validation frames' gas limits are not pinned, except frame 0's
                // zero state limit, which identifies it below. A limit that is too
                // low only makes the transaction invalid, before any nonce key is
                // consumed, and the fee check below covers whatever is declared.
                // Wallets choose the limits and can raise them after a repricing,
                // within the verifier call's fixed 500000 gas.

                // Frame 0: EIP-8272's canonical recent-root verifier, identified as the spec
                // says: resolved target, VERIFY mode, zero flags, one 72-byte tuple, success
                // status and zero state limit, plus zero value. Its success shows the tuple
                // is stored and recent, and the source_id check below makes its root one the
                // pool published, so a spend cannot prove membership in a tree of its own.
                // Taking the root from this frame instead of pool storage keeps validation
                // free of sender storage reads, which ethrex requires before it holds
                // several of the pool's spends in its mempool at once.
                if iszero(eq(frameParam(0, 0x00), recentRootAddress())) { fail(errRoot()) }
                if iszero(eq(frameParam(0, 0x02), 1)) { fail(errRoot()) }
                if frameParam(0, 0x03) { fail(errRoot()) }
                if iszero(eq(frameParam(0, 0x04), 72)) { fail(errRoot()) }
                if iszero(eq(frameParam(0, 0x05), 1)) { fail(errRoot()) }
                if frameParam(0, 0x08) { fail(errRoot()) }
                if frameParam(0, 0x09) { fail(errRoot()) }

                // The first signature: secp256k1 (scheme 1), from the proof's authorizer, with
                // an empty msg (0), so the protocol validated it, low-s, over the canonical
                // signature hash of the whole transaction, which covers the second signature's
                // bytes. Its length is not checked: the protocol fixes it at 65 bytes, and
                // SIGPARAM exposes len(signature) for ARBITRARY entries only.
                let authorizer := frameDataLoad(2, 356)
                if or(iszero(authorizer), shr(160, authorizer)) { fail(errAuthorizer()) }
                if iszero(eq(sigParam(0, 0), authorizer)) { fail(errAuthorizer()) }
                if iszero(eq(sigParam(0, 1), 1)) { fail(errAuthorizer()) }
                if sigParam(0, 2) { fail(errAuthorizer()) }

                // The second signature: secp256k1, over the spend's EIP-712 intent as an
                // explicit digest, which the protocol validated against its signer. That
                // signer is the owner: the proof shows it is a leaf of the owner set the
                // inputs belong to, so only that set's device can authorize the spend.
                if iszero(eq(sigParam(1, 1), 1)) { fail(errOwner()) }
                if iszero(eq(sigParam(1, 2), intentDigest(2))) { fail(errOwner()) }

                // Frame 1: this proof-carrying VERIFY frame, targeting the pool, with flags 3
                // (it may approve execution and payment), the 288-byte proof and zero value.
                if iszero(eq(frameParam(1, 0x00), address())) { fail(errShape()) }
                if iszero(eq(frameParam(1, 0x02), 1)) { fail(errShape()) }
                if iszero(eq(frameParam(1, 0x03), 3)) { fail(errShape()) }
                if iszero(eq(frameParam(1, 0x04), 288)) { fail(errShape()) }
                if frameParam(1, 0x08) { fail(errShape()) }

                // Frame 2: the single settlement call, a SENDER frame to the pool. Zero flags
                // keep it out of an atomic batch, so a failing fourth frame cannot revert it,
                // and zero value because settle is not payable. Its execution limit is pinned
                // at 2,000,000 because running out of gas after approval would burn the notes.
                if iszero(eq(frameParam(2, 0x00), address())) { fail(errShape()) }
                if iszero(eq(frameParam(2, 0x01), 2000000)) { fail(errShape()) }
                // tools/check-gas-profile.ts bounds settlement's new storage slots at five,
                // conservatively: a final root, the epoch counter, two filled subtrees and a
                // withdrawal credit. Five slots of 64 state bytes at 1,530 gas per byte
                // (src/gas.ts) is 489,600, and the state limit is pinned at 550,000 for the
                // same reason as the execution limit.
                if iszero(eq(frameParam(2, 0x09), 550000)) { fail(errShape()) }
                if iszero(eq(frameParam(2, 0x02), 2)) { fail(errShape()) }
                if frameParam(2, 0x03) { fail(errShape()) }
                // settle(Spend) is 388 bytes, followed by two 48-byte notes, optionally
                // after a 1,088-byte ML-KEM-768 ciphertext. Settlement only emits them.
                let settleLength := frameParam(2, 0x04)
                if iszero(or(eq(settleLength, 484), eq(settleLength, 1572))) { fail(errShape()) }
                if frameParam(2, 0x08) { fail(errShape()) }
                if iszero(eq(shr(224, frameDataLoad(2, 0)), 0x921fcac7)) { fail(errShape()) }

                // Frame 3, present when frames == 4: a generic DEFAULT call with zero value
                // and flags to any nonzero target, the pool included. It must not be SENDER,
                // which calls as the pool and could reach settle with a statement no proof
                // covers. A DEFAULT call can do only what any caller can: settle requires the
                // pool as caller, shield requires value, and this VERIFY entry requires
                // frame 1. Its gas and calldata have no pool-specific ceiling: EIP-7825's cap
                // and the chain's transaction size limit are the wallet's job. The
                // authorizer's signature covers this target and calldata; it does not let the
                // call spend from the target account, which sees EIP-8141's entry point as
                // its caller.
                if eq(frames, 4) {
                    let target := frameParam(3, 0x00)
                    if iszero(target) { fail(errShape()) }
                    if frameParam(3, 0x02) { fail(errShape()) }
                    if frameParam(3, 0x03) { fail(errShape()) }
                    if frameParam(3, 0x08) { fail(errShape()) }
                }

                // The consumed EIP-8250 key set is exactly the two nullifiers. EIP-8250's
                // nonce_keys_hash is keccak256(count || keys), with the keys strictly
                // increasing.
                let nf1 := frameDataLoad(2, 132)
                let nf2 := frameDataLoad(2, 164)
                let lo := nf1
                let hi := nf2
                if gt(lo, hi) { lo := nf2 hi := nf1 }
                mstore(0, 2)
                mstore(0x20, lo)
                mstore(0x40, hi)
                if iszero(eq(txParam(0x0F), keccak256(0, 0x60))) { fail(errKeys()) }

                // Bind the exact EIP-8272 tuple the verifier frame proved, including
                // slot and epoch source: source_id at 0, uint64_be(slot) at 32, root
                // at 40 of the frame's 72 data bytes.
                let rootSlot := frameDataLoad(2, 36)
                let epoch := frameDataLoad(2, 68)
                if or(shr(64, rootSlot), shr(64, epoch)) { fail(errCanonical()) }
                if iszero(eq(frameDataLoad(0, 0), sourceId(epoch))) { fail(errRoot()) }
                if iszero(eq(shr(192, frameDataLoad(0, 32)), rootSlot)) { fail(errRoot()) }
                if iszero(eq(frameDataLoad(0, 40), frameDataLoad(2, 4))) { fail(errRoot()) }

                verifyProof(2, sigParam(1, 0))
                // The pool pays the gas, so the proof's fee must cover the transaction's
                // maximum cost (TXPARAM 0x06), or a spend could pay its gas out of other
                // notes' value. Whatever the transaction does not use stays in the pool.
                if lt(frameDataLoad(2, 292), txParam(0x06)) { fail(errFee()) }
                approveExecutionAndPayment()
            }

            // The VERIFY entry is chosen by its length, 288 bytes (the proof, then beta).
            // No well-formed ShieldedPoolLogic call has that length, and outside a frame
            // transaction the first TXPARAM halts.
            if eq(calldatasize(), 288) {
                verifyFrameApprove()
                stop()
            }

            // Delegate everything else to the logic. 0x1c9c380 is 30,000,000, above EIP-7825's
            // 2^24 cap on a transaction's gas, so the call gets all but 1/64 of the
            // remaining gas (EIP-150).
            let target := impl()
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(0x1c9c380, target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
