// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {LibSkewMmr} from "skew-mmr/lib/LibSkewMmr.sol";
import {ShieldedPoolLogic} from "../src/ShieldedPoolLogic.sol";

// ShieldedPoolLogic's storage slots, which the tests write to set up MMR states. The MMR's
// roots[i] is slot MMR_ROOTS_SLOT + i and chains[i] is MMR_CHAINS_SLOT + i; its depth is the
// low byte of MMR_DEPTH_COUNT_SLOT and its count the eight bytes above.
uint256 constant CURRENT_ROOT_SLOT = 0;
uint256 constant CURRENT_EPOCH_SLOT = 2;
uint256 constant MMR_ROOTS_SLOT = 4;
uint256 constant MMR_PACKED_RANKS_SLOT = 46;
uint256 constant MMR_DEPTH_COUNT_SLOT = 47;
uint256 constant MMR_MAX_DEPTH_SLOT = 48;
uint256 constant MMR_CHAINS_SLOT = 49;

uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
uint256 constant MAX_TREES = 20;
uint256 constant TREE_CAPACITY = 2 ** (MAX_TREES + 1) - MAX_TREES - 2;
bytes32 constant EMPTY_ROOT = 0x012893657d8eb2efad4de0a91bcd0e39ad9837745dec3ea923737ea803fc8e3d;

// The note lengths the pool admits: one note for a shield, two for a spend, and either
// after a first payment's ML-KEM-768 ciphertext.
uint256 constant NOTE_BYTES = 48;
uint256 constant KEM_CIPHERTEXT_BYTES = 1088;
uint256 constant SPEND_NOTES_BYTES = 2 * NOTE_BYTES;
uint256 constant FIRST_PAYMENT_NOTES_BYTES = KEM_CIPHERTEXT_BYTES + 2 * NOTE_BYTES;

interface Vm {
    function deal(address, uint256) external;
    function etch(address, bytes calldata) external;
    function expectEmit(bool, bool, bool, bool) external;
    function expectRevert(bytes4) external;
    function getDeployedCode(string calldata artifactPath) external returns (bytes memory);
    function load(address, bytes32) external view returns (bytes32);
    function store(address, bytes32, bytes32) external;
}

interface IPool {
    function shield(bytes32 inner, bytes calldata note) external payable returns (uint64);
    function settle(ShieldedPoolLogic.Spend calldata s) external;
    function publishEpochRoot(uint64 epoch) external;
    function claimWithdrawal(address payable who) external;
    function currentRoot() external view returns (bytes32);
    function currentEpoch() external view returns (uint64);
    function nextIndex() external view returns (uint64);
    function finalRoot(uint64) external view returns (bytes32);
    function withdrawalCredit(address) external view returns (uint256);
    function domain(uint64 epoch) external view returns (bytes32);
    function sourceId(uint64) external view returns (bytes32);
}

/// Stands in for PoseidonT4 with a keccak hash, so most tests run cheaply.
contract MockPoseidonT4 {
    function hash3(uint256 x0, uint256 x1, uint256 x2) external pure returns (uint256) {
        return uint256(keccak256(abi.encode(x0, x1, x2))) % P;
    }
}

/// Stands in for the dispatcher: stores EMPTY_ROOT and the MMR's maxDepth at deployment, as
/// its constructor does, and delegates every call.
contract LogicProxy {
    address immutable implementation;

    constructor(address implementation_) {
        implementation = implementation_;
        assembly {
            sstore(CURRENT_ROOT_SLOT, EMPTY_ROOT)
            sstore(MMR_MAX_DEPTH_SLOT, MAX_TREES)
        }
    }

    /// The dispatcher's SENDER frame: settle(Spend) calldata with the notes appended.
    function settleAsSelf(ShieldedPoolLogic.Spend calldata s, bytes calldata notes) external {
        (bool ok, bytes memory ret) = address(this).call(abi.encodePacked(abi.encodeCall(IPool.settle, (s)), notes));
        if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
    }

    fallback() external payable {
        address target = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

contract RevertingRecentRoot {
    fallback() external payable {
        revert();
    }
}

/// Records the last EIP-8272 write: the salt in slot 0 and the root in slot 1.
contract RecordingRecentRoot {
    bytes32 public lastSalt;
    bytes32 public lastRoot;

    fallback() external payable {
        assembly {
            sstore(0, calldataload(0))
            sstore(1, calldataload(32))
        }
    }

    receive() external payable {}
}

/// A recipient that refuses ETH until told otherwise. tools/run_live_dispatcher.sh deploys
/// it as a live run's withdrawal recipient.
contract RejectEther {
    bool public reject = true;

    function setReject(bool v) external {
        reject = v;
    }

    receive() external payable {
        if (reject) revert();
    }
}

/// Re-enters the claim of its own credit from its receive hook.
contract ReentrantClaimer {
    IPool immutable pool;
    uint256 public payouts;

    constructor(IPool pool_) {
        pool = pool_;
    }

    receive() external payable {
        payouts++;
        if (payouts < 3) {
            try pool.claimWithdrawal(payable(address(this))) {} catch {}
        }
    }
}

contract DispatcherPoolTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant SINK_0 = 0x23f1b896ada6ee5dac80945b11329e7ab64412c2be9f5c87cfa3261cc1d8216f;
    bytes32 constant SINK_1 = 0x2fd476622c67c880b3049a76c7337192362834c9d6dfb55c5060bb96c98932bb;
    address constant ROOT_PREDEPLOY = address(0x8272);
    uint256 constant SETTLE_FRAME_GAS = 2_000_000;

    event SettlementGasMeasured(uint256 gasUsed);
    event Notes(bytes notes);

    ShieldedPoolLogic logic;
    LogicProxy proxy;
    IPool pool;

    /// A pool over the mock hashes, funded so withdrawals can be paid.
    function setUp() public {
        MockPoseidonT4 t4 = new MockPoseidonT4();
        logic = new ShieldedPoolLogic(address(t4));
        proxy = new LogicProxy(address(logic));
        pool = IPool(address(proxy));
        vm.deal(address(proxy), 100 ether);
    }

    /// A second pool whose logic calls the real PoseidonT4 runtime.
    function _realPool() internal returns (LogicProxy realProxy, IPool realPool) {
        address t4 = address(0xA004);
        vm.etch(t4, vm.getDeployedCode("PoseidonT4.sol:PoseidonT4"));
        realProxy = new LogicProxy(address(new ShieldedPoolLogic(t4)));
        realPool = IPool(address(realProxy));
    }

    function _store(address target, uint256 slot, uint256 value) internal {
        vm.store(target, bytes32(slot), bytes32(value));
    }

    /// Writes the MMR of `count` notes: the ranks of count's skew-binary form, largest first,
    /// as LibSkewMmr holds them, with nonzero placeholder roots and chains.
    function _seedMmr(address target, uint256 count) internal {
        uint256 packedRanks;
        uint256 depth;
        uint256 left = count;
        for (uint256 rank = MAX_TREES; rank > 0; rank--) {
            // A tree of rank r holds 2^(r + 1) - 1 notes.
            uint256 size = 2 ** rank - 1;
            while (left >= size) {
                packedRanks |= (rank - 1) << (6 * depth);
                _store(target, MMR_ROOTS_SLOT + depth, depth + 1);
                _store(target, MMR_CHAINS_SLOT + depth, depth + 1);
                depth++;
                left -= size;
            }
        }
        _store(target, MMR_PACKED_RANKS_SLOT, packedRanks);
        _store(target, MMR_DEPTH_COUNT_SLOT, depth | (count << 8));
    }

    /// A spend of epoch 0 on the mock pool, with fixed nullifiers.
    function _spend(bytes32 out1, bytes32 out2, uint256 amount, address recipient)
        internal
        view
        returns (ShieldedPoolLogic.Spend memory s)
    {
        // The logic never reads the frontier: the dispatcher checks it against root.
        bytes32[MAX_TREES] memory frontier;
        s = ShieldedPoolLogic.Spend({
            root: bytes32(uint256(7)),
            rootSlot: 9,
            epoch: 0,
            domain: pool.domain(0),
            nf1: bytes32(uint256(11)),
            nf2: bytes32(uint256(12)),
            outCm1: out1,
            outCm2: out2,
            publicAmount: amount,
            fee: 1,
            recipient: recipient,
            authorizer: address(0xA11CE),
            count: 0,
            packedRanks: 0,
            depth: 0,
            frontier: frontier
        });
    }

    function _settle(ShieldedPoolLogic.Spend memory s) internal {
        proxy.settleAsSelf(s, _notes());
    }

    function _bytes(uint256 length, uint8 seed) internal pure returns (bytes memory b) {
        b = new bytes(length);
        for (uint256 i; i < length; i++) {
            b[i] = keccak256(abi.encode(seed, i))[0];
        }
    }

    /// One note, as a shield carries.
    function _note() internal pure returns (bytes memory) {
        return _bytes(NOTE_BYTES, 0x11);
    }

    /// Two notes, as most spends carry.
    function _notes() internal pure returns (bytes memory) {
        return _bytes(SPEND_NOTES_BYTES, 0x22);
    }

    /// A first payment to a public address: an ML-KEM-768 ciphertext, then two notes.
    function _firstPaymentNotes() internal pure returns (bytes memory) {
        return _bytes(FIRST_PAYMENT_NOTES_BYTES, 0x33);
    }

    function test_direct_implementation_calls_are_rejected() public {
        vm.expectRevert(ShieldedPoolLogic.DirectImplementationCall.selector);
        logic.shield{value: 1}(bytes32(uint256(3)), _note());
    }

    function test_shield_does_not_call_recent_root_predeploy() public {
        vm.etch(ROOT_PREDEPLOY, type(RevertingRecentRoot).runtimeCode);
        uint64 index = pool.shield{value: 1 ether}(bytes32(uint256(33)), _note());
        require(index == 0 && pool.nextIndex() == 1, "shield did not settle");
    }

    function test_repeated_deposit_appends_two_funded_copies() public {
        bytes32 inner = bytes32(uint256(33));
        uint256 beforeBalance = address(pool).balance;
        uint64 first = pool.shield{value: 1 ether}(inner, _note());
        bytes32 firstRoot = pool.currentRoot();
        uint64 second = pool.shield{value: 1 ether}(inner, _note());
        require(first == 0 && second == 1 && pool.nextIndex() == 2, "deposit occurrence missing");
        require(pool.currentRoot() != firstRoot, "duplicate was not appended");
        require(address(pool).balance == beforeBalance + 2 ether, "both deposits must be funded");
        vm.expectRevert(ShieldedPoolLogic.ZeroValueShield.selector);
        pool.shield(inner, _note());
    }

    function test_actual_poseidon_library_runtimes_work_via_staticcall() public {
        (LogicProxy realProxy, IPool realPool) = _realPool();
        realPool.shield{value: 1}(bytes32(uint256(99)), _note());
        uint64 index = realPool.shield{value: 1}(bytes32(uint256(98)), _note());
        realPool.shield{value: 1}(bytes32(uint256(97)), _note());
        require(index == 1 && realPool.currentRoot() != EMPTY_ROOT, "actual Poseidon calls failed");

        _seedMmr(address(realProxy), TREE_CAPACITY - 1);
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(301)), bytes32(uint256(302)), 0, address(0));
        s.domain = realPool.domain(0);
        realProxy.settleAsSelf(s, _notes());
        require(realPool.currentEpoch() == 1 && realPool.nextIndex() == 2, "actual rollover failed");
    }

    // Settlement gas. Forge charges one gas dimension, so these tests check only the
    // settlement frame's 2,000,000 execution limit; the native suite checks the execution
    // and state limits under ethrex. An append takes at most one Poseidon hash, so the
    // heaviest settlements are a rollover and two merges in a row. These tests carry the
    // largest notes the dispatcher admits, a first payment's, and run the default profile's
    // Poseidon build, 8 to 9% cheaper per hash than the libsmall build the pool deploys and
    // the native suite runs.

    function test_two_million_gas_covers_rollover_settlement() public {
        (LogicProxy realProxy, IPool realPool) = _realPool();

        // An MMR one note short of full holds MAX_TREES - 1 trees. The settlement must
        // finalize that epoch, reset it, append two outputs and create a fresh withdrawal
        // credit.
        _seedMmr(address(realProxy), TREE_CAPACITY - 1);
        bytes32 oldRoot = bytes32(uint256(777));
        vm.store(address(realProxy), bytes32(CURRENT_ROOT_SLOT), oldRoot);
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(401)), bytes32(uint256(402)), 7, address(0xB0B));
        s.domain = realPool.domain(0);

        bytes memory call = abi.encodeCall(LogicProxy.settleAsSelf, (s, _firstPaymentNotes()));
        uint256 beforeGas = gasleft();
        (bool ok,) = address(realProxy).call{gas: SETTLE_FRAME_GAS}(call);
        uint256 used = beforeGas - gasleft();
        emit SettlementGasMeasured(used);

        require(ok, "two-million settlement cap exhausted");
        require(realPool.currentEpoch() == 1, "epoch did not roll");
        require(realPool.finalRoot(0) == oldRoot, "final root missing");
        require(realPool.nextIndex() == 2, "outputs missing");
        require(realPool.withdrawalCredit(address(0xB0B)) == 7, "credit missing");
    }

    /// Settles two merges in a row with the gas a 2,000,000 frame forwards past the
    /// dispatcher's delegatecall: all but 1/64 (EIP-150). The MMR's smallest trees have ranks
    /// 1 and 1, so the first output merges them into a rank-2 tree beside another, and the
    /// second output merges those two.
    function test_forwarded_two_million_covers_two_merges() public {
        (LogicProxy realProxy, IPool realPool) = _realPool();
        vm.deal(address(realProxy), 100 ether);
        // Trees of ranks 18 down to 2, then 1 and 1: 2^20 - 21 notes, less trees of ranks 0
        // and 1, plus two of rank 1.
        uint256 count = (1 << 20) - 21 - 1 - 3 + 6;
        _seedMmr(address(realProxy), count);
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(501)), bytes32(uint256(502)), 7, address(0xB0B));
        s.domain = realPool.domain(0);
        uint256 forwarded = (SETTLE_FRAME_GAS * 63) / 64;
        bytes memory call = abi.encodeCall(LogicProxy.settleAsSelf, (s, _firstPaymentNotes()));
        uint256 beforeGas = gasleft();
        (bool ok,) = address(realProxy).call{gas: forwarded}(call);
        emit SettlementGasMeasured(beforeGas - gasleft());
        require(ok, "two merges exhausted EIP-150 forwarded 2M");
        require(uint256(vm.load(address(realProxy), bytes32(MMR_DEPTH_COUNT_SLOT))) & 0xff == 17, "no merges");
        require(realPool.nextIndex() == count + 2, "outputs missing");
        require(realPool.withdrawalCredit(address(0xB0B)) == 7, "credit missing");
    }

    function test_settlement_does_not_call_recent_root_predeploy() public {
        vm.etch(ROOT_PREDEPLOY, type(RevertingRecentRoot).runtimeCode);
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(101)), bytes32(uint256(102)), 0, address(0));
        _settle(s);
        require(pool.nextIndex() == 2 && pool.currentRoot() != EMPTY_ROOT, "outputs missing");
    }

    function test_two_output_spend_rolls_before_cap_boundary() public {
        bytes32 oldRoot = bytes32(uint256(777));
        _seedMmr(address(proxy), TREE_CAPACITY - 1);
        vm.store(address(proxy), bytes32(CURRENT_ROOT_SLOT), oldRoot);
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(201)), bytes32(uint256(202)), 0, address(0));
        _settle(s);
        require(pool.currentEpoch() == 1, "epoch did not roll");
        require(pool.finalRoot(0) == oldRoot, "old root not retained");
        require(pool.nextIndex() == 2, "outputs not inserted into fresh epoch");
    }

    function test_full_tree_exit_consumes_no_capacity() public {
        _seedMmr(address(proxy), TREE_CAPACITY);
        ShieldedPoolLogic.Spend memory s = _spend(SINK_0, SINK_1, 5 ether, address(0xB0B));
        _settle(s);
        require(pool.currentEpoch() == 0, "exit rolled epoch");
        require(pool.nextIndex() == TREE_CAPACITY, "exit consumed capacity");
        require(pool.withdrawalCredit(address(0xB0B)) == 5 ether, "credit missing");
    }

    function test_invalid_sink_positions_and_same_spend_duplicate_outputs_reject() public {
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(55)), bytes32(uint256(55)), 0, address(0));
        vm.expectRevert(ShieldedPoolLogic.InvalidSettlementShape.selector);
        proxy.settleAsSelf(s, _notes());
        s = _spend(SINK_1, SINK_0, 0, address(0));
        vm.expectRevert(ShieldedPoolLogic.InvalidSettlementShape.selector);
        proxy.settleAsSelf(s, _notes());
    }

    function test_output_matching_an_existing_commitment_is_appended() public {
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(57)), bytes32(uint256(58)), 0, address(0));
        _settle(s);
        bytes32 firstRoot = pool.currentRoot();
        s = _spend(bytes32(uint256(57)), bytes32(uint256(59)), 0, address(0));
        s.nf1 = bytes32(uint256(13));
        s.nf2 = bytes32(uint256(14));
        _settle(s);
        require(pool.nextIndex() == 4, "duplicate output was skipped");
        require(pool.currentRoot() != firstRoot, "tree did not change");
    }

    function test_publication_is_separate_authenticated_and_retryable() public {
        vm.etch(ROOT_PREDEPLOY, type(RevertingRecentRoot).runtimeCode);
        vm.expectRevert(ShieldedPoolLogic.RootPublishFailed.selector);
        pool.publishEpochRoot(0);
        require(pool.currentRoot() == EMPTY_ROOT, "failed publish changed pool state");

        vm.etch(ROOT_PREDEPLOY, type(RecordingRecentRoot).runtimeCode);
        pool.publishEpochRoot(0);
        RecordingRecentRoot recorder = RecordingRecentRoot(payable(ROOT_PREDEPLOY));
        require(recorder.lastSalt() == bytes32(0), "wrong epoch salt");
        require(recorder.lastRoot() == EMPTY_ROOT, "wrong root");
    }

    function test_failed_claim_preserves_credit() public {
        RejectEther rejecter = new RejectEther();
        ShieldedPoolLogic.Spend memory s = _spend(SINK_0, SINK_1, 2 ether, address(rejecter));
        _settle(s);
        vm.expectRevert(ShieldedPoolLogic.PayoutFailed.selector);
        pool.claimWithdrawal(payable(address(rejecter)));
        require(pool.withdrawalCredit(address(rejecter)) == 2 ether, "credit was lost");
        rejecter.setReject(false);
        uint256 before = address(rejecter).balance;
        pool.claimWithdrawal(payable(address(rejecter)));
        require(pool.withdrawalCredit(address(rejecter)) == 0, "credit remained");
        require(address(rejecter).balance == before + 2 ether, "payout missing");
    }

    function test_reentrant_recipient_is_paid_its_credit_once() public {
        ReentrantClaimer claimer = new ReentrantClaimer(pool);
        _settle(_spend(SINK_0, SINK_1, 2 ether, address(claimer)));
        uint256 poolBefore = address(proxy).balance;
        pool.claimWithdrawal(payable(address(claimer)));
        require(address(claimer).balance == 2 ether, "credit paid twice");
        require(address(proxy).balance == poolBefore - 2 ether, "pool paid more than the credit");
        require(pool.withdrawalCredit(address(claimer)) == 0, "credit remained");
    }

    function test_filling_the_last_leaf_keeps_the_full_tree_root() public {
        // An MMR one note short of full; the last deposit fills it.
        bytes32 inner = bytes32(uint256(33));
        _seedMmr(address(proxy), TREE_CAPACITY - 1);
        pool.shield{value: 1 ether}(inner, _note());
        require(pool.nextIndex() == TREE_CAPACITY, "last note not appended");
        bytes32 fullRoot = pool.currentRoot();
        // The next deposit rolls the epoch and finalizes that same root.
        pool.shield{value: 1 ether}(inner, _note());
        require(pool.currentEpoch() == 1 && pool.finalRoot(0) == fullRoot, "final root lost");
        require(pool.nextIndex() == 1, "deposit missing from the new epoch");
    }

    /// The dispatcher's constructor writes maxDepth to MMR_MAX_DEPTH_SLOT, and the pool's
    /// appends read it there: capped at one tree, a second deposit needs a second tree.
    function test_mmr_max_depth_is_at_the_slot_the_dispatcher_writes() public {
        _store(address(proxy), MMR_MAX_DEPTH_SLOT, 1);
        pool.shield{value: 1}(bytes32(uint256(33)), _note());
        vm.expectRevert(LibSkewMmr.TooDeep.selector);
        pool.shield{value: 1}(bytes32(uint256(34)), _note());
    }

    function test_withdrawal_credits_to_one_recipient_accumulate() public {
        _settle(_spend(SINK_0, SINK_1, 2 ether, address(0xB0B)));
        _settle(_spend(SINK_0, SINK_1, 3 ether, address(0xB0B)));
        require(pool.withdrawalCredit(address(0xB0B)) == 5 ether, "a later withdrawal replaced a credit");
    }

    function test_second_output_alone_moves_the_root() public {
        _settle(_spend(SINK_0, bytes32(uint256(91)), 0, address(0)));
        LogicProxy other = new LogicProxy(address(logic));
        ShieldedPoolLogic.Spend memory first = _spend(bytes32(uint256(91)), SINK_1, 0, address(0));
        first.domain = IPool(address(other)).domain(0);
        other.settleAsSelf(first, _notes());
        require(pool.nextIndex() == 1, "second output not inserted");
        require(pool.currentRoot() == IPool(address(other)).currentRoot(), "root not recomputed");
    }

    function test_input_epoch_domains_are_distinct() public view {
        require(pool.sourceId(0) != pool.sourceId(1), "epoch sources collide");
        require(pool.domain(0) != pool.domain(1), "epoch domains collide");
        require(pool.domain(0) != bytes32(0), "zero domain");
    }

    function test_old_epoch_spend_uses_input_domain_after_rollover() public {
        _seedMmr(address(proxy), TREE_CAPACITY);
        pool.shield{value: 1}(bytes32(uint256(33)), _note());
        require(pool.currentEpoch() == 1, "epoch did not roll");
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(81)), bytes32(uint256(82)), 0, address(0));
        _settle(s);
        require(pool.nextIndex() == 3, "old epoch spend did not append to current tree");

        s.domain = pool.domain(1);
        vm.expectRevert(ShieldedPoolLogic.InvalidDomain.selector);
        proxy.settleAsSelf(s, _notes());
    }

    function test_current_epoch_spend_requires_current_epoch_domain() public {
        _store(address(proxy), CURRENT_EPOCH_SLOT, 1);
        ShieldedPoolLogic.Spend memory s = _spend(SINK_0, SINK_1, 1, address(0xB0B));
        s.epoch = 1;
        vm.expectRevert(ShieldedPoolLogic.InvalidDomain.selector);
        proxy.settleAsSelf(s, _notes());
        s.domain = pool.domain(1);
        _settle(s);
        require(pool.withdrawalCredit(address(0xB0B)) == 1, "credit missing");
    }

    function test_settlement_publishes_its_notes() public {
        bytes memory notes = _notes();
        vm.expectEmit(false, false, false, true);
        emit Notes(notes);
        _settle(_spend(bytes32(uint256(61)), bytes32(uint256(62)), 0, address(0)));

        notes = _firstPaymentNotes();
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(63)), bytes32(uint256(64)), 0, address(0));
        s.nf1 = bytes32(uint256(15));
        s.nf2 = bytes32(uint256(16));
        vm.expectEmit(false, false, false, true);
        emit Notes(notes);
        proxy.settleAsSelf(s, notes);
        require(pool.nextIndex() == 4, "outputs missing");
    }

    function test_settlement_rejects_other_note_lengths() public {
        uint256[7] memory lengths = [
            uint256(0),
            NOTE_BYTES,
            SPEND_NOTES_BYTES - 1,
            SPEND_NOTES_BYTES + 1,
            FIRST_PAYMENT_NOTES_BYTES - NOTE_BYTES,
            FIRST_PAYMENT_NOTES_BYTES - 1,
            FIRST_PAYMENT_NOTES_BYTES + 1
        ];
        ShieldedPoolLogic.Spend memory s = _spend(bytes32(uint256(65)), bytes32(uint256(66)), 0, address(0));
        for (uint256 i; i < lengths.length; i++) {
            vm.expectRevert(ShieldedPoolLogic.InvalidNotes.selector);
            proxy.settleAsSelf(s, new bytes(lengths[i]));
        }
        require(pool.nextIndex() == 0, "a rejected settlement appended outputs");
    }

    function test_shield_publishes_its_note_and_rejects_other_lengths() public {
        bytes memory note = _note();
        vm.expectEmit(false, false, false, true);
        emit Notes(note);
        pool.shield{value: 1}(bytes32(uint256(71)), note);

        note = _bytes(KEM_CIPHERTEXT_BYTES + NOTE_BYTES, 0x44);
        vm.expectEmit(false, false, false, true);
        emit Notes(note);
        pool.shield{value: 1}(bytes32(uint256(72)), note);

        uint256[5] memory lengths =
            [uint256(0), NOTE_BYTES - 1, NOTE_BYTES + 1, SPEND_NOTES_BYTES, FIRST_PAYMENT_NOTES_BYTES];
        for (uint256 i; i < lengths.length; i++) {
            vm.expectRevert(ShieldedPoolLogic.InvalidNotes.selector);
            pool.shield{value: 1}(bytes32(uint256(73)), new bytes(lengths[i]));
        }
        require(pool.nextIndex() == 2, "a rejected shield appended a leaf");
    }
}
