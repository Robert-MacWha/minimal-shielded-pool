// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {LibSkewMmr} from "skew-mmr/lib/LibSkewMmr.sol";
import {LibSkewMmrVerifier} from "skew-mmr/lib/LibSkewMmrVerifier.sol";

/// @title ShieldedPoolLogic
/// @notice The minimal shielded pool's state and its state-changing entry points: shield,
/// settle, publishEpochRoot and claimWithdrawal. It runs only through the dispatcher
/// (core/dispatcher/ShieldedPoolDispatcher.yul), which delegatecalls every call except its
/// own VERIFY entry, so the state lives in the dispatcher's storage.
/// @dev The dispatcher checks a spend's proof and whole frame transaction before approving
/// it, and approval consumes the spend's nullifiers. A settlement that then fails burns the
/// notes, so every refusal in settle is also made before approval (see settle).
contract ShieldedPoolLogic {
    /// @notice The most trees each epoch's skew-MMR holds, as in the circuit and the dispatcher.
    uint256 public constant MAX_TREES = 20;
    /// @notice The notes each epoch's MMR holds, 2^(MAX_TREES + 1) - MAX_TREES - 2.
    uint256 public constant CAPACITY = 2 ** (MAX_TREES + 1) - MAX_TREES - 2;
    /// @dev BN254's scalar field order p, the circuit's field.
    uint256 internal constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    /// @dev Amounts are below 2^128, the circuit's range check.
    uint256 internal constant MAX_VALUE = 1 << 128;
    /// @notice The root of the empty MMR, LibSkewMmrVerifier's commitment keccak256(0, 0, 0, 0).
    bytes32 public constant EMPTY_ROOT = 0x012893657d8eb2efad4de0a91bcd0e39ad9837745dec3ea923737ea803fc8e3d;
    /// @notice keccak256("minimal-shielded-pool:occurrence-domain:v1"), the first word of
    /// every nullifier domain.
    bytes32 public constant DOMAIN_TAG = 0xa9d03fa1cd97bcf3294dc8e3bb024f555393c98967b356967fa502abab366ed3;
    /// @notice The first output's sink, Poseidon(2, 1, 0): the commitment a zero-value first
    /// output must have. Settlement does not insert sinks.
    bytes32 public constant SINK_0 = 0x23f1b896ada6ee5dac80945b11329e7ab64412c2be9f5c87cfa3261cc1d8216f;
    /// @notice The second output's sink, Poseidon(2, 2, 0).
    bytes32 public constant SINK_1 = 0x2fd476622c67c880b3049a76c7337192362834c9d6dfb55c5060bb96c98932bb;
    /// @notice EIP-8272's RECENT_ROOT_ADDRESS, which publishEpochRoot writes to.
    address public constant RECENT_ROOT_PREDEPLOY = address(0x8272);
    /// @notice A note is a 16-byte tag, a 16-byte encrypted amount and a 16-byte
    /// authentication tag. The pool publishes notes and never reads them: a wrong note only
    /// stops the recipient from finding its payment.
    uint256 public constant NOTE_BYTES = 48;
    /// @notice The length of the ML-KEM-768 ciphertext that a sender's first payment to a
    /// public address puts before its notes.
    uint256 public constant KEM_CIPHERTEXT_BYTES = 1088;
    /// @dev settle(Spend) calldata is the selector, fifteen words and the frontier's MAX_TREES
    /// words; the notes follow.
    uint256 internal constant SETTLE_SPEND_BYTES = 4 + (15 + MAX_TREES) * 32;

    address private immutable IMPLEMENTATION_SELF = address(this);
    address public immutable POSEIDON_T4;

    // The dispatcher's constructor writes EMPTY_ROOT to slot 0 and MAX_TREES to mmr.maxDepth
    // (slot 48), so these slots must not move.
    /// @notice The current MMR's root, the commitment to its frontier (see _insert).
    bytes32 public currentRoot; // slot 0
    /// @notice The ETH settlement owes each recipient, which claimWithdrawal pays out.
    mapping(address => uint256) public withdrawalCredit; // slot 1
    /// @notice The epoch whose MMR takes new notes.
    uint64 public currentEpoch; // slot 2
    /// @notice Each closed epoch's root, from when it closed.
    mapping(uint64 => bytes32) public finalRoot; // slot 3
    /// @dev The current epoch's skew-MMR. LibSkewMmr sizes its arrays by its own MAX_TREES of
    /// 42, so roots take slots 4 to 45, packedRanks 46, depth and count 47, maxDepth 48 and
    /// chains 49 to 90.
    LibSkewMmr.State internal mmr; // slots 4..90

    /// @dev settle's argument. The proof covers the statement nf1, nf2, outCm1, outCm2, domain,
    /// publicAmount, fee, recipient, authorizer, packedRanks, depth and frontier, in that order.
    /// root is the MMR's root that the recent-root tuple names, and the dispatcher checks that
    /// count, packedRanks, depth and frontier open it. rootSlot and epoch name the tuple, and
    /// the domain takes the same epoch.
    struct Spend {
        bytes32 root;
        uint64 rootSlot;
        uint64 epoch;
        bytes32 domain;
        bytes32 nf1;
        bytes32 nf2;
        bytes32 outCm1;
        bytes32 outCm2;
        uint256 publicAmount;
        uint256 fee;
        address recipient;
        address authorizer;
        uint64 count;
        uint256 packedRanks;
        uint256 depth;
        bytes32[MAX_TREES] frontier;
    }

    /// @notice A commitment was appended to the current epoch's MMR.
    /// @param index Its index in that MMR, counted in insertion order.
    /// @param newRoot The MMR's root after every note this call appends, so both outputs of one
    /// settlement carry the same root.
    event LeafAppended(bytes32 indexed cm, uint64 indexed epoch, uint64 index, bytes32 newRoot);
    /// @notice A settled spend's nullifier, which approval consumed as an EIP-8250 nonce key.
    /// Wallets track their spends by it.
    event NoteSpent(bytes32 indexed nf);
    /// @notice The MMR lacked room, so the pool closed an epoch and started an empty MMR.
    /// @param finalRoot The closed epoch's root, which spends of its notes keep proving against.
    event EpochRolled(uint64 indexed closedEpoch, bytes32 finalRoot, uint64 indexed newEpoch);
    /// @notice The pool wrote an epoch's root to EIP-8272.
    event RootPublished(uint64 indexed epoch, bytes32 indexed source, bytes32 root);
    /// @notice A settlement credited a withdrawal, which claimWithdrawal pays out.
    event WithdrawalCredited(address indexed recipient, uint256 amount);
    /// @notice claimWithdrawal paid a recipient its whole credit.
    event Withdrawn(address indexed recipient, uint256 amount);
    /// @notice The encrypted notes a shield or settlement carries, as sent.
    /// @param notes One note for a shield or two for a settlement, optionally after an
    /// ML-KEM-768 ciphertext.
    event Notes(bytes notes);

    error DirectImplementationCall();
    error ZeroValueShield();
    /// @notice An amount is 2^128 or more, which no proof can spend.
    error ValueTooLarge();
    /// @notice A shield's commitment is a sink. A shield's value is never zero, so only a
    /// Poseidon collision reaches this.
    error ReservedSink();
    /// @notice A value that must be a field element is p or more.
    error NotCanonical();
    error NotPoolSender();
    error ZeroNullifier();
    /// @notice A spend's domain is not domain(epoch).
    error InvalidDomain();
    /// @notice The epoch is after the current one.
    error InvalidEpoch();
    error InvalidAuthorizer();
    /// @notice A spend names a recipient without a withdrawal or a withdrawal without a
    /// recipient, has two equal outputs, or has a sink in the other output's position.
    error InvalidSettlementShape();
    /// @notice The epoch has no root, which happens only if the pool's deployment did not
    /// store EMPTY_ROOT.
    error InvalidRoot();
    error RootPublishFailed();
    error NoCredit();
    /// @notice The ETH transfer to the recipient failed, so the credit stays.
    error PayoutFailed();
    error InvalidHashLibrary();
    /// @notice A Poseidon call failed or did not return one field element.
    error HashFailed();
    error InvalidNotes();

    /// @dev Refuses a call to the implementation itself, whose own storage is not the pool's.
    /// A direct shield, for one, would lock its ETH in the implementation.
    modifier onlyDelegate() {
        if (address(this) == IMPLEMENTATION_SELF) revert DirectImplementationCall();
        _;
    }

    /// @dev The dispatcher's constructor, not this one, stores EMPTY_ROOT and the MMR's
    /// maxDepth.
    constructor(address poseidonT4) {
        if (poseidonT4.code.length == 0) revert InvalidHashLibrary();
        POSEIDON_T4 = poseidonT4;
    }

    /// @notice The number of notes in the current epoch's MMR, which is the next note's index.
    function nextIndex() external view returns (uint64) {
        return mmr.count;
    }

    /// @notice The EIP-8272 source_id that publishEpochRoot(epoch) writes under,
    /// keccak256(pool || bytes32(epoch)), where the pool is this contract's address.
    function sourceId(uint64 epoch) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), bytes32(uint256(epoch))));
    }

    /// @notice The nullifier domain of an epoch of this pool on this chain.
    /// @param epoch The epoch of the root a spend proves against.
    function domain(uint64 epoch) public view returns (bytes32) {
        return domainFor(block.chainid, address(this), epoch);
    }

    /// @notice keccak256(DOMAIN_TAG || chainId || pool || epoch) mod p, over 32-byte words.
    /// The domain keeps nullifiers of different chains, pools and epochs apart. Without the
    /// epoch, a commitment appended in two epochs would have one nullifier.
    /// @param epoch The epoch of the root a spend proves against.
    function domainFor(uint256 chainId, address pool, uint64 epoch) public pure returns (bytes32) {
        return bytes32(
            uint256(keccak256(abi.encodePacked(DOMAIN_TAG, chainId, bytes32(uint256(uint160(pool))), uint256(epoch))))
                % P
        );
    }

    /// @notice Deposits msg.value as a note: appends Poseidon(2, inner, msg.value) to the
    /// current MMR and emits the note. Anyone may call it.
    /// @dev The commitment takes its value from msg.value, so a note never holds more than
    /// was paid in. A full MMR starts a new epoch first.
    /// @param inner The recipient's Poseidon(owner_pk, rho), below p.
    /// @param note One note, optionally after an ML-KEM-768 ciphertext. Only its length is
    /// checked.
    /// @return index The new note's index in the current epoch's MMR.
    function shield(bytes32 inner, bytes calldata note) external payable onlyDelegate returns (uint64 index) {
        if (msg.value == 0) revert ZeroValueShield();
        if (msg.value >= MAX_VALUE) revert ValueTooLarge();
        if (uint256(inner) >= P) revert NotCanonical();
        if (note.length != NOTE_BYTES && note.length != KEM_CIPHERTEXT_BYTES + NOTE_BYTES) revert InvalidNotes();

        bytes32 cm = bytes32(_hash3(2, uint256(inner), msg.value));
        if (cm == SINK_0 || cm == SINK_1) revert ReservedSink();

        _ensureCapacity(1);
        bytes32 root;
        (index, root) = _insert(cm);
        currentRoot = root;
        emit LeafAppended(cm, currentEpoch, index, root);
        emit Notes(note);
    }

    /// @notice Settles a spend the dispatcher has approved: appends its outputs other than
    /// sinks, credits any withdrawal to its recipient and emits its notes. Only the pool
    /// itself can call it, as the SENDER frame of the spend's frame transaction.
    /// @dev Approval has already consumed the nullifiers, so a refusal here would burn the
    /// notes. Every check below was made before approval: the dispatcher checks the notes'
    /// length, the nullifiers, authorizer, domain, field elements, amounts, recipient and
    /// frontier; the proof makes the outputs distinct and each sink sit in its own position;
    /// and the recent-root frame proves a root the pool published for the epoch, which
    /// publishEpochRoot does only for an epoch up to currentEpoch. The calldata is
    /// settle(Spend) followed by two notes, optionally after an ML-KEM-768 ciphertext, and
    /// the authorizer's signature covers them.
    function settle(Spend calldata s) external onlyDelegate {
        if (msg.sender != address(this)) revert NotPoolSender();
        // The dispatcher admits the same two lengths before approval.
        uint256 notesLength = msg.data.length - SETTLE_SPEND_BYTES;
        if (notesLength != 2 * NOTE_BYTES && notesLength != KEM_CIPHERTEXT_BYTES + 2 * NOTE_BYTES) {
            revert InvalidNotes();
        }
        if (s.nf1 == bytes32(0) || s.nf2 == bytes32(0)) revert ZeroNullifier();
        if (s.authorizer == address(0)) revert InvalidAuthorizer();
        if (s.domain != domain(s.epoch)) revert InvalidDomain();
        if (s.epoch > currentEpoch) revert InvalidEpoch();
        if (
            uint256(s.domain) >= P || uint256(s.nf1) >= P || uint256(s.nf2) >= P || uint256(s.outCm1) >= P
                || uint256(s.outCm2) >= P
        ) revert NotCanonical();
        if (s.publicAmount >= MAX_VALUE || s.fee >= MAX_VALUE) revert ValueTooLarge();
        if ((s.publicAmount == 0) != (s.recipient == address(0))) revert InvalidSettlementShape();
        if (s.outCm1 == s.outCm2 || s.outCm1 == SINK_1 || s.outCm2 == SINK_0) {
            revert InvalidSettlementShape();
        }
        // Each output other than a sink becomes a new note, even when the MMR already holds
        // the same commitment: nullifiers bind the note's epoch and index, so the two are
        // separate notes.

        emit NoteSpent(s.nf1);
        emit NoteSpent(s.nf2);

        uint64 appendCount;
        if (s.outCm1 != SINK_0) appendCount++;
        if (s.outCm2 != SINK_1) appendCount++;
        _ensureCapacity(appendCount);

        bool new1 = s.outCm1 != SINK_0;
        bool new2 = s.outCm2 != SINK_1;
        uint64 i1;
        uint64 i2;
        bytes32 root;
        if (new1) (i1, root) = _insert(s.outCm1);
        if (new2) (i2, root) = _insert(s.outCm2);
        if (new1 || new2) {
            currentRoot = root;
            if (new1) emit LeafAppended(s.outCm1, currentEpoch, i1, root);
            if (new2) emit LeafAppended(s.outCm2, currentEpoch, i2, root);
        }

        if (s.publicAmount != 0) {
            withdrawalCredit[s.recipient] += s.publicAmount;
            emit WithdrawalCredited(s.recipient, s.publicAmount);
        }
        emit Notes(msg.data[SETTLE_SPEND_BYTES:]);
    }

    /// @notice Writes an epoch's root to EIP-8272, so spends can prove against it. Anyone
    /// may call it: the root comes from pool state, never from the caller.
    /// @dev Settlement never publishes, so a failed publication cannot consume approved
    /// note keys without creating the promised outputs. EIP-8272 keeps only the last root
    /// a source writes in a slot, so a second publication of an epoch in one slot replaces
    /// the first.
    /// @param epoch The current epoch, whose root changes as leaves arrive, or a closed one.
    function publishEpochRoot(uint64 epoch) external onlyDelegate {
        bytes32 root;
        if (epoch == currentEpoch) root = currentRoot;
        else if (epoch < currentEpoch) root = finalRoot[epoch];
        else revert InvalidEpoch();
        if (root == bytes32(0)) revert InvalidRoot();

        bytes32 salt = bytes32(uint256(epoch));
        (bool ok,) = RECENT_ROOT_PREDEPLOY.call(abi.encodePacked(salt, root));
        if (!ok) revert RootPublishFailed();
        emit RootPublished(epoch, sourceId(epoch), root);
    }

    /// @notice Pays a recipient its whole withdrawal credit with a plain ETH call. Anyone
    /// may call it, and the ETH goes only to who.
    /// @dev The credit is zeroed before the call, so a recipient that reenters is paid once.
    /// A failed payout reverts the claim and keeps the credit for a later one.
    function claimWithdrawal(address payable who) external onlyDelegate {
        uint256 amount = withdrawalCredit[who];
        if (amount == 0) revert NoCredit();
        withdrawalCredit[who] = 0;
        emit Withdrawn(who, amount);
        (bool ok,) = who.call{value: amount}("");
        if (!ok) revert PayoutFailed();
    }

    /// @dev Starts a new epoch when the current MMR lacks room for count notes, so an
    /// insertion never fails for lack of room after approval.
    function _ensureCapacity(uint64 count) internal {
        if (count > CAPACITY - mmr.count) _rollEpoch();
    }

    function _rollEpoch() internal {
        uint64 closed = currentEpoch;
        bytes32 closedRoot = currentRoot;
        finalRoot[closed] = closedRoot;
        currentEpoch = closed + 1;
        currentRoot = EMPTY_ROOT;
        // LibSkewMmr leaves roots and chains at or above depth undefined, so only these
        // reset. maxDepth stays.
        mmr.packedRanks = 0;
        mmr.depth = 0;
        mmr.count = 0;
        emit EpochRolled(closed, closedRoot, currentEpoch);
    }

    /// @dev A tree node, Poseidon(element, left, right), as the circuit hashes it.
    function _hashNode(bytes32 element, bytes32 left, bytes32 right) internal view returns (bytes32) {
        return bytes32(_hash3(uint256(element), uint256(left), uint256(right)));
    }

    /// @dev Poseidon(x0, x1, x2) from PoseidonT4.hash3 (selector 0x2dbf86c6). A failed call,
    /// a return other than one word, or an output of p or more reverts, so a faulty library
    /// cannot put a non-canonical node in the MMR.
    function _hash3(uint256 x0, uint256 x1, uint256 x2) internal view returns (uint256 out) {
        (bool ok, bytes memory ret) =
            POSEIDON_T4.staticcall{gas: 200_000}(abi.encodeWithSelector(bytes4(0x2dbf86c6), x0, x1, x2));
        if (!ok || ret.length != 32) revert HashFailed();
        out = abi.decode(ret, (uint256));
        if (out >= P) revert HashFailed();
    }

    /// @dev Appends cm to the current epoch's MMR (LibSkewMmr). Returns its index and the
    /// MMR's new root: LibSkewMmrVerifier's keccak commitment to the frontier, which the
    /// dispatcher opens with a spend's frontier.
    function _insert(bytes32 cm) internal returns (uint64 index, bytes32 root) {
        index = mmr.count;
        root = LibSkewMmrVerifier.append(mmr, cm, _hashNode);
    }
}
