// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ShieldedPoolLogic} from "../src/ShieldedPoolLogic.sol";
import {PoseidonBN254} from "../src/PoseidonBN254.sol";
import {LogicProxy, IPool, Vm, NOTE_BYTES} from "./DispatcherPool.t.sol";

/// The pool's root against a depth-20 Merkle root computed here from the leaves alone, with
/// every empty subtree hashed up from a zero leaf rather than read from _zeros.
contract RootReferenceTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// One level up: pairs of nodes, the last one paired with the empty subtree if alone.
    function _up(uint256[] memory level, uint256 empty) internal pure returns (uint256[] memory next) {
        next = new uint256[]((level.length + 1) / 2);
        for (uint256 i = 0; i < next.length; i++) {
            next[i] = PoseidonBN254.hash2(level[2 * i], 2 * i + 1 < level.length ? level[2 * i + 1] : empty);
        }
    }

    /// The depth-20 root of the leaves, with each empty subtree hashed up from a zero leaf.
    function _reference(uint256[] memory leaves) internal pure returns (uint256) {
        uint256 empty = 0;
        for (uint256 l = 0; l < 20; l++) {
            leaves = _up(leaves, empty);
            empty = PoseidonBN254.hash2(empty, empty);
        }
        return leaves[0];
    }

    /// A pool whose logic calls the real PoseidonT3 and PoseidonT4 runtimes.
    function _realPool() internal returns (IPool) {
        (address t3, address t4) = (address(0xA003), address(0xA004));
        vm.etch(t3, vm.getDeployedCode("PoseidonT3.sol:PoseidonT3"));
        vm.etch(t4, vm.getDeployedCode("PoseidonT4.sol:PoseidonT4"));
        return IPool(address(new LogicProxy(address(new ShieldedPoolLogic(t3, t4)))));
    }

    /// The mock-based tests cannot compare roots with a reference, since _zeros holds the
    /// real Poseidon chain. With the real runtimes, the root after one to five deposits must
    /// equal the reference, which checks _zeros and _computeRoot.
    function test_real_poseidon_root_matches_reference() public {
        for (uint256 n = 1; n <= 5; n++) {
            IPool pool = _realPool();
            uint256[] memory leaves = new uint256[](n);
            for (uint256 i; i < n; i++) {
                pool.shield{value: 1}(bytes32(1000 + i), new bytes(NOTE_BYTES));
                leaves[i] = PoseidonBN254.hash3(2, 1000 + i, 1);
            }
            require(uint256(pool.currentRoot()) == _reference(leaves), "root differs from the reference");
        }
    }

    receive() external payable {}
}
