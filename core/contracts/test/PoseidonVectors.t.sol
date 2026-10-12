// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PoseidonBN254} from "../src/PoseidonBN254.sol";

/// Minimal cheatcode surface (no forge-std dependency).
interface Vm {
    function readFile(string calldata) external view returns (string memory);
    function parseJsonStringArray(string calldata, string calldata) external pure returns (string[] memory);
    function parseJsonString(string calldata, string calldata) external pure returns (string memory);
    function parseUint(string calldata) external pure returns (uint256);
    function toString(uint256) external pure returns (string memory);
}

/// Differential tests against vectors exported from circomlibjs (the package
/// the circuit's poseidon.circom pairs with) by ../../../tools/export_vectors.js.
/// Every Poseidon(2) and Poseidon(3) vector, the pool's tagged
/// owner_pk/cm/nf/out_cm chain, a soundness check that a single flipped input
/// changes the output, and a gas-regression ceiling.
contract PoseidonVectorsTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string constant PATH = "../../test/vectors/poseidon_bn254_vectors.json";

    function _u(string memory json, string memory key) internal pure returns (uint256) {
        return vm.parseUint(vm.parseJsonString(json, key));
    }

    function _arr(string memory json, string memory key) internal pure returns (uint256[] memory out) {
        string[] memory v = vm.parseJsonStringArray(json, key);
        out = new uint256[](v.length);
        for (uint256 i = 0; i < v.length; i++) {
            out[i] = vm.parseUint(v[i]);
        }
    }

    function test_poseidon2_vectors() external view {
        string memory json = vm.readFile(PATH);
        for (uint256 k = 0; k < 16; k++) {
            string memory idx = vm.toString(k);
            uint256[] memory input = _arr(json, string.concat(".poseidon2[", idx, "].in"));
            uint256 expected = _u(json, string.concat(".poseidon2[", idx, "].out"));
            require(
                PoseidonBN254.hash2(input[0], input[1]) == expected, string.concat("poseidon2 mismatch at vector ", idx)
            );
        }
    }

    function test_poseidon3_vectors() external view {
        string memory json = vm.readFile(PATH);
        for (uint256 k = 0; k < 16; k++) {
            string memory idx = vm.toString(k);
            uint256[] memory input = _arr(json, string.concat(".poseidon3[", idx, "].in"));
            uint256 expected = _u(json, string.concat(".poseidon3[", idx, "].out"));
            require(
                PoseidonBN254.hash3(input[0], input[1], input[2]) == expected,
                string.concat("poseidon3 mismatch at vector ", idx)
            );
        }
    }

    /// The pool's value-note spend chain, end to end: owner_pk, inner, cm,
    /// the domain-separated nf, the dummy nf, and both output commitments
    /// (the exact values the circom circuit computes for the same secrets).
    function test_pool_chain() external view {
        string memory json = vm.readFile(PATH);
        uint256 ownerRoot = _u(json, ".pool_chain.owner_root");
        uint256 nk = _u(json, ".pool_chain.nk");
        uint256 rho = _u(json, ".pool_chain.rho");
        uint256 value = _u(json, ".pool_chain.value");
        uint256 domain = _u(json, ".pool_chain.domain");

        uint256 ownerPk = PoseidonBN254.hash3(1, ownerRoot, nk);
        require(ownerPk == _u(json, ".pool_chain.owner_pk"), "owner_pk mismatch");
        uint256 inner = PoseidonBN254.hash2(ownerPk, rho);
        require(inner == _u(json, ".pool_chain.inner"), "inner mismatch");
        uint256 cm = PoseidonBN254.hash3(2, inner, value);
        require(cm == _u(json, ".pool_chain.cm"), "cm mismatch");
        uint256 domainKey = PoseidonBN254.hash2(domain, nk);
        uint256 nf = PoseidonBN254.hash3(4, domainKey, cm);
        require(nf == _u(json, ".pool_chain.nf"), "nf mismatch");
        uint256 nf2 = PoseidonBN254.hash3(4, domainKey, PoseidonBN254.hash3(2, inner, 0));
        require(nf2 == _u(json, ".pool_chain.nf2"), "dummy nf mismatch");

        uint256 outCm1 = PoseidonBN254.hash3(2, _u(json, ".pool_chain.out_inner1"), _u(json, ".pool_chain.out_value1"));
        require(outCm1 == _u(json, ".pool_chain.out_cm1"), "out_cm1 mismatch");
        uint256 outCm2 = PoseidonBN254.hash3(2, _u(json, ".pool_chain.out_inner2"), _u(json, ".pool_chain.out_value2"));
        require(outCm2 == _u(json, ".pool_chain.out_cm2"), "out_cm2 mismatch");
    }

    /// A single flipped input must change the hash (smoke soundness).
    function test_flip_changes_output() external pure {
        uint256 base2 = PoseidonBN254.hash2(1, 2);
        require(PoseidonBN254.hash2(2, 2) != base2, "flip a did not change hash2");
        require(PoseidonBN254.hash2(1, 3) != base2, "flip b did not change hash2");
        uint256 base3 = PoseidonBN254.hash3(1, 2, 3);
        require(PoseidonBN254.hash3(2, 2, 3) != base3, "flip a did not change hash3");
        require(PoseidonBN254.hash3(1, 3, 3) != base3, "flip b did not change hash3");
        require(PoseidonBN254.hash3(1, 2, 4) != base3, "flip c did not change hash3");
    }

    /// Gas ceiling: keep the loop-based implementation honest about its cost.
    function test_gas_hash2_under_ceiling() external view {
        string memory json = vm.readFile(PATH);
        uint256[] memory input = _arr(json, ".poseidon2[3].in");
        uint256 g0 = gasleft();
        PoseidonBN254.hash2(input[0], input[1]);
        uint256 used = g0 - gasleft();
        require(used < 60_000, "hash2 gas regression (>= 60k)");
    }
}
