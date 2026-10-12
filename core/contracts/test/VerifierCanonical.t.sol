// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Groth16Verifier} from "../src/Groth16Verifier.sol";

interface VmJson {
    function readFile(string calldata) external view returns (string memory);
    function parseJsonString(string calldata, string calldata) external pure returns (string memory);
    function parseJsonStringArray(string calldata, string calldata) external pure returns (string[] memory);
    function parseBytes32(string calldata) external pure returns (bytes32);
    function parseUint(string calldata) external pure returns (uint256);
}

contract VerifierCanonicalTest {
    VmJson constant vm = VmJson(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // The statement: twelve values, then the frontier's MAX_TREES roots.
    uint256 constant MAX_TREES = 20;
    uint256 constant N = 12 + MAX_TREES;
    Groth16Verifier verifier;
    string fixture;

    function setUp() public {
        verifier = new Groth16Verifier();
        fixture = vm.readFile("../../test/fixtures/smoke_fixture.json");
    }

    function _u(string memory path) internal view returns (uint256) {
        return vm.parseUint(vm.parseJsonString(fixture, path));
    }

    function _pair(string memory path) internal view returns (uint256[2] memory out) {
        string[] memory values = vm.parseJsonStringArray(fixture, path);
        out[0] = uint256(vm.parseBytes32(values[0]));
        out[1] = uint256(vm.parseBytes32(values[1]));
    }

    // Hybrid compression, as the dispatcher computes it: alpha hashes the
    // statement words, gamma evaluates them at alpha + beta, and the verifier
    // takes (beta, gamma, alpha).
    function _compress(uint256[N] memory s, uint256 beta) internal pure returns (uint256[3] memory input) {
        uint256 alpha = uint256(keccak256(abi.encodePacked(s))) % P;
        uint256 sigma = addmod(alpha, beta, P);
        uint256 gamma;
        for (uint256 i = N; i > 0; i--) {
            gamma = addmod(mulmod(gamma, sigma, P), s[i - 1], P);
        }
        input = [beta, gamma, alpha];
    }

    function _vector()
        internal
        view
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[N] memory s, uint256 beta)
    {
        a = _pair(".transfer.proof.pA");
        b = [_pair(".transfer.proof.pB[0]"), _pair(".transfer.proof.pB[1]")];
        c = _pair(".transfer.proof.pC");
        string[12] memory fields = [
            ".transfer.nf1",
            ".transfer.nf2",
            ".transfer.out_cm1",
            ".transfer.out_cm2",
            ".transfer.domain",
            ".transfer.public_amount",
            ".transfer.fee",
            ".transfer.recipient",
            ".transfer.authorizer",
            ".transfer.owner",
            ".transfer.packed_ranks",
            ".transfer.depth"
        ];
        for (uint256 i; i < fields.length; i++) {
            s[i] = _u(fields[i]);
        }
        string[] memory frontier = vm.parseJsonStringArray(fixture, ".transfer.frontier");
        for (uint256 i; i < MAX_TREES; i++) {
            s[12 + i] = uint256(vm.parseBytes32(frontier[i]));
        }
        beta = _u(".transfer.beta");
    }

    function test_valid_fixture_verifies() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[N] memory s, uint256 beta) =
            _vector();
        require(verifier.verifyProof(a, b, c, _compress(s, beta)), "valid proof rejected");
    }

    function test_noncanonical_coordinate_alias_is_rejected() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[N] memory s, uint256 beta) =
            _vector();
        require(a[1] <= type(uint256).max - Q, "fixture cannot form alias");
        a[1] += Q;
        require(!verifier.verifyProof(a, b, c, _compress(s, beta)), "coordinate alias accepted");
    }

    function test_infinity_is_rejected() public view {
        (, uint256[2][2] memory b, uint256[2] memory c, uint256[N] memory s, uint256 beta) = _vector();
        uint256[2] memory zeroA;
        require(!verifier.verifyProof(zeroA, b, c, _compress(s, beta)), "point at infinity accepted");
    }

    function test_each_statement_value_is_bound() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[N] memory s, uint256 beta) =
            _vector();
        for (uint256 i; i < N; i++) {
            uint256 original = s[i];
            s[i] = addmod(original, 1, P);
            require(!verifier.verifyProof(a, b, c, _compress(s, beta)), "statement mutation accepted");
            s[i] = original;
        }
    }

    function test_beta_and_gamma_are_bound() public view {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[N] memory s, uint256 beta) =
            _vector();
        require(!verifier.verifyProof(a, b, c, _compress(s, addmod(beta, 1, P))), "beta mutation accepted");
        uint256[3] memory input = _compress(s, beta);
        input[1] = addmod(input[1], 1, P);
        require(!verifier.verifyProof(a, b, c, input), "gamma mutation accepted");
    }
}
