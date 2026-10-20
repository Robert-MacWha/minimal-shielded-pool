// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax = 14261448733030150629538958531210717953411030191771716670833247338564075703796;
    uint256 constant alphay = 13347175785706757420795438553611952903490518523821294026140196272487470235892;
    uint256 constant betax1 = 5067336958902161072811313497122240719799651904498896886801600891007861732035;
    uint256 constant betax2 = 1787223480918283003976203421793842741367999089690832016110626272340808495730;
    uint256 constant betay1 = 17680157722770437388178012501248405830973495464702586521313305194474161121313;
    uint256 constant betay2 = 6891723707678154041812719329037725424795184466752518166236770462468627102907;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 3928270146752927743100014493729185363462178384174023037061575900697712845641;
    uint256 constant deltax2 = 6814458440539809386869800340042042920417262739278905745855948720729867250441;
    uint256 constant deltay1 = 3652387463541559095069887541342679804393889678007401252089336964795401029768;
    uint256 constant deltay2 = 3424513738838263089270876838480791871252231542234025870949308890915445159639;

    uint256 constant IC0x = 5677851842183086654123131413968739053927996818006279368859333897912041307574;
    uint256 constant IC0y = 14504714651400549594334018648039841263135727396822185936669902428974985940846;

    uint256 constant IC1x = 10574732878477058027581731984961178862557034036866522340590096295931561428688;
    uint256 constant IC1y = 15959604871242906332206859829309975781358831494269686776027742071830402739230;

    uint256 constant IC2x = 8048119222117197311199207935251415555123219770127086115347075282606867055826;
    uint256 constant IC2y = 10715672195646377433150307210105134029572289492960264042371131865120964414837;

    uint256 constant IC3x = 15430113973335427769572257482798537634402511764429224035562966152976641748692;
    uint256 constant IC3y = 4164976075444428394296845555506982006899890120797894425468140612816333417436;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[3] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(500000, 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(500000, 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(500000, 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            // CANONICAL_PROOF_COORDINATES: the pairing precompile accepts
            // field elements, but a proof has one canonical uint256 encoding.
            // Reject aliases such as pA.y + q and reject infinity points.
            function checkCoordinate(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            let ax := calldataload(_pA)
            let ay := calldataload(add(_pA, 32))
            let bx0 := calldataload(_pB)
            let bx1 := calldataload(add(_pB, 32))
            let by0 := calldataload(add(_pB, 64))
            let by1 := calldataload(add(_pB, 96))
            let cx := calldataload(_pC)
            let cy := calldataload(add(_pC, 32))
            checkCoordinate(ax)
            checkCoordinate(ay)
            checkCoordinate(bx0)
            checkCoordinate(bx1)
            checkCoordinate(by0)
            checkCoordinate(by1)
            checkCoordinate(cx)
            checkCoordinate(cy)
            if iszero(or(ax, ay)) {
                mstore(0, 0)
                return(0, 0x20)
            }
            if iszero(or(or(bx0, bx1), or(by0, by1))) {
                mstore(0, 0)
                return(0, 0x20)
            }
            if iszero(or(cx, cy)) {
                mstore(0, 0)
                return(0, 0x20)
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
