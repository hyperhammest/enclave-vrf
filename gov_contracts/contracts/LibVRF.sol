//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

library LibVRF {

    // function verifyVrfRandom(uint blockNumber, bytes memory pk, bytes memory pi, uint rdm) internal view returns (bool) {
    //     return verify(uint(blockhash(blockNumber)), pk, pi, rdm);
    // }

    function verify(uint alpha, bytes memory pk, bytes memory pi, uint beta) internal view returns (bool) {
        require(pk.length == 33, 'pk.length != 33');
        (bool ok, bytes memory retData) = address(0x2713).staticcall(abi.encodePacked(alpha, pk, pi));
        return ok && abi.decode(retData, (uint)) == beta;
    }

}
