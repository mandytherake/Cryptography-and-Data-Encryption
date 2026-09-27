// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ZKRollupStateVerifier {
    bytes32 public currentStateRoot;

    error WrongPreviousStateRoot();
    error InvalidNewStateRoot();
    error InvalidProof();
    error MalformedPublicInputs();

    function initialize(bytes32 initialStateRoot) external {
        require(currentStateRoot == bytes32(0), "already initialized");
        currentStateRoot = initialStateRoot;
    }

    function verifyAndUpdate(
        bytes32 previousStateRoot,
        bytes32 newStateRoot,
        bytes32 proofHash,
        bytes32 expectedProofHash,
        bytes32[] calldata publicInputs
    ) external returns (bool) {
        require(previousStateRoot == currentStateRoot, "wrong previous state root");
        require(newStateRoot != bytes32(0), "invalid new state root");
        require(publicInputs.length >= 2, "malformed public inputs");
        require(proofHash == expectedProofHash, "invalid proof");

        bytes32 recomputedHash = keccak256(abi.encodePacked(previousStateRoot, newStateRoot, publicInputs[0], publicInputs[1]));
        require(recomputedHash == proofHash, "invalid proof");

        currentStateRoot = newStateRoot;
        return true;
    }
}
