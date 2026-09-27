const { ethers } = require("hardhat");

async function main() {
  const Verifier = await ethers.getContractFactory("ZKRollupStateVerifier");
  const verifier = await Verifier.deploy();

  const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("initial-state"));
  await verifier.initialize(initialRoot);

  const previousRoot = await verifier.currentStateRoot();
  const newRoot = ethers.keccak256(ethers.toUtf8Bytes("updated-state"));
  const publicInputs = [previousRoot, newRoot];
  const proofHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "bytes32", "bytes32"], [previousRoot, newRoot, publicInputs[0], publicInputs[1]])
  );

  const accepted = await verifier.verifyAndUpdate.staticCall(previousRoot, newRoot, proofHash, proofHash, publicInputs);
  await verifier.verifyAndUpdate(previousRoot, newRoot, proofHash, proofHash, publicInputs);
  console.log("Initial state root:", previousRoot);
  console.log("Updated state root:", await verifier.currentStateRoot());
  console.log("Proof accepted:", accepted);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
