const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ZK Rollup State Verifier", function () {
  let verifier;
  let initialRoot;
  let finalRoot;

  beforeEach(async function () {
    const Verifier = await ethers.getContractFactory("ZKRollupStateVerifier");
    verifier = await Verifier.deploy();

    initialRoot = ethers.keccak256(ethers.toUtf8Bytes("initial-state"));
    finalRoot = ethers.keccak256(ethers.toUtf8Bytes("updated-state"));
    await verifier.initialize(initialRoot);
  });

  function buildProof(previous, next) {
    const publicInputs = [previous, next];
    const proofHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "bytes32", "bytes32"], [previous, next, publicInputs[0], publicInputs[1]])
    );
    return { publicInputs, proofHash };
  }

  it("accepts a valid state transition proof and updates state root", async function () {
    const { publicInputs, proofHash } = buildProof(initialRoot, finalRoot);
    const accepted = await verifier.verifyAndUpdate.staticCall(initialRoot, finalRoot, proofHash, proofHash, publicInputs);
    expect(accepted).to.equal(true);

    await verifier.verifyAndUpdate(initialRoot, finalRoot, proofHash, proofHash, publicInputs);
    const current = await verifier.currentStateRoot();
    expect(current).to.equal(finalRoot);
  });

  it("rejects wrong old state root", async function () {
    const wrongRoot = ethers.keccak256(ethers.toUtf8Bytes("wrong-old-state"));
    const { publicInputs, proofHash } = buildProof(wrongRoot, finalRoot);

    await expect(verifier.verifyAndUpdate(wrongRoot, finalRoot, proofHash, proofHash, publicInputs)).to.be.revertedWith("wrong previous state root");
  });

  it("rejects malformed public inputs", async function () {
    const { proofHash } = buildProof(initialRoot, finalRoot);
    await expect(verifier.verifyAndUpdate(initialRoot, finalRoot, proofHash, proofHash, [])).to.be.revertedWith("malformed public inputs");
  });

  it("rejects invalid proof hash", async function () {
    const { publicInputs } = buildProof(initialRoot, finalRoot);
    const badHash = ethers.keccak256(ethers.toUtf8Bytes("bad-proof"));
    await expect(verifier.verifyAndUpdate(initialRoot, finalRoot, badHash, badHash, publicInputs)).to.be.revertedWith("invalid proof");
  });

  it("rejects replayed proof data", async function () {
    const { publicInputs, proofHash } = buildProof(initialRoot, finalRoot);
    await verifier.verifyAndUpdate(initialRoot, finalRoot, proofHash, proofHash, publicInputs);
    await expect(verifier.verifyAndUpdate(initialRoot, finalRoot, proofHash, proofHash, publicInputs)).to.be.revertedWith("wrong previous state root");
  });
});
