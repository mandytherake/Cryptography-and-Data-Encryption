const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

async function main() {
  const circuitDir = path.join(__dirname, "..", "circuits");
  const outputDir = path.join(__dirname, "..", "artifacts", "zk");
  fs.mkdirSync(outputDir, { recursive: true });

  const input = {
    oldBalanceSender: 100,
    oldBalanceReceiver: 50,
    oldNonceSender: 1,
    amount: 20,
    nonce: 1,
    senderExists: 1,
    receiverExists: 1,
    validAmount: 1,
    senderHasFunds: 1,
    validNonce: 1,
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    path.join(circuitDir, "account_rollup.wasm"),
    path.join(circuitDir, "account_rollup.zkey")
  );

  fs.writeFileSync(path.join(outputDir, "proof.json"), JSON.stringify(proof, null, 2));
  fs.writeFileSync(path.join(outputDir, "publicSignals.json"), JSON.stringify(publicSignals, null, 2));
  console.log("Proof generated successfully.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
