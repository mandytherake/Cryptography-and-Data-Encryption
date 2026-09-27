const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

async function main() {
  const projectRoot = path.resolve(__dirname, "..");
  const circuitDir = path.join(projectRoot, "circuits");
  const circuitFile = path.join(circuitDir, "account_rollup.circom");

  if (!fs.existsSync(circuitFile)) {
    throw new Error(`Circuit file not found: ${circuitFile}`);
  }

  const result = spawnSync(
    "npx",
    ["circom", circuitFile, "--r1cs", "--wasm", "--sym", "-o", circuitDir],
    { stdio: "inherit", cwd: projectRoot }
  );

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status || 1);
  }

  console.log("Circuit compiled successfully.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
