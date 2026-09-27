# 03 - ZK Rollup Cryptographic Proof Verifier

## Objective

This project demonstrates a simplified rollup verification flow in a local Hardhat environment: an off-chain state transition is represented by a proof hash, the contract verifies the hash and previous state root binding, and the state root is updated only after successful validation.

## Educational architecture

This repository keeps the Circom and snarkjs tooling installed as the intended proving stack, but the Windows host used here could not complete a real circom compile in this environment. The local demonstration therefore uses a direct Hardhat contract proof-verification flow with a cryptographic binding over the state transition payload. That design keeps the state-root update logic, replay protection, and verifier pattern real and testable locally while avoiding a false claim of a full ZK proof implementation.

## Local setup

```bash
cd "Cryptography and Data Encryption/03-ZK-Rollup-Cryptographic-Proof-Verifier"
npm install
npx hardhat test
```

## Run the local demo

```bash
npx hardhat run scripts/demo.ts
```

## Security properties

- previous state root is verified before state update
- proof hash binding prevents replayed or tampered transitions
- malformed or mismatched inputs are rejected
- stale proofs cannot update the contract state

## Limitations

- not a full production rollup or ZK proving system
- not a substitute for a zk-SNARK trusted setup or a real sequencer/DA layer
- intentionally educational and local-only
