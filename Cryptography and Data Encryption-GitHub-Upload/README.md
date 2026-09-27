# Cryptography and Data Encryption

This repository contains three separate, locally runnable security engineering projects demonstrating core cryptographic and data-protection patterns.

| Project | Main Concept | Primary Security Goal |
| --- | --- | --- |
| Ephemeral DH | Key exchange + authentication | Secure session establishment + MITM defense |
| Database TDE | Encryption + key management | Data-at-rest protection + key rotation |
| ZK-Rollup | Zero-knowledge proofs | Verifiable computation + state integrity |

## Project layout

```text
Cryptography and Data Encryption/
├── 01-Diffie-Hellman-Ephemeral-MITM-Defense/
├── 02-Database-TDE-Automated-Secret-Rotation/
├── 03-ZK-Rollup-Cryptographic-Proof-Verifier/
└── README.md
```

## Security note

These projects are educational implementations designed to illustrate secure design principles and common failure modes. They are not a substitute for a full production security review, external key management, or formal cryptographic validation.

## Local execution

Each project has its own README and a local test command.

- Project 1: Diffie-Hellman with ephemeral keys and MITM defense
- Project 2: Database-level encryption with automated secret rotation
- Project 3: ZK rollup proof verifier with a local Hardhat environment

No GitHub remote is configured or required for the local setup.
