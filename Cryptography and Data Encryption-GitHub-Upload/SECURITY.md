# Security and repository policy

This repository contains educational security-engineering prototypes for cryptographic key exchange, encryption-at-rest design, key rotation, and verifiable-state validation.

## Scope

- Project 1 demonstrates X25519 ephemeral key exchange with Ed25519 authentication and HKDF-derived AES-256-GCM session keys.
- Project 2 demonstrates envelope encryption, key wrapping, versioned key material, and key rotation behavior.
- Project 3 demonstrates a local Hardhat verifier pattern that validates state-root and proof-hash bindings, with explicit limitations as an educational prototype instead of a production zk-rollup.

## Safety expectations

- No hard-coded secrets, passwords, tokens, or private keys are committed to source control.
- Local secrets and key stores must remain outside source control and are ignored by the repository configuration.
- Environment placeholders are used in example files only.
- Security claims must remain limited to what the implementation actually demonstrates.

## Verification expectations

- All cryptographic claims must map to the actual code paths and tests.
- Use modern cryptographic primitives only.
- Avoid implying production readiness beyond the supported educational scope.
