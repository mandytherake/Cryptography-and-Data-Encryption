# Threat Model

## Assets

- identity public keys
- identity private keys
- ephemeral X25519 private keys
- session keys
- authenticated handshake messages

## Threats

- network eavesdropping
- active MITM attacks
- handshake replay
- signature forging
- ciphertext tampering
- metadata modification

## Trust boundaries

- local host and secure key storage are trusted
- network path is untrusted
- identity public keys are assumed to be distributed correctly
- users must verify long-term Ed25519 public keys out-of-band

## Mitigations

- X25519 ephemeral key exchange
- Ed25519 signing of handshake messages
- HKDF-based key derivation
- AEAD encryption with nonce uniqueness
- session context binding
- explicit signature and input validation
