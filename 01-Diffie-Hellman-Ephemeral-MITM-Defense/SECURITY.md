# Security Considerations

## Principles used

- No private keys or session keys are logged or printed
- Fresh ephemeral X25519 keys are generated for each session
- Ed25519 signatures authenticate the ephemeral public key and session context
- HKDF-SHA-256 derives a session key from the shared secret
- AES-256-GCM provides confidentiality and integrity
- Input validation rejects malformed or tampered data

## Known risks and limitations

- This project is designed for educational illustration only
- Not intended to replace peer-reviewed protocol engineering or production deployment testing
- Real network deployment would require certificate management, ratcheting, key rotation, and replay protection beyond this prototype

## Responsible use

- Use only in controlled local learning environments
- Keep long-term identity keys in secure storage
- Never reuse ephemeral keys across sessions
