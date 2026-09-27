# Threat Model

## Assets

- root/master key
- KEKs and DEKs
- encrypted row payloads
- metadata including key version and timestamps

## Adversaries

- direct database access without application privileges
- attacker modifying ciphertext or metadata
- attacker replacing encrypted DEK material
- attacker requesting a revoked key version
- attacker interrupting key rotation or migration

## Security controls

- envelope encryption with separate KEK and DEK
- AES-256-GCM for authenticated encryption
- AAD binding to record metadata
- key version validation
- rotation state tracking
- rejection of revoked keys and invalid versions
- safe failure for tampered records
