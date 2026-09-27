# Security Considerations

## Design goals

- keep root/master keys out of the database
- never log plaintext encryption keys
- use authenticated encryption for record data
- bind metadata and key versions to ciphertext
- reject revoked and invalid keys
- preserve decryptability during rotation

## Key management

This project uses a local development secret manager instead of a real HSM or cloud KMS. It should be treated as a secure educational approximation and later replaced with Vault, AWS KMS, Azure Key Vault, or GCP KMS.

## Operational limits

- not a native database engine
- not a fully hardened production secret store
- not a substitute for network segmentation, access control, or secure key archival
