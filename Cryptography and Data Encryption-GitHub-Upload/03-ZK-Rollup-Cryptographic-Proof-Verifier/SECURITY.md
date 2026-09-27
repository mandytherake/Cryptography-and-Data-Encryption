# Security Considerations

## Proof verification

- previous state root is validated against the contract's current state
- proof payload hash binds the state transition to public inputs and expected root values
- stale or replayed proofs are rejected
- malformed inputs fail fast

## Limitations

This project is a local educational verifier pattern, not a full production rollup engine or a complete zk-SNARK integration.
