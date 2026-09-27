# Threat Model

## Assets

- state root
- public transition inputs
- proof hash binding
- verifier contract state

## Threats

- replayed proof payloads
- wrong previous state root
- malformed proof data
- stale transition submission

## Controls

- contract checks current root before update
- proof hash binds old and new state roots together
- invalid inputs are rejected
- updates happen only after successful validation
