from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ParticipantIdentity:
    name: str
    public_key: bytes
    private_key: bytes


@dataclass(frozen=True)
class HandshakePacket:
    protocol_version: str
    session_id: str
    sender: str
    receiver: str
    ephemeral_public_key: bytes
    signature: bytes
    timestamp: int

    def as_bytes(self) -> bytes:
        return (
            self.protocol_version.encode("utf-8")
            + b"|"
            + self.session_id.encode("utf-8")
            + b"|"
            + self.sender.encode("utf-8")
            + b"|"
            + self.receiver.encode("utf-8")
            + b"|"
            + self.ephemeral_public_key
        )


@dataclass
class EncryptedMessage:
    nonce: bytes
    ciphertext: bytes
    aad: bytes


@dataclass
class Session:
    session_id: str
    alice_identity: str
    bob_identity: str
    alice_ephemeral_public: bytes
    bob_ephemeral_public: bytes
    session_key: bytes
    protocol_version: str
    shared_secret: bytes = b""
    seen_handshakes: set[str] = field(default_factory=set)
    used_aad: Optional[bytes] = None
