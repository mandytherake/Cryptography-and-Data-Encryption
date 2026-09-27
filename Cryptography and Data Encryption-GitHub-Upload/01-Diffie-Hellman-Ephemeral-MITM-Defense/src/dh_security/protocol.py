from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import EncryptedMessage, HandshakePacket, ParticipantIdentity, Session

PROTOCOL_VERSION = "x25519-ed25519-hkdf-aesgcm-v1"


def _hash_bytes(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def generate_identity(name: str) -> ParticipantIdentity:
    if not name or not name.strip():
        raise ValueError("identity name is required")
    ed_key = ed25519.Ed25519PrivateKey.generate()
    public_bytes = ed_key.public_key().public_bytes_raw()
    private_bytes = ed_key.private_bytes_raw()
    return ParticipantIdentity(name=name, public_key=public_bytes, private_key=private_bytes)


def _ed_public_from_private(private_key: bytes) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_key).public_key()


def _x25519_private_from_bytes(private_key: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(private_key)


def _x25519_public_from_bytes(public_key: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(public_key)


def generate_ephemeral_keypair() -> Tuple[bytes, bytes]:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key.private_bytes_raw(), public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def sign_handshake(identity: ParticipantIdentity, session_id: str, sender: str, receiver: str, ephemeral_public_key: bytes) -> bytes:
    message = (
        PROTOCOL_VERSION.encode("utf-8")
        + b"|"
        + session_id.encode("utf-8")
        + b"|"
        + sender.encode("utf-8")
        + b"|"
        + receiver.encode("utf-8")
        + b"|"
        + ephemeral_public_key
    )
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(identity.private_key)
    return private_key.sign(message)


def verify_handshake_signature(sender_identity: ParticipantIdentity, packet: HandshakePacket, *, seen_handshakes: Optional[set[str]] = None) -> bool:
    if seen_handshakes is not None and packet.session_id in seen_handshakes:
        return False
    if packet.sender != sender_identity.name:
        return False
    if not packet.protocol_version == PROTOCOL_VERSION:
        return False
    if len(packet.ephemeral_public_key) != 32:
        return False

    expected_public_key = sender_identity.public_key
    received_public_key = ed25519.Ed25519PublicKey.from_public_bytes(expected_public_key)
    try:
        received_public_key.verify(packet.signature, packet.as_bytes())
        return True
    except InvalidSignature:
        return False


def compute_shared_secret(private_key_bytes: bytes, peer_public_key: bytes) -> bytes:
    local_private = _x25519_private_from_bytes(private_key_bytes)
    peer_public = _x25519_public_from_bytes(peer_public_key)
    return local_private.exchange(peer_public)


def derive_session_key(shared_secret: bytes, *, session_id: str, alice_id: str, bob_id: str) -> bytes:
    if len(shared_secret) != 32:
        raise ValueError("invalid X25519 shared secret length")
    salt = session_id.encode("utf-8")
    info = b"|".join([
        PROTOCOL_VERSION.encode("utf-8"),
        alice_id.encode("utf-8"),
        bob_id.encode("utf-8"),
    ])
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared_secret)
    return derived


def encrypt_message(session_key: bytes, plaintext: bytes, aad: bytes) -> EncryptedMessage:
    if len(session_key) != 32:
        raise ValueError("invalid session key length")
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, aad)
    return EncryptedMessage(nonce=nonce, ciphertext=ciphertext, aad=aad)


def decrypt_message(session_key: bytes, encrypted: EncryptedMessage) -> bytes:
    if len(session_key) != 32:
        raise ValueError("invalid session key length")
    try:
        return AESGCM(session_key).decrypt(encrypted.nonce, encrypted.ciphertext, encrypted.aad)
    except Exception as exc:
        raise ValueError("decryption failed") from exc


def create_handshake_packet(identity: ParticipantIdentity, session_id: str, sender: str, receiver: str, ephemeral_public_key: bytes) -> HandshakePacket:
    signature = sign_handshake(identity, session_id, sender, receiver, ephemeral_public_key)
    return HandshakePacket(
        protocol_version=PROTOCOL_VERSION,
        session_id=session_id,
        sender=sender,
        receiver=receiver,
        ephemeral_public_key=ephemeral_public_key,
        signature=signature,
        timestamp=0,
    )


def verify_packet(packet: HandshakePacket, identity: ParticipantIdentity, *, seen_handshakes: Optional[set[str]] = None) -> bool:
    if not packet.protocol_version == PROTOCOL_VERSION:
        return False
    if len(packet.ephemeral_public_key) != 32:
        return False
    if packet.sender != identity.name:
        return False
    if seen_handshakes is not None and packet.session_id in seen_handshakes:
        return False
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(identity.public_key)
    try:
        public_key.verify(packet.signature, packet.as_bytes())
        return True
    except InvalidSignature:
        return False


def build_session(alice: ParticipantIdentity, bob: ParticipantIdentity, session_id: str) -> Tuple[Session, HandshakePacket, HandshakePacket]:
    alice_private, alice_ephemeral_pub = generate_ephemeral_keypair()
    bob_private, bob_ephemeral_pub = generate_ephemeral_keypair()

    alice_packet = create_handshake_packet(alice, session_id, alice.name, bob.name, alice_ephemeral_pub)
    bob_packet = create_handshake_packet(bob, session_id, bob.name, alice.name, bob_ephemeral_pub)

    shared_secret_alice = compute_shared_secret(alice_private, bob_ephemeral_pub)
    shared_secret_bob = compute_shared_secret(bob_private, alice_ephemeral_pub)
    if shared_secret_alice != shared_secret_bob:
        raise ValueError("session secrets did not match")

    session_key = derive_session_key(shared_secret_alice, session_id=session_id, alice_id=alice.name, bob_id=bob.name)
    session = Session(
        session_id=session_id,
        alice_identity=alice.name,
        bob_identity=bob.name,
        alice_ephemeral_public=alice_ephemeral_pub,
        bob_ephemeral_public=bob_ephemeral_pub,
        session_key=session_key,
        protocol_version=PROTOCOL_VERSION,
        shared_secret=shared_secret_alice,
    )
    return session, alice_packet, bob_packet


def check_authenticated_handshake(alice: ParticipantIdentity, bob: ParticipantIdentity, session_id: str) -> Session:
    alice_private, alice_ephemeral_pub = generate_ephemeral_keypair()
    bob_private, bob_ephemeral_pub = generate_ephemeral_keypair()

    alice_packet = create_handshake_packet(alice, session_id, alice.name, bob.name, alice_ephemeral_pub)
    bob_packet = create_handshake_packet(bob, session_id, bob.name, alice.name, bob_ephemeral_pub)

    if not verify_packet(alice_packet, alice):
        raise ValueError("alice packet signature invalid")
    if not verify_packet(bob_packet, bob):
        raise ValueError("bob packet signature invalid")

    shared_secret = compute_shared_secret(alice_private, bob_ephemeral_pub)
    peer_secret = compute_shared_secret(bob_private, alice_ephemeral_pub)
    if shared_secret != peer_secret:
        raise ValueError("shared secret mismatch")

    session_key = derive_session_key(shared_secret, session_id=session_id, alice_id=alice.name, bob_id=bob.name)
    return Session(
        session_id=session_id,
        alice_identity=alice.name,
        bob_identity=bob.name,
        alice_ephemeral_public=alice_ephemeral_pub,
        bob_ephemeral_public=bob_ephemeral_pub,
        session_key=session_key,
        protocol_version=PROTOCOL_VERSION,
        shared_secret=shared_secret,
    )
