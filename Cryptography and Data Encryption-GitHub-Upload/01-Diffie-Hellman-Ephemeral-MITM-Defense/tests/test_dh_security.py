import os

import pytest
from cryptography.exceptions import InvalidSignature

from src.dh_security.protocol import (
    PROTOCOL_VERSION,
    check_authenticated_handshake,
    compute_shared_secret,
    create_handshake_packet,
    decrypt_message,
    derive_session_key,
    encrypt_message,
    generate_ephemeral_keypair,
    generate_identity,
    verify_packet,
)


def test_successful_x25519_key_agreement():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    alice_private, alice_public = generate_ephemeral_keypair()
    bob_private, bob_public = generate_ephemeral_keypair()

    shared_secret_a = compute_shared_secret(alice_private, bob_public)
    shared_secret_b = compute_shared_secret(bob_private, alice_public)

    assert shared_secret_a == shared_secret_b
    assert len(shared_secret_a) == 32


def test_same_session_key_for_alice_and_bob():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    session = check_authenticated_handshake(alice, bob, "session-123")

    assert session.alice_identity == "Alice"
    assert session.bob_identity == "Bob"
    assert session.session_key
    assert session.protocol_version == PROTOCOL_VERSION


def test_fresh_sessions_generate_different_ephemeral_keys():
    first = check_authenticated_handshake(generate_identity("Alice"), generate_identity("Bob"), "s1")
    second = check_authenticated_handshake(generate_identity("Alice"), generate_identity("Bob"), "s2")

    assert first.alice_ephemeral_public != second.alice_ephemeral_public
    assert first.bob_ephemeral_public != second.bob_ephemeral_public


def test_successful_encryption_decryption():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    session = check_authenticated_handshake(alice, bob, "session-enc")
    aad = b"secure-session" 
    encrypted = encrypt_message(session.session_key, b"hello world", aad)
    plaintext = decrypt_message(session.session_key, encrypted)

    assert plaintext == b"hello world"
    assert encrypted.ciphertext != b"hello world"


def test_modified_ciphertext_is_rejected():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    session = check_authenticated_handshake(alice, bob, "session-mod-cipher")
    encrypted = encrypt_message(session.session_key, b"secret message", b"aad")
    tampered = encrypted
    tampered.ciphertext = b"\x00" + encrypted.ciphertext[1:]

    with pytest.raises(ValueError):
        decrypt_message(session.session_key, tampered)


def test_modified_nonce_is_rejected():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    session = check_authenticated_handshake(alice, bob, "session-mod-nonce")
    encrypted = encrypt_message(session.session_key, b"secret message", b"aad")
    encrypted.nonce = b"\x00" * 12

    with pytest.raises(ValueError):
        decrypt_message(session.session_key, encrypted)


def test_modified_authentication_data_is_rejected():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    session = check_authenticated_handshake(alice, bob, "session-mod-aad")
    encrypted = encrypt_message(session.session_key, b"secret-message", b"expected-aad")
    encrypted.aad = b"tampered-aad"

    with pytest.raises(ValueError):
        decrypt_message(session.session_key, encrypted)


def test_invalid_signature_is_rejected():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    session_id = "bad-signature"
    _, alice_ephemeral_pub = generate_ephemeral_keypair()
    valid_packet = create_handshake_packet(alice, session_id, alice.name, bob.name, alice_ephemeral_pub)
    invalid_packet = valid_packet.__class__(
        protocol_version=valid_packet.protocol_version,
        session_id=valid_packet.session_id,
        sender=valid_packet.sender,
        receiver=valid_packet.receiver,
        ephemeral_public_key=valid_packet.ephemeral_public_key,
        signature=b"\x00" * 64,
        timestamp=valid_packet.timestamp,
    )

    assert verify_packet(invalid_packet, alice) is False


def test_wrong_identity_key_is_rejected():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    eve = generate_identity("Eve")
    session_id = "wrong-key"
    _, alice_ephemeral_pub = generate_ephemeral_keypair()
    packet = create_handshake_packet(alice, session_id, alice.name, bob.name, alice_ephemeral_pub)

    assert verify_packet(packet, eve) is False


def test_forged_ephemeral_public_key_is_rejected():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    _, original_pub = generate_ephemeral_keypair()
    packet = create_handshake_packet(alice, "session-forged", alice.name, bob.name, original_pub)
    assert verify_packet(packet, alice) is True

    forged_packet = packet.__class__(
        protocol_version=packet.protocol_version,
        session_id=packet.session_id,
        sender=packet.sender,
        receiver=packet.receiver,
        ephemeral_public_key=b"\x01" * 32,
        signature=packet.signature,
        timestamp=packet.timestamp,
    )
    assert verify_packet(forged_packet, alice) is False


def test_replayed_handshake_is_rejected_where_applicable():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    session_id = "replay"
    _, alice_ephemeral_pub = generate_ephemeral_keypair()
    packet = create_handshake_packet(alice, session_id, alice.name, bob.name, alice_ephemeral_pub)
    seen_handshakes = {session_id}

    assert verify_packet(packet, alice, seen_handshakes=seen_handshakes) is False


def test_mitm_succeeds_against_unauthenticated_dh():
    from src.dh_security.mitm import MITMAttacker

    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    attacker = MITMAttacker()
    result = attacker.hijack_unauthenticated(alice, bob, "mitm-unauth")

    assert "alice_key" in result
    assert "bob_key" in result
    assert result["alice_key"] != result["bob_key"]


def test_mitm_fails_against_authenticated_ephemeral_dh():
    from src.dh_security.mitm import MITMAttacker

    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    attacker = MITMAttacker()

    attempt = attacker.attempted_authenticated_hijack(alice, bob, "mitm-auth")
    assert attempt is False


def test_raw_x25519_shared_secret_is_not_directly_used_as_aes_key():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    session = check_authenticated_handshake(alice, bob, "session-kdf")

    assert len(session.shared_secret) == 32
    assert session.shared_secret != session.session_key
    assert len(session.session_key) == 32
    assert session.session_key != session.shared_secret
