from __future__ import annotations

from .mitm import MITMAttacker
from .protocol import (
    PROTOCOL_VERSION,
    check_authenticated_handshake,
    decrypt_message,
    derive_session_key,
    encrypt_message,
    generate_identity,
)


def main() -> None:
    print("[1] Authenticated ephemeral session establishment")
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    session = check_authenticated_handshake(alice, bob, "demo-session-001")
    aad = b"demo-aad"
    encrypted = encrypt_message(session.session_key, b"confidential message", aad)
    plaintext = decrypt_message(session.session_key, encrypted)
    print(f"Protocol: {session.protocol_version}")
    print(f"Alice key fingerprint: {session.alice_ephemeral_public.hex()[:16]}")
    print(f"Bob key fingerprint: {session.bob_ephemeral_public.hex()[:16]}")
    print(f"Shared secret length: {len(session.shared_secret)} bytes")
    print(f"Session key length: {len(session.session_key)} bytes")
    print(f"Ciphertext round trip: {plaintext!r}")

    print("\n[2] MITM demonstration without authentication")
    attacker = MITMAttacker()
    unauth_result = attacker.hijack_unauthenticated(alice, bob, "mitm-demo-unauth")
    print(f"Attacker established two separate keys: {unauth_result['alice_key'][:8].hex()} and {unauth_result['bob_key'][:8].hex()}")

    print("\n[3] MITM demonstration with Ed25519 authentication")
    attempt = attacker.attempted_authenticated_hijack(alice, bob, "mitm-demo-auth")
    print("Authenticated handshake rejected attack attempt." if not attempt else "Attack unexpectedly accepted.")

    print("\nDemo complete.")


if __name__ == "__main__":
    main()
