from __future__ import annotations

from .protocol import (
    PROTOCOL_VERSION,
    compute_shared_secret,
    create_handshake_packet,
    derive_session_key,
    generate_ephemeral_keypair,
    generate_identity,
    verify_packet,
)


class MITMAttacker:
    def __init__(self, name: str = "Mallory") -> None:
        self.identity = generate_identity(name)

    def hijack_unauthenticated(self, alice_identity, bob_identity, session_id: str):
        alice_private, alice_ephemeral_pub = generate_ephemeral_keypair()
        bob_private, bob_ephemeral_pub = generate_ephemeral_keypair()
        attacker_alice_private, attacker_alice_pub = generate_ephemeral_keypair()
        attacker_bob_private, attacker_bob_pub = generate_ephemeral_keypair()

        alice_shared = compute_shared_secret(alice_private, attacker_alice_pub)
        attacker_to_alice = compute_shared_secret(attacker_alice_private, alice_ephemeral_pub)
        if alice_shared != attacker_to_alice:
            raise ValueError("unauthenticated MITM key agreement failed")

        bob_shared = compute_shared_secret(bob_private, attacker_bob_pub)
        attacker_to_bob = compute_shared_secret(attacker_bob_private, bob_ephemeral_pub)
        if bob_shared != attacker_to_bob:
            raise ValueError("attacker failed to establish separate Bob key")

        alice_key = derive_session_key(alice_shared, session_id=session_id, alice_id=alice_identity.name, bob_id=self.identity.name)
        bob_key = derive_session_key(bob_shared, session_id=session_id, alice_id=self.identity.name, bob_id=bob_identity.name)
        return {
            "alice_key": alice_key,
            "bob_key": bob_key,
            "alice_shared": alice_shared,
            "bob_shared": bob_shared,
            "session_id": session_id,
        }

    def attempted_authenticated_hijack(self, alice_identity, bob_identity, session_id: str):
        _, attacker_eph_pub = generate_ephemeral_keypair()
        fake_packet = create_handshake_packet(self.identity, session_id, self.identity.name, bob_identity.name, attacker_eph_pub)
        alice_verifies = verify_packet(fake_packet, alice_identity)
        bob_verifies = verify_packet(fake_packet, bob_identity)
        return alice_verifies or bob_verifies
