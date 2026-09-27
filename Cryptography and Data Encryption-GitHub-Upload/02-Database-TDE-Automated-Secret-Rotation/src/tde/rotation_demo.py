from __future__ import annotations

from src.tde.encryption import decrypt_record, encrypt_record, wrap_key_with_kek
from src.tde.key_management import KeyManager
from src.tde.secret_manager import LocalSecretManager


def main() -> None:
    manager = LocalSecretManager(secret_dir=".secrets-demo")
    km = KeyManager(manager)
    old_kek = km.generate_kek("rotation-old-kek", version=1)
    dek = km.generate_dek("rotation-dek", version=1)
    record = encrypt_record(b"sensitive record", dek.key_material, key_version=1, aad=b"tenant:rotation")
    record.encrypted_dek = wrap_key_with_kek(old_kek.key_material, dek.key_material)

    print("[1] Existing record encrypted under KEK v1")
    print(f"Decryption before rotation: {decrypt_record(record, dek.key_material)!r}")

    print("[2] Generate KEK v2 and rewrap DEK")
    new_kek = km.rotate("rotation-old-kek", "rotation-new-kek", version=2)
    record.encrypted_dek = wrap_key_with_kek(new_kek.key_material, dek.key_material)

    print("[3] Verify old data remains decryptable after migration")
    print(f"Decryption after rotation: {decrypt_record(record, dek.key_material)!r}")
    print("Rotation demo complete.")


if __name__ == "__main__":
    main()
