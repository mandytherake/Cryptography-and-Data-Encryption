from __future__ import annotations

from src.tde.encryption import decrypt_record, encrypt_record, unwrap_key_with_kek, wrap_key_with_kek
from src.tde.key_management import KeyManager
from src.tde.secret_manager import LocalSecretManager


def main() -> None:
    print("[1] Initializing local development secret manager")
    manager = LocalSecretManager(secret_dir=".secrets-demo")
    km = KeyManager(manager)
    kek = km.generate_kek("demo-kek", version=1)
    dek = km.generate_dek("demo-dek", version=1)
    wrapped_dek = wrap_key_with_kek(kek.key_material, dek.key_material)

    print("[2] Encrypting customer record with envelope encryption")
    record = encrypt_record(b"customer name: Alice", dek.key_material, key_version=1, aad=b"customer:42")
    record.encrypted_dek = wrapped_dek
    print(f"Record ciphertext length: {len(record.ciphertext)} bytes")

    print("[3] Rotating KEK and re-wrapping DEK")
    new_kek = km.rotate("demo-kek", "demo-kek-v2", version=2)
    record.encrypted_dek = wrap_key_with_kek(new_kek.key_material, dek.key_material)
    print(f"New KEK version: {new_kek.version}")

    print("[4] Decrypting record after rotation")
    plaintext = decrypt_record(record, dek.key_material)
    print(f"Plaintext: {plaintext.decode('utf-8')}")

    print("Demo complete.")


if __name__ == "__main__":
    main()
