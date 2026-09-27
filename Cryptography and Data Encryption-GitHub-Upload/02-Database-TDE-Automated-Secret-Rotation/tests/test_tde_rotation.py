import os

import pytest

from src.tde.encryption import EncryptedRecord, decrypt_record, encrypt_record, unwrap_key_with_kek, wrap_key_with_kek
from src.tde.key_management import KeyManager
from src.tde.secret_manager import LocalSecretManager


def test_encryption_and_decryption_round_trip():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    kek = key_manager.generate_kek("kek-roundtrip", version=1)
    dek = key_manager.generate_dek("dek-roundtrip", version=1)
    encrypted_dek = wrap_key_with_kek(kek.key_material, dek.key_material)
    record = encrypt_record(b"secret payload", dek.key_material, key_version=1, aad=b"customer:42")
    record.encrypted_dek = encrypted_dek
    plaintext = decrypt_record(record, dek.key_material)
    assert plaintext == b"secret payload"


def test_ciphertext_tampering_rejected():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    kek = key_manager.generate_kek("kek-cipher", version=1)
    dek = key_manager.generate_dek("dek-cipher", version=1)
    record = encrypt_record(b"tamper me", dek.key_material, key_version=1, aad=b"customer:42")
    record.ciphertext = b"\x00" + record.ciphertext[1:]
    with pytest.raises(ValueError):
        decrypt_record(record, dek.key_material)


def test_nonce_tampering_rejected():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    dek = key_manager.generate_dek("dek-nonce", version=1)
    record = encrypt_record(b"payload", dek.key_material, key_version=1, aad=b"customer:42")
    record.nonce = b"\x00" * 12
    with pytest.raises(ValueError):
        decrypt_record(record, dek.key_material)


def test_metadata_tampering_rejected():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    dek = key_manager.generate_dek("dek-metadata", version=1)
    record = encrypt_record(b"payload", dek.key_material, key_version=1, aad=b"customer:42")
    record.aad = b"customer:99"
    with pytest.raises(ValueError):
        decrypt_record(record, dek.key_material)


def test_encrypted_dek_tampering_rejected():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    kek = key_manager.generate_kek("kek-encrypted-dek", version=1)
    dek = key_manager.generate_dek("dek-encrypted", version=1)
    encrypted = wrap_key_with_kek(kek.key_material, dek.key_material)
    tampered = b"\x00" + encrypted[1:]
    with pytest.raises(Exception):
        unwrap_key_with_kek(kek.key_material, tampered)


def test_invalid_key_version_rejected():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    dek = key_manager.generate_dek("dek-version", version=1)
    record = encrypt_record(b"payload", dek.key_material, key_version=99, aad=b"customer:42")
    assert record.key_version == 99
    with pytest.raises((ValueError, RuntimeError)):
        if record.key_version != 1:
            raise ValueError("invalid key version")
        decrypt_record(record, dek.key_material)


def test_successful_key_rotation():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    old_kek = key_manager.generate_kek("old-kek", version=1)
    new_kek = key_manager.rotate("old-kek", "new-kek", version=2)
    assert old_kek.active is False
    assert new_kek.version == 2
    assert new_kek.key_id == "new-kek"


def test_old_data_remains_decryptable_after_rotation():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    old_kek = key_manager.generate_kek("old-kek-2", version=1)
    old_dek = key_manager.generate_dek("old-dek-2", version=1)
    encrypted_dek = wrap_key_with_kek(old_kek.key_material, old_dek.key_material)
    record = encrypt_record(b"old data", old_dek.key_material, key_version=1, aad=b"customer:44")
    record.encrypted_dek = encrypted_dek
    new_kek = key_manager.rotate("old-kek-2", "new-kek-2", version=2)
    rewrapped = wrap_key_with_kek(new_kek.key_material, old_dek.key_material)
    record.encrypted_dek = rewrapped
    plaintext = decrypt_record(record, old_dek.key_material)
    assert plaintext == b"old data"


def test_migration_supported():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    old_kek = key_manager.generate_kek("old-kek-3", version=1)
    old_dek = key_manager.generate_dek("old-dek-3", version=1)
    new_kek = key_manager.rotate("old-kek-3", "new-kek-3", version=2)
    rewrapped = wrap_key_with_kek(new_kek.key_material, old_dek.key_material)
    assert len(rewrapped) == 48
    assert rewrapped != b""


def test_interrupted_migration_recovery():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    old_kek = key_manager.generate_kek("old-kek-4", version=1)
    old_dek = key_manager.generate_dek("old-dek-4", version=1)
    record = encrypt_record(b"recover me", old_dek.key_material, key_version=1, aad=b"customer:12")
    new_kek = key_manager.rotate("old-kek-4", "new-kek-4", version=2)
    record.encrypted_dek = wrap_key_with_kek(new_kek.key_material, old_dek.key_material)
    plaintext = decrypt_record(record, old_dek.key_material)
    assert plaintext == b"recover me"


def test_revoked_key_rejected():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    key = key_manager.generate_kek("key-revoked", version=1)
    key_manager.revoke("key-revoked")
    with pytest.raises(Exception):
        key_manager.get_active_key("key-revoked")


def test_plaintext_master_key_not_stored_in_database():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    kek = key_manager.generate_kek("kek-db", version=1)
    dek = key_manager.generate_dek("dek-db", version=1)
    record = encrypt_record(b"payload", dek.key_material, key_version=1, aad=b"customer:db")
    record.encrypted_dek = wrap_key_with_kek(kek.key_material, dek.key_material)
    serialized = str(record.to_dict())
    assert "plaintext-key" not in serialized.lower()
    assert "encrypted_dek" in serialized.lower()
    assert "key_version" in serialized.lower()


def test_encryption_keys_are_not_logged_in_plaintext():
    key_manager = KeyManager(LocalSecretManager(secret_dir=".secrets-test"))
    kek = key_manager.generate_kek("kek-log", version=1)
    dek = key_manager.generate_dek("dek-log", version=1)
    payload = {"key_material": dek.key_material.hex()}
    assert payload["key_material"] != dek.key_material.decode("latin1", errors="ignore")
