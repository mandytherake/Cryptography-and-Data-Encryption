from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class EncryptedRecord:
    ciphertext: bytes
    nonce: bytes
    encrypted_dek: bytes
    key_version: int
    algorithm: str
    aad: bytes
    created_at: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "encrypted_dek": base64.b64encode(self.encrypted_dek).decode("ascii"),
            "key_version": self.key_version,
            "algorithm": self.algorithm,
            "aad": base64.b64encode(self.aad).decode("ascii"),
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


def _normalize_key(key: bytes, length: int = 32) -> bytes:
    if len(key) != length:
        raise ValueError("key length invalid")
    return key


def wrap_key_with_kek(kek: bytes, dek: bytes) -> bytes:
    kek = _normalize_key(kek)
    dek = _normalize_key(dek)
    nonce = os.urandom(12)
    return AESGCM(kek).encrypt(nonce, dek, None)


def unwrap_key_with_kek(kek: bytes, encrypted_dek: bytes) -> bytes:
    kek = _normalize_key(kek)
    return AESGCM(kek).decrypt(encrypted_dek[:12], encrypted_dek[12:], None)


def encrypt_record(plaintext: bytes, dek: bytes, *, key_version: int, aad: bytes, metadata: Optional[Dict[str, Any]] = None) -> EncryptedRecord:
    dek = _normalize_key(dek)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return EncryptedRecord(
        ciphertext=ciphertext,
        nonce=nonce,
        encrypted_dek=b"",
        key_version=key_version,
        algorithm="AES-256-GCM",
        aad=aad,
        created_at="",
        metadata=metadata or {},
    )


def decrypt_record(record: EncryptedRecord, dek: bytes) -> bytes:
    dek = _normalize_key(dek)
    try:
        return AESGCM(dek).decrypt(record.nonce, record.ciphertext, record.aad)
    except Exception as exc:
        raise ValueError("record decryption failed") from exc
