from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecretManagementError(RuntimeError):
    pass


@dataclass
class SecretMaterial:
    key_id: str
    key_material: bytes
    version: int
    created_at: str
    active: bool = True
    revoked: bool = False


class LocalSecretManager:
    """Secure local development secret manager that is not an HSM/KMS."""

    def __init__(self, secret_dir: str = ".secrets") -> None:
        self.secret_dir = secret_dir
        os.makedirs(self.secret_dir, exist_ok=True)
        self._keys: Dict[str, SecretMaterial] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        for filename in os.listdir(self.secret_dir):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.secret_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                    payload["key_material"] = bytes.fromhex(payload["key_material"])
                    self._keys[payload["key_id"]] = SecretMaterial(**payload)
            except Exception:
                continue

    def _persist(self, key: SecretMaterial) -> None:
        path = os.path.join(self.secret_dir, f"{key.key_id}.json")
        payload = key.__dict__.copy()
        payload["key_material"] = key.key_material.hex()
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def create_key(self, key_id: str, *, length: int = 32, version: int = 1) -> SecretMaterial:
        if not key_id or not key_id.strip():
            raise SecretManagementError("key id required")
        key_material = os.urandom(length)
        material = SecretMaterial(
            key_id=key_id,
            key_material=key_material,
            version=version,
            created_at="",
            active=True,
            revoked=False,
        )
        self._keys[key_id] = material
        self._persist(material)
        return material

    def get_key(self, key_id: str) -> SecretMaterial:
        material = self._keys.get(key_id)
        if material is None:
            raise SecretManagementError("key lookup failed")
        if material.revoked:
            raise SecretManagementError("key revoked")
        return material

    def rotate_key(self, old_key_id: str, new_key_id: str, *, version: int = 2) -> SecretMaterial:
        old_key = self.get_key(old_key_id)
        old_key.active = False
        self._persist(old_key)
        new_material = self.create_key(new_key_id, length=32, version=version)
        return new_material

    def add_key_material(self, key_id: str, key_material: bytes, *, version: int, active: bool = True) -> SecretMaterial:
        if len(key_material) != 32:
            raise ValueError("key material must be 32 bytes")
        material = SecretMaterial(
            key_id=key_id,
            key_material=key_material,
            version=version,
            created_at="",
            active=active,
            revoked=False,
        )
        self._keys[key_id] = material
        self._persist(material)
        return material

    def delete_key(self, key_id: str) -> None:
        self._keys.pop(key_id, None)
        path = os.path.join(self.secret_dir, f"{key_id}.json")
        if os.path.exists(path):
            os.remove(path)

    def list_active_keys(self) -> Dict[str, SecretMaterial]:
        return {k: v for k, v in self._keys.items() if v.active and not v.revoked}


class EnvironmentSecretSource:
    def __init__(self, *, env: Optional[Dict[str, str]] = None) -> None:
        self.env = os.environ if env is None else env

    def get(self, name: str) -> str:
        value = self.env.get(name)
        if value is None or not value.strip():
            raise SecretManagementError(f"missing secret: {name}")
        return value
