from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from .secret_manager import LocalSecretManager, SecretMaterial


@dataclass
class KeyRecord:
    key_id: str
    key_material: bytes
    version: int
    active: bool = True
    revoked: bool = False


class KeyManager:
    def __init__(self, secret_manager: Optional[LocalSecretManager] = None) -> None:
        self.secret_manager = secret_manager or LocalSecretManager()
        self.keys: Dict[str, SecretMaterial] = {}

    def generate_kek(self, key_id: str, *, version: int = 1) -> SecretMaterial:
        material = self.secret_manager.create_key(key_id, length=32, version=version)
        self.keys[key_id] = material
        return material

    def generate_dek(self, key_id: str, *, version: int = 1) -> SecretMaterial:
        material = self.secret_manager.create_key(key_id, length=32, version=version)
        self.keys[key_id] = material
        return material

    def get_active_key(self, key_id: str) -> SecretMaterial:
        material = self.secret_manager.get_key(key_id)
        if not material.active:
            raise ValueError("inactive key requested")
        return material

    def rotate(self, old_key_id: str, new_key_id: str, *, version: int = 2) -> SecretMaterial:
        return self.secret_manager.rotate_key(old_key_id, new_key_id, version=version)

    def list_versions(self) -> List[SecretMaterial]:
        return list(self.secret_manager._keys.values())

    def revoke(self, key_id: str) -> None:
        key = self.secret_manager.get_key(key_id)
        key.revoked = True
        key.active = False
        self.secret_manager._persist(key)

    def is_valid_version(self, key_id: str, version: int) -> bool:
        key = self.secret_manager._keys.get(key_id)
        return key is not None and key.version == version and not key.revoked and key.active
