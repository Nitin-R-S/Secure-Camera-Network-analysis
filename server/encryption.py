"""
server/encryption.py

Server-side encryption manager. Wraps camera_node.encryption.FrameEncryptor
and maintains one encryptor per registered camera node so each camera can
(optionally) use its own AES key. Falls back to the global AES_KEY from
settings if a node has no dedicated key configured.
"""

from typing import Dict, Optional

from camera_node.encryption import FrameEncryptor, EncryptedPayload, EncryptionError
from config.settings import settings
from config.logging_setup import security_logger


class EncryptionManager:
    def __init__(self):
        self._encryptors: Dict[str, FrameEncryptor] = {}

    def register_node_key(self, node_id: str, key_b64: str):
        """Register a dedicated AES key for a node (optional)."""
        self._encryptors[node_id] = FrameEncryptor(key_b64=key_b64, node_id=node_id)

    def _get_encryptor(self, node_id: str) -> FrameEncryptor:
        if node_id in self._encryptors:
            return self._encryptors[node_id]
        # fall back to the shared global key
        encryptor = FrameEncryptor(key_b64=settings.aes_key, node_id=node_id)
        self._encryptors[node_id] = encryptor
        return encryptor

    def decrypt(self, payload: EncryptedPayload) -> Optional[dict]:
        try:
            encryptor = self._get_encryptor(payload.node_id)
            return encryptor.decrypt(payload)
        except EncryptionError as exc:
            security_logger.error("Encryption manager error for %s: %s", payload.node_id, exc)
            return None

    def encrypt(self, node_id: str, obj: dict) -> EncryptedPayload:
        encryptor = self._get_encryptor(node_id)
        return encryptor.encrypt(obj)


encryption_manager = EncryptionManager()
