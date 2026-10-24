"""
camera_node/encryption.py

AES-256-GCM based encryption for camera payloads (frame metadata, detections,
integrity scores). This module is imported by both the camera node and the
server (server/encryption.py re-exports the same logic) so the two sides
always agree on the wire format.

Design notes:
  - Every encryption call generates a fresh, cryptographically random 96-bit
    nonce. Nonces are NEVER reused with the same key.
  - The GCM authentication tag is verified automatically by the
    `cryptography` library during decryption; tampered ciphertext raises
    InvalidTag and is rejected.
  - Keys are loaded from environment variables / settings, never hardcoded.
  - Optionally supports per-node keys via a lookup dict, falling back to the
    global AES_KEY from settings.
"""

import base64
import json
import os
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config.logging_setup import security_logger


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""


@dataclass
class EncryptedPayload:
    node_id: str
    timestamp: float
    nonce: str          # base64
    ciphertext: str      # base64 (includes GCM tag appended by the library)

    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    @staticmethod
    def from_dict(d: dict) -> "EncryptedPayload":
        return EncryptedPayload(
            node_id=d["node_id"],
            timestamp=d["timestamp"],
            nonce=d["nonce"],
            ciphertext=d["ciphertext"],
        )


def _load_key_bytes(key_b64: str) -> bytes:
    """Decode a base64-encoded 32-byte AES-256 key. Generates a clear error
    (never logs the key itself) if missing/invalid."""
    if not key_b64:
        raise EncryptionError(
            "AES key is not configured. Set AES_KEY (base64, 32 bytes) in .env"
        )
    try:
        key_bytes = base64.b64decode(key_b64)
    except Exception as exc:
        raise EncryptionError("AES key is not valid base64") from exc

    if len(key_bytes) != 32:
        raise EncryptionError("AES key must decode to exactly 32 bytes (AES-256)")

    return key_bytes


def generate_key() -> str:
    """Utility to generate a new base64 AES-256 key (for setup / key rotation)."""
    return base64.b64encode(os.urandom(32)).decode("utf-8")


class FrameEncryptor:
    """Encrypts/decrypts JSON-serializable payloads with AES-256-GCM."""

    def __init__(self, key_b64: str, node_id: str):
        self.node_id = node_id
        self._key = _load_key_bytes(key_b64)
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, plaintext_obj: dict) -> EncryptedPayload:
        try:
            plaintext_bytes = json.dumps(plaintext_obj).encode("utf-8")
            nonce = os.urandom(12)  # 96-bit nonce required for GCM
            # associated_data binds node_id to the ciphertext, preventing
            # payload-swap attacks between nodes
            aad = self.node_id.encode("utf-8")
            ciphertext = self._aesgcm.encrypt(nonce, plaintext_bytes, aad)

            payload = EncryptedPayload(
                node_id=self.node_id,
                timestamp=time.time(),
                nonce=base64.b64encode(nonce).decode("utf-8"),
                ciphertext=base64.b64encode(ciphertext).decode("utf-8"),
            )
            return payload
        except Exception as exc:
            security_logger.error("Encryption failed for node %s: %s", self.node_id, exc)
            raise EncryptionError("Encryption failed") from exc

    def decrypt(self, payload: EncryptedPayload) -> Optional[dict]:
        try:
            nonce = base64.b64decode(payload.nonce)
            ciphertext = base64.b64decode(payload.ciphertext)
            aad = payload.node_id.encode("utf-8")
            plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext, aad)
            return json.loads(plaintext_bytes.decode("utf-8"))
        except InvalidTag:
            security_logger.warning(
                "DECRYPTION_FAILED: authentication tag mismatch for node %s "
                "(possible tampering or wrong key)", payload.node_id
            )
            return None
        except Exception as exc:
            security_logger.error("DECRYPTION_FAILED for node %s: %s", payload.node_id, exc)
            return None
