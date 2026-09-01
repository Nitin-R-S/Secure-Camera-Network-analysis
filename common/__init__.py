"""
common/crypto_utils.py

End-to-end  encryption for video frames and control metadata.

Supports ChaCha20-Poly1305 (favoured on resource-constrained edge
hardware such as the Raspberry Pi) and AES-256-GCM as an alternative,
selected via common.config.STREAM_CIPHER.

Wire format for an encrypted payload (all fields concatenated, then
base-nothing -- kept as raw bytes for a length-prefixed socket frame):

    nonce (12 bytes) || ciphertext_and_tag (variable)

The associated data (AAD) binds each ciphertext to the node_id and a
monotonic sequence number, so that swapping frames between nodes or
replaying an old frame under a new sequence number causes AEAD
authentication to fail.
"""

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from common import config

NONCE_SIZE = 12


class CryptoError(Exception):
    pass


def load_or_create_key(path) -> bytes:
    """Load a 32-byte symmetric key from disk, generating one on first run.

    In production this key must be provisioned out-of-band during node
    enrollment (e.g. burned in at manufacture / installed via a secure
    channel), never auto-generated on an internet-facing server. Auto
    generation here exists purely so the lab testbed runs out of the box.
    """
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise CryptoError(f"Key file {path} is not 32 bytes")
        return key
    key = os.urandom(32)
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _get_aead(key: bytes):
    if config.STREAM_CIPHER == "chacha20":
        return ChaCha20Poly1305(key)
    elif config.STREAM_CIPHER == "aesgcm":
        return AESGCM(key)
    raise CryptoError(f"Unsupported STREAM_CIPHER: {config.STREAM_CIPHER}")


def make_aad(node_id: str, seq: int) -> bytes:
    """Associated data binding ciphertext to a specific node + sequence
    number, so ciphertexts cannot be replayed under another node's
    identity or reordered without detection."""
    return node_id.encode("utf-8") + b"|" + struct.pack(">Q", seq)


def encrypt(key: bytes, plaintext: bytes, node_id: str, seq: int) -> bytes:
    aead = _get_aead(key)
    nonce = os.urandom(NONCE_SIZE)
    aad = make_aad(node_id, seq)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt(key: bytes, payload: bytes, node_id: str, seq: int) -> bytes:
    if len(payload) < NONCE_SIZE + 16:
        raise CryptoError("Payload too short to be valid AEAD ciphertext")
    aead = _get_aead(key)
    nonce, ct = payload[:NONCE_SIZE], payload[NONCE_SIZE:]
    aad = make_aad(node_id, seq)
    try:
        return aead.decrypt(nonce, ct, aad)
    except Exception as exc:  # cryptography raises InvalidTag
        raise CryptoError(f"Decryption/authentication failed: {exc}") from exc
