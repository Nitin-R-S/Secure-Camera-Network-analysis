"""
tests/test_encryption.py

Unit tests for camera_node/encryption.py: successful encrypt/decrypt,
modified ciphertext rejection, invalid nonce handling.
"""

import base64
import pytest

from camera_node.encryption import FrameEncryptor, EncryptedPayload, generate_key, EncryptionError


@pytest.fixture
def encryptor():
    key = generate_key()
    return FrameEncryptor(key_b64=key, node_id="CAM_TEST")


def test_encrypt_decrypt_roundtrip(encryptor):
    original = {"hello": "world", "value": 42}
    payload = encryptor.encrypt(original)
    decrypted = encryptor.decrypt(payload)
    assert decrypted == original


def test_modified_ciphertext_is_rejected(encryptor):
    payload = encryptor.encrypt({"a": 1})

    # tamper with the ciphertext
    raw = bytearray(base64.b64decode(payload.ciphertext))
    raw[0] ^= 0xFF
    tampered = EncryptedPayload(
        node_id=payload.node_id, timestamp=payload.timestamp,
        nonce=payload.nonce, ciphertext=base64.b64encode(bytes(raw)).decode(),
    )

    assert encryptor.decrypt(tampered) is None


def test_invalid_nonce_handled_safely(encryptor):
    payload = encryptor.encrypt({"a": 1})
    bad_payload = EncryptedPayload(
        node_id=payload.node_id, timestamp=payload.timestamp,
        nonce="not-valid-base64!!", ciphertext=payload.ciphertext,
    )
    # Should not raise -- must fail gracefully and return None
    assert encryptor.decrypt(bad_payload) is None


def test_missing_key_raises():
    with pytest.raises(EncryptionError):
        FrameEncryptor(key_b64="", node_id="CAM_TEST")


def test_wrong_key_cannot_decrypt():
    key_a = generate_key()
    key_b = generate_key()
    enc_a = FrameEncryptor(key_b64=key_a, node_id="CAM_TEST")
    enc_b = FrameEncryptor(key_b64=key_b, node_id="CAM_TEST")

    payload = enc_a.encrypt({"secret": "data"})
    assert enc_b.decrypt(payload) is None
