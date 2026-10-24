"""
tests/test_authentication.py

Unit tests for server/authentication.py: valid auth, invalid auth,
expired challenge, reused challenge.
"""

import hashlib
import hmac
import time

import pytest

from server.authentication import AuthenticationManager
from config.settings import settings


def _hmac_for(secret: str, nonce: str) -> str:
    return hmac.new(secret.encode(), nonce.encode(), hashlib.sha256).hexdigest()


@pytest.fixture
def manager():
    m = AuthenticationManager()
    m.register_node("CAM_TEST", "test-secret-key")
    return m


def test_valid_authentication(manager):
    challenge = manager.issue_challenge("CAM_TEST")
    assert challenge is not None

    digest = _hmac_for("test-secret-key", challenge.nonce)
    assert manager.verify_response(challenge.challenge_id, "CAM_TEST", digest) is True


def test_invalid_authentication_wrong_secret(manager):
    challenge = manager.issue_challenge("CAM_TEST")
    digest = _hmac_for("wrong-secret", challenge.nonce)
    assert manager.verify_response(challenge.challenge_id, "CAM_TEST", digest) is False


def test_unknown_node_rejected(manager):
    challenge = manager.issue_challenge("CAM_DOES_NOT_EXIST")
    assert challenge is None


def test_expired_challenge_rejected(manager, monkeypatch):
    monkeypatch.setattr(settings, "challenge_ttl_seconds", 0)
    challenge = manager.issue_challenge("CAM_TEST")
    time.sleep(0.1)
    digest = _hmac_for("test-secret-key", challenge.nonce)
    assert manager.verify_response(challenge.challenge_id, "CAM_TEST", digest) is False


def test_reused_challenge_rejected(manager):
    challenge = manager.issue_challenge("CAM_TEST")
    digest = _hmac_for("test-secret-key", challenge.nonce)

    first = manager.verify_response(challenge.challenge_id, "CAM_TEST", digest)
    second = manager.verify_response(challenge.challenge_id, "CAM_TEST", digest)

    assert first is True
    assert second is False  # replay of the same challenge must fail
