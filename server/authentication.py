"""
server/authentication.py

Implements:
  1. HMAC-SHA256 challenge-response authentication for camera nodes.
  2. Short-lived session tokens with replay protection.

Security properties:
  - Challenges are cryptographically random, single-use, and expire after
    settings.challenge_ttl_seconds.
  - Secret keys are never transmitted over the network; only HMAC digests are.
  - Unknown node IDs are rejected outright.
  - Reused challenge IDs and reused session/token IDs are rejected.
  - Failed authentication attempts are logged (without secrets).
"""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from config.settings import settings
from config.logging_setup import security_logger


@dataclass
class RegisteredNode:
    node_id: str
    secret_key: str          # shared HMAC secret, loaded from config/DB, never logged
    status: str = "active"   # active | disabled
    created_at: float = field(default_factory=time.time)


@dataclass
class Challenge:
    challenge_id: str
    node_id: str
    nonce: str
    created_at: float
    used: bool = False

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > settings.challenge_ttl_seconds


class AuthenticationManager:
    """In-memory node registry + challenge store.

    In this prototype the registry is in-memory for simplicity and speed;
    server/main.py also persists authentication_events to SQLite for audit.
    A production system would store node secrets in a secrets manager.
    """

    def __init__(self):
        self._nodes: Dict[str, RegisteredNode] = {}
        self._challenges: Dict[str, Challenge] = {}
        self._used_session_ids: Dict[str, float] = {}  # replay protection

    # ---------- Node registration ----------

    def register_node(self, node_id: str, secret_key: str) -> RegisteredNode:
        node = RegisteredNode(node_id=node_id, secret_key=secret_key)
        self._nodes[node_id] = node
        security_logger.info("Node registered: %s", node_id)
        return node

    def is_known_node(self, node_id: str) -> bool:
        return node_id in self._nodes and self._nodes[node_id].status == "active"

    # ---------- Challenge issuance ----------

    def issue_challenge(self, node_id: str) -> Optional[Challenge]:
        if not self.is_known_node(node_id):
            security_logger.warning("AUTHENTICATION_FAILED: unknown node %s requested challenge", node_id)
            return None

        challenge = Challenge(
            challenge_id=secrets.token_hex(16),
            node_id=node_id,
            nonce=secrets.token_hex(32),
            created_at=time.time(),
        )
        self._challenges[challenge.challenge_id] = challenge
        return challenge

    # ---------- Verification ----------

    def verify_response(self, challenge_id: str, node_id: str, hmac_hex: str) -> bool:
        challenge = self._challenges.get(challenge_id)

        if challenge is None:
            security_logger.warning("AUTHENTICATION_FAILED: unknown challenge_id for node %s", node_id)
            return False

        if challenge.used:
            security_logger.warning("AUTHENTICATION_FAILED: challenge reuse attempt by node %s", node_id)
            return False

        if challenge.node_id != node_id:
            security_logger.warning("AUTHENTICATION_FAILED: node_id mismatch on challenge %s", challenge_id)
            return False

        if challenge.is_expired():
            security_logger.warning("AUTHENTICATION_FAILED: expired challenge for node %s", node_id)
            challenge.used = True
            return False

        node = self._nodes.get(node_id)
        if node is None or node.status != "active":
            security_logger.warning("AUTHENTICATION_FAILED: node %s not active", node_id)
            return False

        expected = hmac.new(
            node.secret_key.encode("utf-8"),
            challenge.nonce.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        challenge.used = True  # single-use regardless of outcome

        if not hmac.compare_digest(expected, hmac_hex):
            security_logger.warning("AUTHENTICATION_FAILED: HMAC mismatch for node %s", node_id)
            return False

        security_logger.info("Authentication success for node %s", node_id)
        return True

    # ---------- Session token / replay protection ----------

    def issue_token(self, node_id: str) -> dict:
        token_id = secrets.token_hex(16)
        issued_at = time.time()
        self._used_session_ids[token_id] = issued_at
        return {
            "token_id": token_id,
            "node_id": node_id,
            "issued_at": issued_at,
            "expires_at": issued_at + settings.token_ttl_seconds,
        }

    def validate_token(self, token_id: str, node_id: str, issued_at: float) -> bool:
        """Validates a token for a data-submission request. Rejects expired
        or already-consumed (replayed) tokens."""
        now = time.time()

        if now - issued_at > settings.token_ttl_seconds:
            security_logger.warning("Token expired for node %s", node_id)
            return False

        first_seen = self._used_session_ids.get(token_id)
        if first_seen is None:
            # token wasn't issued by us
            security_logger.warning("Unknown token presented by node %s", node_id)
            return False

        return True

    def consume_token(self, token_id: str):
        """Marks a token as consumed so it cannot be replayed again."""
        self._used_session_ids.pop(token_id, None)


auth_manager = AuthenticationManager()
