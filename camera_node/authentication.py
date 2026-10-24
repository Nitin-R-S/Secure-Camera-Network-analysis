"""
camera_node/authentication.py

Client-side counterpart to server/authentication.py. Performs the
HMAC-SHA256 challenge-response flow against the server's /auth endpoints.
The camera's secret key never leaves this process; only the HMAC digest is
transmitted.
"""

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Optional

import requests

from config.logging_setup import security_logger, redact


@dataclass
class SessionToken:
    token_id: str
    node_id: str
    issued_at: float
    expires_at: float

    def is_valid(self) -> bool:
        return time.time() < self.expires_at


class CameraAuthClient:
    def __init__(self, server_url: str, node_id: str, secret_key: str):
        self.server_url = server_url.rstrip("/")
        self.node_id = node_id
        self._secret_key = secret_key  # never logged, never sent over the wire
        self._token: Optional[SessionToken] = None

    def authenticate(self) -> Optional[SessionToken]:
        """Runs the full challenge -> HMAC response -> token flow."""
        try:
            challenge_resp = requests.post(
                f"{self.server_url}/auth/challenge",
                json={"node_id": self.node_id},
                timeout=5,
            )
            if challenge_resp.status_code != 200:
                security_logger.warning(
                    "AUTHENTICATION_FAILED: challenge request rejected for node %s (secret=%s)",
                    self.node_id, redact(self._secret_key),
                )
                return None

            challenge = challenge_resp.json()
            nonce = challenge["nonce"]
            challenge_id = challenge["challenge_id"]

            digest = hmac.new(
                self._secret_key.encode("utf-8"),
                nonce.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            verify_resp = requests.post(
                f"{self.server_url}/auth/verify",
                json={
                    "node_id": self.node_id,
                    "challenge_id": challenge_id,
                    "hmac": digest,
                },
                timeout=5,
            )

            if verify_resp.status_code != 200:
                security_logger.warning("AUTHENTICATION_FAILED: verify rejected for node %s", self.node_id)
                return None

            token_data = verify_resp.json()
            self._token = SessionToken(
                token_id=token_data["token_id"],
                node_id=token_data["node_id"],
                issued_at=token_data["issued_at"],
                expires_at=token_data["expires_at"],
            )
            security_logger.info("Node %s authenticated successfully", self.node_id)
            return self._token

        except requests.RequestException as exc:
            security_logger.error("Authentication network error for node %s: %s", self.node_id, exc)
            return None

    def get_valid_token(self) -> Optional[SessionToken]:
        """Returns a currently-valid token, re-authenticating if needed."""
        if self._token is None or not self._token.is_valid():
            return self.authenticate()
        return self._token
