"""
server/api_routes.py

Pydantic models for FastAPI request validation. Kept separate from
server/main.py to keep the app factory readable.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ChallengeRequest(BaseModel):
    node_id: str


class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str


class VerifyRequest(BaseModel):
    node_id: str
    challenge_id: str
    hmac: str


class TokenResponse(BaseModel):
    token_id: str
    node_id: str
    issued_at: float
    expires_at: float


class CameraRegisterRequest(BaseModel):
    node_id: str
    secret_key: str
    name: Optional[str] = None
    admin_api_key: str


class EncryptedPayloadRequest(BaseModel):
    node_id: str
    timestamp: float
    nonce: str
    ciphertext: str


class CameraSummary(BaseModel):
    node_id: str
    name: Optional[str]
    status: str
    ip_address: Optional[str]
    last_seen: Optional[float]
    trust_score: Optional[float] = None
    risk_level: Optional[str] = None


class SyntheticEventRequest(BaseModel):
    event_type: str = Field(default="ARP_ANOMALY")
    node_id: Optional[str] = None
    severity: str = Field(default="HIGH")
    description: str = Field(default="Synthetic demo event")
