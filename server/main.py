"""
server/main.py

FastAPI backend: the central server that camera nodes talk to. Handles
node authentication, receives encrypted camera payloads, runs the network
IDS in the background, fuses all signals via the trust fusion engine, and
persists everything to SQLite for the Streamlit dashboard to read.

Run with:
    uvicorn server.main:app --host 0.0.0.0 --port 8000
or simply:
    python server/main.py
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from config.settings import settings
from config.logging_setup import system_logger, security_logger, network_logger

from database import database as db
from server.authentication import auth_manager
from server.encryption import encryption_manager
from camera_node.encryption import EncryptedPayload
from server.network_ids import NetworkIDS, SyntheticNetworkEventGenerator
from server.integrity import build_feed_signals
from server.fusion_engine import evaluate, ContentSignals, NetworkSignals
from server.api_routes import (
    ChallengeRequest, ChallengeResponse, VerifyRequest, TokenResponse,
    CameraRegisterRequest, EncryptedPayloadRequest, SyntheticEventRequest,
)

app = FastAPI(title="Cross-Layer Trust Verification and Anomaly Detection in Secure Edge Camera Networks", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # lab/demo only -- tighten for any non-lab deployment
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- recent network-anomaly cache, used to correlate with camera uploads ----
# Keyed by node_id (or None for network-wide events); stores (event_type, timestamp)
_recent_network_events: List[dict] = []
_RECENT_WINDOW_SECONDS = 15


def _on_network_event(event: dict):
    db.insert_network_event(
        event_id=event["event_id"],
        node_id=event.get("node_id"),
        timestamp=event["timestamp"],
        event_type=event["event_type"],
        severity=event["severity"],
        confidence=event.get("confidence", 0.5),
        description=event["description"],
    )
    _recent_network_events.append(event)
    # keep list bounded
    cutoff = time.time() - 300
    while _recent_network_events and _recent_network_events[0]["timestamp"] < cutoff:
        _recent_network_events.pop(0)


ids = NetworkIDS(on_event=_on_network_event)
synthetic_generator = SyntheticNetworkEventGenerator(on_event=_on_network_event)


@app.on_event("startup")
def on_startup():
    db.init_db()
    ids.start()  # gracefully no-ops with a log message if scapy/privileges unavailable
    system_logger.info("Server started on %s:%s", settings.server_host, settings.server_port)


@app.on_event("shutdown")
def on_shutdown():
    ids.stop()
    system_logger.info("Server shutting down")


# ------------------------- Health -------------------------

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": time.time()}


# ------------------------- Camera registration (admin only) -------------------------

@app.post("/camera/register")
def register_camera(req: CameraRegisterRequest):
    if not settings.admin_api_key or req.admin_api_key != settings.admin_api_key:
        security_logger.warning("Unauthorized camera registration attempt for node %s", req.node_id)
        raise HTTPException(status_code=403, detail="Invalid admin API key")

    auth_manager.register_node(req.node_id, req.secret_key)
    db.upsert_camera(node_id=req.node_id, name=req.name, status="registered")
    system_logger.info("Camera %s registered via API", req.node_id)
    return {"status": "registered", "node_id": req.node_id}


# ------------------------- Authentication -------------------------

@app.post("/auth/challenge", response_model=ChallengeResponse)
def auth_challenge(req: ChallengeRequest):
    challenge = auth_manager.issue_challenge(req.node_id)
    if challenge is None:
        db.insert_auth_event(req.node_id, time.time(), "CHALLENGE_REQUEST", False, "Unknown node")
        raise HTTPException(status_code=403, detail="Unknown or inactive node")

    db.insert_auth_event(req.node_id, time.time(), "CHALLENGE_ISSUED", True, "Challenge issued")
    return ChallengeResponse(challenge_id=challenge.challenge_id, nonce=challenge.nonce)


@app.post("/auth/verify", response_model=TokenResponse)
def auth_verify(req: VerifyRequest):
    ok = auth_manager.verify_response(req.challenge_id, req.node_id, req.hmac)

    if not ok:
        db.insert_auth_event(req.node_id, time.time(), "AUTH_VERIFY", False, "HMAC verification failed")
        ids.record_auth_failure(req.node_id)
        raise HTTPException(status_code=401, detail="Authentication failed")

    db.insert_auth_event(req.node_id, time.time(), "AUTH_VERIFY", True, "Authentication success")
    db.upsert_camera(node_id=req.node_id, status="online")

    token = auth_manager.issue_token(req.node_id)
    return TokenResponse(**token)


# ------------------------- Camera data ingestion -------------------------

@app.post("/camera/data")
def receive_camera_data(req: EncryptedPayloadRequest, request: Request):
    payload = EncryptedPayload(
        node_id=req.node_id, timestamp=req.timestamp,
        nonce=req.nonce, ciphertext=req.ciphertext,
    )

    plaintext = encryption_manager.decrypt(payload)
    if plaintext is None:
        db.insert_auth_event(req.node_id, time.time(), "DECRYPTION_FAILED", False,
                              "Payload rejected: decryption/auth-tag failure")
        raise HTTPException(status_code=400, detail="DECRYPTION_FAILED")

    token_id = plaintext.get("token_id")
    issued_at = plaintext.get("issued_at")
    node_id = plaintext.get("node_id", req.node_id)

    if not auth_manager.validate_token(token_id, node_id, issued_at):
        security_logger.warning("Rejected data from %s: invalid/expired/replayed token", node_id)
        raise HTTPException(status_code=401, detail="Invalid or replayed session token")
    auth_manager.consume_token(token_id)

    client_ip = request.client.host if request.client else None
    db.upsert_camera(node_id=node_id, status="online", ip_address=client_ip)

    detections = plaintext.get("detections", [])
    integrity = plaintext.get("integrity", {})
    ts = plaintext.get("timestamp", time.time())

    for det in detections:
        db.insert_detection(
            node_id=node_id, timestamp=det["timestamp"], object_name=det["object"],
            confidence=det["confidence"], bbox=det["bbox"],
        )

    if integrity:
        db.insert_integrity_event(
            node_id=node_id, timestamp=integrity.get("timestamp", ts),
            motion_score=integrity.get("motion_score", 0.0),
            duplicate_score=integrity.get("duplicate_score", 0.0),
            staticness_score=integrity.get("staticness_score", 0.0),
            replay_score=integrity.get("replay_score", 0.0),
        )

    # ---- Cross-layer trust fusion ----
    has_detection = len(detections) > 0
    avg_conf = (sum(d["confidence"] for d in detections) / len(detections)) if has_detection else 0.0
    content_signals = ContentSignals(has_detection=has_detection, avg_confidence=avg_conf)
    feed_signals = build_feed_signals(integrity) if integrity else build_feed_signals({})

    now = time.time()
    node_recent_events = [
        e for e in _recent_network_events
        if now - e["timestamp"] <= _RECENT_WINDOW_SECONDS and (e.get("node_id") in (None, node_id))
    ]
    network_signals = NetworkSignals(
        arp_anomaly=any(e["event_type"] == "ARP_ANOMALY" for e in node_recent_events),
        unknown_device=any(e["event_type"] == "UNKNOWN_DEVICE" for e in node_recent_events),
        packet_rate_anomaly=any(e["event_type"] == "POSSIBLE_FLOODING" for e in node_recent_events),
        authentication_anomaly=any(e["event_type"] == "AUTH_ANOMALY" for e in node_recent_events),
    )

    result = evaluate(node_id, content_signals, feed_signals, network_signals)

    db.insert_fusion_event(
        node_id=result.node_id, timestamp=result.timestamp, classification=result.classification,
        content_trust=result.content_trust, network_trust=result.network_trust,
        feed_trust=result.feed_trust, overall_trust=result.overall_trust,
        risk_score=result.risk_score, reason=result.reason,
    )

    return {
        "status": "received",
        "classification": result.classification,
        "overall_trust": result.overall_trust,
        "risk_score": result.risk_score,
    }


# ------------------------- Query endpoints -------------------------

@app.get("/cameras")
def list_cameras():
    cameras = db.get_all_cameras()
    for cam in cameras:
        latest = db.get_latest_fusion_for_node(cam["node_id"])
        cam["trust_score"] = latest["overall_trust"] if latest else None
        cam["risk_level"] = latest["classification"] if latest else None
    return cameras


@app.get("/cameras/{node_id}")
def get_camera(node_id: str):
    cam = db.get_camera(node_id)
    if not cam:
        raise HTTPException(status_code=404, detail="Camera not found")
    cam["recent_detections"] = db.get_recent_detections(limit=20, node_id=node_id)
    cam["recent_integrity"] = db.get_recent_integrity_events(limit=20, node_id=node_id)
    cam["recent_fusion"] = db.get_recent_fusion_events(limit=20, node_id=node_id)
    return cam


@app.get("/alerts")
def get_alerts(limit: int = 50):
    events = db.get_recent_fusion_events(limit=limit)
    return [e for e in events if e["classification"] != "NO_ALERT"]


@app.get("/network/events")
def get_network_events(limit: int = 50):
    return db.get_recent_network_events(limit=limit)


@app.get("/fusion/{node_id}")
def get_fusion(node_id: str, limit: int = 20):
    return db.get_recent_fusion_events(limit=limit, node_id=node_id)


# ------------------------- Synthetic demo events (Section 28) -------------------------

@app.post("/demo/synthetic-network-event")
def trigger_synthetic_event(req: SyntheticEventRequest):
    """Safe, isolated demo helper -- fabricates a NetworkIDS-shaped event so
    scenarios 3 and 4 (Section 28) can be demonstrated without needing real
    ARP-spoofing tooling. Never touches the actual network."""
    event = synthetic_generator.generate(
        event_type=req.event_type, node_id=req.node_id,
        severity=req.severity, description=req.description,
    )
    return event


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host=settings.server_host, port=settings.server_port, reload=False)
