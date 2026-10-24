"""
server/integrity.py

Server-side helper that turns a decrypted camera payload's "integrity"
dict into a fusion_engine.FeedSignals object. Kept separate from
camera_node/integrity.py (which does the actual CV computation on-device)
to keep responsibilities clean: the camera computes, the server interprets.
"""

from server.fusion_engine import FeedSignals


def build_feed_signals(integrity_dict: dict) -> FeedSignals:
    return FeedSignals(
        motion_score=float(integrity_dict.get("motion_score", 0.0)),
        duplicate_score=float(integrity_dict.get("duplicate_score", 0.0)),
        staticness_score=float(integrity_dict.get("staticness_score", 0.0)),
        replay_score=float(integrity_dict.get("replay_score", 0.0)),
    )
