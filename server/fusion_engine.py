"""
server/fusion_engine.py

Cross-Layer Trust Fusion Engine -- the core novelty of this project.

Combines three independent signal families into a single, explainable
trust decision:

  1. Content signals   (from YOLOv8n detections)
  2. Feed-integrity signals (from camera_node/integrity.py)
  3. Network signals    (from server/network_ids.py)

Produces:
  content_trust, network_trust, feed_integrity_trust, overall_trust  (0-100)
  classification in {NO_ALERT, NORMAL_AI_ALERT, NETWORK_ONLY_ANOMALY,
                      FEED_SPOOFING_REPLAY_SUSPICION}

IMPORTANT: The weighted scoring model below is a transparent, configurable
heuristic designed for an academic prototype. It has NOT been statistically
validated against a labeled attack dataset, and should not be presented as
such. Section 15/29 note this explicitly; see README "Limitations".
"""

import time
from dataclasses import dataclass
from typing import List, Optional

from config.settings import settings


@dataclass
class ContentSignals:
    has_detection: bool
    avg_confidence: float  # 0-1, 0 if no detections


@dataclass
class FeedSignals:
    motion_score: float
    duplicate_score: float
    staticness_score: float
    replay_score: float


@dataclass
class NetworkSignals:
    arp_anomaly: bool
    unknown_device: bool
    packet_rate_anomaly: bool
    authentication_anomaly: bool


@dataclass
class FusionResult:
    node_id: str
    timestamp: float
    classification: str
    content_trust: float
    network_trust: float
    feed_trust: float
    overall_trust: float
    risk_score: float
    reason: str
    supporting_signals: List[str]


CLASSIFICATIONS = {
    "NO_ALERT",
    "NORMAL_AI_ALERT",
    "NETWORK_ONLY_ANOMALY",
    "FEED_SPOOFING_REPLAY_SUSPICION",
}


def _content_trust(signals: ContentSignals) -> float:
    """Content trust reflects confidence in the AI's read of the scene, not
    whether something alarming was detected. A confident detection OR a
    confident 'nothing here' both score high; low confidence scores low."""
    if signals.has_detection:
        return round(signals.avg_confidence * 100, 2)
    return 85.0  # confident "normal scene", slightly conservative


def _feed_trust(signals: FeedSignals) -> float:
    """Feed integrity trust is high when motion/variation looks natural and
    low when the feed looks suspiciously static/duplicated (possible replay
    or frozen-frame spoofing)."""
    suspicion = max(signals.replay_score, signals.staticness_score, signals.duplicate_score)
    trust = (1.0 - suspicion) * 100
    return round(max(0.0, min(100.0, trust)), 2)


def _network_trust(signals: NetworkSignals) -> float:
    penalties = 0
    if signals.arp_anomaly:
        penalties += 40
    if signals.unknown_device:
        penalties += 20
    if signals.packet_rate_anomaly:
        penalties += 25
    if signals.authentication_anomaly:
        penalties += 30
    trust = max(0.0, 100.0 - penalties)
    return round(trust, 2)


def evaluate(
    node_id: str,
    content: ContentSignals,
    feed: FeedSignals,
    network: NetworkSignals,
) -> FusionResult:
    content_trust = _content_trust(content)
    feed_trust = _feed_trust(feed)
    network_trust = _network_trust(network)

    overall_trust = round(
        content_trust * settings.content_weight +
        network_trust * settings.network_weight +
        feed_trust * settings.feed_weight,
        2,
    )

    network_anomaly_present = (
        network.arp_anomaly or network.unknown_device or
        network.packet_rate_anomaly or network.authentication_anomaly
    )
    feed_suspicious = feed_trust < (100 - settings.replay_threshold * 100)

    supporting_signals = []
    if network.arp_anomaly:
        supporting_signals.append("ARP anomaly")
    if network.unknown_device:
        supporting_signals.append("Unknown device on network")
    if network.packet_rate_anomaly:
        supporting_signals.append("Abnormal packet rate")
    if network.authentication_anomaly:
        supporting_signals.append("Authentication anomaly")
    if feed.replay_score >= settings.replay_threshold:
        supporting_signals.append("High replay-suspicion score")
    if feed.staticness_score >= settings.staticness_threshold:
        supporting_signals.append("Feed unusually static")
    if feed.duplicate_score >= settings.duplicate_threshold:
        supporting_signals.append("High duplicate-frame score")
    if feed.motion_score < 0.01:
        supporting_signals.append("Low motion")
    if content.has_detection:
        supporting_signals.append(f"AI detection (avg conf {content.avg_confidence:.2f})")

    # --- classification decision tree (Section 16) ---
    if network_anomaly_present and feed_suspicious:
        classification = "FEED_SPOOFING_REPLAY_SUSPICION"
        risk_score = round(100 - overall_trust, 2)
        reason = "Network anomaly correlated with suspicious feed-integrity behaviour"
    elif network_anomaly_present and not feed_suspicious:
        classification = "NETWORK_ONLY_ANOMALY"
        risk_score = round((100 - network_trust) * 0.8, 2)
        reason = "Network security anomaly detected; feed integrity appears normal"
    elif content.has_detection and not network_anomaly_present and not feed_suspicious:
        classification = "NORMAL_AI_ALERT"
        risk_score = round(max(0.0, 40 - content_trust * 0.2), 2)
        reason = "AI detected an object/person under normal network and feed conditions"
    else:
        classification = "NO_ALERT"
        risk_score = round(max(0.0, 100 - overall_trust) * 0.2, 2)
        reason = "All signals within normal operating ranges"

    return FusionResult(
        node_id=node_id,
        timestamp=time.time(),
        classification=classification,
        content_trust=content_trust,
        network_trust=network_trust,
        feed_trust=feed_trust,
        overall_trust=overall_trust,
        risk_score=risk_score,
        reason=reason,
        supporting_signals=supporting_signals,
    )
