"""
tests/test_fusion.py

Unit tests for server/fusion_engine.py covering the four required
scenarios from Section 27/28:

    Normal + Normal                    -> NO_ALERT
    AI Alert + Normal Network           -> NORMAL_AI_ALERT
    Network Anomaly + Normal Feed       -> NETWORK_ONLY_ANOMALY
    Network Anomaly + Replay Suspicion  -> FEED_SPOOFING_REPLAY_SUSPICION
"""

from server.fusion_engine import evaluate, ContentSignals, FeedSignals, NetworkSignals


def _normal_feed():
    return FeedSignals(motion_score=0.2, duplicate_score=0.3, staticness_score=0.1, replay_score=0.1)


def _suspicious_feed():
    return FeedSignals(motion_score=0.005, duplicate_score=0.99, staticness_score=0.95, replay_score=0.9)


def _no_network_anomaly():
    return NetworkSignals(arp_anomaly=False, unknown_device=False,
                           packet_rate_anomaly=False, authentication_anomaly=False)


def _network_anomaly():
    return NetworkSignals(arp_anomaly=True, unknown_device=False,
                           packet_rate_anomaly=False, authentication_anomaly=False)


def test_no_alert_scenario():
    content = ContentSignals(has_detection=False, avg_confidence=0.0)
    result = evaluate("CAM_001", content, _normal_feed(), _no_network_anomaly())
    assert result.classification == "NO_ALERT"


def test_normal_ai_alert_scenario():
    content = ContentSignals(has_detection=True, avg_confidence=0.9)
    result = evaluate("CAM_001", content, _normal_feed(), _no_network_anomaly())
    assert result.classification == "NORMAL_AI_ALERT"


def test_network_only_anomaly_scenario():
    content = ContentSignals(has_detection=False, avg_confidence=0.0)
    result = evaluate("CAM_001", content, _normal_feed(), _network_anomaly())
    assert result.classification == "NETWORK_ONLY_ANOMALY"


def test_feed_spoofing_replay_suspicion_scenario():
    content = ContentSignals(has_detection=False, avg_confidence=0.0)
    result = evaluate("CAM_001", content, _suspicious_feed(), _network_anomaly())
    assert result.classification == "FEED_SPOOFING_REPLAY_SUSPICION"
    assert "ARP anomaly" in result.supporting_signals


def test_trust_scores_within_bounds():
    content = ContentSignals(has_detection=True, avg_confidence=0.7)
    result = evaluate("CAM_001", content, _normal_feed(), _no_network_anomaly())
    for value in (result.content_trust, result.network_trust, result.feed_trust, result.overall_trust):
        assert 0.0 <= value <= 100.0
