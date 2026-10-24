"""
tests/test_integrity.py

Unit tests for camera_node/integrity.py using synthetic frames (no real
camera required): normal/high-motion video, static video, repeated frames.
"""

import numpy as np
import pytest

from camera_node.integrity import FeedIntegrityAnalyzer


def _random_frame(seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.integers(0, 255, size=(240, 320, 3), dtype=np.uint8)


def _static_frame() -> np.ndarray:
    return np.full((240, 320, 3), 128, dtype=np.uint8)


def test_first_frame_has_no_comparison():
    analyzer = FeedIntegrityAnalyzer(node_id="CAM_TEST")
    score = analyzer.analyze(_random_frame(1))
    assert score.duplicate_score == 1.0
    assert score.replay_score == 0.0


def test_high_motion_video_has_low_duplicate_score():
    analyzer = FeedIntegrityAnalyzer(node_id="CAM_TEST")
    analyzer.analyze(_random_frame(1))
    score = analyzer.analyze(_random_frame(2))  # completely different random frame
    assert score.motion_score > 0.1
    assert score.duplicate_score < 0.9


def test_static_video_has_high_staticness_and_duplicate_score():
    analyzer = FeedIntegrityAnalyzer(node_id="CAM_TEST")
    frame = _static_frame()
    for _ in range(10):
        score = analyzer.analyze(frame)  # identical frame repeated
    assert score.staticness_score > 0.8
    assert score.duplicate_score > 0.95
    assert score.motion_score < 0.01


def test_repeated_frames_flagged_as_suspicious():
    analyzer = FeedIntegrityAnalyzer(node_id="CAM_TEST")
    frame = _static_frame()
    for _ in range(15):
        score = analyzer.analyze(frame)
    assert analyzer.is_suspicious(score) is True


def test_normal_varied_motion_not_suspicious():
    analyzer = FeedIntegrityAnalyzer(node_id="CAM_TEST")
    score = None
    for i in range(5):
        score = analyzer.analyze(_random_frame(i))
    assert analyzer.is_suspicious(score) is False
