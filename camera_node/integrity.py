"""
camera_node/integrity.py

Defensive feed-integrity analysis. This module does NOT try to detect
sophisticated adversarial video manipulation; it uses simple, explainable,
classical computer-vision signals to flag feeds that look suspiciously
static or repetitive -- the kind of pattern a naive replay attack (looping
a recorded clip, or freezing a single frame) would produce.

Signals computed per frame (relative to the previous frame):
  - frame_difference : mean absolute pixel difference (0-1 normalized)
  - motion_score      : proportion of pixels that changed significantly
  - frame_variance     : variance of the current frame's pixel intensities
  - duplicate_score    : structural similarity to the previous frame (0-1)
  - staticness_score   : rolling measure of how static the feed has been
  - replay_score       : weighted fusion of the above (0-1, higher = more suspicious)

All thresholds are configurable via config/settings.py. No single metric is
used in isolation to make a decision.
"""

import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional

import cv2
import numpy as np

from config.settings import settings


@dataclass
class IntegrityScore:
    node_id: str
    timestamp: float
    motion_score: float
    frame_difference: float
    frame_variance: float
    duplicate_score: float
    staticness_score: float
    replay_score: float


class FeedIntegrityAnalyzer:
    def __init__(self, node_id: str = None, history_size: int = 30):
        self.node_id = node_id or settings.camera_node_id
        self._prev_gray: Optional[np.ndarray] = None
        self._staticness_history: Deque[float] = deque(maxlen=history_size)

    @staticmethod
    def _to_gray(frame: np.ndarray) -> np.ndarray:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        return cv2.GaussianBlur(gray, (5, 5), 0)

    def analyze(self, frame: np.ndarray) -> IntegrityScore:
        gray = self._to_gray(frame)
        ts = time.time()

        if self._prev_gray is None:
            # First frame: nothing to compare against yet.
            self._prev_gray = gray
            score = IntegrityScore(
                node_id=self.node_id, timestamp=ts,
                motion_score=0.0, frame_difference=0.0, frame_variance=float(np.var(gray)),
                duplicate_score=1.0, staticness_score=0.0, replay_score=0.0,
            )
            self._staticness_history.append(0.0)
            return score

        # --- Frame difference (normalized mean absolute difference) ---
        diff = cv2.absdiff(gray, self._prev_gray)
        frame_difference = float(np.mean(diff)) / 255.0

        # --- Motion score: fraction of pixels that changed meaningfully ---
        _, thresh = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)
        motion_score = float(np.count_nonzero(thresh)) / thresh.size

        # --- Frame variance (visual texture / detail) ---
        frame_variance = float(np.var(gray))

        # --- Duplicate score: correlation-based similarity to previous frame ---
        # Normalized cross-correlation coefficient, clipped to [0, 1]
        prev_f = self._prev_gray.astype(np.float32)
        cur_f = gray.astype(np.float32)
        prev_mean, cur_mean = prev_f.mean(), cur_f.mean()
        numerator = np.sum((prev_f - prev_mean) * (cur_f - cur_mean))
        denominator = np.sqrt(np.sum((prev_f - prev_mean) ** 2) * np.sum((cur_f - cur_mean) ** 2))
        correlation = numerator / denominator if denominator != 0 else 1.0
        duplicate_score = float(np.clip((correlation + 1) / 2, 0.0, 1.0))

        # --- Staticness score: rolling average of low-motion frames ---
        is_static_frame = 1.0 if motion_score < 0.01 else 0.0
        self._staticness_history.append(is_static_frame)
        staticness_score = float(np.mean(self._staticness_history))

        # --- Replay suspicion score: weighted fusion (all normalized 0-1) ---
        # High duplicate_score + high staticness + low motion + low frame_difference
        # together suggest a frozen or looping feed.
        replay_score = float(np.clip(
            0.35 * duplicate_score +
            0.35 * staticness_score +
            0.15 * (1.0 - motion_score) +
            0.15 * (1.0 - frame_difference),
            0.0, 1.0,
        ))

        self._prev_gray = gray

        return IntegrityScore(
            node_id=self.node_id,
            timestamp=ts,
            motion_score=round(motion_score, 4),
            frame_difference=round(frame_difference, 4),
            frame_variance=round(frame_variance, 2),
            duplicate_score=round(duplicate_score, 4),
            staticness_score=round(staticness_score, 4),
            replay_score=round(replay_score, 4),
        )

    def is_suspicious(self, score: IntegrityScore) -> bool:
        return (
            score.replay_score >= settings.replay_threshold or
            score.staticness_score >= settings.staticness_threshold or
            score.duplicate_score >= settings.duplicate_threshold
        )
