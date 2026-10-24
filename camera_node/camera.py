"""
camera_node/camera.py

OpenCV-based camera capture. Works with the Raspberry Pi camera (via
libcamera/V4L2, exposed as /dev/video0) or any USB webcam, since OpenCV's
VideoCapture treats both the same way once a video device index is given.

Every captured frame is timestamped and tagged with the node's ID.
"""

import time
from dataclasses import dataclass
from typing import Optional

import cv2
import numpy as np

from config.settings import settings
from config.logging_setup import system_logger


class CameraOfflineError(Exception):
    """Raised when the camera cannot be opened or a frame cannot be read."""


@dataclass
class CapturedFrame:
    node_id: str
    timestamp: float
    frame: np.ndarray  # BGR image array (kept in memory only, never uploaded raw)


class CameraCapture:
    def __init__(
        self,
        node_id: str = None,
        camera_index: int = None,
        width: int = None,
        height: int = None,
        fps: int = None,
        video_file: str = None,
    ):
        self.node_id = node_id or settings.camera_node_id
        self.camera_index = camera_index if camera_index is not None else settings.camera_index
        self.width = width or settings.camera_width
        self.height = height or settings.camera_height
        self.fps = fps or settings.camera_fps
        # When set, a recorded video file is looped as the "feed" instead of a
        # live device. This exists purely to demo/validate the project's own
        # feed-integrity / replay-detection logic (Section 8: Attack Simulation
        # & Evaluation) -- it feeds this node's own pipeline a looping clip so
        # the staticness/duplicate/replay scores and trust-fusion engine can be
        # observed catching a simulated feed-replay condition.
        self.video_file = video_file
        self._cap: Optional[cv2.VideoCapture] = None

    def open(self):
        source = self.video_file if self.video_file else self.camera_index
        self._cap = cv2.VideoCapture(source)
        if not self._cap.isOpened():
            system_logger.error("CAMERA_OFFLINE: node %s could not open source %s",
                                 self.node_id, source)
            raise CameraOfflineError(f"Could not open source {source}")

        if not self.video_file:
            # Resolution/FPS hints only make sense for a live capture device.
            self._cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.width)
            self._cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.height)
            self._cap.set(cv2.CAP_PROP_FPS, self.fps)

        system_logger.info("Camera opened for node %s (source=%s, %sx%s @ %sfps)",
                            self.node_id, source, self.width, self.height, self.fps)

    def read_frame(self) -> CapturedFrame:
        if self._cap is None or not self._cap.isOpened():
            raise CameraOfflineError("Camera is not open")

        ok, frame = self._cap.read()

        if (not ok or frame is None) and self.video_file:
            # End of the demo clip reached -- loop back to the start so the
            # feed keeps "streaming" the same footage on repeat, which is
            # exactly the signature (near-zero motion variance / repeated
            # frames) the feed-integrity analyzer is designed to flag.
            self._cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            ok, frame = self._cap.read()

        if not ok or frame is None:
            system_logger.error("CAMERA_OFFLINE: node %s failed to read frame", self.node_id)
            raise CameraOfflineError("Failed to read frame from camera")

        return CapturedFrame(node_id=self.node_id, timestamp=time.time(), frame=frame)

    def release(self):
        if self._cap is not None:
            self._cap.release()
            system_logger.info("Camera released for node %s", self.node_id)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
