"""
camera_node/client.py

Main entry point for a camera node. Runs the full edge pipeline:

    capture -> YOLOv8n detect -> feed-integrity analysis -> authenticate
    -> AES-GCM encrypt -> POST to server /camera/data

Run with:
    python camera_node/client.py --node-id CAM_001 --secret <secret> --server http://<ip>:8000

Never uploads raw video frames -- only detection metadata and integrity
scores are sent, encrypted.
"""

import time
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests

from camera_node.camera import CameraCapture, CameraOfflineError
from camera_node.detector import ObjectDetector
from camera_node.integrity import FeedIntegrityAnalyzer
from camera_node.authentication import CameraAuthClient
from camera_node.encryption import FrameEncryptor, EncryptionError
from camera_node.node_config import parse_node_config
from config.logging_setup import system_logger, security_logger
from config.settings import settings


def run_node():
    cfg = parse_node_config()

    if not cfg.secret_key:
        system_logger.error("No CAMERA_SECRET configured for node %s. Set it in .env or pass --secret", cfg.node_id)
        sys.exit(1)

    system_logger.info("Starting camera node %s -> server %s", cfg.node_id, cfg.server_url)

    detector = ObjectDetector(node_id=cfg.node_id)
    integrity_analyzer = FeedIntegrityAnalyzer(node_id=cfg.node_id)
    auth_client = CameraAuthClient(cfg.server_url, cfg.node_id, cfg.secret_key)

    try:
        encryptor = FrameEncryptor(key_b64=settings.aes_key, node_id=cfg.node_id)
    except EncryptionError as exc:
        system_logger.error("Cannot start node %s: %s", cfg.node_id, exc)
        sys.exit(1)

    frame_counter = 0

    try:
        with CameraCapture(
            node_id=cfg.node_id,
            camera_index=cfg.camera_index,
            width=cfg.width,
            height=cfg.height,
            fps=cfg.fps,
            video_file=cfg.video_file,
        ) as camera:

            while True:
                try:
                    captured = camera.read_frame()
                except CameraOfflineError:
                    system_logger.error("CAMERA_OFFLINE for node %s. Retrying in 3s...", cfg.node_id)
                    time.sleep(3)
                    continue

                frame_counter += 1

                # Frame skipping to stay lightweight on Raspberry Pi 4
                if frame_counter % max(cfg.frame_skip, 1) != 0:
                    continue

                pipeline_start = time.time()

                detections = detector.detect(captured.frame)
                integrity_score = integrity_analyzer.analyze(captured.frame)

                token = auth_client.get_valid_token()
                if token is None:
                    security_logger.warning("AUTHENTICATION_FAILED: skipping upload for node %s", cfg.node_id)
                    time.sleep(2)
                    continue

                payload_obj = {
                    "node_id": cfg.node_id,
                    "timestamp": captured.timestamp,
                    "token_id": token.token_id,
                    "issued_at": token.issued_at,
                    "detections": [d.__dict__ for d in detections],
                    "integrity": integrity_score.__dict__,
                }

                try:
                    encrypted = encryptor.encrypt(payload_obj)
                except EncryptionError as exc:
                    security_logger.error("Encryption failed, dropping frame for node %s: %s", cfg.node_id, exc)
                    continue

                try:
                    resp = requests.post(
                        f"{cfg.server_url}/camera/data",
                        json=encrypted.__dict__,
                        timeout=5,
                    )
                    if resp.status_code != 200:
                        system_logger.warning(
                            "Server rejected data from node %s: %s %s",
                            cfg.node_id, resp.status_code, resp.text[:200],
                        )
                except requests.RequestException as exc:
                    system_logger.error("Network error sending data for node %s: %s", cfg.node_id, exc)

                pipeline_time = time.time() - pipeline_start
                system_logger.debug("Pipeline latency for node %s: %.3fs", cfg.node_id, pipeline_time)

                # Respect configured FPS
                time.sleep(max(0.0, (1.0 / max(cfg.fps, 1)) - pipeline_time))

    except KeyboardInterrupt:
        system_logger.info("Camera node %s shutting down (keyboard interrupt)", cfg.node_id)
    except Exception as exc:
        system_logger.error("Unhandled error in camera node %s: %s", cfg.node_id, exc)
        raise


if __name__ == "__main__":
    run_node()
