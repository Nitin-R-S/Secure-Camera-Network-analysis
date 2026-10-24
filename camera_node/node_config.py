"""
camera_node/node_config.py

Small helper describing a camera node's runtime identity, separate from the
global settings module so that multiple simulated nodes can each run with
their own node_id / secret / server URL on the same machine (e.g. for
demoing CAM_002 and CAM_003 as laptop webcams).
"""

import argparse
from dataclasses import dataclass

from config.settings import settings


@dataclass
class NodeConfig:
    node_id: str
    secret_key: str
    server_url: str
    camera_index: int
    width: int
    height: int
    fps: int
    frame_skip: int
    video_file: str = None


def parse_node_config() -> NodeConfig:
    """Allows overriding node identity from the command line, e.g.:

        python camera_node/client.py --node-id CAM_002 --secret <secret> \\
            --server http://192.168.1.10:8000 --camera-index 0

    This is what lets one laptop simulate CAM_002 while the Pi runs CAM_001.
    """
    parser = argparse.ArgumentParser(description="Secure camera node client")
    parser.add_argument("--node-id", default=settings.camera_node_id)
    parser.add_argument("--secret", default=settings.camera_secret)
    parser.add_argument("--server", default=f"http://{settings.server_host}:{settings.server_port}")
    parser.add_argument("--camera-index", type=int, default=settings.camera_index)
    parser.add_argument("--width", type=int, default=settings.camera_width)
    parser.add_argument("--height", type=int, default=settings.camera_height)
    parser.add_argument("--fps", type=int, default=settings.camera_fps)
    parser.add_argument("--frame-skip", type=int, default=settings.frame_skip)
    parser.add_argument(
        "--video-file", default=None,
        help="Path to a recorded video clip to loop as this node's feed, instead of a "
             "live camera. For demoing/validating the project's own feed-integrity and "
             "replay-detection logic (Section 8: Attack Simulation & Evaluation).",
    )
    args = parser.parse_args()

    if args.server.replace("http://", "").startswith("0.0.0.0"):
        # 0.0.0.0 is a bind address, not a reachable server address
        args.server = args.server.replace("0.0.0.0", "127.0.0.1")

    return NodeConfig(
        node_id=args.node_id,
        secret_key=args.secret,
        server_url=args.server,
        camera_index=args.camera_index,
        width=args.width,
        height=args.height,
        fps=args.fps,
        frame_skip=args.frame_skip,
        video_file=args.video_file,
    )
