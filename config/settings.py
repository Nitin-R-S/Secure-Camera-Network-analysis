"""
config/settings.py

Central configuration module. Loads all tunable parameters from environment
variables (via a .env file) so that no secrets or magic numbers are
hardcoded anywhere else in the codebase.
"""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


def _get_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _get_float(name: str, default: float) -> float:
    val = os.getenv(name)
    try:
        return float(val) if val is not None else default
    except ValueError:
        return default


def _get_int(name: str, default: int) -> int:
    val = os.getenv(name)
    try:
        return int(val) if val is not None else default
    except ValueError:
        return default


@dataclass
class Settings:
    # --- Server ---
    server_host: str = os.getenv("SERVER_HOST", "0.0.0.0")
    server_port: int = _get_int("SERVER_PORT", 8000)
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/secure_camera_network.db")

    # --- Camera node identity (used when running camera_node/client.py) ---
    camera_node_id: str = os.getenv("CAMERA_NODE_ID", "CAM_001")
    camera_secret: str = os.getenv("CAMERA_SECRET", "")  # must be set in .env, never hardcoded
    camera_index: int = _get_int("CAMERA_INDEX", 0)
    camera_width: int = _get_int("CAMERA_WIDTH", 640)
    camera_height: int = _get_int("CAMERA_HEIGHT", 480)
    camera_fps: int = _get_int("CAMERA_FPS", 10)
    frame_skip: int = _get_int("FRAME_SKIP", 2)  # process every Nth frame (Pi 4 friendly)

    # --- Encryption ---
    aes_key: str = os.getenv("AES_KEY", "")  # base64, 32 bytes when decoded, per-node override possible

    # --- AI / YOLO ---
    yolo_model_path: str = os.getenv("YOLO_MODEL_PATH", "models/yolov8n.pt")
    yolo_confidence: float = _get_float("YOLO_CONFIDENCE", 0.5)
    detectable_classes: tuple = (
        "person", "car", "motorcycle", "bus", "truck", "backpack", "suitcase"
    )

    # --- Feed integrity thresholds ---
    staticness_threshold: float = _get_float("STATICNESS_THRESHOLD", 0.85)
    duplicate_threshold: float = _get_float("DUPLICATE_THRESHOLD", 0.97)
    replay_threshold: float = _get_float("REPLAY_THRESHOLD", 0.75)

    # --- Auth / replay protection ---
    challenge_ttl_seconds: int = _get_int("CHALLENGE_TTL_SECONDS", 30)
    token_ttl_seconds: int = _get_int("TOKEN_TTL_SECONDS", 60)

    # --- Network IDS ---
    packet_rate_threshold: int = _get_int("PACKET_RATE_THRESHOLD", 300)  # packets/sec
    ids_interface: str = os.getenv("IDS_INTERFACE", "")  # empty = scapy default
    ids_window_seconds: int = _get_int("IDS_WINDOW_SECONDS", 1)

    # --- Trust fusion weights (must sum to 1.0 conceptually, not enforced) ---
    content_weight: float = _get_float("CONTENT_WEIGHT", 0.4)
    network_weight: float = _get_float("NETWORK_WEIGHT", 0.3)
    feed_weight: float = _get_float("FEED_WEIGHT", 0.3)

    # --- Server-side API auth (shared secret used for camera registration) ---
    admin_api_key: str = os.getenv("ADMIN_API_KEY", "")

    # --- Logging ---
    log_dir: str = os.getenv("LOG_DIR", "logs")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
