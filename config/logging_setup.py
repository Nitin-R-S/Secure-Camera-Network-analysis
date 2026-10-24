"""
config/logging_setup.py

Configures three separate rotating loggers:
  - logs/system.log    general application events
  - logs/security.log  authentication, encryption, integrity events
  - logs/network.log   network IDS events

Never logs secret keys, passwords, or raw credentials.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

from config.settings import settings

os.makedirs(settings.log_dir, exist_ok=True)

_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def _build_logger(name: str, filename: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(settings.log_level)
    logger.propagate = False

    if logger.handlers:
        return logger  # already configured

    file_path = os.path.join(settings.log_dir, filename)
    handler = RotatingFileHandler(file_path, maxBytes=5_000_000, backupCount=3)
    handler.setFormatter(logging.Formatter(_FORMAT))
    logger.addHandler(handler)

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(_FORMAT))
    logger.addHandler(console)

    return logger


system_logger = _build_logger("system", "system.log")
security_logger = _build_logger("security", "security.log")
network_logger = _build_logger("network", "network.log")


def redact(value: str, keep: int = 2) -> str:
    """Utility to redact secrets before any accidental logging."""
    if not value:
        return "<empty>"
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep)
