"""
common/logging_utils.py

Small shared logging helper: a standard console/file logger for each
module, plus an append-only JSON-lines writer used for the alert log and
IDS event log (so both are easy to replay, grep, or feed into another
tool later).
"""

import json
import logging
import sys
import threading
import time
from pathlib import Path

from common import config


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured
    logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler(config.LOGS_DIR / "pc_node.log")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger


class JsonlWriter:
    """Thread-safe append-only JSON-lines writer."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, record: dict):
        record = dict(record)
        record.setdefault("ts", time.time())
        line = json.dumps(record, default=str)
        with self._lock:
            with open(self.path, "a") as f:
                f.write(line + "\n")


alert_writer = JsonlWriter(config.ALERT_LOG_FILE)
ids_writer = JsonlWriter(config.IDS_LOG_FILE)
