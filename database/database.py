"""
database/database.py

SQLite persistence layer. Uses plain sqlite3 (no heavy ORM) for
transparency and easy inspection with standard SQLite tools during
demonstrations.

Tables: cameras, detections, network_events, integrity_events,
fusion_events, authentication_events.
"""

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from config.settings import settings
from config.logging_setup import system_logger

DB_PATH = settings.database_url.replace("sqlite:///", "")


def _ensure_dir():
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)


@contextmanager
def get_connection():
    _ensure_dir()
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS cameras (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT UNIQUE NOT NULL,
    name TEXT,
    status TEXT DEFAULT 'offline',
    ip_address TEXT,
    created_at REAL,
    last_seen REAL
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    object_name TEXT NOT NULL,
    confidence REAL NOT NULL,
    bbox TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detections_node_ts ON detections(node_id, timestamp);

CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE,
    node_id TEXT,
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_network_events_ts ON network_events(timestamp);

CREATE TABLE IF NOT EXISTS integrity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    motion_score REAL,
    duplicate_score REAL,
    staticness_score REAL,
    replay_score REAL
);
CREATE INDEX IF NOT EXISTS idx_integrity_node_ts ON integrity_events(node_id, timestamp);

CREATE TABLE IF NOT EXISTS fusion_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    classification TEXT NOT NULL,
    content_trust REAL,
    network_trust REAL,
    feed_trust REAL,
    overall_trust REAL,
    risk_score REAL,
    reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_fusion_node_ts ON fusion_events(node_id, timestamp);

CREATE TABLE IF NOT EXISTS authentication_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT,
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,
    success INTEGER NOT NULL,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_events_ts ON authentication_events(timestamp);
"""


def init_db():
    with get_connection() as conn:
        conn.executescript(SCHEMA)
    system_logger.info("Database initialized at %s", DB_PATH)


# ---------- Cameras ----------

def upsert_camera(node_id: str, name: str = None, status: str = "online", ip_address: str = None):
    now = time.time()
    with get_connection() as conn:
        existing = conn.execute("SELECT id FROM cameras WHERE node_id = ?", (node_id,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE cameras SET status=?, ip_address=COALESCE(?, ip_address), last_seen=? WHERE node_id=?",
                (status, ip_address, now, node_id),
            )
        else:
            conn.execute(
                "INSERT INTO cameras (node_id, name, status, ip_address, created_at, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (node_id, name or node_id, status, ip_address, now, now),
            )


def get_all_cameras() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM cameras ORDER BY node_id").fetchall()
        return [dict(r) for r in rows]


def get_camera(node_id: str) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM cameras WHERE node_id=?", (node_id,)).fetchone()
        return dict(row) if row else None


# ---------- Detections ----------

def insert_detection(node_id: str, timestamp: float, object_name: str, confidence: float, bbox: list):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO detections (node_id, timestamp, object_name, confidence, bbox) VALUES (?, ?, ?, ?, ?)",
            (node_id, timestamp, object_name, confidence, str(bbox)),
        )


def get_recent_detections(limit: int = 100, node_id: str = None) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        if node_id:
            rows = conn.execute(
                "SELECT * FROM detections WHERE node_id=? ORDER BY timestamp DESC LIMIT ?",
                (node_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM detections ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


# ---------- Network events ----------

def insert_network_event(event_id: str, node_id: Optional[str], timestamp: float,
                          event_type: str, severity: str, confidence: float, description: str):
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO network_events "
            "(event_id, node_id, timestamp, event_type, severity, confidence, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event_id, node_id, timestamp, event_type, severity, confidence, description),
        )


def get_recent_network_events(limit: int = 100) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM network_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- Integrity events ----------

def insert_integrity_event(node_id: str, timestamp: float, motion_score: float,
                            duplicate_score: float, staticness_score: float, replay_score: float):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO integrity_events "
            "(node_id, timestamp, motion_score, duplicate_score, staticness_score, replay_score) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (node_id, timestamp, motion_score, duplicate_score, staticness_score, replay_score),
        )


def get_recent_integrity_events(limit: int = 100, node_id: str = None) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        if node_id:
            rows = conn.execute(
                "SELECT * FROM integrity_events WHERE node_id=? ORDER BY timestamp DESC LIMIT ?",
                (node_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM integrity_events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


# ---------- Fusion events ----------

def insert_fusion_event(node_id: str, timestamp: float, classification: str,
                         content_trust: float, network_trust: float, feed_trust: float,
                         overall_trust: float, risk_score: float, reason: str):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO fusion_events "
            "(node_id, timestamp, classification, content_trust, network_trust, feed_trust, "
            "overall_trust, risk_score, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (node_id, timestamp, classification, content_trust, network_trust, feed_trust,
             overall_trust, risk_score, reason),
        )


def get_recent_fusion_events(limit: int = 100, node_id: str = None) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        if node_id:
            rows = conn.execute(
                "SELECT * FROM fusion_events WHERE node_id=? ORDER BY timestamp DESC LIMIT ?",
                (node_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM fusion_events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def get_latest_fusion_for_node(node_id: str) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM fusion_events WHERE node_id=? ORDER BY timestamp DESC LIMIT 1",
            (node_id,),
        ).fetchone()
        return dict(row) if row else None


# ---------- Authentication events ----------

def insert_auth_event(node_id: Optional[str], timestamp: float, event_type: str,
                       success: bool, description: str):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO authentication_events (node_id, timestamp, event_type, success, description) "
            "VALUES (?, ?, ?, ?, ?)",
            (node_id, timestamp, event_type, int(success), description),
        )


def get_recent_auth_events(limit: int = 100) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM authentication_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
