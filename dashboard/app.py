"""
dashboard/app.py

Streamlit dashboard for Secure Camera Network Analytics. Reads directly
from the SQLite database (read path is decoupled from the FastAPI server
for simplicity in this prototype) and presents:

  - System summary
  - Camera status table
  - AI detections
  - Network security events
  - Feed integrity scores
  - Trust fusion results
  - Alerts

Deliberately does NOT stream continuous raw video -- only metadata,
detections, and scores, per the project's security-conscious design goal.

Run with:
    streamlit run dashboard/app.py
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
import plotly.express as px
import streamlit as st

from database import database as db
from config.settings import settings

st.set_page_config(page_title="Secure Camera Network Analytics", layout="wide")

SEVERITY_COLORS = {
    "NORMAL": "#2ecc71",
    "WARNING": "#f1c40f",
    "HIGH": "#e67e22",
    "CRITICAL": "#e74c3c",
}

CLASSIFICATION_SEVERITY = {
    "NO_ALERT": "NORMAL",
    "NORMAL_AI_ALERT": "WARNING",
    "NETWORK_ONLY_ANOMALY": "HIGH",
    "FEED_SPOOFING_REPLAY_SUSPICION": "CRITICAL",
}


def safe_table(df: pd.DataFrame) -> pd.DataFrame:
    """Sanitize a DataFrame before handing it to st.dataframe.

    Streamlit's data-grid component (glide-data-grid) can throw a
    'Minified React error #185' (infinite update loop) when a column is
    entirely None/NaN or contains mixed types. Casting every column to a
    plain string and filling blanks avoids that class of crash.
    """
    safe_df = df.copy()
    for col in safe_df.columns:
        safe_df[col] = safe_df[col].apply(lambda v: "-" if v is None or (isinstance(v, float) and pd.isna(v)) else v)
        safe_df[col] = safe_df[col].astype(str)
    return safe_df


def load_data():
    cameras = db.get_all_cameras()
    for cam in cameras:
        latest = db.get_latest_fusion_for_node(cam["node_id"])
        cam["trust_score"] = latest["overall_trust"] if latest else None
        cam["classification"] = latest["classification"] if latest else "NO_ALERT"

    detections = db.get_recent_detections(limit=200)
    network_events = db.get_recent_network_events(limit=200)
    integrity_events = db.get_recent_integrity_events(limit=200)
    fusion_events = db.get_recent_fusion_events(limit=200)
    auth_events = db.get_recent_auth_events(limit=100)

    return cameras, detections, network_events, integrity_events, fusion_events, auth_events


st.title("🔒 SECURE CAMERA NETWORK ANALYTICS")
st.caption("Cross-layer trust fusion: AI content signals + network IDS + feed integrity")

if st.button("🔄 Refresh data"):
    st.rerun()

try:
    cameras, detections, network_events, integrity_events, fusion_events, auth_events = load_data()
except Exception as exc:
    st.error(f"Could not read database: {exc}. Has the server been started at least once "
              f"(so init_db() has run)?")
    st.stop()

# ---------------- System summary ----------------

total = len(cameras)
online = sum(1 for c in cameras if c["status"] == "online")
offline = total - online
suspicious = sum(1 for c in cameras if c.get("classification") == "FEED_SPOOFING_REPLAY_SUSPICION")
active_alerts = sum(1 for e in fusion_events if e["classification"] != "NO_ALERT")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Cameras", total)
col2.metric("Online", online)
col3.metric("Offline", offline)
col4.metric("Suspicious", suspicious)
col5.metric("Active Alerts", active_alerts)

st.divider()

# ---------------- Camera status ----------------

st.subheader("📷 Camera Status")
if cameras:
    cam_df = pd.DataFrame(cameras)
    cam_df["Risk Level"] = cam_df["classification"].map(CLASSIFICATION_SEVERITY).fillna("NORMAL")
    display_cols = ["node_id", "status", "ip_address", "last_seen", "trust_score", "Risk Level"]
    display_df = cam_df[display_cols].rename(columns={
        "node_id": "Node ID", "status": "Status", "ip_address": "IP",
        "last_seen": "Last Seen", "trust_score": "Trust Score",
    })
    st.dataframe(safe_table(display_df), use_container_width=True)
else:
    st.info("No cameras registered yet. Register a node via POST /camera/register.")

st.divider()

tab_ai, tab_net, tab_feed, tab_fusion, tab_alerts = st.tabs(
    ["🎯 AI Detection", "🌐 Network Security", "🎞️ Feed Integrity", "🧩 Trust Fusion", "🚨 Alerts"]
)

with tab_ai:
    st.subheader("Recent AI Detections")
    if detections:
        det_df = pd.DataFrame(detections)
        det_df["time"] = pd.to_datetime(det_df["timestamp"], unit="s")
        st.dataframe(
            safe_table(
                det_df[["time", "node_id", "object_name", "confidence", "bbox"]]
                .rename(columns={"node_id": "Camera", "object_name": "Object", "confidence": "Confidence"})
            ),
            use_container_width=True,
        )
        fig = px.histogram(det_df, x="object_name", color="node_id", title="Detections by Object Type")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No detections yet.")

with tab_net:
    st.subheader("Network Security Events")
    if network_events:
        net_df = pd.DataFrame(network_events)
        net_df["time"] = pd.to_datetime(net_df["timestamp"], unit="s")
        st.dataframe(
            safe_table(net_df[["time", "event_type", "severity", "confidence", "description"]]),
            use_container_width=True,
        )
        freq_fig = px.histogram(net_df, x="event_type", color="severity",
                                 title="Network Event Frequency")
        st.plotly_chart(freq_fig, use_container_width=True)
    else:
        st.info("No network events recorded yet.")

with tab_feed:
    st.subheader("Feed Integrity Scores")
    if integrity_events:
        int_df = pd.DataFrame(integrity_events)
        int_df["time"] = pd.to_datetime(int_df["timestamp"], unit="s")
        st.dataframe(
            safe_table(int_df[["time", "node_id", "motion_score", "duplicate_score",
                     "staticness_score", "replay_score"]]),
            use_container_width=True,
        )
        melt_df = int_df.melt(
            id_vars=["time", "node_id"],
            value_vars=["motion_score", "duplicate_score", "staticness_score", "replay_score"],
            var_name="metric", value_name="value",
        )
        fig = px.line(melt_df, x="time", y="value", color="metric",
                       title="Feed Integrity Score Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No integrity events recorded yet.")

with tab_fusion:
    st.subheader("Cross-Layer Trust Fusion")
    if fusion_events:
        fus_df = pd.DataFrame(fusion_events)
        fus_df["time"] = pd.to_datetime(fus_df["timestamp"], unit="s")
        st.dataframe(
            safe_table(fus_df[["time", "node_id", "classification", "content_trust",
                     "network_trust", "feed_trust", "overall_trust", "risk_score", "reason"]]),
            use_container_width=True,
        )
        trust_fig = px.line(fus_df.sort_values("time"), x="time", y="overall_trust",
                              color="node_id", title="Overall Trust Score Over Time")
        st.plotly_chart(trust_fig, use_container_width=True)
    else:
        st.info("No fusion events recorded yet.")

with tab_alerts:
    st.subheader("Alerts")
    alert_rows = [e for e in fusion_events if e["classification"] != "NO_ALERT"]
    if alert_rows:
        alert_df = pd.DataFrame(alert_rows)
        alert_df["time"] = pd.to_datetime(alert_df["timestamp"], unit="s")
        alert_df["Severity"] = alert_df["classification"].map(CLASSIFICATION_SEVERITY)

        for _, row in alert_df.sort_values("time", ascending=False).iterrows():
            color = SEVERITY_COLORS.get(row["Severity"], "#95a5a6")
            st.markdown(
                f"<div style='border-left:6px solid {color}; padding:8px 12px; margin-bottom:6px; "
                f"background:rgba(128,128,128,0.08)'>"
                f"<b>{row['classification']}</b> — {row['node_id']} — {row['time']}<br>"
                f"<i>{row['reason']}</i></div>",
                unsafe_allow_html=True,
            )

        alerts_over_time = px.histogram(alert_df, x="time", color="classification",
                                          title="Alerts Over Time")
        st.plotly_chart(alerts_over_time, use_container_width=True)
    else:
        st.success("No active alerts. All clear.")

st.divider()
st.caption(
    "This dashboard intentionally does not display continuous raw video streams. "
    "Only detection metadata, integrity scores, and security events are shown, "
    "per the project's security-conscious design (Section 21)."
)
