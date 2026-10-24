"""
server/network_ids.py

Defensive, passive network monitoring for the isolated lab network the
camera system runs on. This module only OBSERVES traffic (via Scapy sniff)
and raises structured alerts; it never sends, injects, spoofs, or floods
any packets. It is meant to be run only on a network the user owns/operates
and is authorized to monitor.

Detections:
  - ARP_ANOMALY:     an IP suddenly maps to a different MAC than before
                      (classic sign of ARP spoofing / man-in-the-middle)
  - UNKNOWN_DEVICE:   a MAC address not in the registered-device list appears
  - POSSIBLE_FLOODING: packets/sec from a source exceeds a configurable threshold
  - AUTH_ANOMALY:     repeated authentication failures (fed in from
                       server/authentication.py rather than sniffed)

Run as a background thread from server/main.py.
"""

import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Optional, Set

from config.settings import settings
from config.logging_setup import network_logger

try:
    from scapy.all import sniff, ARP, IP
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - scapy may need root/npcap on some platforms
    SCAPY_AVAILABLE = False


NetworkEventCallback = Callable[[dict], None]


class NetworkIDS:
    def __init__(self, registered_macs: Optional[Set[str]] = None,
                 on_event: Optional[NetworkEventCallback] = None):
        self.registered_macs: Set[str] = registered_macs or set()
        self.on_event = on_event

        self._ip_to_mac: Dict[str, str] = {}
        self._packet_timestamps: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=2000))
        self._auth_failure_counts: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=100))

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ---------- lifecycle ----------

    def register_device(self, mac_address: str):
        self.registered_macs.add(mac_address.lower())

    def start(self):
        if not SCAPY_AVAILABLE:
            network_logger.error(
                "Scapy is not available/usable in this environment (may require root "
                "privileges or Npcap on Windows). Network IDS will not run."
            )
            return

        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self._thread.start()
        network_logger.info("Network IDS started")

    def stop(self):
        self._stop_event.set()
        network_logger.info("Network IDS stop requested")

    # ---------- core sniffing ----------

    def _run_sniffer(self):
        iface = settings.ids_interface or None
        try:
            sniff(
                iface=iface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda pkt: self._stop_event.is_set(),
            )
        except PermissionError:
            network_logger.error(
                "NETWORK_ANOMALY: insufficient privileges to sniff packets. "
                "Run the server with elevated/admin privileges to enable the IDS."
            )
        except Exception as exc:
            network_logger.error("Network IDS sniffing error: %s", exc)

    def _handle_packet(self, packet):
        now = time.time()

        # --- ARP anomaly + unknown device detection ---
        if packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 2:  # is-at (ARP reply)
                ip = arp.psrc
                mac = arp.hwsrc.lower()

                self._check_unknown_device(mac, now)

                prev_mac = self._ip_to_mac.get(ip)
                if prev_mac and prev_mac != mac:
                    self._emit_event(
                        event_type="ARP_ANOMALY",
                        severity="HIGH",
                        confidence=0.9,
                        description=f"IP {ip} changed MAC from {prev_mac} to {mac}",
                    )
                self._ip_to_mac[ip] = mac

        # --- packet rate / flooding detection ---
        src = None
        if packet.haslayer(IP):
            src = packet[IP].src
        elif packet.haslayer(ARP):
            src = packet[ARP].psrc

        if src:
            dq = self._packet_timestamps[src]
            dq.append(now)
            window_start = now - settings.ids_window_seconds
            while dq and dq[0] < window_start:
                dq.popleft()

            rate = len(dq) / max(settings.ids_window_seconds, 1)
            if rate > settings.packet_rate_threshold:
                self._emit_event(
                    event_type="POSSIBLE_FLOODING",
                    severity="HIGH",
                    confidence=0.8,
                    description=f"Source {src} sending {rate:.0f} pkts/sec "
                                f"(threshold {settings.packet_rate_threshold})",
                )

    def _check_unknown_device(self, mac: str, now: float):
        if self.registered_macs and mac not in self.registered_macs:
            self._emit_event(
                event_type="UNKNOWN_DEVICE",
                severity="MEDIUM",
                confidence=0.7,
                description=f"Unregistered device detected on network: {mac}",
            )

    # ---------- authentication anomaly (called externally) ----------

    def record_auth_failure(self, node_id: str):
        now = time.time()
        dq = self._auth_failure_counts[node_id]
        dq.append(now)
        recent = [t for t in dq if now - t < 60]
        if len(recent) >= 3:
            self._emit_event(
                event_type="AUTH_ANOMALY",
                severity="HIGH",
                confidence=0.85,
                description=f"{len(recent)} authentication failures for node {node_id} in last 60s",
                node_id=node_id,
            )

    # ---------- event emission ----------

    def _emit_event(self, event_type: str, severity: str, confidence: float,
                     description: str, node_id: Optional[str] = None):
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "node_id": node_id,
            "event_type": event_type,
            "severity": severity,
            "confidence": confidence,
            "description": description,
        }
        network_logger.warning("%s | severity=%s | %s", event_type, severity, description)
        if self.on_event:
            self.on_event(event)


class SyntheticNetworkEventGenerator:
    """Safe, synthetic network-event generator for controlled demonstrations
    (Section 28 / 38 scenarios) when live ARP spoofing hardware/tools are not
    available. This NEVER touches the real network -- it only fabricates
    NetworkIDS-shaped events for the fusion engine to consume, for demo
    scenarios 3 and 4."""

    def __init__(self, on_event: Optional[NetworkEventCallback] = None):
        self.on_event = on_event

    def generate(self, event_type: str = "ARP_ANOMALY", node_id: Optional[str] = None,
                 severity: str = "HIGH", confidence: float = 0.9,
                 description: str = "Synthetic demo event") -> dict:
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "node_id": node_id,
            "event_type": event_type,
            "severity": severity,
            "confidence": confidence,
            "description": f"[SYNTHETIC DEMO EVENT] {description}",
        }
        network_logger.info("Synthetic event generated: %s", event_type)
        if self.on_event:
            self.on_event(event)
        return event
