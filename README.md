# Secure Camera Network Analytics

**Encrypted Video Streaming, Real-Time Network Attack Detection, and Cross-Layer Feed-Integrity Verification**

## Overview

IP/CCTV camera networks are widely deployed for physical security, but conventional systems treat **video content analysis** and **network security** as independent concerns. Content-based systems (e.g., YOLO-based intrusion detection) implicitly trust that the video feed they analyze is authentic, while network-based Intrusion Detection Systems (IDS) flag traffic anomalies with no understanding of what the camera is actually seeing.

This creates a critical blind spot: an attacker who compromises the network layer can substitute a live feed with looped, replayed, or falsified footage during an active intrusion — and neither subsystem, working alone, can reliably detect this combined attack.

**Secure Camera Network Analytics** closes this gap with a **Cross-Layer Trust-Fusion Engine** that correlates content-layer signals (video feed variance) with network-layer anomaly flags (IDS alerts) to classify events into distinct, actionable categories — instead of raising generic, disconnected alerts.

## Key Features

- 🎥 **Edge AI Detection** — Real-time person/object/intrusion detection using YOLOv8-nano on a Raspberry Pi 4, plus frame-to-frame content variance scoring
- 🔒 **End-to-End Encrypted Streaming** — Video and metadata encrypted with ChaCha20 / AES-GCM
- 🔑 **Node Authentication** — Challenge-response HMAC authentication with time-bound, single-use tokens (prevents credential replay)
- 🛰️ **Network Intrusion Detection** — Lightweight Scapy-based IDS detecting ARP spoofing/MITM, rogue device joins, DoS flooding, and token replay
- 🔀 **Cross-Layer Trust-Fusion Engine** — Correlates content and network signals to classify events as:
  - Normal Alert
  - Feed-Spoofing / Replay Suspicion
  - Network-Only Anomaly
  - No Alert
- 🖥️ **Monitoring Dashboard** — Encrypted alert feed with snapshots, timestamps, and node identifiers (no continuous raw video transmission)
- 🧪 **Multi-Node Testbed** — One physical Raspberry Pi camera + simulated laptop nodes, evaluated under controlled ARP spoofing, DoS, and feed-replay attacks

## Problem Statement

CCTV networks today treat video analysis and network security as two separate systems. AI tools like YOLO analyze video content but have no way to check if the network carrying that video has been compromised. Network security tools (IDS) detect attacks like ARP spoofing but have no understanding of what's actually in the video feed. Because of this gap, an attacker who breaches the network can replace a live camera feed with old, looped footage while physically breaking in — and neither system, working alone, is designed to catch that combination.

## System Architecture

```
Camera Node (Pi 4)          Network IDS (Scapy)
YOLOv8-nano Detection   →    ARP Spoof / MITM /
        ↓                   DoS / Token-Replay Detection
Encryption Module                    ↓
ChaCha20 / AES-GCM      →   Network Layer (Ethernet/Wi-Fi)
        ↓                            ↓
Node Authentication      →  Central Server
HMAC Token Challenge-       Decryption + Token Verification
Response                             ↓
        ↑                            ↓
Simulated Nodes          Cross-Layer Trust-Fusion Engine
(Laptops, Encrypted       (Correlates content-layer variance
Webcam Streams)            with network-layer anomaly flags)
                                      ↓
                            Event Classification
                        Normal | Feed-Spoof Suspicion |
                       Network-Only Anomaly | No Alert
                                      ↓
                          Monitoring Dashboard
                        Encrypted Alerts, Snapshots,
                          Node Status, Timestamps
```

*(See `/docs/architecture-diagram.png` for the full diagram)*

## Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| Edge AI | YOLOv8-nano, Raspberry Pi 4 | Lightweight enough for real-time inference on constrained edge hardware |
| Encryption | ChaCha20 / AES-GCM | ChaCha20 performs well on low-power CPUs without AES hardware acceleration |
| Authentication | HMAC + time-bound single-use tokens | Prevents replay of captured credentials |
| Network IDS | Scapy (Python) | Lightweight, scriptable packet-level inspection |
| Fusion Engine | Custom rule/threshold-based logic | Low-latency real-time correlation of content + network signals |
| Dashboard | Web-based encrypted alert feed | Minimizes bandwidth and attack surface vs. continuous raw video |

## Workflow

1. **Capture & Edge Inference** — Camera node captures video, runs YOLOv8-nano locally, computes a frame-variance score against a learned baseline
2. **Encryption at Source** — Video/metadata encrypted before leaving the device
3. **Node Authentication** — Time-bound, single-use HMAC token exchanged via challenge-response before streaming is allowed
4. **Network Monitoring (parallel)** — Scapy IDS continuously inspects shared-segment traffic
5. **Central Decryption & Verification** — Server decrypts stream, verifies token, extracts content + network state
6. **Cross-Layer Fusion & Classification** — Trust-Fusion Engine correlates signals and classifies the event
7. **Dashboard Alerting** — Classified, encrypted alert pushed with snapshot, timestamp, node ID
8. **Baseline Adaptation & Evaluation** — Per-camera baselines updated over time; system periodically tested against simulated attacks

## Deployment Approach

- **1 physical node** — Raspberry Pi 4 + camera, representing a real edge-deployed camera
- **N simulated nodes** — Laptops streaming encrypted webcam video using the same protocol, simulating a multi-camera network
- **Isolated test network** — Used for controlled ARP spoofing, DoS, and feed-replay attack simulation without risking a production network

This setup allows network-level behaviors (ARP tables, concurrent streams, shared-segment traffic) to be evaluated realistically, which a single-device demo cannot demonstrate.

## Evaluation

The system is evaluated under three controlled attack scenarios on an isolated test network:

- **ARP Spoofing / MITM**
- **Denial-of-Service (DoS) Flooding**
- **Simulated Feed-Replay**

Metrics: detection accuracy, false positive rate, false negative rate — measured for the Trust-Fusion Engine's event classification against ground-truth attack labels.

## Standards Alignment

- **ISO/IEC 27001** — Confidentiality and integrity principles applied to encryption and data handling
- **IEC 62443 / NIST IoT Security Guidelines** — Inform node authentication and network monitoring design

## Project Status

🚧 Work in progress — this repository is under active development as part of an academic capstone project.

| Module | Status |
|---|---|
| YOLOv8-nano edge detection | ⬜ Not started / 🟨 In progress / ✅ Done |
| Encryption module (ChaCha20/AES-GCM) | ⬜ Not started / 🟨 In progress / ✅ Done |
| HMAC node authentication | ⬜ Not started / 🟨 In progress / ✅ Done |
| Scapy-based network IDS | ⬜ Not started / 🟨 In progress / ✅ Done |
| Cross-Layer Trust-Fusion Engine | ⬜ Not started / 🟨 In progress / ✅ Done |
| Monitoring dashboard | ⬜ Not started / 🟨 In progress / ✅ Done |
| Multi-node testbed | ⬜ Not started / 🟨 In progress / ✅ Done |
| Attack simulation & evaluation | ⬜ Not started / 🟨 In progress / ✅ Done |

*(Update the status markers above as modules are completed)*


## Getting Started

```bash
# Clone the repository
git clone https://github.com/<your-username>/secure-camera-network-analytics.git
cd secure-camera-network-analytics

# Install dependencies
pip install -r requirements.txt

# (Add setup instructions per module as they are implemented)
```

