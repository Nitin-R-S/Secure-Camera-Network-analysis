# Cross-Layer Trust Verification and Anomaly Detection in Secure Edge Camera Networks

**Encrypted Video Streaming, Real-Time Network Attack Detection, and Cross-Layer Feed-Integrity Verification**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-FF4B4B.svg)](https://streamlit.io)
[![YOLOv8](https://img.shields.io/badge/YOLOv8-Nano-00FFFF.svg)](https://ultralytics.com)
[![Cryptography](https://img.shields.io/badge/Cryptography-AES--256--GCM-green.svg)](https://cryptography.io)
[![Scapy](https://img.shields.io/badge/Network_IDS-Scapy-red.svg)](https://scapy.net)
[![Tests: Pytest](https://img.shields.io/badge/Tests-20%20Passed-brightgreen.svg)](tests/)

A secure multi-node IP/CCTV camera network architecture that doesn't just ask *"what is in the camera feed?"* — it also asks **"can this camera feed be trusted?"**

---

## Table of Contents

- [Abstract & Motivation](#abstract--motivation)
- [The Blind Spot: Why Siloed Systems Fail](#the-blind-spot-why-siloed-systems-fail)
- [System Architecture](#system-architecture)
- [Key Features](#key-features)
- [Cross-Layer Trust Fusion Engine](#cross-layer-trust-fusion-engine)
- [Project Directory Structure](#project-directory-structure)
- [Hardware & Software Requirements](#hardware--software-requirements)
- [Installation Guide](#installation-guide)
- [Configuration (.env)](#configuration-env)
- [Running the System](#running-the-system)
  - [1. Initialize Database](#1-initialize-database)
  - [2. Start the Server & Network IDS](#2-start-the-server--network-ids)
  - [3. Register Camera Nodes](#3-register-camera-nodes)
  - [4. Launch Edge Camera Node](#4-launch-edge-camera-node)
  - [5. Launch Monitoring Dashboard](#5-launch-monitoring-dashboard)
- [Multi-Node Setup](#multi-node-setup)
- [Controlled Attack Scenarios & Evaluation](#controlled-attack-scenarios--evaluation)
- [REST API Reference](#rest-api-reference)
- [Standards Alignment](#standards-alignment)
- [Automated Testing](#automated-testing)
- [Troubleshooting](#troubleshooting)
- [Security Considerations & Limitations](#security-considerations--limitations)
- [References](#references)
- [License](#license)

---

## Abstract & Motivation

IP/CCTV camera networks are widely deployed across campuses, corporate facilities, warehouses, and smart-city infrastructure. Conventional deployments treat video content analytics (AI) and network intrusion detection (IDS) as independent, non-communicating silos. Content-based systems (e.g., YOLO) implicitly assume that incoming video frames reflect physical ground truth, while network-based IDSs flag packet anomalies without any context of what the camera observes.

This separation creates an exploitable blind spot: an adversary who achieves local network access (e.g., via ARP spoofing, rogue AP, or switch port access) can replace live camera feeds with replayed, looped, or falsified footage during an active physical intrusion. A vision-only model sees an unremarkable, calm room and raises no alert, while a network IDS raises a generic anomaly that SOC operators often dismiss due to alert fatigue.

**Cross-Layer Trust Verification and Anomaly Detection in Secure Edge Camera Networks** unifies:
1. **Edge-AI Object & Intrusion Detection** (YOLOv8-nano on Raspberry Pi 4 / Laptop)
2. **Feed-Integrity Verification** (Motion, pixel variance, duplicate frame correlation, staticness, and replay scoring)
3. **End-to-End AEAD Encryption** (AES-256-GCM with fresh 96-bit nonces and AAD binding node IDs)
4. **HMAC-SHA256 Challenge-Response Node Authentication** (Single-use nonces and time-bound session tokens)
5. **Passive Network Intrusion Detection System** (Scapy-driven ARP anomaly, unknown MAC, and packet rate monitoring)
6. **Cross-Layer Trust-Fusion Engine** (Correlates content, feed integrity, and network signals into distinct, actionable classifications)

---

## The Blind Spot: Why Siloed Systems Fail

```text
CONVENTIONAL SILOED APPROACH:
   Camera Stream ──> [ Vision AI (YOLO) ] ──> "Scene Calm (No Alert)"  ───┐
                                                                           ├─> Blind Spot (Intrusion Missed)
   Network Wire  ──> [ Network IDS ]      ──> "ARP Table Collision"    ───┘   (Ignored / Alert Fatigue)

PROPOSED CROSS-LAYER TRUST FUSION:
   Camera Stream ──> [ Edge AI (YOLOv8n) ]  ──────────┐
   Camera Stream ──> [ Feed Integrity (CV) ] ─────────┼─> [ Trust-Fusion Engine ] ──> "FEED_SPOOFING_REPLAY_SUSPICION"
   Network Wire  ──> [ Network IDS (Scapy) ] ─────────┘                                (CRITICAL ALERT TRIGGERED)
```

---

## System Architecture

```text
                           CAMERA EDGE NODE (Raspberry Pi 4 / Laptop)
                                               │
                                               ▼
                                      +-----------------+
                                      | Camera Capture  |
                                      +--------+--------+
                                               │
                                               ▼
                                      +-----------------+
                                      |    YOLOv8n      |
                                      | Edge Detection  |
                                      +--------+--------+
                                               │
                        +----------------------+----------------------+
                        │                                             │
                        ▼                                             ▼
                 Content Signals                               Feed Integrity
             (object class, confidence)                   (motion, duplicate, staticness,
                        │                                    variance, replay score)
                        │                                             │
                        +----------------------+----------------------+
                                               │
                                               ▼
                                    Node Authentication
                                 (HMAC challenge-response)
                                               │
                                               ▼
                                    AES-256-GCM Encrypt
                                (payload metadata & scores)
                                               │
                                               ▼
                                         Local Network
                                               │
                    +--------------------------+--------------------------+
                    │                                                     │
                    ▼                                                     ▼
         CENTRAL SERVER (FastAPI)                             NETWORK IDS (Scapy)
        - Decrypt & verify AEAD tag                           - ARP spoofing detection
        - Validate single-use session token                   - Unknown device detection
        - Content & feed score ingestion                      - Packet flooding detection
                    │                                                     │
                    +--------------------------+--------------------------+
                                               │
                                               ▼
                                   CROSS-LAYER TRUST FUSION
                                (Evaluates Content, Feed, Network)
                                               │
                                               ▼
                                      FINAL CLASSIFICATION
                             [NO_ALERT | NORMAL_AI_ALERT |
                              NETWORK_ONLY_ANOMALY |
                              FEED_SPOOFING_REPLAY_SUSPICION]
                                               │
                                               ▼
                                        SQLITE DATABASE
                                               │
                                               ▼
                                     STREAMLIT DASHBOARD
                                 (Metadata & Alerts only;
                                  No raw video streaming)
```

---

## Key Features

- **Edge-Resident AI Inference:** YOLOv8-nano runs locally on edge devices (Raspberry Pi 4 / Laptop), filtering for security-critical classes (`person`, `car`, `motorcycle`, `bus`, `truck`, `backpack`, `suitcase`).
- **Defensive Feed Integrity:** Real-time classical CV metrics detect frozen frames, looping clips, or static image obstruction using normalized cross-correlation, motion thresholds, and staticness history.
- **AEAD Encryption (AES-256-GCM):** Cryptographically binds the camera `node_id` as Additional Authenticated Data (AAD) to prevent payload-swapping attacks. Uses fresh 96-bit nonces per frame payload.
- **Challenge-Response HMAC Authentication:** Prevents rogue camera injection and credential sniffing. Uses expiring, single-use challenges and time-bound session tokens consumed on receipt.
- **Passive Network IDS:** Observes network traffic using Scapy to detect ARP table poisoning, unregistered MAC addresses, and packet-rate flooding without transmitting intrusive packets.
- **Cross-Layer Trust-Fusion Decision:** Blends content, feed, and network signals to produce explainable trust scores ($0 - 100$) and four distinct operational classifications.
- **Zero Raw Video Exposure:** The dashboard strictly streams encrypted detection metadata and security metrics, minimizing bandwidth and eliminating live video eavesdropping risks.
- **Multi-Node Testbed:** Supports one physical Raspberry Pi camera alongside multiple simulated laptop webcam nodes.
- **Synthetic Attack Generator:** Integrated safe simulator for triggering reproducible ARP and flooding events for academic demonstrations without requiring live exploit tooling.

---

## Cross-Layer Trust Fusion Engine

The Trust-Fusion Engine computes three independent trust metrics and blends them into an overall score:

$$\text{Overall Trust} = 0.4 \times T_{\text{content}} + 0.3 \times T_{\text{network}} + 0.3 \times T_{\text{feed}}$$

### Decision Matrix

| Scenario | Content Signal | Feed Integrity | Network IDS Status | Final Classification | Risk Level | Operational Meaning |
|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **1** | Normal / Clear | Normal ($>75$) | Normal (No anomalies) | `NO_ALERT` | Normal | Steady-state scene; no anomalies detected. |
| **2** | Intrusion Detected | Normal ($>75$) | Normal (No anomalies) | `NORMAL_AI_ALERT` | Warning | Genuine physical intrusion under a secure network. |
| **3** | Normal / Clear | Normal ($>75$) | Anomaly Flagged (ARP / Flood) | `NETWORK_ONLY_ANOMALY` | High | Network layer under attack / degraded; video feed is genuine. |
| **4** | Normal / Static | **Suspicious** ($<25$) | **Anomaly Flagged** (ARP / Replay) | `FEED_SPOOFING_REPLAY_SUSPICION` | **Critical** | **Compound Attack:** Video feed frozen/replayed during network compromise! |

---

## Project Directory Structure

```text
secure_camera_network/
├── camera_node/                  # Edge Camera Pipeline
│   ├── __init__.py
│   ├── authentication.py         # Client-side HMAC challenge-response & token manager
│   ├── camera.py                 # OpenCV webcam & video file capture wrapper
│   ├── client.py                 # Main edge camera loop: Capture -> Detect -> Integrity -> Encrypt -> Send
│   ├── detector.py               # YOLOv8-nano inference and bounding box filtering
│   ├── encryption.py             # AES-256-GCM encryption with fresh nonces & AAD
│   ├── integrity.py              # Classical CV feed-integrity and anti-replay analyzer
│   └── node_config.py            # CLI argument and environment parser for camera node
├── config/                       # Configuration & Logging
│   ├── __init__.py
│   ├── logging_setup.py          # Structured multi-file logging (system, security, network)
│   └── settings.py               # Central environment configuration via Pydantic/dataclasses
├── dashboard/                    # Real-Time Monitoring Interface
│   ├── __init__.py
│   └── app.py                    # Streamlit + Plotly visual dashboard (reads SQLite)
├── data/                         # SQLite database storage (.gitkeep)
├── database/                     # Persistence Layer
│   ├── __init__.py
│   └── database.py               # SQLite schema, indexing, and thread-safe CRUD helpers
├── logs/                         # Runtime log directory (.gitkeep)
├── models/                       # YOLO model weights (.pt files) (.gitkeep)
├── server/                       # Central Backend & IDS
│   ├── __init__.py
│   ├── api_routes.py             # Pydantic schemas for request/response models
│   ├── authentication.py         # AuthenticationManager: node registry & token validator
│   ├── encryption.py             # Server-side AES-GCM decryption and tag verification
│   ├── fusion_engine.py          # Cross-Layer Trust-Fusion Engine
│   ├── integrity.py              # Server-side feed signal normalization
│   ├── main.py                   # FastAPI application & REST endpoints
│   └── network_ids.py            # Passive Scapy IDS & Synthetic Event Generator
├── tests/                        # Comprehensive Unit Test Suite
│   ├── __init__.py
│   ├── test_authentication.py    # HMAC, challenge expiry, and token replay tests
│   ├── test_encryption.py        # AEAD round-trip, tampered ciphertext, and wrong-key tests
│   ├── test_fusion.py            # All 4 classification scenarios & score bounds
│   └── test_integrity.py         # Static video, high motion, and frame-replay tests
├── .env.example                  # Environment variable template
├── .gitignore                    # Git ignore file
├── conftest.py                   # Pytest test configuration & safe environment defaults
├── requirements.txt              # Production and development dependencies
├── run.py                        # Database initialisation script
└── README.md                     # Comprehensive project documentation
```

---

## Hardware & Software Requirements

### Hardware Requirements
- **Minimum (Single Machine Demo):**
  - 1 laptop/PC (macOS, Linux, or Windows) with built-in webcam.
- **Full Multi-Node Setup:**
  - 1× Raspberry Pi 4 (2GB+ RAM recommended) with Raspberry Pi Camera Module v2/v3 or USB webcam.
  - 1× Central Server machine (Laptop / Desktop / Cloud VM).
  - Additional laptops/PCs simulating extra camera nodes (`CAM_002`, `CAM_003`).
  - 1× Wi-Fi router or switch forming an isolated local test network.

### Software Requirements
- **Python:** 3.10, 3.11, or 3.12
- **Packet Capture Library:**
  - **Linux / macOS:** Built-in raw socket capabilities (run server with root privileges for packet capture).
  - **Windows:** [Npcap](https://npcap.com/) (install with *WinPcap API-compatible mode* enabled).

---

## Installation Guide

### 1. Clone the Repository
```bash
git clone https://github.com/Nitin-R-S/Secure-Camera-Network-analysis.git
cd Secure-Camera-Network-analysis
```

### 2. Set Up Python Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate       # On Windows: venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Download YOLOv8-nano Weights
Ultralytics downloads the weights automatically on first run, or you can pre-fetch them:
```bash
python -c "from ultralytics import YOLO; YOLO('yolov8n.pt')"
mv yolov8n.pt models/
```

---

## Configuration (.env)

Copy the sample environment file:
```bash
cp .env.example .env
```

Generate secure cryptographic keys and fill in `.env`:
```bash
# Generate 32-byte AES-256 base64 key:
python -c "from camera_node.encryption import generate_key; print(generate_key())"

# Generate 32-byte Admin API key:
python -c "import secrets; print(secrets.token_hex(32))"

# Generate 24-byte Node Shared Secret:
python -c "import secrets; print(secrets.token_hex(24))"
```

Configure your `.env`:
```ini
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
DATABASE_URL=sqlite:///./data/secure_camera_network.db

# Cryptography
AES_KEY=<YOUR_GENERATED_BASE64_AES_KEY>
ADMIN_API_KEY=<YOUR_ADMIN_API_KEY>

# Camera Node
CAMERA_NODE_ID=CAM_001
CAMERA_SECRET=<YOUR_CAMERA_SHARED_SECRET>
CAMERA_INDEX=0
FRAME_SKIP=2

# Network IDS
PACKET_RATE_THRESHOLD=300
IDS_WINDOW_SECONDS=1
```

---

## Running the System

### 1. Initialize Database
```bash
python run.py
```
*Creates the SQLite schema with indexed tables in `data/secure_camera_network.db`.*

### 2. Start the Server & Network IDS
```bash
# On Linux/macOS (sudo enables raw packet sniffing for Scapy):
sudo venv/bin/python server/main.py

# Or via uvicorn directly:
uvicorn server.main:app --host 0.0.0.0 --port 8000
```
Interactive OpenAPI documentation will be accessible at: `http://localhost:8000/docs`

### 3. Register Camera Nodes
Register legitimate camera nodes via the admin API:
```bash
curl -X POST http://localhost:8000/camera/register \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "CAM_001",
    "name": "Entrance Lobby",
    "secret_key": "<YOUR_CAMERA_SHARED_SECRET>",
    "admin_api_key": "<YOUR_ADMIN_API_KEY>"
  }'
```

### 4. Launch Edge Camera Node
Start the camera capture, edge detection, and encrypted transmission loop:
```bash
python camera_node/client.py --node-id CAM_001 --secret <YOUR_CAMERA_SHARED_SECRET> --server http://localhost:8000
```

### 5. Launch Monitoring Dashboard
In a separate terminal, launch the Streamlit interface:
```bash
streamlit run dashboard/app.py
```
Open your browser at `http://localhost:8501`.

---

## Multi-Node Setup

To operate a multi-camera network:
1. Run the central server on your primary workstation.
2. Register additional camera identities:
   ```bash
   curl -X POST http://<SERVER_IP>:8000/camera/register \
     -H "Content-Type: application/json" \
     -d '{"node_id":"CAM_002","secret_key":"<SECRET_CAM_2>","admin_api_key":"<ADMIN_API_KEY>"}'
   ```
3. On additional laptops or Raspberry Pis on the same Wi-Fi/Ethernet network:
   ```bash
   python camera_node/client.py --node-id CAM_002 --secret <SECRET_CAM_2> --server http://<SERVER_IP>:8000
   ```
4. Each node maintains independent authentication tokens, feed-integrity baselines, and trust scores.

---

## Controlled Attack Scenarios & Evaluation

The system supports validating the four operational states through controlled tests:

### Scenario 1: Normal Operation (`NO_ALERT`)
- Camera observes normal room conditions.
- No network attacks active.
- Fusion Engine outputs `NO_ALERT` (Overall trust $\approx 85-95\%$).

### Scenario 2: Physical Intrusion (`NORMAL_AI_ALERT`)
- Person enters the camera field of view.
- Edge YOLOv8n detects `person` with high confidence.
- No network anomalies present.
- Fusion Engine outputs `NORMAL_AI_ALERT`.

### Scenario 3: Network-Only Attack (`NETWORK_ONLY_ANOMALY`)
- Network is subjected to an ARP spoof or high-rate flooding without tampering with the camera feed.
- Trigger via synthetic event generator:
  ```bash
  curl -X POST http://localhost:8000/demo/synthetic-network-event \
    -H "Content-Type: application/json" \
    -d '{
      "event_type": "ARP_ANOMALY",
      "severity": "HIGH",
      "node_id": "CAM_001",
      "description": "Simulated ARP spoofing gateway takeover"
    }'
  ```
- Fusion Engine outputs `NETWORK_ONLY_ANOMALY`.

### Scenario 4: Compound Attack / Feed Spoofing (`FEED_SPOOFING_REPLAY_SUSPICION`)
- An attacker freezes the camera lens (or loops a static image) while launching an ARP spoof.
- Hold a static photograph or cover the camera lens to drop motion to 0 and push staticness/duplicate scores to $>0.95$.
- Simultaneously trigger the network anomaly endpoint above.
- Fusion Engine detects the simultaneous feed freeze and network anomaly, raising a **CRITICAL** alert: `FEED_SPOOFING_REPLAY_SUSPICION`.

---

## REST API Reference

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/health` | Server heartbeat & status | No |
| `POST` | `/camera/register` | Register new camera node identity | Admin API Key |
| `POST` | `/auth/challenge` | Issue random challenge nonce for node | Valid Node ID |
| `POST` | `/auth/verify` | Verify HMAC response and issue session token | Valid HMAC digest |
| `POST` | `/camera/data` | Ingest encrypted payload, evaluate fusion | Valid Session Token |
| `GET` | `/cameras` | List all cameras and current trust scores | No |
| `GET` | `/cameras/{node_id}` | Fetch detailed history for a camera node | No |
| `GET` | `/alerts` | Get recent security alerts (excluding `NO_ALERT`) | No |
| `GET` | `/network/events` | Get recent passive Network IDS events | No |
| `GET` | `/fusion/{node_id}` | Get recent trust fusion records for a node | No |
| `POST` | `/demo/synthetic-network-event` | Inject synthetic network event for safe demo | No |

---

## Standards Alignment

- **ISO/IEC 27001 (Information Security Management):**
  - **Clause A.10 (Cryptographic Controls):** Mandates strong data encryption at rest and in transit. Implemented via AES-256-GCM AEAD encryption with fresh 96-bit nonces.
  - **Clause A.12 (Operations Security):** Requires audit logging and anomaly tracking. Implemented via isolated log streams (`security.log`, `network.log`, `system.log`) and SQLite event history.
- **IEC 62443 / NIST IoT Security Guidelines (Device Identity & Monitoring):**
  - **Device Authentication:** Prohibits static credentials. Implemented via challenge-response HMAC-SHA256 and single-use, expiring session tokens.
  - **Network Anomaly Detection:** Mandates passive network observation on industrial/IoT subnets to prevent MITM and unauthorized node insertion.

---

## Automated Testing

The project includes an automated test suite covering all four subsystems:

```bash
pytest tests/ -v
```

### Test Coverage Summary:
- [`tests/test_authentication.py`](file:///tests/test_authentication.py): Challenge generation, HMAC validation, invalid secret rejection, unknown node rejection, expired challenges, and single-use challenge consumption.
- [`tests/test_encryption.py`](file:///tests/test_encryption.py): AES-256-GCM encryption/decryption round-trip, tampered ciphertext tag verification failure, invalid nonce rejection, missing key handling, and wrong-key rejection.
- [`tests/test_integrity.py`](file:///tests/test_integrity.py): Initial frame baseline, motion scoring under high motion, static video detection, and repeated/frozen frame replay flags.
- [`tests/test_fusion.py`](file:///tests/test_fusion.py): Verification of all 4 Trust-Fusion decision states (`NO_ALERT`, `NORMAL_AI_ALERT`, `NETWORK_ONLY_ANOMALY`, `FEED_SPOOFING_REPLAY_SUSPICION`) and mathematical score bounds ($0 \le \text{trust} \le 100$).

---

## Troubleshooting

| Symptom | Cause | Solution |
|---|---|---|
| `CAMERA_OFFLINE` on startup | Camera index incorrect or device in use | Change `--camera-index 0` to `1` or `2`; close other webcam apps. |
| Network IDS: "insufficient privileges" | Scapy requires raw-socket access | Run server with `sudo` (Linux/macOS) or Administrator (Windows). |
| `DECRYPTION_FAILED` on server | Mismatched `AES_KEY` between client and server | Ensure identical 32-byte base64 `AES_KEY` in `.env`. |
| `AUTHENTICATION_FAILED` | Secret key mismatch or node unregistered | Re-register camera via `/camera/register` with correct secret. |
| Dashboard shows no data | Database path mismatch or server uninitialized | Run `python run.py`; confirm `DATABASE_URL` matches in `.env`. |
| Low FPS on Raspberry Pi 4 | CPU bottleneck with full inference | Set `FRAME_SKIP=2` or `3` and decrease resolution to $640 \times 480$. |

---

## Security Considerations & Limitations

- **Academic Prototype:** Designed for lab and research environments on private subnets. Not hardened for exposure to the public internet.
- **Key Management:** In this prototype, node secrets are maintained in memory across server restarts. In production deployments, integrate with a Hardware Security Module (HSM) or secrets manager (e.g., HashiCorp Vault).
- **Adversarial Video:** Classical CV feed-integrity metrics detect naive replay and frozen frames; they are not intended to detect generative AI deepfakes.

---

## References

1. D. Reis, J. Hong, J. Kupec, and A. Daoudi, *"Real-Time Flying Object Detection with YOLOv8,"* arXiv:2305.09972, 2023.
2. M. Talib, A. H. Y. Al-Noori, and J. Suad, *"YOLOv8-CAB: Improved YOLOv8 for Real-Time Object Detection,"* Karbala International Journal of Modern Science, vol. 10, no. 1, art. 5, 2024.
3. A. Thakur, A. Shrivastav, R. Sharma, T. Kumar, and K. Puri, *"Real-Time Weapon Detection Using YOLOv8 for Enhanced Safety,"* arXiv:2410.19862, 2024.
4. M. Łysakowski et al., *"Real-Time Onboard Object Detection for Augmented Reality: Enhancing Head-Mounted Display with YOLOv8,"* arXiv:2306.03537, 2023.
5. A. Ali et al., *"Intelligent ARP Spoofing Detection Using Multi-Layered Machine Learning Techniques for IoT Networks,"* arXiv:2507.21087, 2025.
6. S. M. Morsy and D. Nashat, *"D-ARP: An Efficient Scheme to Detect and Prevent ARP Spoofing,"* IEEE Access, vol. 10, pp. 49142–49153, 2022.
7. M. M. Alani, A. I. Awad, and E. Barka, *"ARP-PROBE: An ARP Spoofing Detector for Internet of Things Networks Using Explainable Deep Learning,"* Internet of Things, vol. 23, art. 100861, 2023.
8. N. Saritakumar, K. V. Anusuya, and S. Krishnakumar, *"Detection of ARP Spoofing Attacks in Software Defined Networks,"* in Proc. ICISCoIS, IEEE, 2023, pp. 422–426.
9. Q. Hu, *"The New Method to Prevent ARP Spoofing Based on 802.1X Protocol,"* in Proc. JIMET, Atlantis Press, 2015, pp. 556–560.
10. A. Prasad and S. Chandra, *"Defending ARP Spoofing-Based MITM Attack Using Machine Learning and Device Profiling,"* in Proc. ICCCIS, IEEE, 2022, pp. 978–982.
11. A. T. Maolood, E. K. Gbashi, and E. S. Mahmood, *"Novel Lightweight Video Encryption Method Based on ChaCha20 Stream Cipher and Hybrid Chaotic Map,"* IJEE, vol. 12, no. 5, pp. 4988–5000, 2022.
12. X. Zhang, S. H. Seo, and C. Wang, *"A Lightweight Encryption Method for Privacy Protection in Surveillance Videos,"* IEEE Access, vol. 6, pp. 18074–18087, 2018.
13. N. Mekki, M. Hamdi, T. Aguili, and T. H. Kim, *"A Real-Time Chaotic Encryption for Multimedia Data and Application to Secure Surveillance Framework for IoT System,"* in Proc. CommNet, IEEE, 2018, pp. 1–10.
14. Y. Nir and A. Langley, *"ChaCha20 and Poly1305 for IETF Protocols,"* IETF RFC 7539, 2015.
15. U. Chatterjee et al., *"Building PUF Based Authentication and Key Exchange Protocol for IoT Without Explicit CRPs in Verifier Database,"* IEEE TDSC, vol. 16, no. 3, pp. 424–437, 2019.
16. A. Garba et al., *"LightCert4IoTs: Blockchain-Based Lightweight Certificates Authentication for IoT Applications,"* IEEE Access, vol. 11, pp. 28370–28383, 2023.
17. C. Patel, *"Secure Lightweight Authentication for Multi User IoT Environment,"* arXiv:2207.10353, 2022.
18. H. Satilmiş, S. Akleylek, and Z. Y. Tok, *"A Systematic Literature Review on Host-Based Intrusion Detection Systems,"* IEEE Access, vol. 12, pp. 27237–27266, 2024.
19. F. Meneghello, M. Calore, D. Zucchetto, M. Polese, and A. Zanella, *"IoT: Internet of Threats? A Survey of Practical Security Vulnerabilities in Real IoT Devices,"* IEEE IoT Journal, vol. 6, no. 5, pp. 8182–8201, 2019.
20. I. A. Khan et al., *"Enhancing IIoT Networks Protection: A Robust Security Model for Attack Detection in Internet Industrial Control Systems,"* Ad Hoc Networks, vol. 134, art. 102930, 2022.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
