# 🛡️ Sentinel Predictive IDS — Intelligent Intrusion Detection System & SOAR Platform

![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.138%2B-green.svg)
![Machine Learning](https://img.shields.io/badge/ML-LSTM%20%7C%20RF%20%7C%20XGBoost%20%7C%20LR-orange.svg)
![AI Agents](https://img.shields.io/badge/Multi--AI%20Agents-5%20Autonomous%20Agents-purple.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)

> **Sentinel Predictive IDS** is a next-generation, AI-driven Intrusion Detection System (IDS) and Security Orchestration, Automation, and Response (SOAR) platform. It combines real-time network packet capture, multi-model Deep Learning anomaly engines, an autonomous **Multi-AI Agent System**, Large Language Model (LLM) intelligence, static vulnerability code auditing, and automated countermeasure enforcement.

---

## 📑 Table of Contents
1. [🏛️ Overall System Architecture](#️-overall-system-architecture)
2. [🤖 Autonomous Multi-AI Agent System (In-Depth)](#-autonomous-multi-ai-agent-system-in-depth)
   - [1. NetworkAnalyzerAgent](#1-networkanalyzeragent)
   - [2. AttackObservationAgent](#2-attackobservationagent)
   - [3. AutoBlockAgent](#3-autoblockagent)
   - [4. SiteSecurityAuditAgent](#4-sitesecurityauditagent)
   - [5. EmailReportAgent](#5-emailreportagent)
   - [Multi-Agent Consensus & Model Verification Loop](#multi-agent-consensus--model-verification-loop)
3. [🧠 Deep Learning & Machine Learning Engine](#-deep-learning--machine-learning-engine)
4. [💻 Complete Platform Feature Breakdown (20 Modules)](#-complete-platform-feature-breakdown-20-modules)
5. [🔍 Vulnerability Scanner & Remediation Core](#-vulnerability-scanner--remediation-core)
6. [🛠️ Technology Stack](#️-technology-stack)
7. [📥 Installation & Setup Guide](#-installation--setup-guide)
8. [🔌 API Endpoints Reference](#-api-endpoints-reference)

---

## 🏛️ Overall System Architecture

```
                                  ┌─────────────────────────────────────────┐
                                  │      Network Packets / Telemetry        │
                                  └────────────────────┬────────────────────┘
                                                       │
                                                       ▼
                                  ┌─────────────────────────────────────────┐
                                  │ Scapy Packet Sniffer & Feature Stream   │
                                  └────────────────────┬────────────────────┘
                                                       │
                                                       ▼
                                  ┌─────────────────────────────────────────┐
                                  │ Multi-Model ML Engine                   │
                                  │ (LSTM / RF / XGBoost / Logistic Reg)    │
                                  └──────────┬───────────────────┬──────────┘
                                             │                   │
                                Verdict: Anomaly               Verdict: Normal
                                             │                   │
                                             ▼                   ▼
┌───────────────────────────────────────────────────┐     ┌──────────────────────┐
│       🤖 AUTONOMOUS MULTI-AI AGENT SYSTEM         │     │ Live WebSocket Stream│
│ 1. NetworkAnalyzerAgent  (Divergence Audit)       │     │ Real-time Dashboard  │
│ 2. AttackObservationAgent(Threat Profiling)       │     └──────────────────────┘
│ 3. AutoBlockAgent        (Zero-Latency Mitigation)│
│ 4. SiteSecurityAuditAgent(Codebase & Web Scan)    │
│ 5. EmailReportAgent      (Executive Reporting)    │
└────────────────────────┬──────────────────────────┘
                         │
                         ▼
┌───────────────────────────────────────────────────┐
│       ⚡ SOAR AUTOMATION & ENFORCEMENT             │
│ - Instant IP Firewall Blocking (Database & Cache) │
│ - Webhook HTTP Notifications (POST / GET)         │
│ - MITRE ATT&CK & CVE Threat Enrichment            │
│ - Automated PDF & Unified .patch Remediation      │
└───────────────────────────────────────────────────┘
```

---

## 🤖 Autonomous Multi-AI Agent System (In-Depth)

The core strength of Sentinel IDS is its **Multi-AI Agent Architecture** located in [`backend/ai/agents.py`](file:///e:/Ahmed/My%20programes/Projects/UGRF/backend/ai/agents.py). Instead of relying on a single static rule engine or isolated model predictions, Sentinel deploys **5 specialized autonomous AI agents** that collaborate in real time to evaluate threats, audit model outputs, execute zero-latency countermeasures, perform codebase security scans, and generate executive intelligence reports.

---

### 1. `NetworkAnalyzerAgent`
- **Role**: Primary telemetry auditor & model verification engine.
- **Responsibility**:
  - Monitors incoming network flows (connection counts, packet rates, SYN/ACK ratios, inbound byte volumes).
  - Compares live traffic metrics with predictions from the active ML model (LSTM, Random Forest, XGBoost, or Logistic Regression).
  - Calculates a **Consensus Matrix**:
    - `MATCH - Agreement`: Both the ML model and the AI agent agree on traffic classification (Normal vs Anomaly).
    - `DIVERGENCE - Verification Required`: The ML model flags an anomaly but agent heuristics indicate normal traffic, or vice versa.
  - **Auto-Retraining Trigger**: If model divergence is detected during high risk (>50%), the agent logs an `AutoTrainEvent` in the database to trigger model retraining.

---

### 2. `AttackObservationAgent`
- **Role**: Specialized threat intelligence classifier & incident profiler.
- **Responsibility**:
  - Triggered whenever an anomaly or malicious flow is identified.
  - Analyzes multi-vector threat indicators and classifies attacks into specific technical categories:
    - **SYN Flood Attack** (High SYN/ACK ratio).
    - **UDP Volumetric Amplification Flood**.
    - **ICMP Ping Flood / Smurf Attack**.
    - **HTTP/HTTPS Application Layer DDoS**.
    - **Brute Force Credentials Harvesting** (SSH, FTP, RDP, SMB, Telnet).
    - **Port Scanning & Network Reconnaissance Probe**.
    - **SQL Injection (SQLi) & Cross-Site Scripting (XSS)**.
    - **DNS Amplification & Data Exfiltration**.
  - Identifies target IP origins, target ports, and protocols, and automatically constructs exact mitigation rules (e.g. `iptables -A INPUT -s <IP> -j DROP`).

---

### 3. `AutoBlockAgent`
- **Role**: Automated zero-latency countermeasure enforcement engine.
- **Responsibility**:
  - Operates in two distinct modes: **Auto** and **Manual**.
  - **Auto Mode**: Instantly blocks malicious IP origins in the database (`BlockedIP` model) and in-memory fast-lookup cache (`_blocked_ips_cache`) without waiting for human intervention.
  - **Manual Mode**: Logs threat telemetry and prepares one-click defense deploy buttons for security operators.
  - Protects critical infrastructure addresses (`127.0.0.1`, `::1`, `localhost`, `0.0.0.0`) from accidental self-blocking.

---

### 4. `SiteSecurityAuditAgent`
- **Role**: Continuous codebase & remote site vulnerability auditor.
- **Responsibility**:
  - Scans project source code (`.py`, `.html`, `.js`, `.cfg`, `.env`) for security anti-patterns:
    - Default static secret key fallbacks.
    - Permissive host header policies (`allowed_hosts=["*"]`).
    - Permissive CORS wildcard configurations (`allow_origins=["*"]`).
    - Dynamic code execution risks (`eval()`, `exec()`).
    - Hardcoded passwords and credentials.
  - **Remote Linked Site Audit**: Connects via API tokens to external URLs and audits missing HTTP security headers (`X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`, `X-XSS-Protection`).

---

### 5. `EmailReportAgent`
- **Role**: Executive security reporting & automated alert dispatcher.
- **Responsibility**:
  - Compiles comprehensive executive summaries containing network telemetry, risk scores, blocked threat lists, model agreement status, and codebase audit findings.
  - Dispatches styled HTML/Plaintext emails to administrators via configurable SMTP servers (support for Gmail, custom TLS/SSL ports).
  - Can be triggered manually or run on automated background interval loops (e.g. every 30 minutes).

---

### Multi-Agent Consensus & Model Verification Loop

```
 ┌──────────────────────┐      ┌─────────────────────────┐
 │ Scapy Packet Capture │─────>│ Active ML Model (LSTM)  │
 └──────────────────────┘      └────────────┬────────────┘
                                            │ Verdict
                                            ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        NetworkAnalyzerAgent                            │
│  - Evaluates telemetry metrics (Packet Rate, SYN ratio, Bytes)          │
│  - Compares ML Verdict vs Agent Heuristics                             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
               ┌────────────────────┴──────────────────┐
               ▼                                       ▼
    Agreement (Match)                         Divergence (Mismatch)
               │                                       │
               ▼                                       ▼
┌──────────────────────────────┐            ┌───────────────────────────┐
│   AttackObservationAgent     │            │ AutoTrainEvent Triggered  │
│ - Classifies Attack Vector   │            │ Retrains ML Models in DB  │
│ - Profiles Target Endpoint   │            └───────────────────────────┘
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐            ┌───────────────────────────┐
│       AutoBlockAgent         │───────────>│     EmailReportAgent      │
│ - Enforces Instant IP Block  │            │ - Sends Executive Summary │
└──────────────────────────────┘            └───────────────────────────┘
```

---

## 🧠 Deep Learning & Machine Learning Engine

Sentinel IDS features a multi-algorithm machine learning framework:

1. **LSTM Neural Network (`LSTM-UGRF_Final.keras`)**: Sequential Deep Learning model trained on network flow time-series metrics.
2. **Random Forest (`RandomForest_Model.pkl`)**: Ensemble classifier evaluating feature thresholds with high interpretability.
3. **XGBoost (`XGBoost_Model.pkl`)**: Gradient boosted decision tree engine optimized for high-throughput packet processing.
4. **Logistic Regression (`LogisticRegression_Model.pkl`)**: Fast linear baseline model for ultra-low latency edge environments.

### Feature Extraction Pipeline
Each packet processed by Scapy or ingested via API extracts 24 continuous telemetry features:
- `Flow Duration`, `Flow IAT Mean/Max/Min`, `TotLen Fwd/Bwd Pkts`, `Fwd/Bwd Pkt Len Max/Mean/Std`, `Pkt Size Avg`, `Pkt Len Var`.
- **TCP Flags**: `FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`.
- **Window & Header Metrics**: `Init Fwd/Bwd Win Byts`, `Flow Byts/s`, `Flow Pkts/s`, `Fwd Header Len`.

---

## 💻 Complete Platform Feature Breakdown (20 Modules)

| # | Feature / Page | Description | Route / Endpoint |
|---|----------------|-------------|------------------|
| 1 | **Overview Dashboard** | Real-time security operations center displaying connection counters, risk score gauges, live flow tables, and agent status. | `/Dashboard` |
| 2 | **Network Traffic Monitor** | Detailed protocol distribution, packet rates, bandwidth meters, and live connection tables. | `/Network-Traffic` |
| 3 | **Threat Intelligence** | Aggregated threat indicators, IOC lists, malicious IP origins, and attack classification feeds. | `/Threat-Intelligence` |
| 4 | **Explainable AI (XAI)** | Feature importance breakdown, SHAP/LIME-style attribution metrics, and model confidence graphs. | `/XAI-Dashboard` |
| 5 | **Prediction Timeline** | Historical trend graph of risk scores, anomaly timestamps, and model predictions over time. | `/Prediction-Timeline` |
| 6 | **Research Metrics** | Benchmark accuracy, precision, recall, F1-score, and latency performance matrices across all 4 ML models. | `/Research-Metrics` |
| 7 | **LLM Intelligence Core** | Conversational cybersecurity assistant with multi-turn chat session history, code fix generation, and offline fallback. | `/AI` |
| 8 | **Dataset Explorer** | Searchable, paginated grid of raw captured network flows stored in SQLite database. | `/Dataset-Explorer` |
| 9 | **Blocked IPs Management** | Interactive table of blocked malicious IP addresses with manual block/unblock controls and reason tags. | `/Blocked-IPs` |
| 10 | **Vulnerability Scanner** | Unified static code audit engine supporting drag & drop files, folders/ZIPs, and Git Repo URLs with `.patch` export. | `/Vulnerability-Scanner` |
| 11 | **Site Vulnerabilities** | Internal codebase security audit and remote linked website header security verification. | `/Site-Vulnerabilities` |
| 12 | **PCAP File Analyzer** | Offline Wireshark `.pcap`/`.pcapng` parser for protocol dissection, top talker analysis, and AI threat discovery. | `/PCAP-Analyzer` |
| 13 | **3D Attack Globe** | WebGL/Canvas 3D interactive globe with animated attack arcs and real-time network topology visualization. | `/Attack-Globe` |
| 14 | **SOAR Playbooks** | Rule builder (`IF [condition] THEN [action]`) for automated IP blocking, Webhooks, and logging. | `/Playbooks` |
| 15 | **Honeypot Decoy Trap** | Decoy service traps (SSH, FTP, HTTP) that intercept attacker probes and automatically trigger IP blocks. | `/Honeypot` |
| 16 | **Threat Lookup Engine** | Query any IP address, Domain, or File Hash (MD5/SHA256) for threat reputation scores and WHOIS info. | `/Threat-Lookup` |
| 17 | **AI Red Team Simulator** | Catalog of 100 safe breach simulation vectors to benchmark IDS detection speeds and test playbooks. | `/RedTeam-Simulator` |
| 18 | **Incident Timeline** | Chronological forensic event stream logging all alerts, blocks, scans, and system events. | `/Incident-Timeline` |
| 19 | **System Health Monitor** | CPU, Memory, Disk usage, SQLite WAL database status, and ML inference latency counters. | `/System-Health` |
| 20 | **System Settings** | Configuration portal for monitoring mode, active ML model, confidence thresholds, API keys, and SMTP settings. | `/Settings` |

---

## 🔍 Vulnerability Scanner & Remediation Core

The **Vulnerability Scanner** (`/Vulnerability-Scanner`) provides static security analysis and remediation:

1. **Unified Upload Zone**: Drag & drop single source files (`.py`, `.js`, `.ts`, `.php`, `.go`, `.java`, etc.), full project directories (`webkitdirectory`), or ZIP archives.
2. **Git Repository Remote Audit**: Enter a public Git URL (`https://github.com/org/repo.git`) to clone and audit remotely via shallow clone or archive extraction.
3. **Automated Remediation Output**:
   - Generates structured Markdown reports with severity ratings (`[Critical]`, `[High]`, `[Medium]`, `[Low]`, `[Info]`).
   - Includes syntax-highlighted ```code``` remediation patches for direct application.
4. **Export Options**:
   - **Download `.patch` File**: Extracts code remediation blocks into a unified Git-compatible patch file (`POST /api/download-patch`).
   - **Export PDF Report**: Compiles styled PDF reports using ReportLab (`POST /api/export-report-pdf`).
   - **Email Dispatch**: Sends scan reports directly to administrator emails via SMTP.

---

## 🛠️ Technology Stack

### Backend Architecture
- **Framework**: FastAPI 0.138+ (Asynchronous Python Web Framework)
- **Database**: SQLite with WAL mode (`PRAGMA journal_mode=WAL`) & SQLAlchemy ORM (using `NullPool` for thread safety)
- **Machine Learning**: TensorFlow 2.21+ / Keras 3.15 (LSTM), Scikit-Learn 1.6 (Random Forest, Logistic Regression), XGBoost 3.3
- **Network Processing**: Scapy 2.7 (Packet sniffing & PCAP parsing)
- **AI / LLM Integration**: Hugging Face Inference API with fallback model chain (`Qwen 2.5 Coder`, `Llama 3.3 70B`, `Mistral 7B`, `Zephyr 7B`) and local offline security responder
- **PDF & Document Generation**: ReportLab
- **Concurrency & WebSockets**: Python `asyncio`, WebSockets, background threads

### Frontend Architecture
- **Core**: HTML5, Vanilla JavaScript (ES6+), CSS3
- **Design System**: Modern Dark Theme (`#0f172a` base), Glassmorphism, Indigo/Purple accents (`#6366f1`), Google Fonts (`Inter`, `JetBrains Mono`)
- **Graphics & Visualization**: HTML5 Canvas, WebGL 3D Engine, Force-Directed Topology Graph
- **Icons**: Clean inline SVG icons (Zero emojis, zero heavy third-party framework dependencies)

---

## 📥 Installation & Setup Guide

### Prerequisites
- Python 3.10+
- Git

### 1. Clone Repository & Setup Virtual Environment
```bash
git clone https://github.com/ahmedmrefaey2020-svg/UGRF.git
cd UGRF
python -m venv .venv
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables (`.env`)
Create a `.env` file in the project root:
```env
DATABASE_URL=sqlite:///./ips_data.db
API_DATABASE=sqlite:///./api_data.db
HF_TOKEN=your_huggingface_token_here
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
ALLOWED_ORIGINS=*
```

### 4. Run Sentinel IDS Server
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
Open your browser at `http://localhost:8000/Dashboard`.

---

## 🔌 API Endpoints Reference

### Core & Dashboard APIs
- `GET /api/dashboard-data` — Returns live network statistics, XAI explanation, and agent analysis.
- `GET /api/dataset-explorer-data` — Fetches captured network flows from SQLite database.
- `GET /api/agents/status` — Returns status of all 5 autonomous AI agents.
- `POST /api/agents/send-report` — Generates and dispatches executive security report email.

### LLM Chat APIs
- `POST /api/chats/new` — Creates a new LLM chat session.
- `GET /api/chats` — Lists all past chat sessions.
- `GET /api/chats/{session_id}` — Retrieves message history for a chat session.
- `DELETE /api/chats/{session_id}` — Deletes a chat session.
- `POST /api/chat` — Sends a message to the AI Assistant with session context.

### Vulnerability Scanner APIs
- `POST /api/scan-file` — Audits a single uploaded source file.
- `POST /api/scan-folder` — Audits an uploaded folder or ZIP archive.
- `POST /api/scan-repo` — Clones and audits a remote Git repository URL.
- `POST /api/scan-pcap` — Dissects and audits uploaded `.pcap`/`.pcapng` network capture files.
- `POST /api/export-report-pdf` — Converts scan reports into downloadable PDF documents.
- `POST /api/download-patch` — Extracts code remediation blocks into a downloadable `.patch` file.

### SOAR & Playbooks APIs
- `GET /api/playbooks` — Lists all configured SOAR playbooks.
- `POST /api/playbooks` — Creates a new condition-action playbook rule.
- `DELETE /api/playbooks/{playbook_id}` — Deletes a playbook rule.

---

## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more information.
#   S e n t i e l - I D S 2  
 #   S e n t i e l - I D S 2  
 #   S e n t i e l - I D S 2  
 #   S C  
 #   S C  
 #   S C  
 #   S C  
 