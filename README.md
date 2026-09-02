# SpectraShield 1.0 — AI Phishing Detection & Threat Intelligence Platform

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React_18_%2B_Vite-61DAFB.svg?style=flat&logo=react&logoColor=black)](https://react.dev)
[![Manifest V3](https://img.shields.io/badge/Extension-Chrome_Manifest_V3-4285F4.svg?style=flat&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL_%2F_Supabase-4169E1.svg?style=flat&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)

**SpectraShield 1.0** is an enterprise-grade cyber defense and phishing detection ecosystem providing real-time, explainable threat detection across inbound emails (**Gmail**), professional communications (**LinkedIn**), and suspicious standalone URLs.

By fusing natural language manipulation cues, brand typosquatting algorithms, SSL/TLS certificate probing, VirusTotal v3 consensus, and cyber killchain attack simulation, SpectraShield delivers a comprehensive 0–100 threat score alongside actionable remediation steps.

---

## Architecture Overview

```
                                      [ INGESTION CHANNELS ]
                      Gmail Inbox / LinkedIn DMs / Popup Scanner / SOC Web Console
                                                 │
                                                 ▼
                                     [ FASTAPI API GATEWAY ]
                                     (CORS, Caching, Routing)
                                                 │
                    ┌────────────────────────────┼────────────────────────────┐
                    ▼                            ▼                            ▼
         [ LINGUISTIC ENGINE ]         [ BRAND & URL INTEL ]        [ HEADER & PROTOCOL ]
         - Urgency / Fear Heuristics   - Levenshtein Distance       - SPF/DKIM/DMARC Parsing
         - Authority & Scarcity        - SSL/TLS Socket Probing     - Return-Path Mismatch
         - Synthetic Lure Cues         - VirusTotal v3 & OpenPhish  - Sender Verification
                    │                            │                            │
                    └────────────────────────────┼────────────────────────────┘
                                                 │
                                                 ▼
                                 [ MULTI-VECTOR RISK FUSION ]
                                  (0 – 100 Composite Score)
                                                 │
                                                 ▼
                                 [ ATTACK KILLCHAIN SIMULATOR ]
                                  (4-Stage Consequence Model)
                                                 │
                    ┌────────────────────────────┴────────────────────────────┐
                    ▼                                                         ▼
      [ PERSISTENCE / CACHE LAYER ]                             [ CLIENT PRESENTATION ]
      - PostgreSQL / Supabase JSONB                             - In-Inbox Color-Coded Badges
      - MongoDB Storage Driver                                  - High-Risk Warning Banners
      - Privacy Mode In-Memory Fallback                         - React SOC Security Dashboard
```

---

## Key Capabilities

### 1. Explainable Multi-Vector Scoring
Rather than operating as a black box, SpectraShield decomposes threat decisions across four distinct analytical vectors:
- **Linguistic Manipulation (25%):** Quantifies psychological coercion triggers (Urgency, Fear, Authority, Scarcity).
- **Brand Impersonation (25%):** Employs Levenshtein edit distance and token lookups to identify typosquatted domains targeting major brands (Microsoft, Google, Apple, PayPal, etc.).
- **Header & Protocol Integrity (25%):** Analyzes SPF, DKIM, and DMARC parameters alongside envelope Return-Path alignment.
- **URL & Domain Reputation (25%):** Combines multi-engine VirusTotal consensus, OpenPhish daily feeds, live SSL/TLS certificate verification, and WHOIS domain age calculations.

### 2. Zero-Touch Browser Extension (Manifest V3)
- **Gmail In-Inbox Sentinel:** Automatically tracks incoming threads, calculates risk in-memory, and injects color-coded risk pills directly adjacent to email subjects.
- **Opened Email Warning Banner:** Injects a prominent security advisory when an opened email exhibits high-risk indicators or spoofed headers.
- **LinkedIn DM Protection:** Analyzes direct messages, filters internal platform routes, and intercepts malicious outbound links.
- **Quick Scan Popup:** Dedicated on-demand sandbox for instant manual text, header, or URL scanning.

### 3. Cyber Killchain Attack Simulation
For any threat scored $\ge 50$, the system automatically synthesizes a MITRE-aligned 4-stage attack trajectory:
1. *Deceptive Hook* $\rightarrow$ 2. *Credential Harvesting Portal* $\rightarrow$ 3. *Session Compromise* $\rightarrow$ 4. *Asset Exfiltration*.

### 4. Interactive Link Sandboxing
The SOC frontend features an isolated iframe sandbox allowing analysts to preview untrusted landing pages safely without executing malicious payloads, accompanied by live SSL certificate assurance badges.

### 5. Pluggable Dual-Database Engine
Supports both **PostgreSQL / Supabase** (using a custom JSONB Mongo-compatible driver) and native **MongoDB**, with complete lifetime telemetry filtering for SOC analytics.

### 6. Privacy-First Mode (`private_mode: true`)
When enabled, all security evaluations occur purely in transient memory. No message contents, sender identities, or audit logs are stored to disk or database.

---

## Repository Structure

```text
SpectraShield/
├── backend/                      # Python FastAPI Backend
│   ├── app/
│   │   ├── main.py               # API routes, CORS & /analyze dispatcher
│   │   ├── routes.py             # History & dashboard analytics routes
│   │   ├── scanner.py            # HybridConsensusScanner & URLIntelligenceEngine
│   │   ├── schemas.py            # Pydantic data contracts
│   │   ├── database.py           # Pluggable database connection pool
│   │   ├── pg_collection.py      # PostgreSQL JSONB Mongo-compatible driver
│   │   ├── storage.py            # In-memory storage fallback
│   │   ├── services/             # Core threat analysis engines
│   │   │   ├── ai_pattern_detector.py
│   │   │   ├── attack_simulator.py
│   │   │   ├── brand_detector.py
│   │   │   ├── header_analyzer.py
│   │   │   ├── manipulation_detector.py
│   │   │   ├── risk_fusion.py
│   │   │   ├── threat_category.py
│   │   │   ├── threat_intel.py
│   │   │   └── url_analyzer.py
│   │   └── utils/
│   ├── sql/
│   │   └── supabase_schema.sql   # PostgreSQL / Supabase bootstrap DDL
│   ├── requirements.txt
│   └── README.md
│
├── frontend/                     # React 18 + Vite SOC Dashboard
│   ├── src/
│   │   ├── app/
│   │   │   ├── App.tsx           # Layout & view router
│   │   │   ├── api.ts            # Typed API client
│   │   │   └── components/       # UI visualizers & widgets
│   │   │       ├── Dashboard.tsx # Primary SOC operations console
│   │   │       ├── RiskMeter.tsx # Circular SVG risk gauge
│   │   │       ├── RiskBreakdown.tsx # Granular factor progress bars
│   │   │       ├── WhyFlagged.tsx# Explainable reasoning accordion
│   │   │       ├── LinkPreview.tsx # Sandboxed destination previewer
│   │   │       └── GmailDemo.tsx # In-dashboard inbox simulator
│   ├── package.json
│   └── README.md
│
├── extension/                    # Chromium Browser Extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js             # Service worker & badge coordinator
│   ├── content.js                # DOM observers for Gmail & LinkedIn
│   ├── content.css               # Injected badge & banner styles
│   ├── popup.html / popup.js     # On-demand quick scan modal
│   └── README.md
│
├── current-struct.md             # SpectraShield 1.0 Technical Specification
├── upgrade-struct.md             # SpectraShield 2.0 Architectural Blueprint
├── spec.md                       # SIH 2026 Problem Statement Specification
└── README.md                     # Root Project Documentation
```

---

## Quick Start Guide

### Prerequisites
- Python 3.10+
- Node.js 18+ LTS
- Google Chrome or Chromium browser
- PostgreSQL / Supabase instance (or MongoDB)

---

### 1. Backend Setup (FastAPI)

```powershell
# Navigate to backend
cd backend

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
Copy-Item .env.example .env
```

Edit `backend/.env` to configure your database:
```env
DB_BACKEND=postgres
DATABASE_URL=postgresql://postgres:<password>@<host>:5432/postgres

# Optional: VirusTotal API Key for enhanced URL intelligence
# VT_API_KEY=your_key_here
```

Bootstrap your database using [backend/sql/supabase_schema.sql](backend/sql/supabase_schema.sql) in your SQL query editor.

Start the backend server:
```powershell
uvicorn app.main:app --reload --port 8000
```
API Documentation will be accessible at: `http://localhost:8000/docs`

---

### 2. Frontend Setup (React + Vite)

```powershell
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```
The SOC Dashboard will launch at: `http://localhost:5173`

---

### 3. Browser Extension Setup (Chrome Manifest V3)

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked** in the top-left toolbar.
4. Select the `extension/` directory from this repository.
5. Open [Gmail](https://mail.google.com) or [LinkedIn](https://www.linkedin.com) to observe automated threat badges and sentinel alerts.

---

## Core API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/analyze` | Comprehensive evaluation endpoint for email, URL, and messaging payloads. |
| `GET` | `/history` | Paginated scan history filtered by risk level (`all`, `high`, `medium`, `low`). |
| `GET` | `/history/count` | Fast count of total lifetime security evaluations. |
| `DELETE` | `/history` | Clears all stored scan telemetry. |
| `DELETE` | `/history/{scan_id}` | Deletes a specific scan record by ID. |
| `GET` | `/dashboard/top-brands` | Aggregated list of top impersonated enterprise brands. |
| `GET` | `/dashboard/risk-heatmap` | 7-day x 24-hour incident density matrix. |

---

## Roadmap: SpectraShield 2.0 (Forensic Edition)

In alignment with **SIH 2026 Problem Statement ID: 26106** ("AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform"), the codebase is structured to systematically evolve into **SpectraShield 2.0**:

- [ ] **RFC 5322 Multi-Hop Relay Tracer:** Chronological `Received:` header deconstruction isolating the Earliest Reliable Public Node (ERPN).
- [ ] **Cartographic GeoTrace Engine:** MaxMind GeoLite2 City & ASN integration mapping hop-by-hop transmission paths on an interactive Leaflet world map.
- [ ] **Transformer-Powered BEC Models:** Fine-tuned DeBERTa-v3/RoBERTa classifiers for advanced executive impersonation and payment diversion.
- [ ] **Neo4j Threat Graph Attribution:** Correlating Senders, Domains, IPs, and MinHash signatures into unified threat actor campaigns.
- [ ] **Court-Admissible Evidence Vault:** RFC 3161 / ISO 27037 SHA-256 evidence hashing, tamper-evident audit trails, and automated CERT-In / LEA incident response PDF reports.

For the full architectural blueprint, consult [upgrade-struct.md](upgrade-struct.md) and [spec.md](spec.md).

---

## License

This project is licensed under the MIT License.
