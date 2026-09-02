# SpectraShield 1.0 — Backend Threat Intelligence Engine

The **SpectraShield Backend** is a high-performance Python FastAPI service providing explainable, multi-vector threat detection across emails, URLs, and social messaging payloads (Gmail & LinkedIn). It fuses linguistic manipulation analysis, brand typosquatting detection, live threat feeds, SSL/TLS certificate probing, and cyber killchain attack simulation into an actionable 0–100 risk score.

---

## Architecture Overview

```
backend/
├── app/
│   ├── main.py                     # FastAPI application entrypoint, CORS, and /analyze dispatcher
│   ├── routes.py                   # History, metrics, and dashboard analytics endpoints
│   ├── scanner.py                  # HybridConsensusScanner & URLIntelligenceEngine
│   ├── schemas.py                  # Pydantic request/response schemas
│   ├── database.py                 # Pluggable storage abstraction (PostgreSQL & MongoDB)
│   ├── pg_collection.py            # PostgreSQL JSONB Mongo-compatible collection driver
│   ├── storage.py                  # In-memory scan fallback storage
│   ├── services/
│   │   ├── ai_pattern_detector.py  # Synthetic lure & AI generation pattern detector
│   │   ├── attack_simulator.py     # 4-stage cyber killchain simulator
│   │   ├── brand_detector.py       # Levenshtein brand impersonation & typosquatting detector
│   │   ├── header_analyzer.py      # Baseline SPF/DKIM/DMARC & Return-Path analyzer
│   │   ├── manipulation_detector.py# Linguistic pressure heuristics (Urgency, Fear, Authority, Scarcity)
│   │   ├── risk_fusion.py          # Multi-vector weighted risk fusion formula
│   │   ├── threat_category.py      # Threat taxonomy classifier & Explainable AI (XAI) synthesizer
│   │   ├── threat_intel.py         # VirusTotal v3 API & OpenPhish feed synchronizer
│   │   └── url_analyzer.py         # Structural URL heuristics & domain age calculator
│   └── utils/
│       └── text_preprocess.py      # Text normalization and tokenization helpers
├── sql/
│   └── supabase_schema.sql         # PostgreSQL / Supabase bootstrap DDL
├── requirements.txt                # Python dependencies
└── .env.example                    # Environment configuration template
```

---

## Core Detection Services

### 1. Linguistic Manipulation Engine (`manipulation_detector.py`)
Analyzes email and message text for psychological coercion tactics:
- **Urgency:** Demands for immediate action ("act immediately", "within 24 hours").
- **Fear:** Threats of account suspension or legal action ("account terminated", "unauthorized access").
- **Authority:** Impersonation of leadership or technical authority ("IT Department", "Security Notice").
- **Scarcity:** Limited-time access or consequences ("final notice", "last warning").
- Returns a normalized manipulation score, extracted high-risk phrases for UI highlighting, and a cognitive pressure index.

### 2. Brand Impersonation & Typosquatting (`brand_detector.py`)
- Evaluates sender display names, sender email addresses, and referenced URLs against known enterprise targets (Microsoft, Google, Apple, Amazon, PayPal, Netflix, etc.).
- Utilizes Levenshtein distance algorithms to catch visual lookalikes and typosquatted domains (e.g., `micros0ft.com`, `paypa1-security.com`).

### 3. URL Intelligence & Consensus Probing (`scanner.py`, `url_analyzer.py`)
- **VirusTotal v3 API:** Queries engine verdicts with an intelligent local 24-hour cache (`vt_url_cache`).
- **OpenPhish Feed Synchronization:** Synchronizes known malicious URLs into a local queryable cache.
- **SSL/TLS Live Probing:** Connects to destination hostnames over port 443 to inspect certificate validity, expiration, and self-signed status.
- **Domain Age Profiling:** Queries WHOIS/RDAP to calculate domain registration age (flagging domains < 30 days old).

### 4. Cyber Killchain Attack Simulator (`attack_simulator.py`)
For any payload evaluated with a risk score $\ge 50$, the backend automatically projects a 4-stage MITRE-aligned attack sequence:
1. **Initial Lure / Deception:** Visual impersonation and urgency framing.
2. **Credential Harvesting:** Redirection to a weaponized replica login portal.
3. **Account Compromise:** Session token extraction and multi-factor bypass.
4. **Impact & Asset Exfiltration:** Data leakage, unauthorized transactions, or lateral movement.

### 5. Composite Risk Fusion (`risk_fusion.py`)
Fuses independent detection vectors into a unified score (0.0 to 100.0):
- **Linguistic Manipulation:** 25% weight
- **Brand Mismatch & Typosquatting:** 25% weight
- **Header Authentication:** 25% weight
- **URL & Domain Reputation:** 25% weight
- If the attack killchain predicts severe downstream impact, the score dynamically escalates to reflect the highest detected vector.

---

## Storage & Database Architecture

SpectraShield features a pluggable database engine controlled by the `DB_BACKEND` environment variable in `app/database.py`:

1. **PostgreSQL / Supabase (`DB_BACKEND=postgres`):**
   - Utilizes `pg_collection.py` (`PostgresCollection`), implementing a MongoDB-compatible JSONB API directly on PostgreSQL.
   - Manages three collections: `scans`, `threat_feed`, and `vt_url_cache`.
   - Supports row-level security (RLS) and persistent lifetime telemetry for SOC dashboards.
2. **MongoDB (`DB_BACKEND=mongo`):**
   - Direct PyMongo driver connecting to a local or cloud MongoDB instance.
3. **Privacy Mode (`private_mode: true`):**
   - All heuristics execute strictly in-memory. No raw email text, sender identity, or scan records are written to persistent storage.

---

## REST API Specification

### 1. `POST /analyze`
Primary threat evaluation endpoint supporting Gmail and LinkedIn payloads.

**Request Payload:**
```json
{
  "email_text": "Urgent: Your Microsoft 365 password expires today.",
  "email_header": "Return-Path: <spoof@attacker.com>\nFrom: IT Support <support@microsoft.com>",
  "url": "https://micros0ft-login.top/auth",
  "urls": ["https://micros0ft-login.top/auth"],
  "sender_email": "spoof@attacker.com",
  "private_mode": false,
  "thread_id": "18f92b7c4a10",
  "platform": "gmail"
}
```

**Response Payload:**
```json
{
  "final_risk": 88.5,
  "verdict": "High Risk",
  "confidence_level": "Very High Confidence",
  "threat_category": "Credential Harvesting",
  "reasoning_summary": "High urgency language detected combined with a newly registered lookalike domain mimicking Microsoft.",
  "breakdown": {
    "manipulation_score": 85.0,
    "brand_impersonation_score": 90.0,
    "header_score": 80.0,
    "url_score": 95.0
  },
  "highlighted_phrases": ["Urgent", "expires today"],
  "domain_age_days": 3,
  "attack_simulation": [
    { "step": 1, "title": "Deceptive Notice", "description": "Lures user with false account expiration." },
    { "step": 2, "title": "Fake Microsoft Login", "description": "Harvests enterprise credentials." },
    { "step": 3, "title": "Token Extraction", "description": "Captures session tokens." },
    { "step": 4, "title": "Tenant Compromise", "description": "Enables lateral mailbox access." }
  ]
}
```

### 2. Analytics & Management Endpoints
- `GET /history?limit=50&risk=all` — Retrieve historical scan records with pagination and risk filtering (`low`, `medium`, `high`, `all`).
- `GET /history/count` — Fast count of total lifetime scans.
- `DELETE /history` — Clear all stored scan records.
- `DELETE /history/{scan_id}` — Delete a specific scan by ID.
- `GET /dashboard/top-brands?days=30&risk=all` — Aggregated top impersonated enterprise brands.
- `GET /dashboard/risk-heatmap?days=30&risk=all` — 7-day x 24-hour incident density matrix.

---

## Setup & Execution

### 1. Environment Setup
```powershell
# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration (`.env`)
Create `.env` in the `backend/` directory:
```env
DB_BACKEND=postgres
DATABASE_URL=postgresql://postgres:your_password@localhost:5432/postgres

# Optional: VirusTotal API Key for enhanced live URL reputation
# VT_API_KEY=your_virustotal_api_key_here
```

### 3. Database Bootstrap (Supabase / PostgreSQL)
Execute the SQL bootstrap in your database:
```powershell
# Run the DDL script found at backend/sql/supabase_schema.sql
```

### 4. Run Development Server
```powershell
uvicorn app.main:app --reload --port 8000
```
Interactive Swagger UI documentation is available at `http://localhost:8000/docs`.
