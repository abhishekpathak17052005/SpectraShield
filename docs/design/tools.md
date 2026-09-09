# SpectraShield — Tools & APIs Directory

This document provides a comprehensive inventory of all **External APIs**, **Internal Endpoints**, **Forensic Engines**, **Databases**, **Frontend Visualization Libraries**, and **Browser Extension Tooling** implemented across the SpectraShield cybersecurity ecosystem.

---

## Table of Contents
1. [External & Third-Party APIs / Threat Intelligence Feeds](#1-external--third-party-apis--threat-intelligence-feeds)
2. [Internal Platform REST APIs (FastAPI Gateway)](#2-internal-platform-rest-apis-fastapi-gateway)
3. [Backend Forensic Engines & Computational Tools (Python)](#3-backend-forensic-engines--computational-tools-python)
4. [Database, Graph & Storage Technologies](#4-database-graph--storage-technologies)
5. [Frontend UI & Visualization Tooling (React + Vite)](#5-frontend-ui--visualization-tooling-react--vite)
6. [Browser Extension Architecture (Chrome Manifest V3)](#6-browser-extension-architecture-chrome-manifest-v3)
7. [Environment & Configuration Variables](#7-environment--configuration-variables)

---

## 1. External & Third-Party APIs / Threat Intelligence Feeds

SpectraShield integrates multiple authoritative threat intelligence feeds, protocol analyzers, and public reputation datasets to form a multi-vector threat consensus.

| Service / Tool | Protocol / Type | Endpoint / Source | Purpose & Implementation | Key Files |
| :--- | :--- | :--- | :--- | :--- |
| **VirusTotal v3 API** | REST API (JSON) | `https://www.virustotal.com/api/v3/urls/` | Queries multi-engine antivirus consensus for suspicious links. Results are cached locally for 24 hours to preserve API quotas. | [`scanner.py`](backend/app/scanner.py) |
| **OpenPhish Feed** | Automated Data Feed | `https://openphish.com/feed.txt` | Downloads community phishing URL feeds. A 24-hour background task continuously syncs active indicators into the database. | [`threat_intel.py`](backend/app/services/threat_intel.py), [`main.py`](backend/app/main.py) |
| **IP-API.com** | REST API (JSON) | `http://ip-api.com/json/{ip}` | Provides fast public IP geolocation, resolving countries, coordinates, and Internet Service Providers (ISPs) as a fallback lookup. | [`scanner.py`](backend/app/scanner.py) |
| **Tor Project Directory** | Offline Text Feed | `data/tor_exit_nodes.txt` | Tracks confirmed Tor exit node IP addresses to flag anonymized proxies and identify evasive threat origins. | [`geo_trace_agent.py`](backend/app/agents/geo_trace_agent.py) |
| **MaxMind GeoIP2 / GeoLite2** | Local Binary DB (`.mmdb`) | `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb` | High-speed offline IP-to-city geolocation and Autonomous System Number (ASN) mapping using `geoip2` and `maxminddb`. | [`geo_trace_agent.py`](backend/app/agents/geo_trace_agent.py) |
| **DNS Protocol Resolver** | UDP/TCP (Port 53) | DNS Root Servers (`dnspython`) | Executes authoritative DNS lookups for MX records, A records, SPF TXT records, and `_dmarc.{domain}` policy records. | [`header_forensic_agent.py`](backend/app/agents/header_forensic_agent.py), [`scanner.py`](backend/app/scanner.py) |
| **WHOIS Protocol** | TCP (Port 43) | Regional Internet Registries (`python-whois`) | Queries domain registration age, creation dates, and registrar legitimacy to flag freshly registered domains (< 30 days). | [`scanner.py`](backend/app/scanner.py) |
| **SSL/TLS Socket Probing** | TCP / TLS Handshake | Direct Socket (Port 443) | Establishes raw TLS handshakes via Python's native `ssl` and `socket` modules to verify certificate validity, issuer authority, and cipher grade. | [`scanner.py`](backend/app/scanner.py) |

---

## 2. Internal Platform REST APIs (FastAPI Gateway)

The backend provides a set of REST endpoints hosted at `http://localhost:8000` (documented via Swagger UI at `/docs` and ReDoc at `/redoc`).

### 2.1 Threat Analysis & Ingestion

- **`POST /analyze`**
  - **Location:** [`backend/app/main.py`](backend/app/main.py)
  - **Purpose:** Primary multi-channel threat detection endpoint. Ingests raw email bodies, sender addresses, standalone URLs, or LinkedIn messages.
  - **Parameters:** `email_text`, `email_header`, `url`, `urls`, `sender_email`, `private_mode`, `platform`, `thread_id`.
  - **Returns:** Composite risk score (0–100), factor breakdown (Linguistic, Brand, Protocol, URL), verdict, confidence level, and MITRE attack trajectory.

### 2.2 Forensic Investigation & Evidence Vault

- **`POST /api/forensics/analyze-email`**
  - **Location:** [`backend/app/forensic_routes.py`](backend/app/forensic_routes.py)
  - **Purpose:** Dissects RFC 5322 headers, unrolls MTA `Received:` hops, calculates hop transmission latency, evaluates SPF/DKIM/DMARC alignment, traces geographic origin (ERPN), detects BEC intent, and seals a tamper-evident case.
  - **Returns:** Case ID, cryptographic hashes (`sha256`, `sha1`, `md5`), authentication matrix, ERPN originating node, relay path, campaign correlation, and MITRE tactics.

- **`POST /api/forensics/upload-eml`**
  - **Location:** [`backend/app/forensic_routes.py`](backend/app/forensic_routes.py)
  - **Purpose:** Accepts multipart file uploads (`.eml` or `.msg` raw files) directly from investigators and routes them to the forensic analyzer.

- **`GET /api/forensics/cases`**
  - **Location:** [`backend/app/forensic_routes.py`](backend/app/forensic_routes.py)
  - **Purpose:** Returns a paginated list of sealed forensic investigations preserved in the Evidence Vault.

- **`GET /api/forensics/cases/{case_id}`**
  - **Location:** [`backend/app/forensic_routes.py`](backend/app/forensic_routes.py)
  - **Purpose:** Retrieves the full evidentiary dossier, analysis breakdown, and chain-of-custody audit trail for a specific case.

### 2.3 Threat Attribution & Threat Graph

- **`GET /api/forensics/campaigns/{campaign_id}/graph`**
  - **Location:** [`backend/app/forensic_routes.py`](backend/app/forensic_routes.py)
  - **Purpose:** Generates formatted node and edge datasets (compatible with `@xyflow/react` and Cytoscape) mapping Emails, IPs, Domains, ASNs, and Threat Actors.

### 2.4 Legal Evidence Export & CTI Sharing

- **`GET /api/forensics/export/{case_id}/pdf`**
  - **Location:** [`backend/app/forensic_routes.py`](backend/app/forensic_routes.py)
  - **Purpose:** Generates and streams a court-admissible forensic PDF dossier compliant with ISO/IEC 27037 and Indian Evidence Act / BNSS digital forensics requirements.

- **`GET /api/forensics/export/{case_id}/stix`**
  - **Location:** [`backend/app/forensic_routes.py`](backend/app/forensic_routes.py)
  - **Purpose:** Exports a standardized STIX 2.1 Cyber Threat Intelligence (CTI) JSON bundle containing Indicators, Infrastructure, Attack Patterns, and Threat Actors.

### 2.5 SOC Telemetry & Analytics

- **`GET /history`** — Retrieves historical scans with filtering by verdict, channel, or time window.
- **`GET /analytics`** — Aggregated operational metrics, average risk scores, category breakdowns, and resolution counters.
- **`GET /daily-pulse-heatmap`** — Generates a 7×24 (day × hour) matrix of scan activity and risk distribution.

---

## 3. Backend Forensic Engines & Computational Tools (Python)

SpectraShield's backend is implemented in Python 3.10+ using modular, specialized micro-engines:

| Tool / Library | Category | Description & Usage |
| :--- | :--- | :--- |
| **FastAPI** | Web Framework | High-performance asynchronous REST API gateway with automatic OpenAPI documentation. |
| **Uvicorn** | ASGI Server | Lightning-fast ASGI production web server powering the FastAPI gateway. |
| **Pydantic v2** | Data Contracts | Strict schema enforcement, input sanitation, and response model serialization. |
| **mail-parser & email** | MIME Parser | Deconstructs raw RFC 5322 email headers, message bodies, multipart boundaries, and attachment streams. |
| **authres** | Header Parsing | Parses RFC 8601 `Authentication-Results` headers to verify server-side SPF, DKIM, and DMARC results. |
| **datasketch (MinHash)** | Machine Learning / NLP | Computes Locality-Sensitive Hashing (LSH) and Jaccard similarity across email text bodies to cluster distributed attacks into shared Threat Campaigns. |
| **pyzbar & Pillow (PIL)** | Computer Vision / Steg | Decodes QR codes found in MIME attachments and base64 inline images to intercept **Quishing** (QR-code phishing) exploits. |
| **reportlab** | PDF Generation | Generates multi-page forensic dossiers featuring tamper-evident SHA-256 headers, chain of custody logs, and tabular findings. |
| **tldextract** | Domain Utility | Separates subdomains, registered domains, and public suffixes (e.g. `.co.uk`, `.top`) using the Public Suffix List. |
| **Levenshtein DP** | Algorithmic Heuristics | Fast dynamic programming edit-distance calculation used in `brand_detector.py` to identify brand typosquatting (e.g. `micros0ft.com`). |
| **Homoglyph & Zero-Width Engine** | NLP / Heuristics | Maps Cyrillic/Greek lookalike homoglyphs to ASCII equivalents and detects hidden zero-width Unicode steganography. |
| **HTTPX & Requests** | HTTP Clients | Synchronous and asynchronous HTTP clients used for external intelligence fetching and sync loops. |

---

## 4. Database, Graph & Storage Technologies

SpectraShield implements a pluggable persistence architecture supporting both relational and NoSQL engines, alongside dedicated graph databases and privacy guarantees.

```
                  ┌──────────────────────────────────────────────┐
                  │          Database Switch / Storage           │
                  └──────────────────────┬───────────────────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      [ PostgreSQL / Supabase ]      [ MongoDB ]         [ In-Memory Vault ]
      - JSONB Document Store         - Native NoSQL      - Zero-Disk Persistence
      - pg_collection driver         - Collections       - `private_mode: true`
                 │                       │                       │
                 └───────────────────────┼───────────────────────┘
                                         │
                                         ▼
                            [ Threat Graph Database ]
                            - Neo4j (Cypher queries)
                            - NetworkX (In-Memory Fallback)
```

- **PostgreSQL / Supabase:** Primary relational store. Utilizes a custom JSONB document driver ([`pg_collection.py`](backend/app/pg_collection.py)) providing a MongoDB-compatible API over relational tables (`scans`, `threat_feed`, `vt_cache`).
- **MongoDB:** Native NoSQL document store alternative configured via `MONGO_URI`.
- **Neo4j:** Enterprise graph database using the official `neo4j` Python driver for mapping relationships across threat actors, campaigns, domains, and origin IPs.
- **NetworkX:** In-memory directed graph (`DiGraph`) that acts as an automated fallback if Neo4j is unavailable.
- **In-Memory Evidence Vault:** Thread-safe cache ([`storage.py`](backend/app/storage.py)) supporting **Privacy Mode** (`private_mode: true`), ensuring zero disk or database persistence when scanning confidential communications.

---

## 5. Frontend UI & Visualization Tooling (React + Vite)

The frontend console is built with **React 18**, **Vite 6**, and **TypeScript**, located in [`frontend/`](frontend/):

| Tool / Library | Role | Usage in SpectraShield |
| :--- | :--- | :--- |
| **React 18 & Vite** | Frontend Engine | High-speed component rendering, fast HMR development, and modular architecture. |
| **Tailwind CSS v4** | Design System | Futuristic dark-mode cyber aesthetic featuring custom glassmorphism and liquid glass styling. |
| **Radix UI Primitives** | Component Library | Accessible unstyled primitives: Dialogs, Accordions, Tabs, Tooltips, Dropdowns, and Sliders. |
| **Lucide React** | Iconography | High-fidelity icons for forensic indicators, threat severity, and network infrastructure. |
| **@xyflow/react** (React Flow) | Graph Visualizer | Interactive canvas visualizing threat attribution networks, campaign IOC clusters, and multi-hop relay chains. |
| **Leaflet & @types/leaflet** | Geographic Mapping | Cartographic map rendering tracing public IP relay flight paths, origin coordinates, and server locations. |
| **Recharts** | Data Analytics | Renders threat severity distributions, category breakdowns, and SOC pulse metrics. |
| **Motion** (Framer Motion) | Micro-Interactions | Hardware-accelerated UI transitions, fluid risk meter sweeps, and dynamic tab switching. |
| **Sonner** | Alerts | High-visibility toast notifications for incoming threats and investigation updates. |
| **jsPDF** | Client PDF Fallback | In-browser PDF generation fallback when server-side ReportLab rendering is bypassed. |

---

## 6. Browser Extension Architecture (Chrome Manifest V3)

Located in [`extension/`](extension/), the browser extension provides zero-touch inline protection:

- **Manifest V3 Specification:** Fully compliant with Chrome's modern security and service worker standards ([`manifest.json`](extension/manifest.json)).
- **Background Service Worker (`background.js`):**
  - Manages inter-component messaging between page content scripts and the FastAPI backend.
  - Proxies cross-origin scanning requests to `http://localhost:8000/analyze`.
- **DOM Content Script (`content.js` + `content.css`):**
  - **Gmail In-Inbox Sentinel:** MutationObserver dynamically tracks inbox rows, analyzes message metadata, and injects color-coded risk pills adjacent to email subjects.
  - **Opened Email Advisory Banner:** Injects prominent security warnings at the top of high-risk opened emails.
  - **LinkedIn Messaging Protection:** Evaluates direct messages in real time, filtering internal platform links and flagging malicious external targets.
- **Quick-Scan Popup Sandbox (`popup.html` + `popup.js` + `popup.css`):**
  - Standalone popover sandbox allowing users to manually paste and scan suspicious URLs, email text, or raw header strings.

---

## 7. Environment & Configuration Variables

SpectraShield uses environment variables (`.env`) to configure external API keys, database connection strings, and behavioral flags:

| Variable Name | Required | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `VT_API_KEY` | Optional | `None` | VirusTotal v3 API key for automated multi-engine URL consensus lookups. |
| `DATABASE_URL` | Optional | `None` | PostgreSQL / Supabase connection URI (e.g. `postgresql://user:pass@host:5432/db`). |
| `DB_BACKEND` | Optional | `auto` | Database engine selection (`postgres`, `supabase`, `mongo`, or `memory`). |
| `MONGO_URI` | Optional | `mongodb://localhost:27017/` | Connection string for MongoDB deployments. |
| `MONGO_DB_NAME` | Optional | `spectrashield_db` | Database name when running on MongoDB. |
| `NEO4J_URI` | Optional | `None` | Neo4j Bolt protocol URI (e.g. `bolt://localhost:7687` or `neo4j+s://...`). |
| `NEO4J_USER` | Optional | `neo4j` | Neo4j authentication username. |
| `NEO4J_PASSWORD` | Optional | `None` | Neo4j authentication password. |
