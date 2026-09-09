# SpectraShield 2.0 (Forensic Edition) — Master Upgrade Specification

**Document Title:** System Architecture, Forensic Engine Specification & Implementation Master Contract  
**Project Name:** SpectraShield 2.0 (Forensic Edition)  
**SIH Problem Statement ID:** 26106  
**Problem Statement Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Category:** Software | **Theme:** Cybersecurity & Digital Forensics  
**Target Beneficiaries:** Security Operations Center (SOC) Teams, Law Enforcement Agencies (LEAs), Fraud Response Units, Enterprise Security Administrators  
**Baseline Codebase:** SpectraShield 1.0 (FastAPI + React 18/Vite + Chrome Manifest V3 Extension)  

---

## 1. Executive Summary & Strategic Transformation

### 1.1 Project Overview
Modern cyber adversaries have evolved past simple bulk spam. Enterprise threat vectors are dominated by **Business Email Compromise (BEC)**, executive impersonation, supplier invoice diversion, domain lookalike typosquatting, multi-hop relay manipulation, open relay exploitation, and proxy evasion chains (Tor, commercial VPNs, bulletproof hosting).

While traditional Secure Email Gateways (SEGs) and client-side heuristics rely on static keyword lists and superficial headers, **SpectraShield 2.0 (Forensic Edition)** transforms the existing SpectraShield 1.0 platform into an **end-to-end, enterprise-grade Email Threat Detection, Origin Geolocation, and Digital Forensic Intelligence Platform**.

SpectraShield 2.0 ingests raw RFC 5322 email headers and MIME bodies (`.eml`, `.msg`), parses multi-hop transmission chains, filters internal RFC 1918 bogons to isolate the **Earliest Reliable Public Node (ERPN)**, resolves originating geolocations via offline MaxMind databases, executes transformer-based NLP intent classification, correlates threat infrastructure into an interactive graph database (Neo4j), and compiles court-admissible forensic dossiers with cryptographic SHA-256 chain-of-custody verification.

### 1.2 Transformation Matrix: SpectraShield 1.0 vs. SpectraShield 2.0

| Subsystem | SpectraShield 1.0 (Baseline) | SpectraShield 2.0 (Target Upgrade) |
| :--- | :--- | :--- |
| **Header & Relay Engine** | Substring checks (`"spf=fail" in header`) in `header_analyzer.py` | **RFC 5322 Multi-Hop Relay Decompiler**: Parses bottom-to-top `Received:` hops, detects timestamp time-travel anomalies, and executes live cryptographic SPF, DKIM, and DMARC alignment checks. |
| **Origin & Geolocation** | Basic IP host lookup in `scanner.py` | **Earliest Reliable Public Node (ERPN) Engine**: Discards private/carrier bogon IPs, resolves physical origin coordinates and ASN via offline MaxMind GeoLite2, and flags Tor/VPN/Cloud exit nodes. |
| **Linguistic & Content AI** | Keyword heuristics (Urgency, Fear, Authority, Scarcity) in `manipulation_detector.py` | **Transformer-Powered BEC & Cognitive Engine**: Fine-tuned DeBERTa-v3/RoBERTa for financial fraud intent, fake invoices, homoglyph character spoofing, and inline QR-code link extraction. |
| **Threat Graph & Attribution** | Flat 24-hour VirusTotal cache + daily OpenPhish sync in `threat_intel.py` | **Neo4j Threat Attribution Graph**: Ingests Senders, IPs, Subnets, Domains, and MinHash email body fingerprints to cluster discrete incidents into named **Threat Actor Campaigns**. |
| **Forensic Evidence & Chain of Custody** | Ephemeral `scan_history = []` or unverified JSONB in PostgreSQL | **Court-Admissible Evidence Vault (ISO/IEC 27037 & BNSS)**: RFC 3161 SHA-256 evidence hashing upon arrival, tamper-evident audit logs, STIX 2.1 JSON exporter, and automated forensic PDF dossiers. |
| **Client Interface** | React 18 + Vite SOC Dashboard (KPIs, Heatmap, Brand list) | **Full Forensic Investigation Console**: Interactive Leaflet relay trajectory map (`HopMapVisualizer.tsx`), `@xyflow/react` threat network explorer, and header timeline inspector. |
| **Browser Extension** | Gmail and LinkedIn Sentinel DOM observer badges | **1-Click Forensic Escalator**: Adds an in-inbox "Escalate to Forensic SOC" action that packages raw headers and dispatches them directly to the forensic vault. |

---

## 2. End-to-End System Architecture

SpectraShield 2.0 retains the unified, high-performance **Python FastAPI** backend architecture. By keeping API routing, MIME parsing, DNS cryptography, machine learning, and report generation in a single asynchronous Python engine, it avoids the latency and complexity of unnecessary multi-tier microservice bridges.

```
                                 [ INGESTION CHANNELS ]
                 (Browser Extension / .EML & .MSG Drag-and-Drop / API Endpoints)
                                            │
                                            ▼
                       [ SHA-256 IMMUTABILITY & EVIDENCE VAULT ]
                 - Calculates SHA-256, SHA-1, and MD5 evidence hashes
                 - Stores immutable raw artifact with cryptographic timestamp
                                            │
                                            ▼
                       [ MULTI-AGENT FORENSIC ENGINE PIPELINE ]
                                            │
    ┌───────────────────────┬───────────────┴───────────────┬───────────────────────┐
    ▼                       ▼                               ▼                       ▼
[ HeaderForensicAgent ]  [ GeoTraceAgent ]              [ NLPThreatAgent ]      [ OSINTDomainAgent ]
- RFC 5322 Hop Parsing   - ERPN Algorithm               - DeBERTa-v3 BEC Cues   - WHOIS / RDAP Age
- SPF/DKIM/DMARC Align   - MaxMind GeoLite2 City/ASN    - Cognitive Pressure    - Spamhaus DNSBL Check
- Relay Time Anomalies   - Tor / VPN / Cloud Detect     - Homoglyph & QR Lures  - Reverse DNS (PTR)
    │                       │                               │                       │
    └───────────────────────┼───────────────────────────────┴───────────────────────┘
                            │
                            ▼
           [ GRAPH ATTRIBUTION & CAMPAIGN AGENT ]
           - Neo4j Graph Correlation: (IP)-[HOSTS]->(Domain)-[SENT]->(Target)
           - MinHash / LSH Body Fingerprint Clustering
           - Campaign Attribution & Confidence Scoring
                            │
                            ▼
           [ COMPOSITE FORENSIC RISK FUSION (0-100) ]
           - Weighted Multi-Vector Heuristic Fusion
           - MITRE ATT&CK Matrix Mapping & Explainable XAI Synthesis
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
[ BROWSER EXTENSION SENTINEL ]   [ SOC INVESTIGATION DASHBOARD ]
- 1-Click Forensic Escalation    - Hop-by-Hop World Map (Leaflet)
- In-Inbox Threat Ribbon         - Interactive Entity Graph (@xyflow/react)
- Raw Header Extraction          - Court-Admissible PDF & STIX 2.1 Exporter
```

---

## 3. Micro-Agent & Forensic Subsystems

The backend core is organized into modular forensic agents located in `backend/app/agents/`:

### 3.1 Header Forensic Agent (`header_forensic_agent.py`)
- **Multi-Hop Traversal:** Reconstructs the end-to-end transmission journey by reading `Received:` headers in reverse chronological order (bottom-to-top: from the first submission client MTA to the final destination MX server).
- **Cryptographic Protocol Validation:**
  - **SPF (`v=spf1`):** Resolves DNS TXT records for the envelope sender domain (`Return-Path`), tests the sending MTA IP against CIDR blocks and `include:` directives, and assigns status (`Pass`, `Fail`, `SoftFail`, `Neutral`, `PermError`, `TempError`).
  - **DKIM (`DKIM-Signature`):** Extracts `d=` (signing domain) and `s=` (selector), queries public key records at `<selector>._domainkey.<domain>`, and verifies the cryptographic signature over header fields and the body hash (`bh=`).
  - **DMARC (`_dmarc.<domain>`):** Evaluates whether SPF and DKIM domains align with the visible RFC 5322 `From:` header domain (strict vs. relaxed alignment). Detects organizational enforcement policies (`none`, `quarantine`, `reject`).
- **Relay Forgery & Anomaly Detection:**
  - Identifies timestamp inversions (where hop $N+1$ claims a timestamp earlier than hop $N$, indicating clock drift or falsified headers).
  - Detects bogus `Message-ID` syntax and mismatches between envelope `Return-Path` and visible `From:`.
  - Computes inter-MTA transit latency across intermediate hops.

### 3.2 Origin & Cartographic GeoTrace Agent (`geo_trace_agent.py`)
- **Earliest Reliable Public Node (ERPN) Algorithm:**
  1. Inspects the chronologically first `Received:` hop.
  2. Evaluates the IP address against bogon, loopback, and private IPv4/IPv6 CIDR ranges:
     - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918)
     - `127.0.0.0/8` (RFC 5735 Loopback)
     - `169.254.0.0/16` (Link-Local)
     - `100.64.0.0/10` (Carrier-Grade NAT)
     - `::1/128`, `fc00::/7`, `fe80::/10` (IPv6 Private/Local)
  3. Steps outward along the hop sequence until encountering the **first authentic public internet IP**.
- **MaxMind GeoLite2 Resolution:** Queries local offline databases (`GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`) to resolve Country, City, Postal Code, Latitude, Longitude, Autonomous System Number (ASN), and ISP Organization name.
- **Anonymization & Proxy Identification:**
  - Cross-references IP addresses with daily cached lists of public **Tor Exit Nodes** (`tor_exit_nodes.txt`).
  - Flags known commercial VPN subnets (NordVPN, ExpressVPN, Surfshark) and major cloud providers (AWS, GCP, Azure, DigitalOcean, OVH) commonly abused for disposable relaying.

### 3.3 NLP Intent & Cognitive Pressure Agent (`nlp_threat_agent.py`)
- **Transformer-Based BEC Classification:** Incorporates lightweight fine-tuned transformer inference (DeBERTa-v3 / RoBERTa via ONNX Runtime or PyTorch) to classify message body text into:
  - *Clean / Legitimate*
  - *Credential Harvesting Phishing*
  - *Business Email Compromise (BEC) / Wire Transfer Fraud / Payroll Diversion*
  - *Executive / VIP Impersonation*
  - *Malware / Exploit Delivery*
- **Linguistic Pressure Extraction:** Preserves and deepens SpectraShield 1.0 heuristics for psychological pressure triggers (Artificial Urgency, Fear/Coercion, Authority Mandates, Scarcity).
- **Homoglyph & Cousin Domain Detection:** Evaluates sender domains for Cyrillic/Greek character substitution (IDN homograph attacks) and zero-width spaces designed to evade keyword filters.
- **Inline QR-Code Extraction (`qr_detector.py`):** Scans embedded and attached inline images for QR codes, extracts encoded URLs, and routes them through the URL reputation engine.

### 3.4 OSINT & Domain Intelligence Agent (`osint_domain_agent.py`)
- **WHOIS & RDAP Profiling:** Queries domain registration dates, flagging newly registered domains (< 30 days old).
- **DNSBL & IP Reputation:** Queries Spamhaus ZEN (`sbl.spamhaus.org`, `xbl.spamhaus.org`) and local OpenPhish/VirusTotal feeds.
- **Reverse DNS (PTR Validation):** Validates forward-confirmed reverse DNS (FCrDNS) to detect generic residential dynamic IP hostnames sending direct mail.

### 3.5 Threat Attribution & Graph Agent (`graph_attribution_agent.py`)
- **Neo4j Cypher Data Modeling:** Connects extracted entities into a queryable graph:
  - Nodes: `(:Email)`, `(:IPAddress)`, `(:Domain)`, `(:ASN)`, `(:ThreatCampaign)`, `(:DKIMSelector)`
  - Edges: `(:Email)-[:ORIGINATED_FROM]->(:IPAddress)`, `(:IPAddress)-[:HOSTED_BY]->(:ASN)`, `(:Email)-[:USES_DOMAIN]->(:Domain)`, `(:Email)-[:PART_OF]->(:ThreatCampaign)`
- **MinHash / LSH Body Fingerprinting:** Computes MinHash signatures on normalized body text to cluster structurally identical phishing lures across multiple victims into named campaigns (e.g., `"Campaign-2026-M365-Finance"`).
- **In-Memory Fallback:** When Neo4j is not connected, the agent executes graph community detection in-memory via `networkx` to ensure zero runtime breakage in local testing.

### 3.6 Forensic Report & Evidence Agent (`forensic_report_agent.py`)
- **Cryptographic Immutability:** Computes SHA-256, SHA-1, and MD5 hashes upon ingestion. Raw email blobs are written to an evidence storage vault with immutable timestamps.
- **STIX 2.1 Threat Intelligence Export:** Serializes scan findings into standard STIX 2.1 JSON bundles (`indicator`, `observed-data`, `infrastructure`, `threat-actor`) for SIEM/SOAR ingestion.
- **Court-Admissible PDF Dossier:** Uses Python `reportlab` to compile formatted evidentiary reports including evidence hashes, RFC 5322 header breakdown, SPF/DKIM/DMARC cryptographic proofs, hop trajectory tables, and analyst sign-off blocks (ISO/IEC 27037 compliant).

---

## 4. Annotated Directory Structure

```text
SpectraShield/
├── spec.md                                 # Original SIH 26106 AegisMail Specification
├── upgraded-spec.md                        # THIS DOCUMENT: Master SpectraShield 2.0 Specification
├── current-struct.md                       # SpectraShield 1.0 Baseline Reference
├── upgrade-struct.md                       # Upgrade Blueprint & Transformation Guide
├── README.md                               # Root Project Documentation
├── .gitignore                              # Environment & artifact exclusions
│
├── backend/                                # Unified Python FastAPI Engine
│   ├── README.md
│   ├── requirements.txt                    # Extended: maxminddb, geoip2, dnspython, authres, mail-parser, neo4j, reportlab, datasketch
│   ├── .env.example
│   ├── data/                               # Offline Threat & Geo Databases
│   │   ├── GeoLite2-City.mmdb              # Offline MaxMind City Database
│   │   ├── GeoLite2-ASN.mmdb               # Offline MaxMind ASN Database
│   │   └── tor_exit_nodes.txt              # Tor Project daily exit nodes list
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                         # FastAPI application entrypoint & middleware
│   │   ├── routes.py                       # REST routes & dashboard controller
│   │   ├── schemas.py                      # Pydantic models (RelayHop, OriginGeo, Campaign, STIX)
│   │   ├── database.py                     # PostgreSQL / Supabase + MongoDB pool
│   │   ├── graph_db.py                     # [NEW] Neo4j connection manager with NetworkX fallback
│   │   ├── storage.py                      # [UPGRADED] Evidence vault with SHA-256 immutability
│   │   ├── pg_collection.py                # PostgreSQL JSONB Mongo-compatible driver
│   │   ├── scanner.py                      # Orchestrator dispatching to forensic agents
│   │   │
│   │   ├── agents/                         # [NEW] Multi-Agent Forensic Computation Modules
│   │   │   ├── __init__.py
│   │   │   ├── header_forensic_agent.py    # Multi-hop RFC 5322 parsing & SPF/DKIM/DMARC
│   │   │   ├── geo_trace_agent.py          # ERPN algorithm & MaxMind GeoIP2 resolution
│   │   │   ├── nlp_threat_agent.py         # DeBERTa-v3 BEC, urgency & homoglyph scoring
│   │   │   ├── osint_domain_agent.py       # RDAP, WHOIS, DNSBL & SSL inspection
│   │   │   ├── graph_attribution_agent.py  # Neo4j graph correlation & MinHash clustering
│   │   │   └── forensic_report_agent.py    # STIX 2.1 bundle & PDF dossier generator
│   │   │
│   │   ├── services/                       # Preserved SpectraShield Services
│   │   │   ├── ai_pattern_detector.py      # LLM synthetic lure detector
│   │   │   ├── attack_simulator.py         # 4-stage cyber killchain generator
│   │   │   ├── brand_detector.py           # Levenshtein typosquatting detector
│   │   │   ├── header_analyzer.py          # Legacy header fallback
│   │   │   ├── manipulation_detector.py    # Urgency, Fear, Authority, Scarcity heuristics
│   │   │   ├── qr_detector.py              # [NEW] Inline image QR code extractor
│   │   │   ├── risk_fusion.py              # Upgraded 0-100 forensic score fusion engine
│   │   │   ├── threat_category.py          # Threat taxonomy classifier & XAI synthesizer
│   │   │   ├── threat_intel.py             # OpenPhish synchronization & VirusTotal worker
│   │   │   └── url_analyzer.py             # Structural URL heuristics & domain age calculator
│   │   │
│   │   └── utils/
│   │       ├── text_preprocess.py          # Text normalization helpers
│   │       └── ip_utils.py                 # [NEW] Bogon & RFC 1918 CIDR subnet utilities
│   └── sql/
│       ├── supabase_schema.sql             # SpectraShield 1.0 DDL
│       └── supabase_schema_v2.sql          # [NEW] Forensic audit logs, evidence hashes & campaigns
│
├── frontend/                               # React 18 + Vite SOC Dashboard
│   ├── README.md
│   ├── package.json                        # Added: leaflet, react-leaflet, @xyflow/react, jspdf
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── styles/
│       └── app/
│           ├── App.tsx                     # Extended layout with Forensic Investigation tabs
│           ├── api.ts                      # Typed client for forensic endpoints
│           └── components/
│               ├── Dashboard.tsx           # SOC dashboard with Geo Map & Campaign stats
│               ├── RiskMeter.tsx           # Circular SVG risk gauge
│               ├── RiskBreakdown.tsx       # Granular risk breakdown progress bars
│               ├── WhyFlagged.tsx          # Explainable AI reasoning accordion
│               ├── ActionButtons.tsx       # Triage & export controls
│               ├── LinkPreview.tsx         # Live sandboxed URL previewer
│               ├── GmailDemo.tsx           # Inbox row simulator
│               │
│               └── forensics/              # [NEW] Dedicated Forensic Visualizers
│                   ├── HopMapVisualizer.tsx # Leaflet world map showing hop-by-hop relay path
│                   ├── RelayHopTimeline.tsx # Chronological RFC 5322 relay hop cards
│                   ├── ThreatGraphExplorer.tsx # Interactive @xyflow/react Campaign Graph
│                   ├── AuthStatusMatrix.tsx # Visual SPF, DKIM, DMARC alignment badges
│                   └── StixExportModal.tsx  # STIX 2.1 JSON viewer & downloader
│
└── extension/                              # Chromium Browser Extension (Manifest V3)
    ├── README.md
    ├── manifest.json
    ├── background.js                       # Handles background uploads & badge state
    ├── content.js                          # Gmail & LinkedIn observers + [NEW] 1-Click Forensic Escalator
    ├── content.css                         # Injected badge, ribbon & modal styling
    ├── popup.html                          # Quick Scan interface
    ├── popup.js                            # Popup controller
    └── popup.css                           # Popup styling
```

---

## 5. Mathematical Threat Scoring & Risk Fusion (2.0)

The composite risk score is computed by aggregating forensic vectors through a multi-tier fusion formula:

### 5.1 Sub-Vector Scoring Formulas

#### 1. Header & Protocol Authentication Score ($S_{\text{Header}}$)
$$S_{\text{Header}} = (0.40 \times S_{\text{SPF}}) + (0.35 \times S_{\text{DKIM}}) + (0.25 \times S_{\text{DMARC}}) + P_{\text{Anomaly}}$$
- $S_{\text{SPF}} \in \{ \text{Pass}: 0, \text{Neutral}: 20, \text{SoftFail}: 60, \text{Fail}: 100 \}$
- $S_{\text{DKIM}} \in \{ \text{Pass}: 0, \text{None}: 40, \text{Fail}: 100 \}$
- $S_{\text{DMARC}} \in \{ \text{Pass}: 0, \text{Policy=None}: 50, \text{Policy=Quarantine}: 80, \text{Policy=Reject}: 100 \}$
- $P_{\text{Anomaly}} \in [0, 30]$: Added penalty for timestamp inversions, return-path mismatches, or invalid Message-ID syntax.

#### 2. Origin & Infrastructure Reputation Score ($S_{\text{Origin}}$)
$$S_{\text{Origin}} = S_{\text{ASN\_Rep}} + P_{\text{Anonymized}} + P_{\text{Bogon\_Violation}}$$
- $S_{\text{ASN\_Rep}} \in [0, 50]$: Historical malicious activity rating for the originating Autonomous System.
- $P_{\text{Anonymized}} = 35$ if the originating public IP is an identified Tor Exit Node, bulletproof proxy, or commercial VPN exit; otherwise $0$.
- $P_{\text{Bogon\_Violation}} = 25$ if external relay claims originating from unroutable bogon IP space.

#### 3. Linguistic & BEC Intent Score ($S_{\text{NLP}}$)
$$S_{\text{NLP}} = \max\left( S_{\text{Manipulation}}, S_{\text{DeBERTa\_BEC}} \right) + P_{\text{Homoglyph}}$$
- $S_{\text{Manipulation}} \in [0, 100]$: Normalized heuristic score across Urgency, Fear, Authority, and Scarcity.
- $S_{\text{DeBERTa\_BEC}} \in [0, 100]$: Transformer inference probability of financial diversion / executive spoofing.
- $P_{\text{Homoglyph}} = 30$ if IDN Cyrillic/Greek homograph characters or invisible zero-width spaces are detected in domain or body.

#### 4. URL & Destination Reputation Score ($S_{\text{URL}}$)
$$S_{\text{URL}} = \max_{u \in \text{URLs}} \left( S_{\text{VT}}(u) + S_{\text{SSL}}(u) + S_{\text{DomainAge}}(u) \right)$$
- $S_{\text{VT}}(u) \in [0, 100]$: Multi-engine consensus from VirusTotal and OpenPhish feeds.
- $S_{\text{SSL}}(u) \in \{ \text{Valid}: 0, \text{Untrusted/Self-Signed}: 40, \text{Expired}: 50 \}$.
- $S_{\text{DomainAge}}(u) = 35$ if registered $< 30$ days ago; $15$ if $< 90$ days ago; otherwise $0$.

### 5.2 Composite Forensic Score & Killchain Escalation
$$S_{\text{Composite}} = (0.25 \times S_{\text{Header}}) + (0.25 \times S_{\text{Origin}}) + (0.25 \times S_{\text{NLP}}) + (0.25 \times S_{\text{URL}})$$

$$\text{FinalRisk} = \min\left(100.0, \; \max\left( S_{\text{Composite}}, \; S_{\text{Killchain\_Severity}} \right)\right)$$

If the Cyber Killchain simulator determines that the payload combines deceptive executive impersonation with an active credential harvesting portal, $S_{\text{Killchain\_Severity}} \ge 85.0$, overriding lower individual heuristics.

---

## 6. Database Models & Persistence Layer

### 6.1 PostgreSQL / Supabase Forensic Schema (`supabase_schema_v2.sql`)

```sql
-- 1. Cases Table (Central Investigation Unit)
CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_number VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    threat_category VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN')),
    status VARCHAR(20) NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'INVESTIGATING', 'ESCALATED', 'RESOLVED', 'ARCHIVED')),
    overall_risk_score NUMERIC(5, 2) NOT NULL,
    sha256_evidence_hash VARCHAR(64) NOT NULL,
    raw_email_path TEXT,
    assigned_analyst VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Email Analyses Table (Forensic Dissection)
CREATE TABLE IF NOT EXISTS email_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    message_id TEXT,
    envelope_from TEXT,
    header_from TEXT,
    reply_to TEXT,
    subject TEXT,
    date_header TIMESTAMPTZ,
    authentication_results JSONB NOT NULL,
    relay_hops JSONB NOT NULL,
    originating_node JSONB NOT NULL,
    nlp_intelligence JSONB NOT NULL,
    iocs JSONB NOT NULL,
    mitre_tactics TEXT[],
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Threat Campaigns Table (Attribution Clusters)
CREATE TABLE IF NOT EXISTS threat_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_identifier VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    threat_actor_signature TEXT,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    associated_ips TEXT[],
    associated_domains TEXT[],
    minhash_cluster_id VARCHAR(64),
    confidence_score NUMERIC(5, 2) NOT NULL DEFAULT 75.0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Forensic Audit Logs (Tamper-Evident Chain-of-Custody)
CREATE TABLE IF NOT EXISTS forensic_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    actor VARCHAR(100) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL,
    metadata JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);
```

### 6.2 Neo4j Threat Graph Schema & Cypher Queries

#### Graph Node Labels & Properties
- `(:Email {hash: String, subject: String, timestamp: String})`
- `(:IPAddress {ip: String, country: String, is_tor: Boolean, is_vpn: Boolean})`
- `(:Domain {name: String, age_days: Integer, registrar: String})`
- `(:ASN {number: String, organization: String})`
- `(:ThreatCampaign {id: String, name: String, confidence: Float})`

#### Ingestion Cypher Mutation
```cypher
MERGE (e:Email {hash: $email_hash})
  ON CREATE SET e.subject = $subject, e.created_at = datetime()
MERGE (ip:IPAddress {ip: $origin_ip})
  ON CREATE SET ip.country = $country, ip.is_tor = $is_tor
MERGE (d:Domain {name: $sender_domain})
  ON CREATE SET d.age_days = $domain_age
MERGE (asn:ASN {number: $asn_number})
  ON CREATE SET asn.organization = $isp_name
MERGE (camp:ThreatCampaign {id: $campaign_id})
  ON CREATE SET camp.name = $campaign_name

MERGE (e)-[:ORIGINATED_FROM]->(ip)
MERGE (ip)-[:HOSTED_BY]->(asn)
MERGE (e)-[:USES_DOMAIN]->(d)
MERGE (e)-[:PART_OF]->(camp)
MERGE (d)-[:RESOLVES_TO]->(ip)
```

---

## 7. Upgraded REST API Specification

### 7.1 `POST /api/forensics/analyze-email`
Full forensic ingestion endpoint supporting multipart upload of `.eml` / `.msg` files or raw text payloads.

**Request Body (JSON option):**
```json
{
  "raw_eml": "Received: from mail.attacker.com ...\nSubject: Overdue Wire Transfer...",
  "sender_email": "finance@micro-soft-billing.com",
  "private_mode": false
}
```

**Response Body (200 OK):**
```json
{
  "case_id": "8f3b2c1a-5e7d-4b9a-8c1e-9f3a2b1c0d5e",
  "sha256_evidence_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "final_risk": 94.5,
  "verdict": "High Risk / Malicious",
  "threat_category": "Business Email Compromise (BEC)",
  "authentication": {
    "spf": { "status": "Fail", "domain": "micro-soft-billing.com", "sender_ip": "185.220.101.5" },
    "dkim": { "status": "Fail", "selector": "default", "domain": "micro-soft-billing.com", "valid": false },
    "dmarc": { "status": "Fail", "policy": "none", "aligned": false }
  },
  "originating_node": {
    "ip": "185.220.101.5",
    "country": "Germany",
    "city": "Frankfurt",
    "latitude": 50.1109,
    "longitude": 8.6821,
    "asn": "AS60729",
    "isp": "Tor Exit Router Network",
    "is_anonymized": true,
    "anonymization_type": "TOR"
  },
  "relay_path": [
    {
      "hop": 1,
      "received_from": "client-sub.local",
      "by": "smtp.attacker-relay.com",
      "ip": "185.220.101.5",
      "is_private": false,
      "is_origin": true,
      "geo": { "country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821 },
      "timestamp": "2026-09-02T10:14:02Z",
      "delay_seconds": 0
    },
    {
      "hop": 2,
      "received_from": "smtp.attacker-relay.com",
      "by": "mx.victim-domain.com",
      "ip": "172.217.194.27",
      "is_private": false,
      "is_origin": false,
      "geo": { "country": "United States", "city": "Mountain View", "lat": 37.422, "lon": -122.084 },
      "timestamp": "2026-09-02T10:14:04Z",
      "delay_seconds": 2
    }
  ],
  "campaign": {
    "id": "CAMP-2026-042",
    "name": "Targeted European Wire Diversion",
    "linked_incidents_count": 8,
    "attribution_confidence": 88.0
  },
  "mitre_tactics": [
    "T1566.002 - Spearphishing Link",
    "T1598.003 - Spearphishing for Information"
  ],
  "reasoning_summary": "Cryptographic DMARC alignment failure, origin traced to a verified Tor Exit Node in Frankfurt, combined with high-urgency financial wire fraud language."
}
```

### 7.2 `GET /api/forensics/campaigns/{id}/graph`
Returns nodes and edges formatted for `@xyflow/react` or Cytoscape.js visualizers.

**Response Body:**
```json
{
  "nodes": [
    { "id": "ip-185.220.101.5", "type": "ip", "data": { "label": "Origin IP: 185.220.101.5", "country": "Germany", "is_tor": true } },
    { "id": "dom-micro-soft-billing.com", "type": "domain", "data": { "label": "micro-soft-billing.com", "age_days": 4 } },
    { "id": "camp-042", "type": "campaign", "data": { "label": "Campaign #042: Wire Diversion" } }
  ],
  "edges": [
    { "id": "e1", "source": "dom-micro-soft-billing.com", "target": "ip-185.220.101.5", "label": "RESOLVES_TO" },
    { "id": "e2", "source": "dom-micro-soft-billing.com", "target": "camp-042", "label": "PART_OF" }
  ]
}
```

### 7.3 `GET /api/forensics/export/{case_id}/pdf`
Streams a court-admissible PDF forensic dossier with SHA-256 evidence integrity proofs.

### 7.4 `GET /api/forensics/export/{case_id}/stix`
Streams a structured STIX 2.1 JSON bundle for integration with enterprise SIEM/SOAR platforms (Splunk, Microsoft Sentinel, IBM QRadar).

---

## 8. Frontend Forensic Visualizers (`frontend/src/app/components/forensics/`)

### 8.1 Cartographic Relay Map (`HopMapVisualizer.tsx`)
- Built with **Leaflet / React-Leaflet** using high-contrast dark vector tiles.
- Renders origin and intermediary MTA coordinates as pulsing geographic markers.
- Draws an animated geodesic flight path connecting Hop 1 $\rightarrow$ Hop 2 $\rightarrow$ Receiver.
- Interactive popups display MTA hostname, IP address, ISP/ASN, and anonymization flags (Tor/VPN).

### 8.2 Relay Hop Timeline (`RelayHopTimeline.tsx`)
- Vertical chronological card sequence displaying each MTA hop.
- Highlights hop latency (transmission delays between MTAs), alerting on time-travel anomalies.
- Flags bogon IP filtering and highlights the detected Earliest Reliable Public Node (ERPN).

### 8.3 Threat Graph Explorer (`ThreatGraphExplorer.tsx`)
- Interactive force-directed canvas using **`@xyflow/react`**.
- Visualizes the correlation between Senders, Domains, IPs, ASNs, and shared Campaigns.
- Enables SOC analysts to click any node to expand connected historical incidents across the organization.

### 8.4 Cryptographic Protocol Matrix (`AuthStatusMatrix.tsx`)
- Visual pill grid displaying real-time SPF, DKIM, and DMARC status.
- Displays evaluated DNS records, selector names, and domain alignment status (Strict vs. Relaxed).

### 8.5 STIX & Dossier Export Modal (`StixExportModal.tsx`)
- One-click PDF download trigger.
- STIX 2.1 syntax-highlighted JSON viewer with a "Copy to Clipboard" action for SOC automation pipelines.

---

## 9. Browser Extension 2.0 (Forensic Escalator)

The Manifest V3 browser extension (`extension/`) is enhanced to serve as a high-fidelity ingestion bridge:

### 1. In-Inbox "Escalate to Forensic SOC" Action
- When an analyst or user inspects an email in Gmail, `content.js` injects an **"Escalate to Forensic SOC"** button into the email action bar.
- Clicking the button automatically extracts:
  - Raw `Received:` and authentication headers via the Gmail DOM / raw message stream.
  - Thread ID, sender envelope address, and embedded links.
- Packages the payload and dispatches it directly to `POST /api/forensics/analyze-email`.

### 2. High-Risk Threat Ribbon
- Injects a red animated warning ribbon across the top of the message pane if the backend returns a BEC or credential harvesting score $\ge 75\%$.
- Defangs embedded links automatically, replacing raw URLs with safe inspection modals.

---

## 10. Step-by-Step 6-Phase Implementation Roadmap

The upgrade will be implemented sequentially across 6 distinct development phases:

### Phase 1: Environment & Dependencies Setup
- Add forensic dependencies to `backend/requirements.txt`: `geoip2`, `maxminddb`, `dnspython`, `authres`, `mail-parser`, `neo4j`, `datasketch`, `reportlab`, `qrcode[pil]`.
- Bootstrap `backend/data/` with `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`, and `tor_exit_nodes.txt`.
- Add frontend visualizer packages to `frontend/package.json`: `leaflet`, `react-leaflet`, `@xyflow/react`, `jspdf`.
- Apply `backend/sql/supabase_schema_v2.sql` to PostgreSQL.

### Phase 2: Multi-Hop Header & Origin GeoTrace Agents
- Implement `backend/app/agents/header_forensic_agent.py`:
  - Bottom-to-top RFC 5322 `Received:` header decompiler.
  - Live DNS queries for SPF, DKIM public keys, and DMARC alignment policies.
- Implement `backend/app/agents/geo_trace_agent.py`:
  - ERPN algorithm filtering RFC 1918/bogon IP spaces.
  - MaxMind GeoLite2 City and ASN lookups with in-memory fallbacks for development.
- Implement `backend/app/utils/ip_utils.py` for bogon CIDR masking.

### Phase 3: Threat Attribution & Graph Clustering
- Implement `backend/app/graph_db.py`: Neo4j driver with in-memory NetworkX fallback.
- Implement `backend/app/agents/graph_attribution_agent.py`:
  - MinHash / LSH body fingerprinting.
  - Campaign correlation algorithm linking shared infrastructure.
- Implement REST endpoint: `GET /api/forensics/campaigns/{id}/graph`.

### Phase 4: Chain-of-Custody Vault & Evidentiary Reporting
- Upgrade `backend/app/storage.py` to calculate SHA-256, SHA-1, and MD5 evidence hashes upon ingestion.
- Implement `backend/app/agents/forensic_report_agent.py`:
  - STIX 2.1 JSON exporter (`GET /api/forensics/export/{case_id}/stix`).
  - ReportLab PDF generator compiling court-admissible forensic dossiers (`GET /api/forensics/export/{case_id}/pdf`).

### Phase 5: Frontend Forensic Visualizers
- Create `frontend/src/app/components/forensics/HopMapVisualizer.tsx` (Leaflet animated trajectory map).
- Create `frontend/src/app/components/forensics/RelayHopTimeline.tsx` (RFC 5322 chronological cards).
- Create `frontend/src/app/components/forensics/ThreatGraphExplorer.tsx` (`@xyflow/react` campaign network).
- Create `frontend/src/app/components/forensics/AuthStatusMatrix.tsx` (SPF/DKIM/DMARC badges).
- Integrate visualizers into `frontend/src/app/components/Dashboard.tsx` under a new **"Forensic Deep Dive"** tab.

### Phase 6: Browser Extension 1-Click Forensic Escalator
- Update `extension/content.js` to add the **"Escalate to Forensic SOC"** button inside the Gmail message banner.
- Update `extension/background.js` to handle authenticated API dispatch to `/api/forensics/analyze-email`.
- Test the end-to-end flow from Gmail inbox $\rightarrow$ extension escalation $\rightarrow$ forensic analysis $\rightarrow$ PDF dossier generation.

---

## 11. Digital Forensics, Legal Admissibility & Compliance

### 11.1 Evidence Admissibility (ISO/IEC 27037 & Indian BNSS / Evidence Act)
- **Immutable Evidence Hashing:** The moment a raw email payload reaches the backend, its SHA-256 checksum is computed and permanently bound to the `cases` record.
- **Append-Only Cryptographic Audit Log:** Every analyst action (viewing raw headers, annotating notes, exporting reports) is recorded in `forensic_audit_logs` with a hash pointer to the previous entry ($H_n = \text{SHA256}(H_{n-1} + \text{action} + \text{timestamp})$), creating a blockchain-style tamper-evident ledger.
- **Time Synchronization:** All timestamps are recorded in UTC with ISO 8601 formatting and validated against NTP-synchronized MTA hops.

### 11.2 Privacy & Defanging Safeguards
- **Mandatory Defanging:** All extracted URLs, domains, and IP addresses presented in the UI or exported in reports are defanged by default (e.g., `hxxps[://]evil-phish[.]com`, `185[.]220[.]101[.]5`) to eliminate accidental click-through risks for analysts.
- **PII Redaction Engine:** Analysts can toggle automated masking of sensitive personal data (bank account numbers, national IDs, passwords) prior to generating external dossiers.
- **Privacy Mode Guarantee:** In testing or standard consumer mode, `private_mode: true` continues to guarantee zero persistence of email contents or sender identities to disk or database.

---

## 12. Verification & Acceptance Criteria

| Capability | Verification Procedure | Expected Outcome |
| :--- | :--- | :--- |
| **Multi-Hop Relay Extraction** | Submit raw `.eml` with 4 intermediate hops | Parses all 4 hops chronologically, flags internal bogons, and isolates Hop 2 as the true ERPN. |
| **Cryptographic DNS Validation** | Scan spoofed email pretending to be from `paypal.com` | Correctly queries live DNS, detects SPF SoftFail/Fail, DKIM signature invalidity, and DMARC alignment failure. |
| **Origin Geolocation & Tor Flag** | Scan sample email relaying through IP `185.220.101.5` | Maps coordinates to Frankfurt, Germany, flags `is_anonymized = true`, and identifies `TOR Exit Node`. |
| **Campaign Attribution Graph** | Submit 3 separate emails sharing the same sending subnet and MinHash body text | Ingests into graph, automatically groups them under the same Campaign ID, and renders connected nodes in `@xyflow/react`. |
| **Court-Admissible PDF Export** | Click "Export Forensic PDF" on a completed case | Downloads a multi-page PDF containing SHA-256 evidence hashes, relay trajectory tables, authentication proofs, and analyst signature blocks. |
| **Browser Extension Escalation** | Open suspicious email in Gmail and click "Escalate to Forensic SOC" | Dispatches headers to backend, creates new case record, and opens the deep-dive forensic tab in the dashboard within 2 seconds. |
