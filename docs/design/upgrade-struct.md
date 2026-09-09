# SpectraShield 2.0 — Architecture & Upgrade Blueprint (SIH 2026: PS ID 26106)

> **Document Type**: System Architecture, Upgrade Roadmap & Antigravity Implementation Specification  
> **Platform Name**: SpectraShield 2.0 (Forensic Edition)  
> **Problem Statement**: SIH 2026 - Problem Statement ID: 26106 (AICTE Cyber Security Cell)  
> **Title**: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
> **Baseline Codebase**: SpectraShield 1.0 (FastAPI + React/Vite + Manifest V3 Extension)  

---

## 1. Upgrade Executive Summary & Transformation Matrix

SpectraShield 2.0 elevates the existing **SpectraShield 1.0** threat detection engine from a client-side heuristic phishing detector into an **enterprise-grade forensic investigation, multi-hop relay traceability, geolocation intelligence, and campaign attribution platform**.

### Transformation Matrix

| Subsystem | SpectraShield 1.0 (Baseline) | SpectraShield 2.0 (Target Upgrade) |
| :--- | :--- | :--- |
| **Header & Protocol Engine** | Regex parsing of `Received-SPF`, `DKIM-Signature`, and `Authentication-Results` in `header_analyzer.py`. | **RFC 5322 Multi-Hop Relay Parser**: Step-by-step extraction of the full `Received:` chain, timestamp anomaly detection, envelope vs. header alignment, and relay manipulation detection. |
| **Origin & Geolocation** | Basic single-IP hosting lookup in `scanner.py`. | **Earliest Reliable Public Node (ERPN) Engine**: Traverses relay chain outside private subnets, resolves origin coordinates via offline MaxMind GeoLite2, and flags VPN / Tor / Proxy / Cloud exit infrastructure. |
| **Linguistic & Content AI** | Keyword manipulation scoring (Urgency, Fear, Authority, Scarcity) + Levenshtein typosquatting in `manipulation_detector.py`. | **Transformer-based BEC & Social Engineering Engine**: Fine-tuned DeBERTa-v3/RoBERTa for financial diversion, fake invoices, homoglyphs, and inline QR-code payload link extraction. |
| **Threat Graph & Attribution** | Flat 24-hour VirusTotal cache + daily OpenPhish feed sync in `threat_intel.py`. | **Neo4j Entity Infrastructure Graph**: Correlates Domains, IPs, ASNs, Registrars, and MinHash email body fingerprints into unified threat actor campaigns. |
| **Forensics & Chain of Custody** | Ephemeral `private_mode` or unverified JSONB storage in Supabase / MongoDB. | **Court-Admissible Evidence Engine**: RFC 3161 SHA-256 artifact hashing, immutable forensic audit trail, STIX 2.1 JSON exporter, and automated CERT-In / LEA incident response PDF reports. |
| **SOC Console & Extension** | React + Vite Dashboard (heatmap, top brands) + Gmail/LinkedIn Chrome Extension badges. | **Full Forensic SOC Console**: Interactive Leaflet hop-by-hop relay world map, `@xyflow/react` Threat Graph Explorer, and Chrome Extension with a 1-click SOC forensic escalation button. |

---

## 2. Upgraded System Architecture & End-to-End Pipeline

```
                                 [ INGESTION CHANNELS ]
           (Manifest V3 Extension / .EML & .MSG Drag-and-Drop / API / IMAP Webhook)
                                            |
                                            v
                        [ SHA-256 IMMUTABILITY EVIDENCE LAYER ]
                   - Computes RFC 3161 Cryptographic Checksum
                   - Stores raw artifact in encrypted vault with audit log
                                            |
                                            v
                       [ MULTI-AGENT FORENSIC PIPELINE ]
                                            |
    +-----------------------+-----------------------+-----------------------+
    |                       |                       |                       |
    v                       v                       v                       v
[ Header & Routing ]    [ Origin & GeoTrace ]   [ NLP & Content ]       [ Domain & OSINT ]
- RFC 5322 Lexical       - ERPN Algorithm        - DeBERTa-v3 BEC Cues   - WHOIS / RDAP Age
- SPF/DKIM/DMARC Align   - MaxMind GeoLite2      - Homoglyph Detection   - DNSBL Check (Spamhaus)
- Relay Forgery Detect   - Tor/VPN/Cloud Detect  - QR / Link Sandboxing  - Reverse DNS (PTR)
    |                       |                       |                       |
    +-----------------------+-----------------------+-----------------------+
                                            |
                                            v
                   [ CAMPAIGN ATTRIBUTION & GRAPH ENGINE ]
              - Neo4j Graph Correlation: (IP)-[HOSTS]->(Domain)-[SENT]->(Target)
              - MinHash / SSDEEP Structural Body Fingerprinting
              - Campaign Clustering (e.g., "Campaign #402: Edu Phish")
                                            |
                                            v
                   [ COMPOSITE FORENSIC RISK FUSION (0-100) ]
              - Weighted Heuristic Fusion + MITRE ATT&CK Matrix Mapping
              - Explainable AI (XAI) Forensic Summary Synthesis
                                            |
                    +-----------------------+-----------------------+
                    |                                               |
                    v                                               v
     [ CLIENT EXTENSION & NOTIFICATION ]             [ SOC INVESTIGATION DASHBOARD ]
     - In-Inbox Color Coded Threat Ribbon            - Interactive Hop-by-Hop World Map
     - 1-Click Forensic Case Escalation              - Visual Infrastructure Threat Graph
                                                     - STIX 2.1 & PDF Report Exporter
```

---

## 3. Upgraded Annotated Directory Structure

```text
SpectraShield/
├── spec.md                                 # Spec-Driven Development Master Contract
├── struct.md                               # This architecture and implementation blueprint
├── current-struct.md                       # SpectraShield 1.0 Legacy Reference
│
├── backend/                                # Python FastAPI Backend (Upgraded Engine)
│   ├── .env.example
│   ├── requirements.txt                    # Added: maxminddb, geoip2, dnspython, authres, mail-parser, neo4j, reportlab, datasketch
│   ├── data/                               # Offline Threat & Geo Databases
│   │   ├── GeoLite2-City.mmdb              # Offline MaxMind City Database
│   │   ├── GeoLite2-ASN.mmdb               # Offline MaxMind ASN Database
│   │   └── tor_exit_nodes.txt              # Tor Project daily exit nodes list
│   │
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                         # Extended FastAPI app with forensic & campaign routes
│   │   ├── routes.py                       # Modular route controllers
│   │   ├── schemas.py                      # Extended Pydantic schemas (RelayHop, OriginGeo, Campaign, STIX)
│   │   ├── database.py                     # PostgreSQL / Supabase + MongoDB connection pool
│   │   ├── graph_db.py                     # [NEW] Neo4j connection pool and Cypher query builder
│   │   ├── storage.py                      # Storage abstraction with SHA-256 evidence hashing
│   │   ├── pg_collection.py                # PostgreSQL JSONB Mongo-compatible driver
│   │   ├── scanner.py                      # Refactored scanner calling modular micro-agents
│   │   │
│   │   ├── agents/                         # [NEW] Multi-Agent Forensic Computation Modules
│   │   │   ├── __init__.py
│   │   │   ├── header_forensic_agent.py    # Multi-hop RFC 5322 parsing & SPF/DKIM/DMARC alignment
│   │   │   ├── geo_trace_agent.py          # Earliest Reliable Public Node (ERPN) & GeoIP2 resolution
│   │   │   ├── nlp_threat_agent.py         # DeBERTa-v3 BEC, urgency, and cognitive pressure scoring
│   │   │   ├── osint_domain_agent.py       # RDAP, WHOIS, DNSBL (Spamhaus), and SSL inspection
│   │   │   ├── graph_attribution_agent.py  # Neo4j graph linkage & MinHash campaign clustering
│   │   │   └── forensic_report_agent.py    # STIX 2.1 generator & PDF Chain-of-Custody exporter
│   │   │
│   │   ├── services/                       # Preserved & Refactored SpectraShield Services
│   │   │   ├── ai_pattern_detector.py      # LLM synthetic phishing lure detector (Preserved)
│   │   │   ├── attack_simulator.py         # 4-stage killchain consequence generator (Preserved)
│   │   │   ├── brand_detector.py           # Levenshtein typosquatting & brand mismatch (Preserved)
│   │   │   ├── manipulation_detector.py    # Urgency, Fear, Authority, Scarcity heuristics (Preserved)
│   │   │   ├── qr_detector.py              # [NEW] Inline image QR code extractor & URL sandboxing
│   │   │   ├── risk_fusion.py              # Upgraded 0-100 forensic score fusion engine
│   │   │   ├── threat_category.py          # Threat taxonomy classifier & XAI synthesizer (Preserved)
│   │   │   ├── threat_intel.py             # OpenPhish synchronization & VirusTotal worker (Preserved)
│   │   │   └── url_analyzer.py             # Structural URL heuristics & domain age calculator (Preserved)
│   │   │
│   │   └── utils/
│   │       ├── text_preprocess.py          # Text sanitization & regex tokenizers
│   │       └── ip_utils.py                 # [NEW] CIDR subnet checks for private/bogon IP isolation
│   │
│   └── sql/
│       └── supabase_schema_v2.sql          # Extended PostgreSQL DDL (Audit logs, Evidence hashes, Campaigns)
│
├── extension/                              # Chromium Browser Extension (Manifest V3 - Upgraded)
│   ├── manifest.json
│   ├── background.js                       # Handles background forensic uploads & badge states
│   ├── content.js                          # DOM observers for Gmail and LinkedIn + [NEW] 1-Click Forensic Escalator
│   ├── content.css                         # Injected badges, modal styles, and threat ribbons
│   ├── popup.html                          # Quick Scan + Forensic Escalation UI
│   ├── popup.js
│   └── popup.css
│
└── frontend/                               # React 18 + Vite SOC Dashboard (Upgraded)
    ├── package.json                        # Added: leaflet, react-leaflet, @xyflow/react, jspdf
    ├── vite.config.ts
    └── src/
        ├── app/
        │   ├── App.tsx                     # Extended with forensic investigation tabs
        │   ├── api.ts                      # Typed API client for forensic endpoints
        │   │
        │   └── components/
        │       ├── Dashboard.tsx           # Upgraded SOC dashboard with Geo Map & Campaign stats
        │       ├── RiskMeter.tsx           # Preserved circular SVG risk gauge
        │       ├── RiskBreakdown.tsx       # Granular risk bars (Header, Geo, Linguistic, URL)
        │       ├── WhyFlagged.tsx          # Preserved forensic explanation accordion
        │       ├── ActionButtons.tsx       # Preserved remediation controls + [NEW] PDF/STIX export
        │       ├── LinkPreview.tsx         # Preserved sandboxed URL previewer
        │       ├── GmailDemo.tsx           # Preserved Gmail simulation
        │       │
        │       └── forensics/              # [NEW] Dedicated Forensic Visualizers
        │           ├── HopMapVisualizer.tsx # Leaflet world map showing hop-by-hop email relay path
        │           ├── RelayHopTimeline.tsx # Chronological RFC 5322 relay hop cards with IP/ASN
        │           ├── ThreatGraphExplorer.tsx # Interactive @xyflow/react Campaign Graph (IP-Domain-Actor)
        │           ├── AuthStatusMatrix.tsx # Visual SPF, DKIM, DMARC alignment badges
        │           └── StixExportModal.tsx  # STIX 2.1 Threat Intelligence JSON viewer & downloader
```

---

## 4. Upgraded Modules & Algorithms

### 4.1 Header & Relay Path Forensic Agent (`header_forensic_agent.py`)
- **Multi-Hop Extraction**: Parses all `Received:` headers from bottom-to-top (chronological relay order).
- **Authentication Matrix**:
  - **SPF**: Verifies whether sending IP matches SPF records on `Return-Path` domain (`Pass`, `Fail`, `SoftFail`, `Neutral`).
  - **DKIM**: Checks cryptographic header signatures against DNS public keys (`Pass`, `Fail`, `None`).
  - **DMARC**: Evaluates alignment between `From` header and SPF/DKIM domains, checking enforcement policy (`none`, `quarantine`, `reject`).
- **Relay Manipulation Detection**:
  - Flags timestamp inversions (hop $N+1$ timestamp earlier than hop $N$).
  - Flags private IP injection in external hops.
  - Flags synthetic Message-ID mismatches.

### 4.2 Origin Resolution & Geolocation Agent (`geo_trace_agent.py`)
- **Earliest Reliable Public Node (ERPN)**:
  1. Inspects the chronologically first `Received:` hop.
  2. If the IP belongs to a private/bogon range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`), moves to the next outer hop until the first public IPv4/IPv6 address is reached.
  3. Queries `GeoLite2-City.mmdb` for Country, City, Latitude, and Longitude.
  4. Queries `GeoLite2-ASN.mmdb` for Autonomous System Number and ISP Name.
  5. Cross-references against `tor_exit_nodes.txt` and known VPN subnet lists to detect anonymization.

### 4.3 Campaign Attribution & Graph Agent (`graph_attribution_agent.py`)
- **Neo4j Cypher Data Ingestion**:
  ```cypher
  MERGE (e:Email {hash: $email_hash})
  MERGE (ip:IPAddress {ip: $origin_ip, country: $country})
  MERGE (d:Domain {name: $sender_domain})
  MERGE (asn:ASN {number: $asn_number, org: $isp})
  MERGE (e)-[:ORIGINATED_FROM]->(ip)
  MERGE (ip)-[:HOSTED_BY]->(asn)
  MERGE (e)-[:USES_DOMAIN]->(d)
  ```
- **Structural Similarity Clustering**:
  - Computes a MinHash signature on normalized email text.
  - Clusters emails with Jaccard similarity $\ge 0.75$ into named threat campaigns (e.g., `"Campaign-2026-M365-Finance"`).

### 4.4 Upgraded Risk Fusion Algorithm (`risk_fusion.py`)

$$	ext{HeaderScore} = (0.4 	imes S_{	ext{SPF}}) + (0.35 	imes S_{	ext{DKIM}}) + (0.25 	imes S_{	ext{DMARC}}) + 	ext{AnomalyPenalty}$$

$$	ext{OriginScore} = S_{	ext{ASN\_Rep}} + (30 	ext{ if Anonymized else } 0)$$

$$	ext{CompositeScore} = (0.25 	imes S_{	ext{Manipulation}}) + (0.25 	imes S_{	ext{Header}}) + (0.25 	imes S_{	ext{Origin}}) + (0.25 	imes S_{	ext{URL}})$$

$$	ext{FinalRisk} = \minig(100.0, \max(	ext{CompositeScore}, S_{	ext{Killchain\_Severity}})ig)$$

---

## 5. Upgraded REST API Specification

### `POST /api/forensics/analyze-email`
- **Description**: Full forensic evaluation endpoint accepting raw `.eml` text, headers, and metadata.
- **Request Body**:
```json
{
  "raw_eml": "Received: from mail.attacker.com ...
Subject: Urgent Invoice
...",
  "sender_email": "billing@micro-soft-sec.top",
  "private_mode": false
}
```
- **Response**:
```json
{
  "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "final_risk": 96.5,
  "verdict": "High Risk / Malicious",
  "threat_category": "Business Email Compromise (BEC)",
  "authentication": {
    "spf": { "status": "fail", "domain": "micro-soft-sec.top" },
    "dkim": { "status": "none", "domain": null },
    "dmarc": { "status": "fail", "policy": "none", "aligned": false }
  },
  "originating_node": {
    "ip": "185.220.101.5",
    "country": "Germany",
    "city": "Frankfurt",
    "lat": 50.1109,
    "lon": 8.6821,
    "isp": "Tor Exit Router Network",
    "asn": "AS60729",
    "is_anonymized": true,
    "anonymization_type": "TOR"
  },
  "relay_path": [
    {
      "hop": 1,
      "from_host": "client-host.local",
      "by_host": "mail.attacker.com",
      "ip": "185.220.101.5",
      "geo": { "country": "Germany", "lat": 50.1109, "lon": 8.6821 },
      "timestamp": "2026-09-02T02:00:00Z"
    },
    {
      "hop": 2,
      "from_host": "mail.attacker.com",
      "by_host": "mx.google.com",
      "ip": "172.217.194.27",
      "geo": { "country": "United States", "lat": 37.422, "lon": -122.084 },
      "timestamp": "2026-09-02T02:00:02Z"
    }
  ],
  "campaign": {
    "id": "CAMP-2026-089",
    "name": "Targeted Financial BEC Campaign",
    "linked_incidents_count": 14
  },
  "mitre_tactics": ["T1566.002 - Spearphishing Link", "T1598.003 - Spearphishing for Information"],
  "reasoning_summary": "Failed DMARC alignment, origin traced to a known Tor Exit Node in Germany, and high urgency financial coercion language detected."
}
```

### `GET /api/forensics/campaigns/:id/graph`
- **Description**: Returns Neo4j nodes and edges for the visual graph explorer in the frontend.
- **Response**:
```json
{
  "nodes": [
    { "id": "ip-185.220.101.5", "label": "Origin IP: 185.220.101.5", "type": "ip" },
    { "id": "dom-micro-soft-sec.top", "label": "Domain: micro-soft-sec.top", "type": "domain" },
    { "id": "camp-089", "label": "Campaign #089", "type": "campaign" }
  ],
  "edges": [
    { "source": "dom-micro-soft-sec.top", "target": "ip-185.220.101.5", "label": "RESOLVES_TO" },
    { "source": "dom-micro-soft-sec.top", "target": "camp-089", "label": "PART_OF" }
  ]
}
```

### `GET /api/forensics/export/:id/pdf`
- **Description**: Generates and downloads a court-admissible PDF forensic incident report with SHA-256 evidence verification.

---

## 6. Phased Antigravity Implementation Plan

To systematically upgrade the SpectraShield repository using Antigravity, execute the following 6 sequential phases:

### Phase 1: Environment & Dependencies Setup
1. Update `backend/requirements.txt` with `geoip2`, `maxminddb`, `dnspython`, `authres`, `mail-parser`, `neo4j`, `datasketch`, `reportlab`, and `qrcode[pil]`.
2. Add offline database bootstrap script to automatically download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` into `backend/data/`.
3. Update `frontend/package.json` to include `leaflet`, `react-leaflet`, `@xyflow/react`, and `jspdf`.

### Phase 2: Multi-Hop Header & Origin GeoTrace Agents
1. Implement `backend/app/agents/header_forensic_agent.py` to tokenize `Received:` hops and validate SPF/DKIM/DMARC.
2. Implement `backend/app/agents/geo_trace_agent.py` with ERPN resolution and MaxMind GeoIP lookups.
3. Add in-memory fallback for MaxMind when `.mmdb` files are missing during dev tests.

### Phase 3: Graph Attribution & Campaign Clustering
1. Implement `backend/app/graph_db.py` to establish connection to Neo4j (with in-memory dictionary fallback).
2. Build `backend/app/agents/graph_attribution_agent.py` using MinHash / LSH to cluster similar email bodies into campaigns.
3. Add `GET /api/forensics/campaigns/:id/graph` endpoint.

### Phase 4: Forensics Reporting & Evidence Vault
1. Implement `backend/app/agents/forensic_report_agent.py` to generate STIX 2.1 JSON and PDF reports via `reportlab`.
2. Implement SHA-256 cryptographic immutability hashing upon ingestion in `backend/app/storage.py`.

### Phase 5: Frontend Forensic Visualizers
1. Create `HopMapVisualizer.tsx` using `react-leaflet` to draw animated polyline paths across email relay hops.
2. Create `RelayHopTimeline.tsx` for step-by-step RFC 5322 header inspection.
3. Create `ThreatGraphExplorer.tsx` using `@xyflow/react` to render connected campaign nodes.
4. Integrate visualizers into `frontend/src/app/components/Dashboard.tsx` and `App.tsx`.

### Phase 6: Browser Extension 1-Click Forensic Escalator
1. Update `extension/content.js` to add an **"Escalate to Forensic SOC"** button inside the Gmail opened email banner.
2. Update `extension/background.js` to handle authenticated API dispatch to `/api/forensics/analyze-email`.
3. Verify end-to-end integration and run tests.
