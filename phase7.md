# Software Design Document (SDD) & Technical Specification — Phase 7

**Document Title:** External Threat Feeds (CTI), Active DNS Cryptographic DKIM Validation & Deep Transformer NLP Pipeline  
**Project Name:** SpectraShield 2.0 (Forensic Edition)  
**Short Name:** AegisMail Forensics (AegisMail_AI)  
**Phase Identifier:** Phase 7 of Version 2.0 (Sprint 4 Roadmap — 100% Target Specification Completion)  
**SIH Problem Statement ID:** 26106 (AICTE Cyber Security Cell)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  
**Target Beneficiaries:** Enterprise Threat Intelligence Teams, Advanced Cyber Defense Units, Federal LEA Cyber Investigators  
**Baseline System State:** SpectraShield 2.0 (Phase 6 Foundation)  
**Date:** September 2026  

---

## 1. Project Overview & Phase 7 Executive Summary

### 1.1 Executive Summary
SpectraShield 2.0 has systematically evolved into a formidable, court-admissible forensic investigation console with persistent case storage, multi-format binary ingestion (`.eml`, `.msg`, `.mbox`), quarantine isolation, quishing QR extraction, and 4-tier RBAC security with 2FA TOTP.

To reach **100% strict compliance** with the SIH 26106 AegisMail Forensics master specification, three final analytical frontiers must be integrated:
1. **Multi-Feed External Cyber Threat Intelligence (CTI) Connectors (`INT-03`, `GEO-02`):** Real-time asynchronous hooks to Google Safe Browsing API v4, abuse.ch URLhaus, and AbuseIPDB, coupled with a commercial VPN subnet CIDR matcher (NordVPN, ExpressVPN, Surfshark, Mullvad).
2. **Active Standalone DNS DKIM RSA Validation (`HDR-03`):** Resolving raw DNS TXT records (`selector._domainkey.domain.com`) via `dnspython` and mathematically validating RSA-SHA256 / Ed25519 cryptographic signatures independently of potentially spoofed upstream MTA headers.
3. **Deep Transformer NLP BEC Classifier & VIP Roster (`NLP-01`, `NLP-03`):** Deploying an offline-capable, quantized RoBERTa / DeBERTa-v3 model via Hugging Face `transformers` for zero-shot semantic intent classification, coupled with dynamic organizational VIP roster management in the frontend.
4. **Graph Community Modularity Clustering (`GRP-02`):** Implementing the Louvain modularity clustering algorithm to automatically partition multi-case threat graphs into named attack syndicates (e.g. FIN7, Storm-0539).

**Phase 7** brings SpectraShield to absolute completion, uniting deep machine learning, live threat intelligence feeds, and mathematical cryptographic rigor.

### 1.2 Phase 7 Mission & Objectives
- **Integrate Global CTI Feeds:** Connect asynchronous clients for Google Safe Browsing v4, URLhaus, and AbuseIPDB with zero-key fallback resilience.
- **Stand-Alone Cryptographic Verification:** Calculate DKIM canonicalization and RSA signature verification from raw DNS keys.
- **Deep Semantic Language Models:** Augment heuristic urgency scoring with fine-tuned transformer classification for financial wire fraud and credential lures.
- **Syndicate Community Detection:** Execute Louvain community clustering on the threat network graph to identify distributed infrastructure clusters.

---

## 2. Tech Stack & Dependencies

### 2.1 Backend Architecture
- **Runtime:** Python 3.11+
- **DNS Protocol Engine:** `dnspython` 2.6+ (direct asynchronous DNS queries, DNSSEC validation)
- **Cryptographic Math:** `cryptography` 42.0+ (RSA public key parsing, SHA256 signature verification)
- **Deep Learning / NLP Pipeline:**
  - `transformers` 4.38+ / `torch` (CPU-quantized ONNX / PyTorch inference)
  - Pre-trained / Fine-tuned model: `cross-encoder/ms-marco-MiniLM-L-6-v2` or quantized `DeBERTa-v3-small` for intent classification
- **Threat Intelligence & Graph Analytics:**
  - `httpx` 0.27+ (Asynchronous HTTP client for threat feeds)
  - `python-louvain` 0.16+ / `networkx.algorithms.community` (Graph community detection)
  - `ipaddress` (Standard library for high-speed CIDR subnet matching)

### 2.2 Frontend Architecture
- **Framework:** React 18, TypeScript, Vite
- **Visual Graph:** `@xyflow/react` with color-coded community cluster boundaries
- **Universal Liquid Glass Components:** CTI Multi-Feed reputation badge, VIP Impersonation alert card, Live DNS protocol inspector

---

## 3. Core Features & Detailed Specifications

### 3.1 Feature INT-03/GEO-02-EXT: Multi-Feed CTI & Commercial VPN Matcher
- **Technical Description:**
  1. **Google Safe Browsing v4 Client:** Asynchronously dispatches batch threat queries (`POST https://safebrowsing.googleapis.com/v4/threatMatches:find`) checking for `MALWARE`, `SOCIAL_ENGINEERING`, and `UNWANTED_SOFTWARE`.
  2. **URLhaus Live API Client:** Queries `https://urlhaus-api.abuse.ch/v1/url/` to check whether extracted links match known malware drop sites.
  3. **AbuseIPDB Client:** Queries `https://api.abuseipdb.com/api/v2/check` for originating IP abuse confidence scores.
  4. **Commercial VPN CIDR Database:** Offline IPv4/IPv6 CIDR table indexing 4,500+ commercial VPN exit subnets (NordVPN, ExpressVPN, Surfshark, Mullvad, CyberGhost). Matches originating IP in <1ms without external network latency.

### 3.2 Feature HDR-03-DNS: Independent DKIM RSA Cryptographic Math
- **Technical Description:**
  1. Extract `d=` (domain), `s=` (selector), `b=` (signature), `bh=` (body hash), and `h=` (signed headers) from the `DKIM-Signature` header.
  2. Fetch the public key TXT record directly from DNS: `<selector>._domainkey.<domain>`.
  3. Parse the public key from the `p=` tag (base64-encoded ASN.1 SubjectPublicKeyInfo).
  4. Recompute the canonicalized body hash and verify it matches `bh=`.
  5. Mathematically verify the RSA-SHA256 signature using `cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15`.
  6. Return a deterministic verdict: `PASS (RSA-2048 Verified)`, `FAIL (Body Hash Mismatch)`, `FAIL (Bad Signature)`, or `FAIL (DNS Key Not Found)`.

### 3.3 Feature NLP-01-TRANS: Quantized Transformer BEC Classifier
- **Technical Description:**
  - Integrates a compact, quantized transformer pipeline running locally in Python.
  - Classifies email text across 6 primary tactical vectors:
    1. `CLEAN_BENIGN`
    2. `CREDENTIAL_HARVESTING`
    3. `FINANCIAL_WIRE_FRAUD`
    4. `INVOICE_SUPPLIER_FRAUD`
    5. `EXECUTIVE_IMPERSONATION`
    6. `EXTORTION_BLACKMAIL`
  - Fuses transformer probabilities with heuristic urgency cues to produce an explainable semantic risk score.

### 3.4 Feature GRP-02-LOUVAIN: Threat Actor Campaign Community Detection
- **Technical Description:**
  - Evaluates the global incident correlation graph in `app/graph_db.py`.
  - Executes the Louvain modularity algorithm ($Q \ge 0.65$) to partition interconnected entities into cohesive clusters.
  - Automatically identifies infrastructure reuse: when distinct cases share an ASN, a lookalike domain registrar, and an attachment SimHash, they are grouped into a named threat syndicate (e.g. `SYNDICATE-FIN-2026-A`).

---

## 4. Architecture & Feed Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PHASE 7 ADVANCED INTELLIGENCE PIPELINE                 │
└─────────────────────────────────────────────────────────────────────────────┘
  [ Ingested Email Headers & Body ]
                 │
  ┌──────────────┼──────────────────────────────┬─────────────────────────────┐
  ▼              ▼                              ▼                             ▼
[ Active DKIM ] [ Commercial VPN Subnets ]    [ Multi-Feed CTI ]        [ Transformer NLP ]
- dnspython     - Local CIDR Radix Tree       - Google Safe Browsing    - RoBERTa / DeBERTa
- RSA Math      - 4,500+ VPN IP Ranges        - URLhaus API             - Zero-Shot Intent
- Key Length    - NordVPN/ExpressVPN/Tor      - AbuseIPDB Confidence    - Financial Diversion
  │              │                              │                             │
  └──────────────┼──────────────────────────────┴─────────────────────────────┘
                 │
                 ▼
    [ COMPOSITE RISK FUSION 2.0 ]
                 │
                 ▼
    [ LOUVAIN COMMUNITY CLUSTERING ]
    - NetworkX modularity partitioning
    - Maps campaign syndicates
                 │
                 ▼
    [ FORENSIC SOC CONSOLE / EXPORTS ]
    - Visual CTI Badges
    - Cluster Highlighting in Threat Graph
```

---

## 5. Database Schemas & Pydantic Models

### 5.1 Updated Pydantic Models (`backend/app/schemas.py`)
```python
class CtiReputationRecord(BaseModel):
    indicator: str
    source: str  # "Google Safe Browsing" | "URLhaus" | "AbuseIPDB" | "Commercial VPN"
    is_malicious: bool
    threat_category: Optional[str] = None
    confidence_score: float
    details: Dict[str, Any] = {}

class DkimVerificationDetails(BaseModel):
    selector: str
    signing_domain: str
    key_length_bits: int
    algorithm: str  # "rsa-sha256" | "ed25519"
    body_hash_valid: bool
    signature_math_valid: bool
    dns_key_published: bool
    raw_public_key: Optional[str] = None
    verification_status: str  # "PASS" | "FAIL" | "NONE"

class TransformerNlpResult(BaseModel):
    predicted_category: str
    confidence: float
    category_probabilities: Dict[str, float]
    model_name: str
    inference_latency_ms: float
```

---

## 6. API Endpoints Specification

### 6.1 `GET /api/forensics/cti/lookup`
- **Parameters:** `query: str` (IP, Domain, or URL)
- **Response:** Consolidated reputation verdicts across Safe Browsing, URLhaus, AbuseIPDB, and VPN databases.

### 6.2 `GET /api/forensics/campaigns/communities`
- **Response:** Clustered graph communities computed via the Louvain algorithm for `@xyflow/react` visual grouping.

---

## 7. Frontend Components & Universal Liquid Glass UI

### 7.1 Multi-Feed Threat Badge (`CtiReputationMatrix.tsx`)
- Displays live query status and verdicts for Google Safe Browsing, URLhaus, and AbuseIPDB.
- Pulsing glass indicators showing query latency and source feed attribution.

### 7.2 Dynamic VIP Roster Configuration Modal
- Allows SOC administrators to define high-value executive names (CEO, CFO, Legal Counsel) and corporate email domains.
- Automatically flags free webmail addresses spoofing executive display names.

### 7.3 Community-Clustered Threat Graph
- Renders glowing chromatic halos around nodes belonging to the same Louvain cluster in `ThreatGraphView.tsx`.

---

## 8. Annotated File Modification Matrix

```text
SpectraShield/
├── backend/
│   ├── requirements.txt                         # Added: dnspython, cryptography, transformers, python-louvain
│   ├── app/
│   │   ├── services/
│   │   │   ├── cti_service.py                   # [NEW] Safe Browsing, URLhaus, AbuseIPDB async clients
│   │   │   ├── vpn_matcher.py                   # [NEW] CIDR subnet matcher for commercial VPNs
│   │   │   └── dkim_verifier.py                 # [NEW] dnspython & cryptography RSA signature validator
│   │   ├── agents/
│   │   │   ├── nlp_threat_agent.py              # [MODIFY] Integrated local quantized transformer pipeline
│   │   │   └── graph_attribution_agent.py       # [MODIFY] Added Louvain community clustering
│   │   └── forensic_routes.py                   # [MODIFY] Exposed CTI query and community endpoints
│
└── frontend/
    └── src/
        ├── app/
        │   └── components/
        │       └── forensics/
        │           ├── CtiReputationMatrix.tsx  # [NEW] Multi-feed threat badge visualizer
        │           └── VipRosterModal.tsx       # [NEW] Executive display name management dialog
```

---

## 9. Step-by-Step Implementation Roadmap

### Milestone 7.1: Multi-Feed CTI Clients & Commercial VPN Radix Tree
- [ ] Implement `cti_service.py` with asynchronous clients for Safe Browsing v4, URLhaus, and AbuseIPDB.
- [ ] Build offline commercial VPN CIDR subnet database in `vpn_matcher.py`.
- [ ] Fuse feed results into `risk_fusion.py`.

### Milestone 7.2: Active DNS DKIM RSA Signature Verifier
- [ ] Implement `dkim_verifier.py` using `dnspython` and `cryptography`.
- [ ] Verify body hash canonicalization and RSA public key validation.
- [ ] Integrate into `header_forensic_agent.py` and the frontend Protocol Matrix.

### Milestone 7.3: Local Transformer NLP Pipeline
- [ ] Setup CPU-quantized HuggingFace pipeline in `nlp_threat_agent.py` with heuristic fallback.
- [ ] Add executive display name VIP roster matching (`VipRosterModal.tsx`).

### Milestone 7.4: Threat Graph Louvain Clustering
- [ ] Implement Louvain modularity algorithm on the NetworkX threat graph.
- [ ] Update `@xyflow/react` canvas to display community cluster bounding boxes.

---

## 10. Verification & Quality Gates

1. **DKIM Math Gate:** Test against an email with a valid DKIM signature; verify that `dkim_verifier.py` queries DNS, computes the RSA math, and returns `PASS`.
2. **CTI Feed Gate:** Submit a known malicious test URL (e.g. `http://malware.testing.google.test/testing/malware/`); verify Safe Browsing flags the threat.
3. **VPN Subnet Gate:** Test IP `185.220.101.5` and NordVPN exit ranges; verify that `vpn_matcher.py` detects commercial anonymization with zero network latency.
4. **Final 100% Compliance Audit:** Run the full automated test suite: `pytest tests/` covering all 7 phases with 100% pass rate.
5. **Production Build Gate:** Execute `npm run build` with clean zero-warning compilation.
