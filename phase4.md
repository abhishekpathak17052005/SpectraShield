# Software Design Document (SDD) & Technical Specification — Phase 4

**Document Title:** Database Persistence, Defanged CSV Threat Export & Homoglyph Visual Substitution  
**Project Name:** SpectraShield 2.0 (Forensic Edition)  
**Short Name:** AegisMail Forensics (AegisMail_AI)  
**Phase Identifier:** Phase 4 of Version 2.0 (Sprint 1 Roadmap)  
**SIH Problem Statement ID:** 26106 (AICTE Cyber Security Cell)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  
**Target Beneficiaries:** SOC Analysts, Incident Response Teams, Forensic Investigators, Law Enforcement Agencies (LEAs)  
**Baseline System State:** `SpectraShield 2.0.0-phase3` (Verified Operational Baseline)  
**Date:** September 2026  

---

## 1. Project Overview & Phase 4 Executive Summary

### 1.1 Executive Summary
SpectraShield 2.0 currently delivers state-of-the-art email forensic capabilities: multi-hop RFC 5322 relay decompilation, Earliest Reliable Public Node (ERPN) geolocation, Levenshtein typosquatting detection, Shannon entropy attachment triage, NetworkX threat attribution graphing, and ISO/IEC 27037 compliant PDF reporting.

However, an operational audit reveals three critical production gaps in the active system:
1. **In-Memory Volatility of Forensic Evidence:** While regular scan telemetry (`/history`) persists in PostgreSQL/MongoDB, deep forensic cases instantiated in `app/storage.py` (`EvidenceVault`) reside in an ephemeral in-memory Python dictionary. Server reboots or worker recycling wipe active investigations, reverting cases to baseline mocks.
2. **Missing Tabular Threat IOC Exporter (`REP-02`):** While STIX 2.1 JSON and PDF dossiers are operational, security analysts and SOC firewalls require a rapid, defanged CSV export containing extracted IPs, domains, and file hashes for immediate blocklist deployment into SIEM/SOAR platforms (Splunk, Microsoft Sentinel, Fortinet).
3. **Punycode & Unicode Homoglyph Visual Diff (`INT-02`):** Although Levenshtein distance detects typosquatted brands, analysts lack a dedicated visual diff chip highlighting deceptive Cyrillic, Greek, or Punycode character substitutions (e.g. Cyrillic `а` `\u0430` substituted for Latin `a` `\u0061`).

**Phase 4** resolves these gaps by establishing persistent database storage for the Evidence Vault, delivering a one-click defanged CSV threat exporter, and building a high-fidelity visual homoglyph substitution diff viewer adhering to the Universal Liquid Glass design system.

### 1.2 Phase 4 Mission & Objectives
- **Persistent Evidence Vault Storage:** Connect `EvidenceVault` to MongoDB collections (`forensic_cases`, `forensic_analyses`, `audit_ledger`) and PostgreSQL JSONB tables with automated fallback to in-memory mode when database drivers are offline.
- **Defanged CSV IOC Exporter:** Implement `GET /api/forensics/export/{case_id}/csv` in FastAPI and integrate a "Download Defanged CSV" action with preview modal into `StixExportModal.tsx`.
- **Cyrillic & Punycode Visual Substitution Engine:** Build a Unicode homoglyph analysis engine in `brand_detector.py` and a dedicated Universal Liquid Glass visual diff chip in the frontend displaying replaced character code points side-by-side.
- **Zero-Downtime Migration:** Ensure 100% backward compatibility with existing unit tests (`test_forensics.py`, `test_phase3.py`) and maintain the zero-credential out-of-the-box evaluation mode.

---

## 2. Tech Stack & Dependencies

### 2.1 Backend Architecture
- **Runtime:** Python 3.11+
- **API Framework:** FastAPI 0.109+ with Uvicorn
- **Database Drivers:**
  - `motor` 3.3+ / `pymongo` 4.6+ (MongoDB async driver)
  - `asyncpg` 0.29+ / `psycopg2-binary` (PostgreSQL async engine)
- **Data Serialization & Validation:** Pydantic v2
- **Text & Encoding Analysis:** Python standard library `unicodedata`, `idna` (RFC 3492 Punycode decompiler)

### 2.2 Frontend Architecture
- **Framework:** React 18, TypeScript, Vite
- **Styling:** Tailwind CSS, Universal Liquid Glass design tokens (`theme.css`)
- **Icons:** Lucide React (`FileSpreadsheet`, `Download`, `Sparkles`, `Binary`, `AlertTriangle`)
- **State & Data Fetching:** Native fetch client in `frontend/src/app/api.ts`

---

## 3. Core Features & Detailed Specifications

### 3.1 Feature CAS-01/02-DB: Persistent Evidence Vault Engine
- **Technical Description:** Transition `EvidenceVault` in `backend/app/storage.py` from an in-memory dictionary `_cases: Dict[str, Dict]` to an asynchronous database-backed persistence layer supporting MongoDB and PostgreSQL (with transparent in-memory dev fallback).
- **Inputs:** Case metadata, RFC 5322 header analyses, SHA-256 evidence digests, investigator notes, and audit log blocks.
- **Outputs:** Persistent case retrieval across backend reboots, queryable case archives, and immutable block-linked audit ledger.
- **Implementation Logic:**
  1. Inspect `app/config.py` for `DATABASE_URL` (PostgreSQL) or `MONGODB_URI`.
  2. If configured, initialize `AsyncIOMotorClient` (MongoDB) or async connection pool (PostgreSQL).
  3. Implement asynchronous CRUD methods: `save_case()`, `get_case()`, `list_cases()`, `update_status()`, `append_note()`, `append_audit_block()`.
  4. If neither database is reachable, log a graceful warning and fall back to the existing in-memory dictionary so local development and automated CI tests never fail.

### 3.2 Feature REP-02-CSV: Defanged CSV Threat IOC Exporter
- **Technical Description:** Provide high-speed tabular export of all indicators of compromise (IOCs) discovered during email decompilation, formatted as a defanged RFC 4180 CSV stream.
- **Inputs:** `case_id` via HTTP request.
- **Outputs:** `text/csv` stream with headers: `ioc_type,defanged_value,raw_value,threat_category,confidence_score,context_source,first_seen`.
- **Defanging Rules:**
  - IPv4/IPv6: `185.220.101.5` -> `185[.]220[.]101[.]5`
  - Domains: `micro-soft-sec.top` -> `micro-soft-sec[.]top`
  - URLs: `https://login.evil.com/auth` -> `hxxps[://]login[.]evil[.]com/auth`
  - Email Addresses: `phish@evil.com` -> `phish[@]evil[.]com`
  - Hashes (SHA-256, MD5): Kept intact for SIEM hash matching.

### 3.3 Feature INT-02-DIFF: Punycode & Homoglyph Visual Substitution Engine
- **Technical Description:** Detect lookalike Internationalized Domain Names (IDN) and mixed-script homoglyphs where attackers substitute visually indistinguishable characters from non-Latin scripts (Cyrillic, Greek, Armenian) to spoof protected organizational brands.
- **Homoglyph Substitution Mapping Matrix:**
  | Latin Character | Unicode Code Point | Lookalike Cyrillic Character | Cyrillic Code Point |
  | :--- | :--- | :--- | :--- |
  | `a` | `U+0061` | `а` | `U+0430` |
  | `c` | `U+0063` | `с` | `U+0441` |
  | `e` | `U+0065` | `е` | `U+0435` |
  | `i` | `U+0069` | `і` | `U+0456` |
  | `j` | `U+006A` | `ј` | `U+0458` |
  | `o` | `U+006F` | `о` | `U+043E` |
  | `p` | `U+0070` | `р` | `U+0440` |
  | `s` | `U+0073` | `ѕ` | `U+0455` |
  | `x` | `U+0078` | `х` | `U+0445` |
  | `y` | `U+0079` | `у` | `U+0443` |
- **Inputs:** Extracted sender domain and visible URLs.
- **Outputs:** Homoglyph detection summary with flag `is_homoglyph: bool`, `punycode: str`, `target_brand: str`, and `substituted_chars: List[Dict]` specifying each character index, original character, lookalike character, and Unicode script category.

---

## 4. Architecture & Service Decomposition

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FASTAPI BACKEND PIPELINE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. INGESTION & PARSER                                                       │
│    POST /api/forensics/analyze-email ────────┐                              │
│                                              ▼                              │
│ 2. BRAND DETECTOR ENHANCEMENT           [ EvidenceVault ]                   │
│    - detect_brand_typosquatting()       (app/storage.py)                    │
│    - analyze_homoglyphs()                    │                              │
│      ├── Punycode decode (idna)              ├── PostgreSQL / Supabase      │
│      └── unicodedata script audit            ├── MongoDB Collections        │
│                                              └── In-Memory Fallback         │
│ 3. IOC CSV EXPORT ENGINE                     │                              │
│    GET /api/forensics/export/{id}/csv ───────┘                              │
│    - Iterates extracted_urls, hops, attachments                             │
│    - Applies RFC 4180 formatting and IOC defanging                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ JSON / CSV
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        REACT FORENSIC SOC FRONTEND                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. StixExportModal.tsx: Added "Download Defanged CSV" button & IOC preview  │
│ 2. HomoglyphDiffChip.tsx: Visual Unicode comparison chip with pill labels   │
│ 3. ForensicOpsView.tsx: Injected homoglyph alert card with char inspector   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Database Collections, Models & Schemas

### 5.1 MongoDB Collections / PostgreSQL Tables
1. **`forensic_cases`**:
   ```json
   {
     "_id": "CASE-2026-0906-8A1F",
     "case_id": "CASE-2026-0906-8A1F",
     "created_at": "2026-09-06T14:20:00Z",
     "updated_at": "2026-09-06T14:20:00Z",
     "sha256_hash": "e8e4a726b23...a48c",
     "status": "NEW",
     "final_risk": 87.5,
     "verdict": "High Risk / Malicious",
     "threat_category": "Business Email Compromise (BEC)",
     "assigned_analyst": "Senior Forensic Lead",
     "tags": ["BEC", "Tor-Origin", "DMARC-Fail"]
   }
   ```

2. **`forensic_analyses`**:
   Stores the full multi-agent output (header hops, origin geolocation, NLP scores, authentication matrix, attachments, and homoglyph analysis).

3. **`forensic_audit_ledger`**:
   Stores ISO 27037 block-linked entries:
   ```json
   {
     "_id": "LOG-001",
     "case_id": "CASE-2026-0906-8A1F",
     "timestamp": "2026-09-06T14:20:01Z",
     "actor": "System / Automated Forensic Ingestion",
     "action": "EVIDENCE_SEALED",
     "details": "SHA-256: e8e4a726... computed. Case sealed.",
     "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
     "block_hash": "a1b2c3d4..."
   }
   ```

### 5.2 Python Pydantic Schemas (`backend/app/schemas.py`)
```python
class HomoglyphChar(BaseModel):
    index: int
    raw_char: str
    lookalike_char: str
    unicode_hex: str
    script: str

class HomoglyphAnalysis(BaseModel):
    has_homoglyphs: bool
    is_punycode: bool
    punycode_ascii: Optional[str] = None
    target_brand: Optional[str] = None
    substituted_characters: List[HomoglyphChar] = []
    risk_score_modifier: float = 0.0
```

---

## 6. API Endpoints Specification

### 6.1 `GET /api/forensics/export/{case_id}/csv`
- **Method:** `GET`
- **Parameters:**
  - Path: `case_id` (str, required)
  - Query: `defang` (bool, default `true`)
- **Response Type:** `text/csv`
- **Content-Disposition:** `attachment; filename="SpectraShield_IOCs_{case_id}.csv"`
- **Response Example:**
  ```csv
  ioc_type,defanged_value,raw_value,threat_category,confidence_score,context_source,first_seen
  origin_ip,185[.]220[.]101[.]5,185.220.101.5,Tor Exit Router,95.0,Relay Hop 1,2026-09-06T14:20:00Z
  sender_domain,micro-soft-sec[.]top,micro-soft-sec.top,Typosquatting/Homoglyph,88.0,Header From,2026-09-06T14:20:00Z
  phishing_url,hxxps[://]micro-soft-sec[.]top/login.php,https://micro-soft-sec.top/login.php,Credential Harvester,92.0,Email Body Link,2026-09-06T14:20:00Z
  attachment_hash,9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08,9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08,Malicious Macro Payload,85.0,invoice_overdue.docm,2026-09-06T14:20:00Z
  ```

---

## 7. Frontend Components & Universal Liquid Glass UI

### 7.1 New Component: `HomoglyphDiffChip.tsx`
- **Location:** `frontend/src/app/components/forensics/HomoglyphDiffChip.tsx`
- **Visual Design:** Universal Liquid Glass card with specular amber caustic pooling (`--accent-warning`), displaying:
  - Deceptive Domain side-by-side with genuine target brand.
  - Substituted character highlighted with an optical lens magnifying effect and Unicode code point badge (`U+0430` Cyrillic Small Letter A).
  - Punycode string representation (`xn--...`).

### 7.2 Updated Component: `StixExportModal.tsx`
- **Location:** `frontend/src/app/components/forensics/StixExportModal.tsx`
- **Enhancements:**
  - Segmented control toggling between **STIX 2.1 JSON** view and **Defanged CSV IOC** tabular view.
  - One-click `[ Download Defanged CSV ]` button with diagonal specular sheen wave sweep.

---

## 8. Annotated File Modification Matrix

```text
SpectraShield/
├── backend/
│   ├── requirements.txt                         # Added: asyncpg, motor (optional db drivers)
│   ├── app/
│   │   ├── storage.py                           # [MODIFY] Persistent Mongo/Postgres storage for EvidenceVault
│   │   ├── schemas.py                           # [MODIFY] Added HomoglyphChar and HomoglyphAnalysis
│   │   ├── forensic_routes.py                   # [MODIFY] Added /export/{id}/csv endpoint
│   │   ├── services/
│   │   │   └── brand_detector.py                # [MODIFY] Added Unicode homoglyph & Punycode analysis
│   │   └── agents/
│   │       └── forensic_report_agent.py         # [MODIFY] Added generate_ioc_csv_stream()
│
└── frontend/
    └── src/
        ├── app/
        │   ├── api.ts                           # [MODIFY] Added exportCaseIocCsv() helper
        │   └── components/
        │       └── forensics/
        │           ├── StixExportModal.tsx      # [MODIFY] Added Defanged CSV download button & preview
        │           ├── HomoglyphDiffChip.tsx    # [NEW] Visual character substitution inspector
        │           └── ForensicOpsView.tsx      # [MODIFY] Injected HomoglyphDiffChip in Protocol view
```

---

## 9. Step-by-Step Implementation Roadmap

### Milestone 4.1: Database-Backed Evidence Vault Persistence
- [ ] Refactor `backend/app/storage.py` to create `DatabaseEvidenceVault` inheriting from `EvidenceVault`.
- [ ] Connect `DatabaseEvidenceVault` to MongoDB (`forensic_cases`, `forensic_analyses`, `audit_ledger`) or PostgreSQL JSONB.
- [ ] Retain automatic in-memory fallback so tests run seamlessly without requiring local MongoDB/Postgres instances.
- [ ] Write persistence tests in `backend/tests/test_phase4.py`.

### Milestone 4.2: Defanged CSV IOC Export Engine
- [ ] Implement `generate_ioc_csv()` in `backend/app/agents/forensic_report_agent.py`.
- [ ] Register `GET /api/forensics/export/{case_id}/csv` in `backend/app/forensic_routes.py`.
- [ ] Add CSV export action button and tabular preview in `frontend/src/app/components/forensics/StixExportModal.tsx`.

### Milestone 4.3: Unicode Homoglyph & Punycode Analyzer
- [ ] Implement `analyze_homoglyphs(domain)` in `backend/app/services/brand_detector.py` using `unicodedata`.
- [ ] Embed homoglyph findings into `POST /api/forensics/analyze-email` response schema.
- [ ] Create `HomoglyphDiffChip.tsx` with Universal Liquid Glass styling in the frontend.
- [ ] Inject `HomoglyphDiffChip` into `ForensicOpsView.tsx` and `LinkPreviewView.tsx`.

---

## 10. Verification & Quality Gates

1. **Vault Persistence Gate:** Restart backend server process; verify that previously analyzed cases via `POST /api/forensics/analyze-email` can still be fetched via `GET /api/forensics/cases/{case_id}` without reverting to mock seeds.
2. **CSV Admissibility Gate:** Download CSV via `GET /api/forensics/export/{case_id}/csv`; verify all URLs, domains, and IPs conform to standard defanging formatting (`hxxps`, `[.]`).
3. **Homoglyph Detection Gate:** Test domain `micrоsoft.com` (with Cyrillic `о` `U+043E`); verify that `brand_detector.py` flags homoglyph spoofing with 100% precision.
4. **Test Suite Execution:** Run `pytest tests/test_phase4.py tests/test_forensics.py tests/test_phase3.py` with 100% pass rate.
5. **Frontend Build Gate:** Run `npm run build` with clean zero-error compilation.
