# SpectraShield 2.0 — Phase 3 Implementation Blueprint

**Document Title:** Enterprise Hardening, Advanced Forensics & System Completion Specification  
**Project Name:** SpectraShield 2.0 (Forensic Edition)  
**Release Target:** Phase 3 of Version 2.0 (*Not a breaking 3.0 release; this completes the 2.0 vision*)  
**SIH Problem Statement ID:** 26106  
**Problem Statement Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Beneficiaries:** Security Operations Center (SOC) Teams, Law Enforcement Agencies (LEAs), Fraud Response Units, Enterprise Security Administrators  

---

## 1. Executive Summary & Phase 3 Mandate

### 1.1 Scope Definition
SpectraShield 2.0 successfully established the foundational multi-agent forensic computation engine, RFC 5322 relay decompiler, Earliest Reliable Public Node (ERPN) geolocation engine, cryptographic Evidence Vault (SHA-256 chain of custody), Neo4j/NetworkX attribution graph, STIX 2.1 / ISO 27037 PDF dossier generator, and the React-based Forensic Operations Center.

**Phase 3** represents the **completion, enterprise hardening, and production maturity layer of SpectraShield 2.0**. It addresses every remaining requirement from the SIH 26106 AegisMail Forensics specification and the master architecture that was not implemented in the initial 2.0 milestone.

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                       SPECTRASHIELD 2.0 LIFECYCLE                             │
├───────────────────────────────┬───────────────────────────────────────────────┤
│ Milestone 1 & 2 (Completed)   │ Multi-Agent Pipeline, ERPN GeoTrace, RFC 5322 │
│                               │ Decompiler, SHA-256 Vault, Graph Attribution, │
│                               │ PDF/STIX Exporter, Forensic Workspace, Ext.   │
├───────────────────────────────┼───────────────────────────────────────────────┤
│ Phase 3 (Current Focus)       │ Attachment Static Triage, PII Redaction Engine,│
│                               │ Live Mailbox Poller (IMAP), Liquid Glass UI,  │
│                               │ WebSocket Live Stream, RBAC & Case Workflow.  │
└───────────────────────────────┴───────────────────────────────────────────────┘
```

---

## 2. Audit Matrix: Completed vs. Remaining Phase 3 Capabilities

| Domain | Implemented in 2.0 Baseline | Remaining for Phase 3 (Under 2.0) | Priority |
| :--- | :--- | :--- | :--- |
| **Email Header & Hop Forensics** | Reverse chronological RFC 5322 parsing, ERPN IP extraction, inter-MTA transit latency, SPF/DKIM/DMARC DNS checks. | FCrDNS (Forward-Confirmed Reverse DNS) validation, SPF macro expansion, DKIM RSA key length audit (512 vs 1024 vs 2048-bit weak keys). | Medium |
| **Origin Geolocation & Proxy Intel** | MaxMind GeoLite2 City/ASN offline fallback, Tor exit node detection, private RFC 1918 bogon filtering. | Commercial VPN subnet CIDR range matcher, bulletproof hosting ASN database, BGP route flapping detection. | Medium |
| **Attachment & Payload Forensics** | QR code scanning from inline images (`qr_detector.py`). | **Static Attachment Extraction & Triage Engine:** MIME octet extraction (`.zip`, `.pdf`, `.iso`, `.exe`, `.vbs`), multi-hash fingerprinting (MD5, SHA-256, SSDEEP fuzzy hash), PDF embedded JavaScript detection, Office macro stream inspection. | **Critical** |
| **Evidence Vault & Legal Admissibility** | SHA-256/SHA-1/MD5 evidence hashing upon ingestion, block-linked audit ledger (`storage.py`), STIX 2.1 JSON, court-admissible PDF dossier. | **PII Redaction & Sanitization Engine (GDPR / DPDP / HIPAA):** Automated masking of credit cards, national IDs, and bank accounts in exported dossiers while retaining cryptographic integrity of raw evidence. | **Critical** |
| **Ingestion Channels** | Raw header/MIME paste, `.eml` / `.msg` drag-and-drop file upload, browser extension 1-click escalator. | **Automated Live Mailbox Poller (IMAP / Graph API):** Daemon service to poll quarantine/abuse mailboxes (`abuse@enterprise.com`) and ingest incidents autonomously into the Evidence Vault. | High |
| **User Interface & Aesthetics** | Dark vector Leaflet map, chronological hop timeline, `@xyflow/react` threat network graph, auth matrix pills. | **Liquid Glass Design System Implementation (`universal-liquid-glass-design.md`):** Caustic radial glares, specular rim highlights, fluid sliding tab switchers, glassmorphic modals, and backdrop saturation boosts. | High |
| **SOC Workflow & Collaboration** | Case creation, immutable audit logging, case detail endpoint. | **Role-Based Access Control (RBAC) & Case Management:** Analyst assignment, case triage status transitions (`NEW` → `UNDER_INVESTIGATION` → `ESCALATED` → `CLOSED`), analyst investigation notes log. | High |
| **Real-Time Responsiveness** | Synchronous REST requests (`POST /api/forensics/analyze-email`). | **WebSocket Live Analysis Streaming (`/ws/forensics/analyze`):** Progress streaming showing hop-by-hop resolution, DNS queries, and graph correlation in real-time. | Medium |
| **Browser Extension** | In-inbox "🚨 Escalate to Forensic SOC" button in Gmail opened emails, row badges. | **Extension Popup Quick Dashboard:** View active cases, backend connection health status, and quick-scan text area in `popup.html`. | Medium |

---

## 3. Detailed Specifications for Phase 3 Components

### Component 1: Attachment Static Triage & Multi-Hash Analysis Engine
**Target File:** `backend/app/agents/attachment_forensic_agent.py`  
**Service Hook:** Injected into `backend/app/scanner.py` and `backend/app/forensic_routes.py`

#### Capabilities:
1. **MIME Stream Decompiler:** Recursively parses `multipart/mixed` and `multipart/related` payloads to extract attached binaries, archives, and documents without executing untrusted code.
2. **Multi-Hash Generation:** Computes:
   - SHA-256 (NIST collision-resistant hash)
   - SHA-1 & MD5 (Legacy IOC cross-referencing)
   - SSDEEP / TLSH (Context-triggered fuzzy hashing to detect polymorphic variants of the same exploit)
3. **Heuristic File Content Probing:**
   - **PDF Inspection:** Scans for `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles`, and `/OpenAction` streams commonly leveraged in PDF exploits.
   - **Office Macro Detection:** Scans compound binary files (`.doc`, `.xls`) and OOXML packages (`.docx`, `.xlsm`) for VBA project streams (`vbaProject.bin`).
   - **Double Extension Lures:** Flags deceptive extensions such as `invoice_overdue.pdf.exe` or `contract.docx.iso`.
   - **High Entropy Detection:** Calculates Shannon entropy of attachments to flag encrypted/packed malware payloads.

#### Pydantic Schema Addition (`schemas.py`):
```python
class AttachmentEvidence(BaseModel):
    filename: str
    content_type: str
    file_size_bytes: int
    sha256: str
    md5: str
    ssdeep: Optional[str] = None
    is_executable_or_script: bool
    has_macros: bool
    has_embedded_scripts: bool
    entropy_score: float
    risk_level: str  # "clean" | "suspicious" | "malicious"
    risk_reasons: list[str]
```

---

### Component 2: Privacy & PII Redaction Engine (ISO 27037 / GDPR / DPDP)
**Target File:** `backend/app/services/pii_redactor.py`  
**Integration:** `backend/app/agents/forensic_report_agent.py`

#### Capabilities:
When an investigator exports a court dossier or STIX feed for external third parties or legal submission, the system must allow compliant PII redaction while maintaining cryptographic evidence integrity.

1. **Detection Patterns:**
   - **Financial Data:** Credit/Debit Card PANs (Luhn-checked), International Bank Account Numbers (IBAN).
   - **Identity Numbers:** Social Security Numbers (SSN), Indian Aadhaar & PAN numbers.
   - **Credentials:** Password leaks in plaintext (`password=`, `pwd=`, `secret:`).
   - **Personal Contacts:** Private phone numbers, employee home addresses.
2. **Dual-Vault Architecture:**
   - **Primary Vault (`raw_eml`):** Preserves the untouched, original RFC 5322 byte-stream with the canonical SHA-256 hash.
   - **Sanitized Artifact (`redacted_eml`):** Generates a redacted copy with masked tokens (`[REDACTED_IBAN_xxxx]`, `[REDACTED_PHONE]`).
   - The PDF Dossier and STIX export include a **Redaction Manifest** verifying which tokens were masked and by which authorized analyst ID.

---

### Component 3: Live Enterprise Mailbox Ingestion Poller (IMAP / OAuth)
**Target File:** `backend/app/services/mailbox_poller.py`  
**Configuration:** `backend/app/config.py` & `.env`

#### Capabilities:
Enterprise SOCs require continuous, autonomous intake of user-reported phishing emails without manual copy-pasting.

1. **IMAP / POP3 SSL Worker:** Connects via TLS to an enterprise abuse mailbox (e.g. `phish-report@company.com`).
2. **Automated Header & Body De-packaging:**
   - Detects forwarded phishing messages (where the malicious email is attached as an `.eml` or RFC 822 message).
   - Unpacks the nested payload and submits it directly into `POST /api/forensics/analyze-email`.
3. **Automated Triage Routing:**
   - If `final_risk >= 70`: Triggers automated case sealing, assigns a High-Priority incident ticket, and alerts on-duty analysts.
   - If `final_risk < 30`: Automatically marks the report as benign and archives the thread.

---

### Component 4: Liquid Glass Design System Modernization
**Target Reference:** [`universal-liquid-glass-design.md`](file:///d:/Project/SpectraShield/universal-liquid-glass-design.md)  
**Target Files:**
- `frontend/src/styles/theme.css`
- `frontend/src/app/components/forensics/ForensicWorkspace.tsx`
- `frontend/src/app/components/forensics/HopMapVisualizer.tsx`
- `frontend/src/app/components/forensics/ThreatGraphExplorer.tsx`
- `frontend/src/app/components/forensics/RelayHopTimeline.tsx`

#### UI Enhancements:
1. **Refractive Backdrop Blur Tiers:** Apply multi-tier depth blurs (`backdrop-blur-xl` + `backdrop-saturate-150` on card bases).
2. **Specular Rim Lighting:** Replace flat borders with directional 1px gradient highlights (`linear-gradient(135deg, rgba(255,255,255,0.3) 0%, rgba(255,255,255,0.05) 100%)`).
3. **Liquid Caustic Glares:** Add subtle ambient radial glows inside cards to give the Forensic Operations Center a fluid, high-tech command center aesthetic.
4. **Liquid Sliding Segmented Tabs:** Upgrade the tab bar (`Overview & Protocols`, `Relay World Map`, `Hop-by-Hop Timeline`, `Attribution Graph`) to use a sliding glass pill indicator with fluid cubic-bezier easing.
5. **Interactive Glow Droplets:** Micro-animated status indicators for ERPN nodes, Tor alerts, and cryptographic authentication pills.

---

### Component 5: Case Workflow & Role-Based Access Control (RBAC)
**Target Files:**
- `backend/app/routes/case_management.py`
- `backend/sql/supabase_schema_v2.sql`
- `frontend/src/app/components/forensics/CaseManagementView.tsx`

#### Capabilities:
1. **Case Lifecycle State Machine:**
   - `NEW` → `TRIAGED` → `INVESTIGATING` → `ESCALATED_LE` → `CLOSED_FALSE_POSITIVE` → `CLOSED_RESOLVED`
2. **Analyst Collaboration:**
   - Assign case to specific analyst handle (e.g., `analyst_rajesh`).
   - Add timestamped investigation notes preserved in the cryptographic audit ledger.
   - Set evidentiary tags (`#BEC`, `#TargetedExecutive`, `#SpoofedVendor`, `#PhishLure`).
3. **Role Enforcement:**
   - **`Viewer / Tier-1 SOC`:** Ingest emails, view threat scores, trigger standard scans.
   - **`Forensic Investigator`:** Full access to raw byte-stream evidence, edit investigation notes, generate court-admissible PDF dossiers.
   - **`Security Admin`:** User management, API key rotation, evidence purging policies.

---

### Component 6: Real-Time WebSocket Analysis Streaming
**Target File:** `backend/app/forensic_routes.py` (`/ws/forensics/analyze`)  
**Frontend Hook:** `frontend/src/app/components/forensics/LiveScanStream.tsx`

#### Capabilities:
When decompiling a complex 12-hop email with live DNSSEC lookups, WHOIS queries, and graph correlation, analysts should see real-time streaming feedback:
```json
{"stage": "UNROLLING_HOPS", "progress": 20, "message": "Extracted 4 MTA hops. Evaluating ERPN..."}
{"stage": "CRYPTOGRAPHIC_DNS", "progress": 45, "message": "Querying SPF TXT & DKIM selector DNSSEC..."}
{"stage": "GEOLOCATION", "progress": 65, "message": "Origin resolved to Frankfurt, Germany. Tor Exit node confirmed."}
{"stage": "GRAPH_CORRELATION", "progress": 85, "message": "Clustered into Campaign #BD8E8E via MinHash..."}
{"stage": "COMPLETE", "progress": 100, "case_id": "CASE-20260904-XYZ"}
```

---

### Component 7: Chromium Extension Quick-Scan Popup Polish
**Target Files:** `extension/popup.html`, `extension/popup.js`, `extension/popup.css`

#### Capabilities:
1. **Quick Ingestion Area:** Allow pasting a snippet or raw headers directly into the browser extension popup without leaving the browser tab.
2. **Active Case Counter:** Displays the number of active unread forensic cases waiting in the SOC vault.
3. **1-Click Deep Link:** Includes a direct action button: `[ Open Forensic Operations Center ↗ ]` that opens `http://localhost:5173/?view=forensics` with one click.
4. **Backend Connectivity Monitor:** Live ping indicator showing whether the local FastAPI backend is online and accepting evidence.

---

## 4. Proposed Annotated Directory Updates (Phase 3)

```text
SpectraShield/
├── phase3.md                                # THIS BLUEPRINT: Phase 3 Completion Roadmap
├── upgraded-spec.md                        # SpectraShield 2.0 Master Contract
│
├── backend/
│   ├── app/
│   │   ├── agents/
│   │   │   ├── attachment_forensic_agent.py # [PHASE 3] MIME octet extractor, macro & script triage
│   │   │   └── ... (existing 2.0 agents)
│   │   ├── services/
│   │   │   ├── pii_redactor.py             # [PHASE 3] GDPR/DPDP compliant PII masking engine
│   │   │   ├── mailbox_poller.py           # [PHASE 3] Autonomous IMAP/POP3 inbox poller
│   │   │   └── ... (existing services)
│   │   └── routes/
│   │       └── case_management.py         # [PHASE 3] Case triage transitions & analyst notes
│
└── frontend/
    └── src/
        ├── styles/
        │   └── theme.css                   # [PHASE 3] Liquid Glass tokens & caustic animations
        └── app/
            └── components/
                └── forensics/
                    ├── CaseManagementView.tsx # [PHASE 3] SOC case triage & notes board
                    ├── AttachmentTriageCard.tsx# [PHASE 3] Macro, script & multi-hash breakdown
                    └── ... (existing 2.0 components)
```

---

## 5. Phase 3 Execution Roadmap & Work Breakdown

### Milestone 3.1: Attachment Static Triage & PII Redaction
- [ ] Implement `AttachmentForensicAgent` to extract attached binary streams and generate MD5, SHA-256, and SSDEEP hashes.
- [ ] Add static heuristic analyzers for PDF `/JavaScript` streams and Office `vbaProject.bin` macros.
- [ ] Implement `PiiRedactor` in `backend/app/services/pii_redactor.py` supporting configurable masking of bank accounts, national IDs, and card PANs.
- [ ] Connect PII redaction toggle to `forensic_report_agent.py` for court dossier exports.

### Milestone 3.2: Liquid Glass Visual Modernization
- [ ] Import and configure Liquid Glass design tokens from `universal-liquid-glass-design.md` into `frontend/src/styles/theme.css`.
- [ ] Refactor `ForensicWorkspace.tsx` cards with specular top rim highlights and refractive background blurs.
- [ ] Upgrade tab navigation with the animated liquid sliding segmented control.

### Milestone 3.3: Case Management & Autonomous Mailbox Ingestion
- [ ] Implement case triage endpoints (`PATCH /api/forensics/cases/{id}/status`, `POST /api/forensics/cases/{id}/notes`).
- [ ] Build `CaseManagementView.tsx` in the frontend showing active cases, priority filters, and assigned investigators.
- [ ] Implement the `MailboxPoller` daemon to monitor test IMAP abuse mailboxes and ingest incoming suspicious emails.

### Milestone 3.4: Extension Popup & Live WebSocket Stream
- [ ] Update `extension/popup.html` with the Quick Scan input, live backend ping indicator, and 1-click SOC launcher.
- [ ] Add WebSocket streaming endpoint `/ws/forensics/analyze` in FastAPI and connect a progress ribbon in the frontend.
- [ ] Perform full end-to-end integration tests and update project documentation.

---

## 6. Verification & Quality Gates

Each Phase 3 component must pass the following quality thresholds before release:
1. **Forensic Integrity Test:** PII redaction must never alter the canonical raw evidence SHA-256 stored in the Evidence Vault.
2. **Safe Static Attachment Triage:** Attachment extraction must execute safely without executing any binaries, scripts, or macros.
3. **Zero Frontend Regressions:** Frontend must compile cleanly with `npm run build` with zero TypeScript errors.
4. **Automated Test Coverage:** New unit test suite `backend/tests/test_phase3.py` covering attachment extraction, PII masking, and case transitions with 100% pass rate.
