# Features Implementation Roadmap & Matrix

**Project:** AegisMail Forensics (AegisMail_AI)  
**Problem Statement ID:** 26106 (SIH 2026)  
**Document Purpose:** Complete, categorized inventory of all functional, technical, and analytical features required for implementation, detailing technical descriptions, inputs, outputs, and implementation priority.

---

## 1. Feature Matrix Overview

| Feature Code | Feature Name | Core Component | Priority | Complexity |
| :--- | :--- | :--- | :--- | :--- |
| **ING-01** | Multi-Format Raw Email Ingestion | Ingestion & Evidence Engine | High | Medium |
| **ING-02** | Cryptographic Pre-Hashing & Evidence Immutability | Evidence & Forensics Engine | Critical | Low |
| **ING-03** | MIME & Payload Decoupling | Parsing Engine | High | Medium |
| **HDR-01** | RFC 5322/822 Header Decomposition | Header Forensics | Critical | High |
| **HDR-02** | Relay Chain Reverse-Traversal & Bogon Pruning | Routing Forensics | Critical | High |
| **HDR-03** | Cryptographic Protocol Authentication (SPF/DKIM/DMARC)| Security Protocols | Critical | High |
| **HDR-04** | Header Anomaly & Time Travel Analysis | Heuristic Forensics | High | Medium |
| **GEO-01** | Originating Public IP Resolution & Hop Coordinates | Geolocation Engine | Critical | Medium |
| **GEO-02** | Proxy, VPN, Botnet & TOR Exit Node Detection | Network Intelligence | High | Medium |
| **GEO-03** | Animated Visual Flight Path Cartography | UI / Frontend | Medium | Medium |
| **INT-01** | Domain WHOIS, RDAP & Registrar Profiling | Threat Intelligence | High | Medium |
| **INT-02** | Homoglyph, Punycode & Typosquatting Analyzer | Spoof Detection | High | High |
| **INT-03** | URL Extraction, Safe Defanging & Live Reputation | Threat Feeds | High | Medium |
| **INT-04** | Attachment Extraction & Malware Static Scoring | Malware Analysis | Medium | Medium |
| **NLP-01** | Transformer BEC & Phishing Intent Classifier | AI / NLP Engine | Critical | High |
| **NLP-02** | Social Engineering & Urgency Cue Highlighter | AI / NLP Engine | High | High |
| **NLP-03** | Executive & VIP Display Name Impersonation Engine | Fraud Prevention | High | Medium |
| **GRP-01** | Multi-Entity Cross-Case Graph Builder | Attribution Engine | High | High |
| **GRP-02** | Threat Actor & Campaign Clustering | Attribution Engine | High | High |
| **GRP-03** | Interactive Threat Graph Canvas | UI / Frontend | Medium | High |
| **CAS-01** | Forensic Incident Workspace & Case Triage | Case Management | High | Medium |
| **CAS-02** | Tamper-Evident SHA-256 Audit Ledger | Compliance & Legal | Critical | Medium |
| **REP-01** | Court-Admissible PDF Forensic Dossier Generator | Forensic Reporting | High | Medium |
| **REP-02** | STIX 2.1 & Defanged IOC Threat Export | SIEM Interoperability | Medium | Low |
| **SEC-01** | PII Redaction & Data Sanitization Engine | Privacy Compliance | High | Medium |
| **SEC-02** | Role-Based Access Control (RBAC) & 2FA TOTP | Core Security | High | Medium |

---

## 2. Detailed Feature Descriptions

### 2.1 Email Ingestion & Evidence Preservation

#### Feature ING-01: Multi-Format Raw Email Ingestion
- **Description:** Provide a resilient ingestion pipeline accepting raw email files in `.eml`, `.msg` (Outlook OLE storage), and `.mbox` formats via drag-and-drop web upload, REST API endpoints, and raw text pasting.
- **Inputs:** Binary file payload, drag-and-drop dropzone, or raw text input.
- **Outputs:** Ingestion confirmation, file metadata (file size, encoding, byte structure), and a unique `caseId`.
- **Key Implementation Details:**
  - Support Outlook `.msg` parsing via Python `extract_msg`.
  - Validate MIME types and check magic bytes to prevent shellcode or malicious payload uploads.

#### Feature ING-02: Cryptographic Pre-Hashing & Evidence Immutability
- **Description:** Instantly compute SHA-256, SHA-1, and MD5 checksums of the uploaded raw email payload before any parsing or modification occurs. The raw file is written to an immutable S3/MinIO bucket with strict read-only permissions.
- **Inputs:** Raw binary stream of uploaded email.
- **Outputs:** Immutable evidence record with cryptographic hashes stored in the database.
- **Key Implementation Details:**
  - Guarantees ISO/IEC 27037 and Section 65B/BNSS compliance for digital forensics chain-of-custody.
  - Ensures the defense cannot argue that the server modified raw message headers during processing.

#### Feature ING-03: MIME & Payload Decoupling
- **Description:** Deconstruct raw RFC 2045/2046 multi-part payloads into clean, isolated streams: `text/plain`, `text/html`, embedded inline assets (CID), attachment octet-streams, and nested attached `.eml` files.
- **Inputs:** Raw email file stream.
- **Outputs:** Clean JSON payload of email body parts, attachment metadata arrays, and sanitized HTML previews.
- **Key Implementation Details:**
  - Strip executable macros and inline script tags (`<script>`, `<iframe>`, `onload=`).
  - Quarantine extracted attachments by applying a `.quarantine` file suffix.

---

### 2.2 Header Protocol Forensics & Relay Tracing

#### Feature HDR-01: RFC 5322/822 Header Decomposition
- **Description:** Parse and normalize all RFC 5322 header keys and values into structured JSON. Extract crucial routing indicators including `Return-Path`, `From`, `Reply-To`, `Sender`, `Message-ID`, `Date`, `Subject`, and X-headers (`X-Mailer`, `X-Originating-IP`).
- **Inputs:** Raw RFC 822/5322 text.
- **Outputs:** Key-value dictionary of normalized headers, highlighting non-standard or missing standard headers.
- **Key Implementation Details:**
  - Flag mismatches between envelope `Return-Path` and header `From`.
  - Detect anomalous `Reply-To` entries steering responses away from legitimate organizational inboxes.

#### Feature HDR-02: Relay Chain Reverse-Traversal & Bogon Pruning
- **Description:** Parse every `Received:` header line in reverse chronological order (chronological transit order). Traverse each hop, parse client and server hostnames/IPs, transmission protocols (ESMTPA, ESMTPS, LMTPA), and timestamps. Prune private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and carrier loopback/bogon addresses to identify the **Earliest Reliable Public Originating Hop**.
- **Inputs:** Array of raw `Received:` header strings.
- **Outputs:** Array of structured relay hop objects (`hopNumber`, `fromHost`, `byHost`, `ipAddress`, `isPrivate`, `transitDelaySeconds`, `isOriginatingHop`).
- **Key Implementation Details:**
  - Calculate hop-by-hop latency and flag abnormal delays (>30 minutes) indicating queue tampering or intentional delays.

#### Feature HDR-03: Cryptographic Protocol Authentication (SPF/DKIM/DMARC)
- **Description:** Mathematically validate sender domain cryptographic and authorization frameworks against live DNS records.
- **Inputs:** Email headers, envelope from domain, sending IP, DKIM-Signature header.
- **Outputs:** Tri-protocol verification status:
  - **SPF:** `Pass`, `Fail`, `SoftFail`, `Neutral`, `TempError`, `PermError` with resolved SPF record.
  - **DKIM:** Cryptographic signature verification status (`Pass`, `Fail`), selector name, signing domain, and hash verification over canonicalized headers and body.
  - **DMARC:** Compliance verdict (`Pass`, `Fail`), alignment mode (Strict vs. Relaxed), and domain policy enforcement (`none`, `quarantine`, `reject`).
- **Key Implementation Details:**
  - Direct DNS query resolution via `dnspython` to avoid OS-level resolver caching bugs.

#### Feature HDR-04: Header Anomaly & Time Travel Analysis
- **Description:** Detect heuristic protocol irregularities and forge indicators across header fields.
- **Inputs:** Parsed headers dictionary and relay hop timestamps.
- **Outputs:** Anomaly warning flags list with severity weights.
- **Key Implementation Details:**
  - Flag "Time Travel" anomalies where hop timestamps move backwards in time.
  - Detect duplicate critical headers (e.g., multiple `From:` headers exploited in email client rendering bugs).
  - Validate `Message-ID` syntax against RFC 5322 requirements (domain portion matching originating MTA domain).

---

### 2.3 Geolocation & Infrastructure Intelligence

#### Feature GEO-01: Originating Public IP Resolution & Hop Coordinates
- **Description:** Query local MaxMind GeoLite2/GeoIP2 City and ASN databases to identify the physical geographic location of the originating public IP and intermediate mail transfer agents (MTAs).
- **Inputs:** Validated public IP addresses extracted from relay hops.
- **Outputs:** Geographic metadata: Country, City, Region, Postal Code, Latitude, Longitude, ISP, ASN, and Organization.

#### Feature GEO-02: Proxy, VPN, Botnet & TOR Exit Node Detection
- **Description:** Cross-reference extracted IP hops with known proxy lists, commercial VPN CIDR blocks (NordVPN, ExpressVPN), TOR exit node directories, and abuse databases (AbuseIPDB, Spur).
- **Inputs:** Originating public IP address.
- **Outputs:** Infrastructure classification: `RESIDENTIAL`, `DATACENTER`, `TOR_EXIT_NODE`, `COMMERCIAL_VPN`, `OPEN_RELAY`, `BOTNET`.
- **Key Implementation Details:**
  - Assign high risk multiplier to emails originating directly from TOR or bulletproof hosting providers.

#### Feature GEO-03: Animated Visual Flight Path Cartography
- **Description:** Render an interactive world map (MapLibre / Leaflet) showing the transmission flight path of the email, animating lines from the sender origin across intermediate mail gateways to the destination server.
- **Inputs:** Array of relay hop geolocation coordinates.
- **Outputs:** Interactive cartographic canvas with clickable nodes detailing MTA information and latencies.

---

### 2.4 Threat Intelligence & Domain Forensics

#### Feature INT-01: Domain WHOIS, RDAP & Registrar Profiling
- **Description:** Query domain registration metadata for the sender domain and links found in the message body.
- **Inputs:** Sender domain name (`example.com`).
- **Outputs:** Domain Creation Date, Domain Age (in days), Registrar Name, WHOIS Privacy Guard status, and Name Servers.
- **Key Implementation Details:**
  - Newly Registered Domain (NRD) alert: Automatically escalate risk score if domain age is < 30 days.

#### Feature INT-02: Homoglyph, Punycode & Typosquatting Analyzer
- **Description:** Compare the sender domain against institutional target domains and well-known financial/technology brands using Levenshtein edit distance, Cyrillic/Latin homoglyph mapping, and Punycode (`xn--`) detection.
- **Inputs:** Sender domain name and internal organization protected domain list.
- **Outputs:** Spoof likelihood score, visual diff of character substitutions (e.g., `microsоft.com` with Cyrillic 'о'), and Punycode ASCII translation.

#### Feature INT-03: URL Extraction, Safe Defanging & Live Reputation
- **Description:** Parse all links in the email body (including HTML anchors, image links, and plain-text URLs). Automatically defang all URLs (`hxxps[://]domain[.]com`) and submit them asynchronously to Google Safe Browsing, VirusTotal, and URLhaus.
- **Inputs:** Raw HTML/text email body.
- **Outputs:** List of defanged URLs, detected redirection chains, and external threat engine detection scores.

#### Feature INT-04: Attachment Extraction & Malware Static Scoring
- **Description:** Extract attachment binaries, calculate SHA-256 hashes, identify true file types via magic bytes (independent of file extension), and scan against known malware hash databases.
- **Inputs:** Ingested email attachment octet streams.
- **Outputs:** Attachment metadata: Filename, File Type, File Size, SHA-256, Entropy score, and Malicious flag.
- **Key Implementation Details:**
  - Detect double-extension deception (e.g., `invoice_march.pdf.exe`).

---

### 2.5 AI & Natural Language Processing (NLP) Engine

#### Feature NLP-01: Transformer BEC & Phishing Intent Classifier
- **Description:** Fine-tuned transformer model (RoBERTa / DeBERTa-v3) that evaluates the semantic intent of email subjects and message bodies to classify messages into specific attack vectors.
- **Inputs:** Decoded subject line and normalized email text body.
- **Outputs:** Threat Category classification (`CLEAN`, `PHISHING`, `BEC_FINANCIAL`, `IMPERSONATION`, `MALWARE_DELIVERY`) with class probabilities (0.00 – 1.00).

#### Feature NLP-02: Social Engineering & Urgency Cue Highlighter
- **Description:** Detect psychological persuasion and coercive cues commonly leveraged in phishing campaigns: Artificial Time Urgency, Fear of Penalty, Executive Authority, and Unusual Secrecy.
- **Inputs:** Email body text.
- **Outputs:** Extracted cue phrases with character offsets, sentiment intensity scores, and highlighted UI text ranges.

#### Feature NLP-03: Executive & VIP Display Name Impersonation Engine
- **Description:** Compare the display name (friendly name) in the `From:` header against a protected directory of VIP executives, board members, and finance personnel to catch display name spoofing sent via free webmail services (e.g., `"CEO Name" <randomuser123@gmail.com>`).
- **Inputs:** Display name string, sender email address, internal VIP roster.
- **Outputs:** Impersonation flag (`TRUE`/`FALSE`), targeted VIP profile, and sender address divergence score.

---

### 2.6 Threat Attribution & Graph Correlation

#### Feature GRP-01: Multi-Entity Cross-Case Graph Builder
- **Description:** Ingest extracted IOCs (Sender Email, Reply-To, Originating IP, Originating Subnet /24, DKIM Selector, Phishing URL Domain, Attachment Hashes) into a persistent graph database (Neo4j / NetworkX).
- **Inputs:** Structured email IOC analysis objects from past and present cases.
- **Outputs:** Interconnected node-edge graph modeling relationships across distinct security incidents.

#### Feature GRP-02: Threat Actor & Campaign Clustering
- **Description:** Run community clustering algorithms (Louvain / Connected Components) across the threat graph to identify shared infrastructure patterns and group isolated attacks into named **Threat Campaigns**.
- **Inputs:** Global threat graph dataset.
- **Outputs:** Campaign ID, cluster confidence score (0–100%), shared attack infrastructure summary, and estimated threat actor fingerprint.

#### Feature GRP-03: Interactive Threat Graph Canvas
- **Description:** Web-based, force-directed graph explorer allowing analysts to click, zoom, inspect, and expand connected entities across email cases.
- **Inputs:** Graph API response (`nodes`, `edges`).
- **Outputs:** Interactive Canvas rendering with distinct node icons (IP, Domain, Email, Case, Campaign).

---

### 2.7 Case Management & Chain-of-Custody

#### Feature CAS-01: Forensic Incident Workspace & Case Triage
- **Description:** Centralized analyst dashboard for triaging suspicious emails, assigning cases to investigators, adjusting threat severity levels, adding forensic notes, and toggling case status (`NEW`, `INVESTIGATING`, `ESCALATED`, `RESOLVED`, `ARCHIVED`).
- **Inputs:** Case records and analyst interaction events.
- **Outputs:** Filterable, paginated case repository with status metrics and real-time activity indicators.

#### Feature CAS-02: Tamper-Evident SHA-256 Audit Ledger
- **Description:** An append-only audit ledger tracking every action taken on evidence. Each entry records the previous record's SHA-256 hash, actor ID, action type, and timestamp, forming a blockchain-style immutable cryptographic ledger.
- **Inputs:** Analyst activity events (Evidence viewed, report generated, note appended).
- **Outputs:** Verified chain-of-custody verification badge and exportable audit trail.

---

### 2.8 Forensic Reporting & Interoperability

#### Feature REP-01: Court-Admissible PDF Forensic Dossier Generator
- **Description:** Generate court-admissible, executive-quality PDF reports summarizing the entire incident investigation.
- **Inputs:** Case ID and email analysis JSON.
- **Outputs:** Downloadable, styled PDF report.
- **Key Inclusions in Report:**
  - Case metadata and raw evidence SHA-256 checksums.
  - Visual summary of Header hops, SPF/DKIM/DMARC verdicts.
  - Origin Geolocation coordinates and ISP/VPN attribution.
  - AI confidence scores and highlighted social engineering cues.
  - Cryptographic chain-of-custody signature blocks.

#### Feature REP-02: STIX 2.1 & Defanged IOC Threat Export
- **Description:** Export structured threat intelligence feeds in STIX 2.1 JSON and CSV formats for automated ingestion into SIEM/SOAR platforms (Splunk, Microsoft Sentinel, IBM QRadar).
- **Inputs:** Selected case IOC list.
- **Outputs:** Standardized STIX 2.1 JSON bundle and defanged CSV export.

---

### 2.9 Privacy & System Security

#### Feature SEC-01: PII Redaction & Data Sanitization Engine
- **Description:** Automated privacy filters that identify and mask Personally Identifiable Information (PII) such as bank account numbers, credit cards, telephone numbers, and passwords in email previews and exportable reports.
- **Inputs:** Extracted email text body and headers.
- **Outputs:** Redacted email text with toggleable analyst authorization reveal.

#### Feature SEC-02: Role-Based Access Control (RBAC) & 2FA TOTP
- **Description:** Enforce strict access boundaries across four distinct organizational tiers: Super Admin, Forensic Analyst, SOC Operator, and Auditor. Authenticate users using JWT access/refresh tokens and TOTP RFC 6238 two-factor authentication.
- **Inputs:** User credentials and 6-digit TOTP authenticator codes.
- **Outputs:** Scoped session tokens with role-restricted route access.

---

## 3. Implementation Phasing Matrix

```
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 1: Ingestion, Evidence Hashing & Authentication                      │
│ [ING-01, ING-02, ING-03, SEC-02, CAS-01]                                   │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 2: Deep Header Forensics & Protocol Verification                     │
│ [HDR-01, HDR-02, HDR-03, HDR-04]                                           │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 3: GeoLocation & Threat Intelligence Profiling                       │
│ [GEO-01, GEO-02, GEO-03, INT-01, INT-02, INT-03, INT-04]                   │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 4: NLP Intent Detection & Social Engineering Scoring                 │
│ [NLP-01, NLP-02, NLP-03, SEC-01]                                           │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 5: Threat Attribution & Cross-Case Graph Correlation                 │
│ [GRP-01, GRP-02, GRP-03]                                                   │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 6: Chain-of-Custody Ledger, Dossier Reporting & SIEM Export          │
│ [CAS-02, REP-01, REP-02]                                                   │
└────────────────────────────────────────────────────────────────────────────┘
```
