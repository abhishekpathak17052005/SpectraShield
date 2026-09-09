# Software Design Document (SDD) & Technical Specification

**Project Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Short Name:** AegisMail Forensics (AegisMail_AI)  
**SIH Problem Statement ID:** 26106  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  
**Target Beneficiaries:** Cybersecurity Teams, Law Enforcement Agencies (LEAs), Fraud Response Units, Enterprise & Institutional Administrators  

---

## 1. Project Overview

### 1.1 Executive Summary
Email remains the primary initial access vector for over 90% of cyberattacks worldwide, encompassing Phishing, Business Email Compromise (BEC), Executive Impersonation, Credential Harvesting, and Malware Delivery. While traditional Secure Email Gateways (SEGs) and standard spam filters rely on static signatures, basic keyword heuristics, and simple domain blacklists, threat actors have evolved to leverage AI-generated social engineering, display name spoofing, domain lookalikes (typosquatting/homoglyphs), hidden multi-hop redirection links, open relay networks, compromised cloud mailboxes, and proxy evasion chains (VPNs/TOR).

Crucially, modern organizations lack the technical capabilities to perform **deep forensic tracing** of email origin paths, correlate distributed metadata, reconstruct intermediate SMTP relay hops, evaluate cryptographic authentication anomalies (SPF/DKIM/DMARC alignment breaks), estimate sender physical geolocation, and generate legally admissible, tamper-evident forensic intelligence.

**AegisMail Forensics (AegisMail_AI)** is an end-to-end, enterprise-grade, AI-powered Cyber Threat Detection and Forensic Intelligence Platform. It ingests raw RFC 5322 email headers and MIME bodies (.eml, .msg, MBOX, and IMAP/OAuth live feeds), executes natural language and deep-learning threat scoring, analyzes protocol authenticity, reconstructs SMTP relay hops, geolocates originating and intermediary mail transport agents (MTAs), correlates IOCs across threat-intelligence graph databases, and generates legally compliant forensic reports complete with cryptographic SHA-256 chain-of-custody verification.

### 1.2 Mission & Strategic Objectives
- **Zero-Trust Header Decoupling:** Ingest, parse, and mathematically validate RFC 5322/822 headers, tracing from the first reliable non-private `Received:` hop down to client submission agents (MUA).
- **Multi-Modal AI Threat Detection:** Combine NLP (BERT/RoBERTa transformers + DeBERTa-v3) for social engineering cues (urgency, coercive authority, payment diversion) with structural parsing for homoglyph/Cousin domain spoofing, obfuscated URLs, and malicious attachments.
- **Relay Reconstruction & GeoLocation Engine:** Unpack multi-hop routing, filter out RFC 1918 private/bogon IP spaces, pinpoint the originating public IP, and cross-reference MaxMind GeoIP2, BGP autonomous system numbers (ASN), VPN/TOR exit nodes, and residential proxy databases.
- **Identity Graph Correlation & Threat Attribution:** Unify threat indicators (sender emails, Reply-To discrepancies, envelope From vs. Header From, WHOIS registrars, IP subnets, TLS fingerprints, DKIM selector domains) into an interactive Graph Database (Neo4j / NetworkX) to uncover coordinated fraud campaigns.
- **Forensic Case Management & Chain-of-Custody:** Provide evidentiary preservation conforming to ISO/IEC 27037 and Indian Evidence Act / BNSS digital forensics standards with automated SHA-256 hashing, audit logging, redaction controls, and exportable PDF/JSON court-ready evidence dossiers.

---

## 2. Tech Stack

### 2.1 Frontend Architecture
- **Framework:** Next.js 14+ (App Router), React 19, TypeScript
- **Styling & Design System:** Tailwind CSS v3.4+, Shadcn/UI, Radix UI primitives, Lucide React icons, Tailwind Typography
- **Interactive Visualizations:**
  - **Relay & Graph Visualizer:** React Flow (`@xyflow/react`) for SMTP hop chains and attack path visualization.
  - **Forensic Graph Engine:** Cytoscape.js or Force Graph 2D/3D for threat entity correlation.
  - **Cartographic Geolocation:** MapLibre GL JS / Leaflet / Mapbox GL with vector tiles and IP node trajectory lines.
- **State Management & Data Fetching:** Zustand (client state, auth, filters, current case selection), TanStack React Query v5 (server-state caching, optimistic mutations), Axios.
- **Real-Time Communications:** Socket.IO Client (live analysis streaming, alert notifications).

### 2.2 Backend Architecture & Micro-Engines
- **Runtime Environment:** Node.js v20+ LTS / Express.js (API Gateway, Case Orchestration, Auth, Ingestion)
- **Deep Forensic & ML Microservice:** Python 3.11+ FastAPI (dedicated service for asynchronous high-throughput header parsing, NLP inference, WHOIS/DNS resolution, and graph construction)
- **Email Parsers:** Python `mail-parser`, `flanker`, `extract_msg`, and Native Node.js `mailparser` (streaming MIME, RFC 2045/2046, winmail.dat decoding)
- **Background Task & Queue Pipeline:** Redis v7+ with BullMQ (asynchronous email job queues, bulk processing, recurring threat-feed sync, forensic report generation)
- **Real-Time Websockets:** Socket.IO v4+ on Node.js cluster with Redis adapter

### 2.3 Machine Learning, NLP & Forensics Stack
- **Transformer Inference:** Hugging Face `transformers`, ONNX Runtime / PyTorch (fine-tuned RoBERTa / DeBERTa-v3 for BEC & phishing intent detection, urgency scoring, credential harvest categorization)
- **Feature Extraction & Classical ML:** Scikit-Learn, LightGBM (tabular header anomaly detection, sender score, lexical URL features)
- **Domain & URL Analysis:** `dnspython` (MX, TXT, SPF, DKIM DNSSEC verification), `tldextract`, `whois`, Google Safe Browsing API, VirusTotal v3 API, URLhaus, PhishTank
- **IP & Geo-Intelligence:** MaxMind GeoIP2 / GeoLite2 (City & ASN databases), IPinfo, abuseIPDB API, Spur / TorProject exit node feeds

### 2.4 Database & Persistent Storage
- **Primary Operational Database:** PostgreSQL 16+ with Prisma ORM / Mongoose on MongoDB (Cases, Users, Scans, Forensic Logs, Settings)
- **Graph Threat Database:** Neo4j Community / Aura (or embedded NetworkX + In-memory graph serialized to disk) for cross-case entity correlation (Sender <-> IP <-> Domain <-> Registrar <-> Campaign)
- **Caching & Ephemeral Store:** Redis 7 (rate limiting, session tokens, WHOIS/DNS caching, queue brokers)
- **Evidence Object Storage:** MinIO / AWS S3 compliant storage (immutable raw `.eml` and parsed forensic artifact blobs with SHA-256 checksums)

---

## 3. Core Features

### 3.1 Raw Email Ingestion Engine
- Ingest raw `.eml`, `.msg` (Outlook), `.mbox` files via drag-and-drop, API endpoints, or direct IMAP/POP3 / Google Workspace / Microsoft Graph webhook polling.
- Cryptographically calculate SHA-256, SHA-1, and MD5 hashes of the raw file instantly upon upload to ensure legal chain-of-custody integrity.
- Normalize and extract MIME parts: raw headers, decoded text/plain, text/html, embedded inline images, attachment octet-streams, and nested `.eml` payloads.

### 3.2 Deep Header Forensics & Protocol Verification Engine
- **Relay Chain Reconstruction:** Extract all `Received:` headers, reverse chronological sorting, parsing IP addresses, timestamp hops, protocol (ESMTP, ESMTPS, LMTPA), and transmission delays between MTAs.
- **Bogon & Private IP Filtering:** Discard internal RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and RFC 5735 loopback/carrier IPs to isolate the **Earliest Reliable Public Originating Hop**.
- **Cryptographic Sender Authentication:**
  - **SPF Verification:** Query DNS for published `v=spf1` records, validate client IP authorization against sender envelope domain (`smtp.mailfrom`), compute Pass / Fail / SoftFail / Neutral / TempError / PermError.
  - **DKIM Validation:** Extract DKIM-Signature header, query selector public key DNS (`<selector>._domainkey.<domain>`), mathematically verify RSA/Ed25519 signature over body hash (`bh=`) and specified header fields.
  - **DMARC Compliance & Alignment:** Validate whether SPF and/or DKIM domains align with the RFC 5322 `From:` header domain (strict vs. relaxed alignment). Detect policy directives (`p=none`, `p=quarantine`, `p=reject`).
- **Header Anomaly Detection:** Check for multiple `From` headers, Return-Path vs. Header-From mismatches, Reply-To discrepancies, Message-ID format forgery, and invalid date hops (time travel anomalies).

### 3.3 Natural Language & Multi-Modal Threat Detection
- **AI-Powered BEC & Phishing Classifier:** Fine-tuned NLP model categorizing email body content into:
  - *Legitimate (Clean)*
  - *Suspicious Marketing / Spam*
  - *Credential Harvesting Phishing*
  - *Business Email Compromise (Wire transfer / Payroll diversion / Invoice fraud)*
  - *Executive / VIP Impersonation*
  - *Malware / Exploit Delivery*
- **Social Engineering Cues Extraction:** Real-time extraction of psychological pressure triggers: Artificial Urgency, Authority Coercion, Fear/Panic, Unusual Financial Requests, Secretive Directives.
- **Optical & HTML Analysis:** Detect obfuscated text (zero-width spaces, Cyrillic homoglyphs in text), hidden `display:none` styling, and fake login forms embedded directly in the HTML markup.

### 3.4 Origin GeoLocation & Infrastructure Intelligence
- **Geographic Mapping:** Map originating and intermediate MTAs to Country, State/Region, City, Postal Code, Latitude/Longitude, ISP, and Autonomous System (ASN).
- **Infrastructure Fingerprinting:** Detect whether the sender IP is hosted on AWS, GCP, Azure, DigitalOcean, OVH, or identified as a known TOR Exit Node, Commercial VPN (NordVPN, ExpressVPN, etc.), Public Proxy, or Residential Botnet node.
- **Domain WHOIS & DNS Threat Intel:**
  - Calculate Domain Age (flagging newly registered domains < 30 days old).
  - Registrar and Privacy Guard detection.
  - Typo-squatting & Cousin Domain score against legitimate enterprise targets using Levenshtein distance, Bit-squatting, and Homoglyph algorithms.
  - NameServer and MX infrastructure verification.

### 3.5 Threat Attribution & Graph Correlation (Campaign Tracker)
- Ingest extracted IOCs (Sender Email, Reply-To, Origin IP, Sending Subnet, Attachment Hashes, Phishing URLs, DKIM Selectors) into a Graph Database.
- Connect historical incidents into **Fraud Campaigns** (e.g., Identifying that 15 different emails targeting finance executives share the exact same DKIM key, Russian hosting provider subnet, and zero-width obfuscation pattern).
- Generate a unified **Threat Actor Attribution Confidence Score** (0–100%) indicating whether the attack is an isolated opportunistic phish, automated botnet spray, or organized Advanced Persistent Threat (APT) / BEC syndicate.

### 3.6 Forensic Reporting & Legal Chain-of-Custody
- Generate court-admissible Forensic Dossiers in PDF and STIX 2.1 / MISP JSON formats.
- Each report encapsulates: Case ID, Evidence Hash (SHA-256), Timestamped Audit Trail, Full Header Dissection, SPF/DKIM/DMARC Cryptographic Proofs, World Geo-Trajectory Map, IOC List, and AI Confidence Matrix.
- Privacy & Redaction Engine: Automatically sanitize PII (passwords, banking numbers, employee personal identifiers) based on customizable compliance rules (GDPR / DPDP Act / HIPAA).

---

## 4. Authentication & Access Control

### 4.1 Security Protocols
- **JWT (JSON Web Tokens):** Short-lived Access Tokens (15 mins) and cryptographically stored Refresh Tokens in secure `httpOnly`, `SameSite=Strict` cookies.
- **Password Security:** Scrypt / Bcrypt (cost factor 12) with mandatory complexity validation (minimum 12 characters, uppercase, lowercase, numbers, special characters).
- **Two-Factor Authentication (2FA / MFA):** TOTP (RFC 6238) via Authenticator apps (Google Authenticator, Authy) with backup recovery codes.

### 4.2 Role-Based Access Control (RBAC)
- **Super Admin:** System configuration, API key management, audit trail inspection, user provisioning, global threat feed sync.
- **Forensic Investigator / Senior Analyst:** Full access to all cases, raw evidence inspection, deep header analysis, threat graph querying, evidence export, and case closure.
- **SOC Tier-1 / Junior Analyst:** Ingest emails, view threat scores, run automated scans, triage suspicious emails, submit escalation requests (read-only raw evidence).
- **Institutional Auditor / Legal Counsel:** View-only access to completed forensic reports and immutable chain-of-custody audit logs.

---

## 5. Frontend Pages & User Flows

The application adopts a Next.js 14 App Router layout, engineered as an elite **Cyber Defense Operations Center**:

- `/` – **Landing & Live Demo Portal:** Overview of the platform, architecture breakdown, interactive sample email sandbox analyzer, and live threat feed ticker.
- `/login` & `/register` – **Authentication Gateways:** Secure sign-in with 2FA TOTP verification, password strength indicators, and session validation.
- `/dashboard` – **SOC Command Center:**
  - Real-time KPI metrics: Total Ingested, High Risk / BEC Detections, Impersonation Attempts, Origin Nations Distribution.
  - Live Incident Stream (WebSocket connected).
  - High-priority threat alert ticker and quick triage drawer.
- `/analyzer` – **Interactive Email Forensic Workbench:**
  - Drag-and-drop zone for `.eml` / `.msg` files or raw header string input.
  - Multi-tab inspection view:
    1. *Summary Overview:* Fraud Score Gauge, Threat Classification, Primary Verdict.
    2. *Header Inspector:* Interactive RFC 5322 tree with hop-by-hop latency and SPF/DKIM/DMARC status pills.
    3. *NLP & Body Decompiler:* Social engineering cues highlighter, extracted URLs, decoded attachments.
    4. *GeoLocation & Relay Map:* Interactive world map displaying MTA hops from sender to receiver.
    5. *Raw Header & Hex:* Color-syntax highlighted raw RFC 822 view.
- `/cases` – **Forensic Case Management:**
  - Filterable, searchable repository of all active and archived investigations.
  - Case metadata: Evidence hash, assigned investigator, threat severity, status (Open, Investigating, Escalated, Closed).
- `/cases/[id]` – **Deep Dive Forensic Dossier:**
  - Consolidated incident workspace with timeline, evidence snapshots, chain-of-custody signatures, and investigator note-taking canvas.
- `/threat-graph` – **Interactive Threat Correlation Network:**
  - Full-screen force-directed graph (Cytoscape / React Flow) mapping relationships between Senders, Domains, IPs, DKIM keys, and Threat Campaigns.
- `/reports` – **Evidence & Legal Dossier Generator:**
  - One-click PDF generation preview, STIX/TAXII export, IOC CSV export, and compliance redaction toggles.
- `/settings` – **Platform Administration:**
  - API Keys (VirusTotal, Shodan, MaxMind, AbuseIPDB, Google Safe Browsing), User Management (RBAC), Retention Policies, and Notification Webhooks (Slack, MS Teams, SIEM Syslog).

---

## 6. Backend Architecture & Service Decomposition

The platform utilizes a modular, resilient Service-Oriented Architecture (SOA):

```
                       ┌─────────────────────────────────────────┐
                       │          Client (Next.js 14 UI)         │
                       └────────────────────┬────────────────────┘
                                            │ HTTPS / WSS
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │        API Gateway / Express Server     │
                       │    (Auth, RBAC, Validation, Routing)    │
                       └──────┬───────────────────────────┬──────┘
                              │                           │
                   REST / IPC │                           │ BullMQ Redis Queue
                              ▼                           ▼
        ┌───────────────────────────────┐   ┌───────────────────────────────┐
        │    Python Forensics Engine    │   │   Asynchronous Job Worker     │
        │  (FastAPI + Transformers)     │   │   (Bulk Ingestion, Scans)     │
        ├───────────────────────────────┤   ├───────────────────────────────┤
        │ • RFC Header & Relay Parser   │   │ • Automated Threat Intel Sync │
        │ • SPF/DKIM/DMARC Validator    │   │ • WHOIS / RDAP Async Fetch    │
        │ • MaxMind GeoIP2 / ASN Engine │   │ • PDF Report Generator        │
        │ • DeBERTa-v3 NLP Intent Model │   │ • SIEM Webhook Dispatcher     │
        │ • Attachment & URL Extractor  │   └───────────────────────────────┘
        └──────────────┬────────────────┘
                       │
         ┌─────────────┴───────────────┬──────────────────────────┐
         ▼                             ▼                          ▼
┌──────────────────┐         ┌──────────────────┐       ┌──────────────────┐
│  PostgreSQL /    │         │  Neo4j Threat    │       │  MinIO / S3      │
│  MongoDB Store   │         │  Graph Database  │       │  Encrypted Blob  │
│  (Metadata/Cases)│         │  (Attribution)   │       │  (Raw .EML/Evid) │
└──────────────────┘         └──────────────────┘       └──────────────────┘
```

### 6.1 Backend Modular Services
- **AuthService:** User credentialing, password hashing, JWT creation/refresh, TOTP 2FA validation, and audit trail logging.
- **IngestionService:** Validates MIME structure, checks magic bytes, extracts attachments, calculates SHA-256 evidence hashes, and stores raw blobs into MinIO/S3.
- **HeaderForensicsService:** Decompiles `Received:` lines, isolates timestamps, detects MTA timezone manipulation, evaluates SPF records, queries DKIM DNS records, and evaluates DMARC alignment.
- **GeoLocationService:** Parses public IP hops, resolves geolocation coordinates, ASN, organization, and cross-checks with TOR exit node lists and VPN ranges.
- **NLPThreatService:** Executes tokenization and transformer inference on subject/body to score BEC likelihood, psychological coercion, and impersonation indicators.
- **ThreatIntelService:** Connects to VirusTotal, AbuseIPDB, Shodan, and local reputation caches to score URLs, IP addresses, and file hashes.
- **GraphAttributionService:** Ingests scan IOCs into Neo4j, computes community clustering algorithms to link separate cases to the same campaign.
- **ReportService:** Compiles structured forensic results into formatted PDF dossiers and STIX/TAXII threat feeds.

---

## 7. Database Collections & Schemas

### 7.1 PostgreSQL / MongoDB Schema Overview

#### 1. `users`
- `id` (UUID / ObjectId): Primary key.
- `email` (String, unique): User work email.
- `passwordHash` (String): Bcrypt-hashed password.
- `role` (Enum: `SUPER_ADMIN`, `FORENSIC_ANALYST`, `SOC_OPERATOR`, `AUDITOR`).
- `name` (String): Full name.
- `twoFactorSecret` (String, encrypted): TOTP secret.
- `twoFactorEnabled` (Boolean): 2FA activation status.
- `createdAt`, `updatedAt`, `lastLogin` (Timestamps).

#### 2. `cases`
- `id` (UUID / ObjectId): Case reference ID (e.g., `CASE-2026-0982`).
- `title` (String): Descriptive incident title.
- `status` (Enum: `NEW`, `IN_REVIEW`, `INVESTIGATING`, `ESCALATED`, `RESOLVED`, `ARCHIVED`).
- `severity` (Enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `BENIGN`).
- `assignedTo` (User UUID / ObjectId, nullable).
- `overallRiskScore` (Float: 0.0 – 100.0).
- `threatCategory` (Enum: `BEC`, `PHISHING`, `IMPERSONATION`, `SPOOFED_DOMAIN`, `MALWARE`, `CLEAN`).
- `rawEmailStorageKey` (String): S3/MinIO bucket path.
- `sha256EvidenceHash` (String, immutable): Cryptographic signature of original `.eml`.
- `createdAt`, `updatedAt` (Timestamps).

#### 3. `email_analyses`
- `id` (UUID / ObjectId): Primary key.
- `caseId` (Reference to `cases.id`).
- `messageId` (String): Extracted RFC 5322 Message-ID.
- `envelopeFrom` (String): Return-Path address.
- `headerFrom` (String): RFC 5322 From address.
- `replyTo` (String, nullable): Reply-To header value.
- `subject` (String): Normalized subject line.
- `date` (Timestamp): Timestamp stated in email.
- `authenticationResults`:
  - `spf`: `{ status: "PASS"|"FAIL"|"SOFTFAIL", domain: String, ip: String }`
  - `dkim`: `{ status: "PASS"|"FAIL", selector: String, domain: String, signatureValid: Boolean }`
  - `dmarc`: `{ status: "PASS"|"FAIL", policy: "none"|"quarantine"|"reject", alignment: "strict"|"relaxed" }`
- `relayHops` (Array of Sub-documents):
  - `hopNumber` (Integer)
  - `receivedFrom` (String)
  - `by` (String)
  - `ipAddress` (String)
  - `isPrivate` (Boolean)
  - `geo`: `{ country: String, city: String, lat: Float, lon: Float, isp: String, asn: String }`
  - `delaySeconds` (Integer)
  - `isOriginatingHop` (Boolean)
- `nlpIntelligence`:
  - `becScore` (Float: 0.0 - 1.0)
  - `urgencyCues` (Array of Strings)
  - `coercionDetected` (Boolean)
  - `financialIntent` (Boolean)
  - `impersonatedEntity` (String, nullable)
- `iocs`:
  - `extractedUrls` (Array of `{ url: String, domain: String, isDefanged: Boolean, reputationScore: Float }`)
  - `attachments` (Array of `{ filename: String, size: Number, mimeType: String, sha256: String, isMalicious: Boolean }`)

#### 4. `threat_actors_campaigns`
- `id` (UUID / ObjectId): Primary key.
- `campaignName` (String): Generated or analyst-assigned campaign identifier.
- `firstSeen` (Timestamp), `lastSeen` (Timestamp).
- `associatedIps` (Array of Strings).
- `associatedDomains` (Array of Strings).
- `attributionConfidence` (Float: 0.0 - 100.0).
- `threatActorSignature` (String, nullable).

#### 5. `forensic_audit_logs` (Chain-of-Custody)
- `id` (UUID / ObjectId): Primary key.
- `caseId` (Reference to `cases.id`).
- `actorId` (Reference to `users.id`).
- `action` (Enum: `EVIDENCE_UPLOADED`, `HASH_VERIFIED`, `NOTE_ADDED`, `REPORT_GENERATED`, `REDACTION_APPLIED`, `EVIDENCE_EXPORTED`).
- `previousHash` (String): Cryptographic link to prior log entry (blockchain-style tamper resistance).
- `currentHash` (String): SHA-256 hash of log content.
- `timestamp` (Timestamp).

---

## 8. API Endpoints

### 8.1 Authentication & Profile
- `POST /api/v1/auth/register` – Create investigator account (Admin only in production).
- `POST /api/v1/auth/login` – Authenticate via email & password, return JWT & trigger 2FA check.
- `POST /api/v1/auth/2fa/verify` – Verify TOTP code, return full session token.
- `GET  /api/v1/auth/me` – Retrieve active user profile and permissions.
- `POST /api/v1/auth/logout` – Clear session tokens.

### 8.2 Email Ingestion & Analysis
- `POST /api/v1/emails/analyze` – Multipart upload of `.eml` / `.msg` file. Triggers immediate sync parsing or enqueues async job. Returns `analysisId` & `caseId`.
- `POST /api/v1/emails/analyze-raw` – JSON payload containing raw RFC 822 text string for quick inspection.
- `GET  /api/v1/emails/:id/status` – Poll status of long-running email deep scans.
- `GET  /api/v1/emails/:id/results` – Retrieve full structured forensic analysis (Headers, Geo, NLP, IOCs).

### 8.3 Case Management & Forensics
- `GET  /api/v1/cases` – List all forensic cases with pagination, search, severity, and status filters.
- `GET  /api/v1/cases/:id` – Fetch single case workspace including timeline and audit chain.
- `PATCH /api/v1/cases/:id/status` – Update case triage status (`RESOLVED`, `ESCALATED`, etc.).
- `POST /api/v1/cases/:id/notes` – Append immutable analyst forensic notes.
- `GET  /api/v1/cases/:id/chain-of-custody` – Fetch complete tamper-evident audit history.

### 8.4 Threat Graph & Correlation
- `GET  /api/v1/graph/correlations` – Query connected entities (IPs, Domains, Sender Addresses, Campaign clusters) with depth parameter.
- `GET  /api/v1/graph/campaigns` – List detected cross-case campaign patterns and threat actor clusters.

### 8.5 Reporting & Export
- `GET  /api/v1/reports/:caseId/pdf` – Stream compiled court-admissible PDF forensic dossier.
- `GET  /api/v1/reports/:caseId/stix` – Export structured STIX 2.1 JSON bundle for SIEM/SOAR ingestion.
- `GET  /api/v1/reports/:caseId/iocs` – Export defanged CSV list of IOCs (IPs, Domains, Hashes).

---

## 9. Folder Structure

```
aegismail-forensics/
├── docker-compose.yml
├── .env.example
├── README.md
│
├── client/                               # Next.js 14+ Frontend
│   ├── public/
│   │   ├── geojson/                      # World borders GeoJSON for offline maps
│   │   └── assets/                       # Static badges, logos
│   ├── src/
│   │   ├── app/                          # App Router
│   │   │   ├── (auth)/
│   │   │   │   ├── login/page.tsx
│   │   │   │   └── register/page.tsx
│   │   │   ├── dashboard/page.tsx
│   │   │   ├── analyzer/page.tsx
│   │   │   ├── cases/
│   │   │   │   ├── page.tsx
│   │   │   │   └── [id]/page.tsx
│   │   │   ├── threat-graph/page.tsx
│   │   │   ├── reports/page.tsx
│   │   │   ├── settings/page.tsx
│   │   │   ├── layout.tsx
│   │   │   └── page.tsx                  # Landing & Live Sandbox
│   │   ├── components/
│   │   │   ├── analyzer/
│   │   │   │   ├── EmailDropzone.tsx
│   │   │   │   ├── HeaderHierarchyTree.tsx
│   │   │   │   ├── GeoRelayMap.tsx       # Leaflet / MapLibre visualization
│   │   │   │   ├── NLPCueHighlighter.tsx
│   │   │   │   └── AuthProtocolPills.tsx # SPF/DKIM/DMARC badges
│   │   │   ├── graph/
│   │   │   │   ├── ForceGraphCanvas.tsx
│   │   │   │   └── NodeDetailsDrawer.tsx
│   │   │   ├── layout/
│   │   │   │   ├── AppHeader.tsx
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   └── NotificationDrawer.tsx
│   │   │   └── ui/                       # Shadcn/Radix atomic components
│   │   ├── hooks/
│   │   │   ├── useSocket.ts
│   │   │   └── useForensicAnalysis.ts
│   │   ├── lib/
│   │   │   ├── api.ts                    # Axios client
│   │   │   └── utils.ts
│   │   └── store/
│   │       ├── authStore.ts
│   │       └── caseStore.ts
│
├── server/                               # Node.js Gateway & Orchestrator
│   ├── src/
│   │   ├── config/
│   │   │   ├── env.js
│   │   │   ├── db.js                     # Postgres / Mongo connection
│   │   │   ├── redis.js
│   │   │   └── s3.js                     # Object storage client
│   │   ├── controllers/
│   │   │   ├── authController.js
│   │   │   ├── emailController.js
│   │   │   ├── caseController.js
│   │   │   ├── graphController.js
│   │   │   └── reportController.js
│   │   ├── middlewares/
│   │   │   ├── authMiddleware.js
│   │   │   ├── rbacMiddleware.js
│   │   │   ├── rateLimiter.js
│   │   │   └── uploadMiddleware.js
│   │   ├── models/
│   │   │   ├── User.js
│   │   │   ├── Case.js
│   │   │   ├── EmailAnalysis.js
│   │   │   ├── ThreatCampaign.js
│   │   │   └── AuditLog.js
│   │   ├── queues/
│   │   │   └── emailScanQueue.js         # BullMQ worker initialization
│   │   ├── services/
│   │   │   ├── authService.js
│   │   │   ├── evidenceStorageService.js
│   │   │   ├── fastApiClient.js          # Microservice IPC bridge
│   │   │   ├── auditTrailService.js
│   │   │   └── pdfReportService.js
│   │   └── app.js
│
└── ml_engine/                            # Python Deep Forensics & NLP Engine
    ├── app/
    │   ├── main.py                       # FastAPI entry point
    │   ├── core/
    │   │   ├── config.py
    │   │   └── logger.py
    │   ├── parsers/
    │   │   ├── rfc_parser.py             # MIME/RFC 5322 deconstruction
    │   │   ├── relay_tracer.py           # Received header hop analyzer
    │   │   └── protocol_verifier.py      # SPF, DKIM, DMARC DNS validator
    │   ├── intelligence/
    │   │   ├── geo_locator.py            # MaxMind GeoIP2 + ASN resolver
    │   │   ├── whois_resolver.py         # Domain age & registrar scanner
    │   │   ├── homoglyph_detector.py     # Typosquatting / spoof detection
    │   │   └── threat_feeds.py           # AbuseIPDB, TOR, VirusTotal hooks
    │   ├── nlp/
    │   │   ├── model_loader.py           # Transformers pipeline manager
    │   │   ├── bec_classifier.py         # DeBERTa-v3 / RoBERTa classifier
    │   │   └── cue_extractor.py          # Urgency, coercion, payment triggers
    │   └── graph/
    │       └── correlation_builder.py    # NetworkX / Neo4j entity graph mapper
    ├── models/                           # Fine-tuned PyTorch / ONNX model weights
    ├── requirements.txt
    └── Dockerfile
```

---

## 10. Development Phases

### Phase 1: Environment Setup, Architecture Foundation & Auth
- Initialize Next.js 14 client, Node.js API server, and FastAPI Python microservice.
- Configure MongoDB/PostgreSQL database connections, Redis queues, and local MinIO container.
- Implement User Authentication with JWT, Bcrypt password hashing, TOTP 2FA, and RBAC middleware.
- Build basic AppShell layout, SOC dark theme, and navigation drawer.

### Phase 2: Core Header Parsing & Protocol Cryptographic Verification
- Build RFC 5322 parsing engine in Python: extract all headers, body parts, and attachments.
- Implement `relay_tracer.py` to reverse-traverse `Received:` headers, handle private IP exclusions, and identify the true originating public IP.
- Implement DNS query validators for SPF record checking, DKIM signature verification, and DMARC alignment validation.
- Deliver `/analyzer` initial UI to render parsed header trees and protocol status badges.

### Phase 3: GeoLocation Mapping & Infrastructure Threat Intelligence
- Integrate MaxMind GeoLite2 City and ASN databases to resolve country, city, coordinates, and ISP for each mail hop.
- Implement VPN/TOR/Proxy identification checks against open-source threat lists and public node endpoints.
- Build domain intelligence pipeline: WHOIS registration date, registrar name, DNS MX/NS consistency, and homoglyph spoofing algorithms.
- Render interactive cartographic trace map (MapLibre / Leaflet) showing the transmission flight path of the email.

### Phase 4: NLP Intent Detection & Social Engineering Scoring
- Integrate transformer-based NLP models (RoBERTa / DeBERTa-v3) for BEC and phishing text classification.
- Build regex and heuristic extractors for psychological urgency, authority impersonation, financial terms, and fake payment routing cues.
- Implement malicious link extraction, URL defanging, and reputation checking against external threat APIs (Google Safe Browsing, PhishTank).
- Display interactive NLP analysis view with visual text highlighting of detected threat triggers.

### Phase 5: Threat Attribution Graph & Campaign Correlation
- Integrate Graph correlation engine (Neo4j / NetworkX) connecting Senders, Origin IPs, DKIM keys, and Domains across historical cases.
- Implement graph clustering algorithms to group related phishing attacks into distinct Threat Actor Campaigns.
- Build interactive frontend Graph Explorer using Cytoscape.js / React Flow allowing analysts to explore interconnected infrastructure nodes.

### Phase 6: Case Management, Chain-of-Custody & Forensic Reporting
- Implement complete Case Management lifecycle (Create, Assign, Triage, Annotate, Close).
- Implement tamper-evident cryptographic audit logs (SHA-256 block-linked logs) for legal chain-of-custody.
- Develop court-admissible PDF Forensic Dossier generation and STIX 2.1 export engine.
- Final end-to-end integration testing, Docker Compose orchestration, and security hardening.

---

## 11. UI and UX Requirements

- **Aesthetic Direction:** Modern, mission-critical Cyber Operations Center aesthetic. Deep slate/neutral backgrounds (`#0B0F17`, `#111827`), high-contrast clean typography, and purposeful status accents:
  - **Critical / Phishing:** Crimson Red (`#EF4444`)
  - **Suspicious / Warning:** Amber / Orange (`#F59E0B`)
  - **Clean / Verified:** Emerald Green (`#10B981`)
  - **Information / Relay Hop:** Cyan / Electric Indigo (`#06B6D4` / `#6366F1`)
- **Responsive Layout:** Optimized for high-resolution SOC monitor arrays (1440p / 1080p desktop) while maintaining clean responsiveness on laptop viewports.
- **Relay Map Visualizer:** Visual animated flight path between intermediate MTA hops on an interactive world vector map, displaying hop time, MTA name, and IP reputation upon hover.
- **Header Tree Component:** Hierarchical, collapsible display of email headers with one-click "Copy Clean", "Copy Defanged", and "Search Threat DB" quick actions.
- **NLP Visual Cue Highlighter:** Inline visual markup over the email body text highlighting phrases containing artificial urgency (yellow), credential harvesting triggers (red), or bank account diversion cues (orange).
- **Accessibility & Feedback:** Micro-animations for asynchronous scan states, skeleton loading screens for AI analysis passes, and toast alerts for critical updates.

---

## 12. Security & Compliance Requirements

### 12.1 Digital Forensics & Chain-of-Custody (ISO/IEC 27037 & BNSS)
- **Immutable Evidence Storage:** Uploaded `.eml` files are hashed with SHA-256 immediately upon arrival at the gateway, saved into read-only object storage, and never modified in place.
- **Cryptographic Audit Ledger:** Every analyst action (viewing raw headers, extracting attachments, modifying tags, downloading dossiers) is recorded in an append-only audit log with SHA-256 block hashing.

### 12.2 Application & Network Security
- **Defanging Indicators:** All URLs, domain names, and IP addresses displayed on the dashboard are automatically defanged by default (e.g., `hxxps[://]evil-phish[.]com`, `192[.]0[.]2[.]1`) to prevent accidental analyst click-throughs.
- **Attachment Sandboxing:** Uploaded email attachments are stripped, stored with `.quarantine` extensions, never executed on host servers, and analyzed strictly via static hash lookups and isolated sandboxed extraction.
- **Input Validation & Sanitization:** Strict multipart payload validation with magic-byte checking; express-validator and Pydantic models on all endpoints to prevent SQLi, NoSQLi, and Path Traversal attacks.
- **API Security:** Rate-limiting via Redis (`express-rate-limit`), secure HTTP security headers via `helmet`, strict CORS whitelisting, and encryption of third-party API keys at rest using AES-256-GCM.

### 12.3 Privacy & Data Protection (DPDP Act & GDPR)
- **PII Redaction Engine:** Ability to mask sensitive customer or employee personal data (e.g., credit card numbers, phone numbers, personal identifiers) in generated forensic reports and public-facing displays.
- **Configurable Retention Windows:** Automatic scheduled purging of email content older than standard organizational retention policies (e.g., 90 / 180 / 365 days).

---

## 13. Final Expected Outcome

The finished **AegisMail Forensics** platform will deliver a fully working, comprehensive cyber defense solution that allows security analysts and law enforcement personnel to:

1. **Instantly Triage & Decompile Any Email:** Ingest any suspicious `.eml` or `.msg` file and obtain a comprehensive forensic breakdown within seconds.
2. **Expose Spoofed & Impersonated Identities:** Immediately surface mismatches between visible Display Names, Header From, Return-Path, and envelope headers, backed by real-time SPF, DKIM, and DMARC verification.
3. **Trace Origin Down to the Physical Map:** Trace the true origin of an email through intermediate relays, stripping away spoofed local headers and isolating the originating public MTA with geolocation, ISP, and proxy/TOR flagging.
4. **Detect AI-Generated & Advanced BEC Attacks:** Uncover zero-day social engineering and executive impersonation using fine-tuned transformer NLP models that evaluate emotional urgency and financial compromise cues.
5. **Connect Coordinated Threat Campaigns:** Traverse an interactive threat correlation graph that links disparate emails across organizations to common malicious infrastructure and threat actors.
6. **Export Evidentiary Reports:** Generate court-admissible, tamper-evident forensic PDF dossiers and automated STIX 2.1 feeds ready for legal presentation or SIEM ingestion.

---

## 14. Codex & AI Agent Implementation Instructions

When building this application, the AI coding agent must follow these strict operational rules:

1. **Strict Service Decoupling:** Keep the Express Gateway and the Python FastAPI ML microservice completely separated. The Express server handles authentication, DB persistence, file uploads, and case tracking. The Python service handles raw email parsing, DNS protocol validation, GeoIP lookups, and NLP inference.
2. **Stateless ML & Pure Parsing:** The Python microservice must remain stateless. It accepts raw email streams or header structures via REST/IPC, executes analysis, and returns structured JSON schemas.
3. **Defanging by Default:** All extracted URLs, domains, and IP addresses returned from forensic endpoints must include a `defanged` field or be defanged in preview representations to safeguard analysts.
4. **Never Direct DB Access from Fast-Path Controllers:** Controllers must parse requests and delegate business logic to dedicated services (`caseService`, `emailService`, `graphService`).
5. **Robust In-Memory Fallbacks:** When external services (like Neo4j, MaxMind GeoIP license, or external threat APIs like VirusTotal) are not active or keys are omitted, provide graceful in-memory fallbacks (e.g., NetworkX graph, bundled GeoLite2-City sample database, heuristic threat scoring) so the system remains fully operational in local development.
6. **Immutable Hashing First:** Whenever an email is ingested, calculate and log its SHA-256 hash before running any extraction, parsing, or storage pipeline.
7. **Phase-by-Phase Verification:** Build and verify modules incrementally according to the Development Phases in Section 10, producing an auditable list of created files and test endpoints upon completion of each phase.
