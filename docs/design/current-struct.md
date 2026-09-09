# SpectraShield — Current Project Structure & Detailed Working Specification

> **Last Updated**: September 2, 2026  
> **Repository**: `SpectraShield`  
> **Type**: Full-Stack AI Phishing Detection, Browser Protection & Threat Intelligence Platform  

---

## Table of Contents
1. [Project Executive Summary](#1-project-executive-summary)
2. [High-Level Architecture & End-to-End Data Flows](#2-high-level-architecture--end-to-end-data-flows)
3. [Complete Annotated Directory Tree](#3-complete-annotated-directory-tree)
4. [File-by-File Detailed Working & Logic Breakdown](#4-file-by-file-detailed-working--logic-breakdown)
   - [4.1 Backend Engine (`backend/`)](#41-backend-engine-backend)
   - [4.2 Browser Extension (`extension/`)](#42-browser-extension-extension)
   - [4.3 Frontend Web Application (`frontend/`)](#43-frontend-web-application-frontend)
5. [Database Schemas, Models & Persistence Layer](#5-database-schemas-models--persistence-layer)
6. [Threat Scoring Formulas & Fusion Algorithms](#6-threat-scoring-formulas--fusion-algorithms)
7. [REST API Specification](#7-rest-api-specification)
8. [Configuration & Environment Variables](#8-configuration--environment-variables)
9. [Installation & Execution Guide](#9-installation--execution-guide)

---

## 1. Project Executive Summary

**SpectraShield** is an AI-powered, multi-vector threat intelligence and phishing detection system. It provides real-time protection across emails (Gmail), social messaging (LinkedIn DMs), and standalone suspicious URLs.

### Key Capabilities
- **Explainable Multi-Vector Scoring**: Fuses linguistic manipulation heuristics, brand impersonation distance algorithms, URL reputation, SSL/TLS certificate validation, domain age profiling, and email authentication headers (SPF/DKIM/DMARC).
- **Zero-Touch Browser Extension**: Manifest V3 extension that automatically parses Gmail inbox rows and LinkedIn messages, displaying color-coded risk badges and banners without requiring user manual copying.
- **Privacy-First Operational Mode**: Supports a `private_mode: true` flag that computes all security heuristics entirely in-memory without storing payloads or email text in the database.
- **Cyber Killchain Attack Simulation**: Predicts downstream attack consequences (e.g., Fake Login $\rightarrow$ Credential Harvesting $\rightarrow$ Account Takeover $\rightarrow$ Financial Loss) for any threat scored $\ge 50$.
- **SOC Security Analytics Dashboard**: Interactive React dashboard providing 7x24 incident heatmaps, top impersonated brand intelligence, live link sandboxing, and full scan history auditing.
- **Dual-Database Support**: Pluggable storage engine supporting Supabase / PostgreSQL (with JSONB collections and RLS) as well as MongoDB.

---

## 2. High-Level Architecture & End-to-End Data Flows

```mermaid
flowchart TD
    subgraph ClientLayer["1. Client Layer"]
        EXT_GMAIL["Chrome Extension: Gmail Content Script"]
        EXT_LINKEDIN["Chrome Extension: LinkedIn Sentinel"]
        EXT_POPUP["Chrome Extension: Quick Scan Popup"]
        FE_APP["React + Vite Security Dashboard"]
    end

    subgraph APILayer["2. FastAPI Application Layer (backend/app/)"]
        API_GATEWAY["FastAPI Engine (main.py / routes.py)"]
        AUTH_ROUTER["CORS & Cache Dispatcher"]
        HYBRID_SCANNER["HybridConsensusScanner (scanner.py)"]
        URL_ENGINE["URLIntelligenceEngine (scanner.py)"]
    end

    subgraph ServiceLayer["3. Analysis Services Layer (backend/app/services/)"]
        SRV_MANIP["Manipulation Detector\n(Urgency, Fear, Authority, Scarcity)"]
        SRV_BRAND["Brand Impersonation Detector\n(Levenshtein Distance + Heuristics)"]
        SRV_HDR["Header Analyzer\n(SPF / DKIM / DMARC)"]
        SRV_SIM["Attack Simulator\n(4-Stage Killchain)"]
        SRV_CAT["Threat Categorizer & Reasoning Engine"]
        SRV_FUSION["Risk Fusion Algorithm"]
    end

    subgraph ExternalIntelligence["4. External Intelligence & Network Probing"]
        VT_API["VirusTotal v3 API (URL Analysis)"]
        OPENPHISH["OpenPhish Threat Feed (Daily Pulse)"]
        WHOIS_DNS["WHOIS / RDAP & DNS Resolver"]
        SSL_SOCKET["Direct SSL/TLS Certificate Prober"]
    end

    subgraph StorageLayer["5. Persistence & Cache Layer"]
        PG_COL["PostgresCollection (PostgreSQL JSONB / Supabase)"]
        MONGO_COL["MongoDB Collections (Fallback)"]
        CACHE_VT["vt_url_cache Table"]
        FEED_DB["threat_feed Table"]
        SCANS_DB["scans Table"]
    end

    %% Client to API
    EXT_GMAIL -->|POST /analyze (thread_id, private_mode)| API_GATEWAY
    EXT_LINKEDIN -->|POST /analyze (platform: linkedin)| API_GATEWAY
    EXT_POPUP -->|POST /analyze| API_GATEWAY
    FE_APP -->|POST /analyze, GET /dashboard/*, GET /history| API_GATEWAY

    %% API to Engines
    API_GATEWAY --> AUTH_ROUTER
    AUTH_ROUTER -->|Cache Hit| SCANS_DB
    AUTH_ROUTER -->|Cache Miss| HYBRID_SCANNER
    HYBRID_SCANNER --> URL_ENGINE
    HYBRID_SCANNER --> SRV_MANIP
    HYBRID_SCANNER --> SRV_BRAND
    HYBRID_SCANNER --> SRV_HDR
    HYBRID_SCANNER --> SRV_CAT
    HYBRID_SCANNER --> SRV_FUSION
    API_GATEWAY --> SRV_SIM

    %% Network & Intel Calls
    URL_ENGINE --> VT_API
    URL_ENGINE --> CACHE_VT
    HYBRID_SCANNER --> WHOIS_DNS
    HYBRID_SCANNER --> SSL_SOCKET
    API_GATEWAY --> OPENPHISH
    OPENPHISH --> FEED_DB

    %% Persistence
    API_GATEWAY -->|If private_mode == false| PG_COL
    PG_COL --> SCANS_DB
    PG_COL --> FEED_DB
    PG_COL --> CACHE_VT
    API_GATEWAY -.-> MONGO_COL
```

---

## 3. Complete Annotated Directory Tree

```text
SpectraShield/
├── .gitignore                              # Git exclusion rules for python, node, envs, OS artifacts
├── README.md                               # Project documentation & setup overview
├── current-struct.md                       # Comprehensive architectural & technical specification
│
├── backend/                                # Python FastAPI Backend Service
│   ├── .env.example                        # Example configuration template for database and VT credentials
│   ├── .gitignore                          # Virtualenv and cache ignore rules
│   ├── requirements.txt                    # Python dependencies (FastAPI, uvicorn, psycopg2, pymongo, etc.)
│   │
│   ├── app/                                # Core Application Package
│   │   ├── __init__.py                     # App package marker
│   │   ├── database.py                     # Database initialization, backend selection, schema auto-migration
│   │   ├── main.py                         # Primary application entry point, lifecycle events, core endpoints
│   │   ├── pg_collection.py                # MongoDB-compatible driver implementation for PostgreSQL JSONB
│   │   ├── routes.py                       # Modular API router for /analyze and /history endpoints
│   │   ├── scanner.py                      # Multi-layer consensus scanner & URL intelligence engine
│   │   ├── schemas.py                      # Pydantic data contract definitions
│   │   ├── storage.py                      # Storage abstraction interface
│   │   │
│   │   ├── services/                       # Granular Threat Analysis Services
│   │   │   ├── ai_pattern_detector.py      # Linguistic AI-generation pattern detector
│   │   │   ├── attack_simulator.py         # 4-stage killchain simulation generator
│   │   │   ├── brand_detector.py           # Brand impersonation & sender mismatch heuristics
│   │   │   ├── header_analyzer.py          # SPF, DKIM, DMARC authentication verification
│   │   │   ├── manipulation_detector.py    # Psychological pressure scoring (Urgency, Fear, Authority, Scarcity)
│   │   │   ├── risk_fusion.py              # Mathematical score fusion formulas
│   │   │   ├── threat_category.py          # Threat taxonomy classifier & explanation synthesizer
│   │   │   ├── threat_intel.py             # OpenPhish synchronization worker & feed matcher
│   │   │   └── url_analyzer.py             # URL structural heuristics & domain age calculator
│   │   │
│   │   └── utils/                          # Common Utilities
│   │       └── text_preprocess.py          # String normalization, regex tokenizers & sanitation
│   │
│   ├── scripts/                            # Database Migration & Administrative Scripts
│   │   └── migrate_mongo_to_postgres.py    # Live ETL script migrating MongoDB documents to Supabase PostgreSQL
│   │
│   └── sql/                                # Database DDL Schemas
│       └── supabase_schema.sql             # PostgreSQL baseline DDL with JSONB structures and RLS policies
│
├── extension/                              # Chromium Browser Extension (Manifest V3)
│   ├── manifest.json                       # Extension manifest declaring permissions, scripts & service worker
│   ├── background.js                       # Service worker for extension lifecycle & message forwarding
│   ├── content.js                          # Gmail & LinkedIn DOM observer, badge injector & link inspector
│   ├── content.css                         # CSS styling for injected badges, tooltips, and warning banners
│   ├── popup.html                          # Extension popup HTML user interface
│   ├── popup.js                            # Logic for popup scan execution and result rendering
│   ├── popup.css                           # Visual styles and animations for the popup UI
│   └── README.md                           # Extension setup and developer mode installation instructions
│
└── frontend/                               # React 18 + Vite Web Application
    ├── index.html                          # Single Page Application HTML document entry
    ├── package.json                        # NPM package manifest with dependencies, scripts and build tools
    ├── package-lock.json                   # Deterministic package lockfile
    ├── postcss.config.mjs                  # PostCSS plugins configuration
    ├── vite.config.ts                      # Vite build tool & React plugin configuration
    ├── README.md                           # Frontend overview & quickstart
    ├── ATTRIBUTIONS.md                     # Open-source library attributions & licenses
    ├── DASHBOARD_GUIDE.md                  # Comprehensive dashboard operational manual
    ├── FEATURES_OVERVIEW.md                # Feature inventory across all application views
    ├── INTEGRATION_GUIDE.md                # API integration guide for third-party tools
    ├── LINK_PREVIEW_GUIDE.md               # Documentation on URL sandboxing & preview features
    ├── STYLE_GUIDE.md                      # UI style guide, tokens, typography, and color palettes
    │
    ├── guidelines/                         # UI/UX & Code Standards
    │   └── Guidelines.md                   # Engineering standards for frontend components
    │
    └── src/                                # Frontend Source Code
        ├── main.tsx                        # React application bootstrap & DOM mounting
        │
        ├── app/                            # Application Layer
        │   ├── App.tsx                     # Root state container, navigation tabs, deep-linking handler
        │   ├── api.ts                      # Typed API client for backend communication
        │   ├── gmail-content.tsx           # Gmail simulation view state & mock mailbox records
        │   │
        │   └── components/                 # Feature & Presentation Components
        │       ├── ActionButtons.tsx       # Remediation controls (Mark Safe, Report Phishing, Safe Mode)
        │       ├── Dashboard.tsx           # SOC dashboard with 7x24 heatmap, top brands, and history table
        │       ├── GmailDemo.tsx           # Full interactive Gmail inbox mock with risk badges
        │       ├── GmailInboxRiskIndicators.tsx # Badge rendering & tooltip component for Gmail simulation
        │       ├── LinkPreview.tsx         # Sandboxed URL previewer with SSL, DNS & WHOIS telemetry
        │       ├── LinkPreviewDemo.tsx     # Step-by-step interactive link analysis demo walkthrough
        │       ├── PhishingWarningBanner.tsx # Top floating critical warning banner
        │       ├── RiskBreakdown.tsx       # Progress bars displaying granular threat category scores
        │       ├── RiskMeter.tsx           # Circular SVG gauge with animated arc & score count-up
        │       ├── StyleGuide.tsx          # Design token viewer showcasing typography, badges, buttons
        │       ├── ThemeProvider.tsx       # Theme wrapper providing Light/Dark/System modes via next-themes
        │       ├── ThemeToggle.tsx         # Theme toggle button with icons
        │       ├── WhyFlagged.tsx          # Expandable accordion detailing forensic evidence & reasoning
        │       │
        │       ├── figma/                  # Specialized Asset Components
        │       │   └── ImageWithFallback.tsx # Image component with error handling and fallback states
        │       │
        │       └── ui/                     # 48 Radix UI & Shadcn Component Primitives
        │           ├── accordion.tsx       # Collapsible content container
        │           ├── alert-dialog.tsx    # Modal confirmation dialog
        │           ├── alert.tsx           # Inline alert banner
        │           ├── aspect-ratio.tsx    # Responsive aspect ratio wrapper
        │           ├── avatar.tsx          # User profile avatar with fallback
        │           ├── badge.tsx           # Status badge primitive
        │           ├── breadcrumb.tsx      # Navigation breadcrumb hierarchy
        │           ├── button.tsx          # Styled button variants with loading states
        │           ├── calendar.tsx        # Date selector calendar
        │           ├── card.tsx            # Card containers (Header, Content, Footer)
        │           ├── carousel.tsx        # Embla carousel integration
        │           ├── chart.tsx           # Recharts wrapper for analytics
        │           ├── checkbox.tsx        # Accessible checkbox input
        │           ├── collapsible.tsx     # Expandable block primitive
        │           ├── command.tsx         # Command palette primitive (cmdk)
        │           ├── context-menu.tsx    # Right-click context menu
        │           ├── dialog.tsx          # Modal dialog primitive
        │           ├── drawer.tsx          # Slide-out drawer primitive (vaul)
        │           ├── dropdown-menu.tsx   # Floating dropdown menu
        │           ├── form.tsx            # React Hook Form integration wrappers
        │           ├── hover-card.tsx      # Hover popover container
        │           ├── input-otp.tsx       # Multi-segment OTP input
        │           ├── input.tsx           # Form input field
        │           ├── label.tsx           # Form label primitive
        │           ├── menubar.tsx         # Desktop-style menubar
        │           ├── navigation-menu.tsx # Hierarchical navigation menu
        │           ├── pagination.tsx      # Table pagination controls
        │           ├── popover.tsx         # Floating popover primitive
        │           ├── progress.tsx        # Accessible progress bar
        │           ├── radio-group.tsx     # Radio group selection
        │           ├── resizable.tsx       # Split-pane resizable layout
        │           ├── scroll-area.tsx     # Custom scrollbar container
        │           ├── select.tsx          # Custom select dropdown
        │           ├── separator.tsx       # Visual horizontal/vertical divider
        │           ├── sheet.tsx           # Off-canvas side sheet
        │           ├── sidebar.tsx         # Expandable application sidebar
        │           ├── skeleton.tsx        # Content placeholder skeleton
        │           ├── slider.tsx          # Range slider primitive
        │           ├── sonner.tsx          # Toast notification provider
        │           ├── switch.tsx          # Toggle switch input
        │           ├── table.tsx           # Data table components
        │           ├── tabs.tsx            # Tabbed navigation container
        │           ├── textarea.tsx        # Multiline text input
        │           ├── toggle-group.tsx    # Multi-button toggle group
        │           ├── toggle.tsx          # Single toggle button
        │           ├── tooltip.tsx         # Hover tooltip primitive
        │           ├── use-mobile.ts       # Responsive viewport hook
        │           └── utils.ts            # Tailwind class merging utility (clsx + twMerge)
        │
        └── styles/                         # Application CSS
            ├── fonts.css                   # Custom web font declarations
            ├── index.css                   # Global CSS reset & base layer
            ├── tailwind.css                # Tailwind CSS v4 setup
            └── theme.css                   # HSL theme variables for Dark and Light modes
```

---

## 4. File-by-File Detailed Working & Logic Breakdown

### 4.1 Backend Engine (`backend/`)

#### [`backend/app/main.py`](file:///d:/Project/SpectraShield/backend/app/main.py)
- **Role**: Primary application orchestrator and unified API gateway.
- **Key Mechanics & Working**:
  1. **Startup Lifecycle (`start_daily_pulse`)**: Launches an asynchronous background worker (`_daily_pulse_loop`) that calls `sync_openphish()` every 24 hours to refresh known phishing URLs into the `threat_feed` table.
  2. **CORS Configuration**: Configures open cross-origin resource sharing (`*`) to allow seamless requests from Chrome extension service workers and the Vite frontend.
  3. **Scan Caching & Deduplication**: Checks `scans_collection` for previous high/moderate confidence scans matching `thread_id` or `linkedin_thread_id`. If a valid cached scan exists, it returns immediately with `cached: true`.
  4. **Platform-Specific Routing (`platform: "linkedin"`)**:
     - Extracts message text and link pairs from LinkedIn DMs.
     - Ignores internal LinkedIn navigation routes (`/in/`, `/messaging/`, `/company/`).
     - Queries VirusTotal engine stats on external links, adds SSL risk penalties, and calculates `corrected_url_score`.
     - Blends content analysis (35%) with worst link score (65%).
     - Upserts results using `linkedin_thread_id` and constructs `linkedin_sentinel` telemetry.
  5. **Unified Email/Link Analysis (`platform: "gmail"` / default)**:
     - Dispatches extraction to `HybridConsensusScanner.scan()`.
     - Analyzes SPF/DKIM/DMARC headers with `analyze_email_header()`.
     - Evaluates body URLs via `compute_mail_severity()`.
     - Profiles SSL certificate parameters (`_ssl_status_profile`) — gives a -40% risk discount for EV certificates; adds +50% for self-signed/untrusted, +60% for expired, and +80% for hostname mismatches.
     - Adjusts for domain age (`_apply_domain_age_adjustment`) — adds +50% for burner domains ($\le 30$ days) and +25% for new entities ($\le 180$ days).
     - Fuses scores into `final_risk` = $\min(100, \max(\text{fusion\_score}, \text{mail\_severity\_score}))$.
     - Conditionally persists to `scans_collection` if `private_mode` is false.
  6. **Dashboard Endpoints**:
     - `GET /dashboard/top-brands`: Aggregates brand impersonation occurrences across internal scans and OpenPhish feeds over a dynamic window (1–365 days) and risk filters (low/medium/high/all).
     - `GET /dashboard/risk-heatmap`: Transforms scan UTC timestamps into day-of-week (0=Sun..6=Sat) and hour-of-day (0..23) buckets to construct a 7x24 matrix for SOC heatmap visualizations.

#### [`backend/app/scanner.py`](file:///d:/Project/SpectraShield/backend/app/scanner.py)
- **Role**: Core intelligence engine encapsulating the `HybridConsensusScanner` and `URLIntelligenceEngine`.
- **Key Mechanics & Working**:
  1. **`_levenshtein(a, b)`**: DP implementation of edit distance used for typosquatting detection against protected brand names (e.g., `micros0ft` vs `microsoft`).
  2. **`get_vt_url_id(url)`**: Computes RFC 4648 Base64URL encoding without trailing `=` padding required for VirusTotal v3 API lookups.
  3. **`URLIntelligenceEngine`**:
     - Evaluates domain structural anomalies: high-risk TLDs (`.top`, `.xyz`, `.tk`, `.gq`, `.ml`), raw IP address hosts, excessive subdomain depth ($> 3$).
     - Implements 24-hour cached lookup to VirusTotal v3. If a URL is unseen, submits it via POST for asynchronous analysis while continuing scan without blocking.
     - Flags brand typosquatting if edit distance $\le 2$ or if protected brand names appear as subdomains on untrusted root domains.
  4. **`HybridConsensusScanner`**:
     - **Direct TLS Prober (`_ssl_details`)**: Opens a direct socket to port 443 with timeout, extracts binary certificate, decodes issuer, validity dates, subject organization, and detects self-signed chains.
     - **WHOIS & RDAP Engine (`_whois_domain_age`)**: Connects to domain registries to compute exact domain age in days.
     - **DNS Engine (`_dns_records`)**: Resolves A, AAAA, and MX records to verify if the domain has mail-exchange capability.
     - **Geo-Location (`_location_data`)**: Identifies server hosting country, IP address, and ISP.
     - **Consensus Arbiter**: Assigns consensus mode (`local_only`, `external_only`, `hybrid_consensus`).
  5. **`analyze_linkedin_message()`**: Detects job scams (unrealistic salaries, WhatsApp/Telegram redirection), crypto investment fraud, and urgent verification requests in direct messages.
  6. **`compute_mail_severity()`**: Evaluates emails containing multiple URLs, identifies the most dangerous link, and calculates overall mail threat severity.

#### [`backend/app/routes.py`](file:///d:/Project/SpectraShield/backend/app/routes.py)
- **Role**: Modular API router providing standard REST endpoints.
- **Key Mechanics & Working**:
  - `POST /analyze`: Standardized entry point running manipulation heuristics, URL inspection, AI generation checks, brand impersonation, and header analysis.
  - `GET /history`: Fetches stored historical scan records ordered from newest to oldest.
  - `GET /history/count`: Returns a lightweight count object `{ "total_scans": N }`.
  - `DELETE /history`: Purges all stored scan records.
  - `DELETE /history/{scan_id}`: Deletes a specific scan record by UUID.

#### [`backend/app/database.py`](file:///d:/Project/SpectraShield/backend/app/database.py)
- **Role**: Storage layer dispatcher and database schema initializer.
- **Key Mechanics & Working**:
  - Checks `DB_BACKEND` environment variable (`postgres` or `mongo`). If not explicitly set, infers PostgreSQL if `DATABASE_URL` is present.
  - For PostgreSQL: Connects via `psycopg2` with `RealDictCursor`, runs DDL statements to auto-create `scans`, `threat_feed`, and `vt_url_cache` tables with B-Tree indexes, and instantiates `PostgresCollection` wrappers.
  - For MongoDB: Connects via `pymongo.MongoClient`, drops legacy TTL expiration indexes to preserve scan history, and creates index constraints.

#### [`backend/app/pg_collection.py`](file:///d:/Project/SpectraShield/backend/app/pg_collection.py)
- **Role**: MongoDB-to-PostgreSQL compatibility driver.
- **Key Mechanics & Working**:
  - Translates PyMongo dictionary queries (`find_one`, `find`, `insert_one`, `update_one`, `delete_one`, `count_documents`) into parameterized SQL over PostgreSQL `JSONB` columns (`payload`).
  - Supports MongoDB operators: `$in`, `$gt`, `$gte`, `$lt`, `$lte`, `$ne`, `$set`, `$setOnInsert`.
  - Implements atomic upserts via `INSERT INTO ... ON CONFLICT (key) DO UPDATE`.

#### [`backend/app/schemas.py`](file:///d:/Project/SpectraShield/backend/app/schemas.py)
- **Role**: Pydantic data contract definitions.
- **Key Models**:
  - `SimulationStep`: Represents a single stage in an attack killchain (`step`, `title`, `description`).
  - `EmailRequest`: Incoming request payload schema (`email_text`, `email_header`, `url`, `urls`, `sender_email`, `private_mode`).
  - `EmailResponse`: Outgoing response payload schema (`final_risk`, `verdict`, `confidence_level`, `breakdown`, `highlighted_phrases`, `domain_age_days`, `attack_simulation`).

#### [`backend/app/services/manipulation_detector.py`](file:///d:/Project/SpectraShield/backend/app/services/manipulation_detector.py)
- **Role**: Psychological trigger analyzer.
- **Key Mechanics & Working**:
  - Evaluates message text against four psychological manipulation dictionaries:
    - **Urgency**: `urgent`, `immediately`, `act now`, `within 24 hours` (+15 pts).
    - **Fear**: `suspended`, `blocked`, `legal action`, `security alert` (+20 pts).
    - **Authority**: `official`, `admin`, `support team`, `security department` (+10 pts).
    - **Scarcity**: `limited time`, `expires today`, `only few hours` (+15 pts).
  - Returns `manipulation_score` (capped at 100), unique flagged phrases, and a normalized `psychological_index` dictionary (0–100 per vector).

#### [`backend/app/services/brand_detector.py`](file:///d:/Project/SpectraShield/backend/app/services/brand_detector.py)
- **Role**: Brand impersonation and sender spoofing detector.
- **Key Mechanics & Working**:
  - Compares mentioned brands (Microsoft, Google, Apple, PayPal, Netflix, Amazon, etc.) in the text against the domain in `sender_email`.
  - Penalizes mismatched domains with high brand impersonation risk scores (up to 100).

#### [`backend/app/services/header_analyzer.py`](file:///d:/Project/SpectraShield/backend/app/services/header_analyzer.py)
- **Role**: Email authentication header inspector.
- **Key Mechanics & Working**:
  - Scans headers for `Received-SPF`, `DKIM-Signature`, and `Authentication-Results`.
  - Flags `spf=fail`, `dkim=fail`, `dmarc=fail` or missing authentication records with severity penalties.

#### [`backend/app/services/attack_simulator.py`](file:///d:/Project/SpectraShield/backend/app/services/attack_simulator.py)
- **Role**: Downstream attack consequence generator.
- **Key Mechanics & Working**:
  - For any scan resulting in `final_risk >= 50`, generates a 4-step killchain:
    1. *Fake Login Page*: Redirection to an adversary-controlled landing page.
    2. *Credential Harvesting*: Victim enters corporate/personal credentials.
    3. *Account Takeover*: Attacker leverages harvested credentials.
    4. *Financial/Data Loss*: Exfiltration of sensitive files or fraudulent transactions.

#### [`backend/app/services/threat_category.py`](file:///d:/Project/SpectraShield/backend/app/services/threat_category.py)
- **Role**: Threat taxonomy classification and natural language reasoning synthesizer.
- **Key Mechanics & Working**:
  - Evaluates dominant risk signals and keywords to classify into one of 5 categories: `Credential Harvesting`, `Brand Impersonation`, `Financial Scam`, `Account Takeover`, or `Urgency-Based Attack`.
  - `build_reasoning_summary()`: Combines flagged findings (domain age, pressure language, header failures) into an explainable summary sentence for end-users.

#### [`backend/app/services/threat_intel.py`](file:///d:/Project/SpectraShield/backend/app/services/threat_intel.py)
- **Role**: Threat intelligence synchronization worker.
- **Key Mechanics & Working**:
  - `sync_openphish()`: Fetches the latest community phishing feed from OpenPhish, parses active URLs, and stores them in the `threat_feed` collection with timestamps.
  - `analyze_threat_intel()`: Cross-checks submitted headers and URLs against local threat databases.

#### [`backend/app/services/risk_fusion.py`](file:///d:/Project/SpectraShield/backend/app/services/risk_fusion.py)
- **Role**: Score fusion mathematical model.
- **Key Mechanics & Working**:
  - Combines individual category scores into `final_risk`, assigns qualitative `verdict` (Low / Medium / High Risk), and calculates `confidence_level`.

#### [`backend/app/services/ai_pattern_detector.py`](file:///d:/Project/SpectraShield/backend/app/services/ai_pattern_detector.py)
- **Role**: Synthetic text and AI-generated phishing detector.
- **Key Mechanics & Working**:
  - Evaluates unnatural syntactic symmetry, generic opening/closing salutations, and robotic urgency patterns typical of LLM-generated phishing lures.

#### [`backend/scripts/migrate_mongo_to_postgres.py`](file:///d:/Project/SpectraShield/backend/scripts/migrate_mongo_to_postgres.py)
- **Role**: Database ETL migration utility.
- **Key Mechanics & Working**:
  - Connects to source MongoDB and destination Supabase PostgreSQL database.
  - Migrates documents from `scans`, `threat_feed`, and `vt_url_cache` collections into PostgreSQL JSONB tables while preserving IDs and timestamps.

---

### 4.2 Browser Extension (`extension/`)

#### [`extension/manifest.json`](file:///d:/Project/SpectraShield/extension/manifest.json)
- **Role**: Chromium extension manifest (Manifest V3).
- **Key Declarations**:
  - Host permissions: `http://localhost:8000/*`, `https://mail.google.com/*`, `*://*.linkedin.com/*`.
  - Background service worker: `background.js`.
  - Content scripts: `content.js` and `content.css` executed on Gmail and LinkedIn messaging pages at `document_end`.
  - Web accessible resources: Injected stylesheets.

#### [`extension/content.js`](file:///d:/Project/SpectraShield/extension/content.js)
- **Role**: Client-side DOM observer, zero-touch telemetry extractor, and UI injector.
- **Key Mechanics & Working**:
  1. **Gmail Inbox Row Observer**:
     - Observes inbox table rows (`tr.zA`).
     - Extracts email subject (`span.bog`) and sender name (`span.bA4`).
     - Computes a deterministic hash of the subject/sender to avoid duplicate requests.
     - Debounces scroll events (350ms) to ensure smooth performance while fast scrolling.
     - Calls backend `POST /analyze` with `private_mode: true`.
     - Injects `.spectrashield-badge` element next to the subject (Green: Safe, Yellow: Suspicious, Red: High Risk) with a hover tooltip displaying the risk percentage.
     - Handles Gmail DOM recycling during scrolling by maintaining an in-memory cache and reattaching badges when rows re-enter the viewport.
  2. **Gmail Opened Email Inspector**:
     - Monitors opened email containers (`div.adn`).
     - Extracts the full rendered email body and all embedded anchor tags (`<a href="...">`).
     - Transmits extracted payload to the backend.
     - Injects a top floating banner (`.spectrashield-mail-banner`) above the email body displaying risk score, primary reason, and quick actions (Safe / Report).
  3. **LinkedIn Messaging Sentinel**:
     - Monitors LinkedIn chat container selectors (`.msg-s-message-list`, `.msg-s-event-listitem`).
     - Extracts message text and outgoing links.
     - Injects inline risk badges into chat bubbles and highlights dangerous links.
  4. **Zero-Touch Hover Link Inspector**:
     - Attaches `mouseenter` listeners to suspicious links in emails and messages.
     - Performs a background URL reputation lookup and displays an interactive preview popover.

#### [`extension/content.css`](file:///d:/Project/SpectraShield/extension/content.css)
- **Role**: Styling rules for all injected DOM elements.
- **Key Styles**:
  - Badge layouts, pulsating animation keyframes for high-risk badges (`@keyframes spectrashield-pulse`), severity color variables, Gmail banner overlays, and tooltips.

#### [`extension/popup.html`](file:///d:/Project/SpectraShield/extension/popup.html) & [`extension/popup.js`](file:///d:/Project/SpectraShield/extension/popup.js)
- **Role**: Extension toolbar popup UI.
- **Key Mechanics & Working**:
  - Provides input fields for manually pasting Email Text, Raw Headers, URLs, and Sender Email.
  - Private Mode toggle switch.
  - Renders dynamic risk score circle, category breakdown bars, flagged phrase tags, and attack simulation steps.

---

### 4.3 Frontend Web Application (`frontend/`)

#### [`frontend/src/app/App.tsx`](file:///d:/Project/SpectraShield/frontend/src/app/App.tsx)
- **Role**: Root application controller, routing coordinator, and global state provider.
- **Key Mechanics & Working**:
  - **View Navigation**: Manages 6 distinct application modes:
    1. `popup`: Extension popup simulator & manual scanner.
    2. `gmail`: Interactive Gmail inbox simulation.
    3. `linkpreview`: Deep link sandboxing & technical telemetry.
    4. `linkdemo`: Phishing link simulation walkthrough.
    5. `dashboard`: Security Operations Center analytics dashboard.
    6. `styleguide`: Design system tokens & UI components preview.
  - **Deep-Linking Support**: Parses query parameters (`?email_text=...&url=...`) from URL or hash, allowing direct deep-linking from browser extension badge clicks.
  - **Theme Coordination**: Integrates `next-themes` to support Light, Dark, and System modes.

#### [`frontend/src/app/api.ts`](file:///d:/Project/SpectraShield/frontend/src/app/api.ts)
- **Role**: Strongly typed HTTP API client.
- **Key Mechanics & Working**:
  - Resolves `VITE_API_URL` (defaults to `http://localhost:8000`).
  - Exports TypeScript interfaces: `AnalyzeRequest`, `AnalyzeResponse`, `IntelligenceProfile`, `DomainAgeContext`, `SSLContext`, `TopBrandsResponse`, `RiskHeatmapResponse`.
  - Implements typed fetch functions: `analyzeEmail()`, `getHistory()`, `getHistoryCount()`, `getTopBrands()`, `getRiskHeatmap()`, `clearHistory()`, `deleteScan()`.

#### [`frontend/src/app/components/Dashboard.tsx`](file:///d:/Project/SpectraShield/frontend/src/app/components/Dashboard.tsx)
- **Role**: SOC incident analytics dashboard.
- **Key Mechanics & Working**:
  - **Time & Risk Filtering**: Allows filtering data across 7, 30, or 90 days, and risk levels (All, Low, Medium, High).
  - **7x24 Risk Heatmap**: Renders an interactive hour-of-day vs. day-of-week grid visualizing attack distribution over time.
  - **Top Impersonated Brands**: Displays frequency bar charts of targeted brands across internal scans and OpenPhish feeds.
  - **Scan Audit Table**: Provides a searchable, paginated history of all recorded scans with individual delete and bulk clear capabilities.

#### [`frontend/src/app/components/RiskMeter.tsx`](file:///d:/Project/SpectraShield/frontend/src/app/components/RiskMeter.tsx)
- **Role**: Animated circular SVG risk score gauge.
- **Key Mechanics & Working**:
  - Calculates SVG stroke-dashoffset based on risk score (0–100).
  - Employs smooth Framer Motion animations with dynamic color shifting:
    - **Safe (0–34)**: Emerald / Green.
    - **Suspicious (35–69)**: Amber / Orange.
    - **High Risk (70–100)**: Rose / Red with pulsing halo effects.

#### [`frontend/src/app/components/RiskBreakdown.tsx`](file:///d:/Project/SpectraShield/frontend/src/app/components/RiskBreakdown.tsx)
- **Role**: Granular risk factor breakdown component.
- **Key Mechanics & Working**:
  - Renders progress bars for:
    - Manipulation Tactics (Urgency, Fear, Scarcity).
    - URL & Domain Intelligence.
    - Brand & Sender Verification.
    - Header & Authentication Checks.

#### [`frontend/src/app/components/WhyFlagged.tsx`](file:///d:/Project/SpectraShield/frontend/src/app/components/WhyFlagged.tsx)
- **Role**: Forensic explanation accordion.
- **Key Mechanics & Working**:
  - Displays natural language reasoning summary, highlighted psychological phrases, domain age status, and SSL validation details.

#### [`frontend/src/app/components/LinkPreview.tsx`](file:///d:/Project/SpectraShield/frontend/src/app/components/LinkPreview.tsx)
- **Role**: URL sandboxing and deep network telemetry viewer.
- **Key Mechanics & Working**:
  - Renders sandboxed preview of destination URL.
  - Displays SSL certificate details (issuer, validation status, expiry date), WHOIS domain age badges, DNS A/MX records, and redirect hops.

#### [`frontend/src/app/components/GmailDemo.tsx`](file:///d:/Project/SpectraShield/frontend/src/app/components/GmailDemo.tsx)
- **Role**: High-fidelity Gmail inbox simulation.
- **Key Mechanics & Working**:
  - Emulates Gmail interface with real-time risk badges, interactive emails, and preview modals to demonstrate extension behavior.

#### [`frontend/src/app/components/StyleGuide.tsx`](file:///d:/Project/SpectraShield/frontend/src/app/components/StyleGuide.tsx)
- **Role**: Design system showcase.
- **Key Mechanics & Working**:
  - Displays color swatches, typography hierarchy, button variants, badge styles, and card components used across SpectraShield.

---

## 5. Database Schemas, Models & Persistence Layer

SpectraShield utilizes a hybrid JSONB storage model in PostgreSQL / Supabase, combining structured querying on primary keys/indexes with flexible schema evolution.

### 5.1 Tables & Indices

```sql
-- 1. Scan Results Table
CREATE TABLE IF NOT EXISTS public.scans (
    id TEXT PRIMARY KEY,
    thread_id TEXT UNIQUE,
    linkedin_thread_id TEXT UNIQUE,
    created_at TIMESTAMPTZ NULL,
    updated_at TIMESTAMPTZ NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_updated_at ON public.scans(updated_at);

-- 2. OpenPhish & Live Threat Feed Table
CREATE TABLE IF NOT EXISTS public.threat_feed (
    url TEXT PRIMARY KEY,
    first_seen TIMESTAMPTZ NULL,
    last_seen TIMESTAMPTZ NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_threat_feed_last_seen ON public.threat_feed(last_seen);

-- 3. VirusTotal Response Cache Table (24-hour TTL in application logic)
CREATE TABLE IF NOT EXISTS public.vt_url_cache (
    url TEXT PRIMARY KEY,
    fetched_at TIMESTAMPTZ NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_vt_url_cache_fetched_at ON public.vt_url_cache(fetched_at);

-- Row Level Security
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_feed ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vt_url_cache ENABLE ROW LEVEL SECURITY;
```

---

## 6. Threat Scoring Formulas & Fusion Algorithms

### 6.1 Multi-Vector Risk Fusion

$$\text{FusionScore} = (0.35 \times S_{\text{local}}) + (0.55 \times S_{\text{url\_corrected}}) + (0.10 \times S_{\text{ssl\_age}})$$

$$\text{FinalRisk} = \min\Big(100.0, \max\big(\text{FusionScore}, S_{\text{mail\_severity}}\big)\Big)$$

Where:
- $S_{\text{local}}$: Psychological manipulation score derived from urgency, fear, authority, and scarcity.
- $S_{\text{url\_corrected}}$: URL structural and reputation score adjusted by SSL risk penalties and domain age modifiers.
- $S_{\text{ssl\_age}}$: Combined raw SSL validity and domain age risk score.
- $S_{\text{mail\_severity}}$: Maximum severity across all detected URLs in multi-link emails.

### 6.2 SSL & Domain Age Adjustments

- **SSL Modifiers**:
  - Extended Validation (EV) Certificate: $-40\%$ risk discount.
  - Expiring Soon ($< 7$ days): $+15\%$ risk boost.
  - Untrusted / Self-Signed Certificate: $+50\%$ risk boost.
  - Expired Certificate: $+60\%$ risk boost.
  - Hostname Mismatch: $+80\%$ risk boost.
- **Domain Age Modifiers**:
  - Burner Domain ($\le 30$ days): $+50\%$ risk boost.
  - New Entity ($\le 180$ days): $+25\%$ risk boost.
  - Established Domain ($> 365$ days): $0\%$ modifier.

### 6.3 Qualitative Verdict & Confidence Mapping

| Risk Score Range | Verdict | Confidence Level | Badge Color |
|---|---|---|---|
| **$0.00 - 34.99$** | Low Risk / Safe | Low / Moderate Confidence | Emerald Green |
| **$35.00 - 69.99$** | Medium Risk / Suspicious | High Confidence | Amber Orange |
| **$70.00 - 100.00$** | High Risk / Malicious | Very High Confidence | Rose Red (Pulsing) |

---

## 7. REST API Specification

### `POST /analyze`
- **Description**: Main evaluation endpoint for email content, URLs, headers, and social messages.
- **Request Body**:
```json
{
  "email_text": "URGENT: Verify your account now. Your Microsoft account is locked.",
  "email_header": "Received-SPF: fail ...",
  "url": "https://secure-verify-account.tk/login/microsoft",
  "sender_email": "security-noreply@accountverify.tk",
  "private_mode": false,
  "thread_id": "gmail_thread_12345",
  "platform": "gmail"
}
```
- **Response**:
```json
{
  "final_risk": 94.5,
  "verdict": "High Risk",
  "confidence_level": "Very High Confidence",
  "threat_category": "Credential Harvesting",
  "reasoning_summary": "Detected urgent language, suspicious new domain, and brand impersonation.",
  "breakdown": {
    "manipulation_score": 75.0,
    "url_score": 92.0,
    "ai_generated_score": 0.0,
    "brand_impersonation_score": 100.0,
    "header_score": 40.0
  },
  "psychological_index": {
    "urgency": 75,
    "fear": 50,
    "authority": 25,
    "scarcity": 25
  },
  "highlighted_phrases": ["urgent", "locked", "verify your account"],
  "domain_age_days": 12,
  "attack_simulation": [
    { "step": 1, "title": "Fake Login Page", "description": "User is redirected to a fake login page." },
    { "step": 2, "title": "Credential Harvesting", "description": "Victim enters credentials captured by attacker." },
    { "step": 3, "title": "Account Takeover", "description": "Attacker accesses victim's real account." },
    { "step": 4, "title": "Financial/Data Loss", "description": "Sensitive data or funds are stolen." }
  ]
}
```

### `GET /dashboard/top-brands`
- **Query Parameters**: `days` (default: 7), `risk` (`all`|`low`|`medium`|`high`), `source` (`internal`|`external`|`blended`), `limit` (default: 6).
- **Response**:
```json
{
  "days": 7,
  "risk": "all",
  "source": "blended",
  "updated_at": "2026-09-02T02:00:00Z",
  "total_brands": 4,
  "brands": [
    { "name": "Microsoft", "count": 28 },
    { "name": "PayPal", "count": 14 },
    { "name": "Google", "count": 9 },
    { "name": "Amazon", "count": 5 }
  ]
}
```

### `GET /dashboard/risk-heatmap`
- **Query Parameters**: `days` (default: 7), `risk` (`all`|`low`|`medium`|`high`).
- **Response**:
```json
{
  "days": 7,
  "risk": "all",
  "updated_at": "2026-09-02T02:00:00Z",
  "max_count": 12,
  "cells": [
    { "dayIndex": 0, "hour": 0, "value": 2 },
    { "dayIndex": 0, "hour": 1, "value": 0 }
  ]
}
```

---

## 8. Configuration & Environment Variables

### Backend Configuration (`backend/.env`)

| Variable | Type | Default | Description |
|---|---|---|---|
| `DB_BACKEND` | `string` | `postgres` | Database backend: `postgres` or `mongo` |
| `DATABASE_URL` | `string` | — | Supabase / PostgreSQL connection string |
| `MONGO_URI` | `string` | `mongodb://localhost:27017/` | MongoDB connection URI (fallback) |
| `MONGO_DB_NAME` | `string` | `spectrashield_db` | MongoDB database name |
| `VT_API_KEY` | `string` | — | VirusTotal v3 API Key for URL lookups |

### Frontend Configuration (`frontend/.env`)

| Variable | Type | Default | Description |
|---|---|---|---|
| `VITE_API_URL` | `string` | `http://localhost:8000` | Backend API base URL |

---

## 9. Installation & Execution Guide

### 1. Backend Service
```powershell
# Navigate to backend
cd backend

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Start FastAPI dev server with auto-reload
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Web Application
```powershell
# Navigate to frontend
cd frontend

# Install node packages
npm install

# Start Vite development server
npm run dev
```

### 3. Chrome Extension
1. Open Google Chrome and go to `chrome://extensions`.
2. Enable **Developer mode** via the top-right toggle.
3. Click **Load unpacked** and select the `extension/` folder.
4. Open Gmail (`https://mail.google.com`) or LinkedIn Messaging (`https://www.linkedin.com/messaging`) to view real-time badges.
