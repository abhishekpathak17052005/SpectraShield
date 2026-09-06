# 🌊 SpectraShield 2.0 (Forensic Edition) — Master Product Architecture & Unified Liquid Glass Design Specification (`updated_design.md`)

> **Document Type**: Master System Architecture, Product Design Specification, Component Blueprint & Integration Contract  
> **Platform Name**: SpectraShield 2.0 (Forensic Edition)  
> **Version Target**: 2.1.0-Unified  
> **SIH Problem Statement ID**: 26106 (AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform)  
> **UI Architecture Style**: **Universal Liquid Glass Physics Engine** (Fluid Glassmorphism, Specular Caustics, Viscous Momentum & Zero-Layout-Shift Volumetric Morphing)  
> **Regulatory Compliance**: ISO/IEC 27037 (Digital Evidence Chain of Custody), Indian Bharatiya Nagarik Suraksha Sanhita (BNSS) Electronic Evidence Standards, GDPR Art 32 & India DPDP Act 2023 (PII Redaction)  
> **Technology Stack**: React 18/19, TypeScript, Vite, Tailwind CSS v3/v4, Lucide Icons, Leaflet / React-Leaflet, `@xyflow/react` (React Flow), Recharts, Python 3.11+ FastAPI, PyMongo / PostgreSQL (JSONB), NetworkX / Neo4j.

---

## 1. Executive Master Prompt for Engineering & AI Web Builders

*Use this master prompt to guide development or copy directly into AI coding agents (Antigravity, Cursor, Claude, Lovable):*

```text
You are engineering SpectraShield 2.0 (Forensic Edition), an enterprise-grade Email Threat Detection, Multi-Hop Relay Traceability, Origin Geolocation, and Digital Forensic Intelligence Platform fulfilling SIH Problem Statement ID 26106.

CRITICAL DESIGN & AESTHETIC MANDATE:
The frontend must strictly adhere to the "Universal Liquid Glass" design system. The interface must NOT look like generic flat dashboards or basic CSS glassmorphism. It must simulate real-world optical physics:
1. Multi-Tier Optical Refraction Blurs (12px to 32px) boosted with backdrop-saturate-150 to backdrop-saturate-200.
2. Microscopic Specular Top Rim Highlights (1px border-t gradient from rgba(255,255,255,0.8) to transparent).
3. Directional Ambient Caustic Radial Glares pooling inside surfaces (color-coded to threat severity).
4. Viscous Surface Tension and fluid cubic beziers: cubic-bezier(0.16, 1, 0.3, 1) and cubic-bezier(0.34, 1.56, 0.64, 1).
5. Continuous Diagonal Specular Sheen Sweeps (skew-x-12 animate-liquid-sheen) across active action buttons.
6. Zero-Layout-Shift Volumetric Accordions using CSS Grid fractional rows (grid-template-rows: 0fr -> 1fr).
7. Fluid Sliding Droplet Segmented Controls where the navigation indicator glides with elastic momentum.

FULL-STACK CAPABILITIES & SEVEN UNIFIED PRODUCT VIEWS:
1. "Executive SOC Dashboard": Volumetric KPI cards, AreaChart incident velocity, 168-cell 7x24 risk heatmap, top impersonated brands bar chart, and real-time incident audit logs.
2. "Forensic Operations Center": Multi-format ingestion studio (RFC 5322 raw text, .eml, Outlook .msg, .mbox), Earliest Reliable Public Node (ERPN) isolation, Leaflet cartographic hop-by-hop relay flight-path map with pulsing beacons, chronological hop timeline with latency calculations, cryptographic SPF/DKIM/DMARC matrix, static attachment triage (multi-hash, Shannon entropy, SimHash, VBA macros), court-admissible ISO 27037 PDF dossier exporter, STIX 2.1 JSON and defanged CSV export modal.
3. "Threat Attribution Graph": Force-directed entity network (@xyflow/react) linking Emails, Origin IPs, Sender Domains, ASNs, and shared Threat Actor Campaigns with community clustering.
4. "Sandboxed URL Previewer": Isolated link sandbox iframe, SSL certificate validation inspector, WHOIS domain age radar, homoglyph/Punycode visual substitution diff chip, and multi-feed reputation (VirusTotal, OpenPhish, Google Safe Browsing, URLhaus).
5. "Client Sentinel Inboxes": Interactive Gmail and LinkedIn desktop inbox replicas with liquid threat ribbons, inline badges, and a 1-click "Escalate to Forensic SOC" action, alongside an Enterprise Abuse Mailbox (IMAP/TLS) autonomous poller.
6. "Enterprise Identity & Case Management": 4-tier Role-Based Access Control (Super Admin, Analyst, Operator, Auditor), JWT authentication, RFC 6238 TOTP 2FA modal, tamper-evident SHA-256 audit ledger, case status workflow (NEW -> IN_PROGRESS -> RESOLVED -> CLOSED), analyst assignment, and case notes.
7. "Extension Sentinel Popup": 400x600px Chrome extension popup widget with animated circular risk gauge, threat breakdown bars, cognitive pressure cues, and deep links to the SOC console.

Ensure full responsiveness (custom xs: 400px breakpoint, mobile floating liquid drawer, desktop grid) and complete offline mock resilience.
```

---

## 2. Product Architecture & Multi-Agent Forensic Pipeline

SpectraShield 2.0 unifies high-throughput heuristic scanning with deep multi-agent forensic reconstruction in a single asynchronous Python FastAPI backend, eliminating brittle microservice latency while maintaining strict digital evidence chain-of-custody.

```
                              [ INGESTION CHANNELS ]
     ┌───────────────────────────────┬───────────────────────────────┐
     ▼                               ▼                               ▼
[ Web Console (.eml/.msg/mbox) ] [ Browser Ext (Gmail/LinkedIn) ] [ Abuse Mailbox Poller (IMAP) ]
     │                               │                               │
     └───────────────────────────────┼───────────────────────────────┘
                                     │
                                     ▼
                  [ CRYPTOGRAPHIC EVIDENCE PRE-HASHING ]
             - SHA-256, SHA-1, MD5 computed before byte mutation
             - Evidence sealed conforming to ISO/IEC 27037 & BNSS
                                     │
                                     ▼
                  [ MULTI-AGENT FORENSIC ENGINE PIPELINE ]
     ┌───────────────────────┬───────┴───────────────┬───────────────────────┐
     ▼                       ▼                       ▼                       ▼
[ HeaderForensicAgent ] [ GeoTraceAgent ]       [ NLPThreatAgent ]      [ AttachmentAgent ]
- RFC 5322 Hop Parsing  - ERPN Algorithm        - Cognitive Urgency     - Multi-Hash Fingerprint
- SPF/DKIM/DMARC Align  - MaxMind Offline DB    - Financial BEC Intent  - Shannon Entropy
- Hop Latency Anomaly   - Tor / VPN Detection   - VIP Impersonation     - Office VBA Macro Check
     │                       │                       │                       │
     └───────────────────────┼───────────────────────┴───────────────────────┘
                             │
                             ▼
              [ COMPOSITE RISK FUSION & CYBER KILLCHAIN ]
         - 4-Vector Risk Scoring: Headers (25%) + Geo/Rep (25%) + NLP (25%) + Attachments (25%)
         - MITRE ATT&CK 4-Stage Cyber Killchain Projection (Risk >= 50)
                             │
                             ▼
              [ THREAT CORRELATION & ATTRIBUTION GRAPH ]
         - NetworkX / Neo4j Graph Correlation Engine (Campaign Clustering)
         - Ingests: Email <-> Origin IP <-> Domain <-> ASN <-> Campaign
                             │
                             ▼
              [ EVIDENCE VAULT & DUAL EXPORT ENGINES ]
     ┌───────────────────────────────────────────────┬───────────────────────────────────────┐
     ▼                                               ▼                                       ▼
[ ISO 27037 PDF Dossier ]                 [ STIX 2.1 JSON CTI Feed ]                [ Defanged CSV Export ]
(ReportLab with PII Redaction)            (OASIS Compliant for SIEM)                 (Firewall Blocklists)
```

---

## 3. Universal Liquid Glass Physics Model & Design Tokens

Liquid Glass transforms standard 2D glassmorphism into a dynamic, physically plausible digital material with depth, refraction, specular sheen, and surface tension.

```
       ┌───────────────────────────────────────────────────────────────────┐
       │ 🌟 Specular Top Rim Highlight (1px border-t: rgba(255,255,255,0.8))│
       │                                                                   │
       │   ☀️ Directional Caustic Radial Glare (severity-coded flare)       │
       │                                                                   │
       │      [ Interactive Content / Telemetry / Visualizations ]         │
       │                                                                   │
       │   🌊 Specular Sheen Wave Sweep (skew-x-12 animate-liquid-sheen)   │
       │                                                                   │
       │ 🌑 Ambient Translucent Base (backdrop-blur-2xl + saturate-180)    │
       │ 💧 Deep Ambient Occlusion Shadow (0 24px 48px -12px rgba(0,0,0...))│
       └───────────────────────────────────────────────────────────────────┘
```

### 3.1 Five Core Optical Physics Principles

1. **Optical Refraction & Saturation Boost**: Background surfaces diffuse across tiered blurs (`backdrop-blur-md` 12px for tooltips, `backdrop-blur-2xl` 24px for standard cards, `backdrop-blur-3xl` 32px for modals). Every blurred surface enforces `backdrop-saturate-150` to `backdrop-saturate-200` to prevent washed-out, dull grays.
2. **Microscopic Specular Top Rim Highlight**: A 1px top border gradient (`border-t border-white/80` in light mode; `border-t border-white/20` in dark mode) simulates overhead ambient lighting reflecting off the curved top bevel of the glass.
3. **Internal Caustic Diffusion**: Reflected light pools inside cards via subtle radial gradients, visually conveying threat severity:
   - **Forensics / Investigation**: Cyan (`rgba(6, 182, 212, 0.12)`)
   - **Critical Malicious / BEC**: Crimson (`rgba(239, 68, 68, 0.14)`)
   - **Suspicious / Warning**: Amber (`rgba(245, 158, 11, 0.12)`)
   - **Clean / Verified Safe**: Emerald (`rgba(16, 185, 129, 0.12)`)
   - **Threat Campaign Correlation**: Purple (`rgba(168, 85, 247, 0.14)`)
4. **Viscous Surface Tension & Momentum**: Interactive surfaces compress slightly on click (`active:scale-[0.985]`) and spring back with Apple-grade fluid cubic beziers:
   - Bounce / Pop: `cubic-bezier(0.34, 1.56, 0.64, 1)`
   - Smooth Glide: `cubic-bezier(0.16, 1, 0.3, 1)`
5. **Diagonal Specular Caustic Sheen**: High-velocity light rays sweep diagonally (`skew-x-12`) across primary buttons and progress bars on hover or execution (`animate-liquid-sheen`).

---

### 3.2 CSS Variables & Design Tokens

```css
:root {
  /* Surface Foundations */
  --liquid-bg-base: rgba(255, 255, 255, 0.72);
  --liquid-bg-active: rgba(255, 255, 255, 0.92);
  --liquid-bg-elevated: rgba(255, 255, 255, 0.85);

  /* Specular Rim & Borders */
  --liquid-border-rim: rgba(255, 255, 255, 0.85);
  --liquid-border-subtle: rgba(226, 232, 240, 0.80);
  --liquid-border-dark: rgba(0, 0, 0, 0.06);

  /* Ambient Occlusion & Depth */
  --liquid-shadow-sm: 0 4px 12px -2px rgba(15, 23, 42, 0.05), 0 2px 6px -1px rgba(15, 23, 42, 0.03);
  --liquid-shadow-md: 0 12px 28px -6px rgba(15, 23, 42, 0.08), 0 4px 12px -2px rgba(15, 23, 42, 0.04);
  --liquid-shadow-lg: 0 24px 48px -12px rgba(15, 23, 42, 0.12), 0 8px 24px -4px rgba(15, 23, 42, 0.06);
  --liquid-inner-glow: inset 0 1px 2px 0 rgba(255, 255, 255, 0.95), inset 0 -1px 2px 0 rgba(0, 0, 0, 0.04);

  /* Threat Status Accents */
  --accent-forensics: #06b6d4;   /* Cyan */
  --accent-critical: #ef4444;    /* Crimson */
  --accent-warning: #f59e0b;     /* Amber */
  --accent-safe: #10b981;        /* Emerald */
  --accent-campaign: #a855f7;    /* Purple */

  /* Timing Curves */
  --liquid-ease-spring: cubic-bezier(0.34, 1.56, 0.64, 1);
  --liquid-ease-apple: cubic-bezier(0.16, 1, 0.3, 1);
  --liquid-ease-fluid: cubic-bezier(0.4, 0, 0.2, 1);
}

.dark {
  /* Dark Mode Surfaces (Obsidian & Deep Tech Navy) */
  --liquid-bg-base: rgba(15, 23, 42, 0.65);
  --liquid-bg-active: rgba(30, 41, 59, 0.85);
  --liquid-bg-elevated: rgba(30, 41, 59, 0.75);

  /* Specular Rim & Borders */
  --liquid-border-rim: rgba(255, 255, 255, 0.18);
  --liquid-border-subtle: rgba(255, 255, 255, 0.08);
  --liquid-border-dark: rgba(0, 0, 0, 0.40);

  /* Deep Occlusion Shadows */
  --liquid-shadow-sm: 0 4px 14px -2px rgba(0, 0, 0, 0.35), 0 2px 6px -1px rgba(0, 0, 0, 0.25);
  --liquid-shadow-md: 0 16px 32px -8px rgba(0, 0, 0, 0.50), 0 6px 16px -4px rgba(0, 0, 0, 0.35);
  --liquid-shadow-lg: 0 30px 60px -15px rgba(0, 0, 0, 0.70), 0 10px 30px -5px rgba(0, 0, 0, 0.45);
  --liquid-inner-glow: inset 0 1px 1px 0 rgba(255, 255, 255, 0.16), inset 0 -1px 1px 0 rgba(0, 0, 0, 0.50);
}
```

---

## 4. Master Navigation & Seven Unified Views

The application provides seamless navigation across seven specialized operational centers via a fixed, translucent liquid navbar (`CyberNavbar`) with an active gliding droplet indicator. Analysts can switch views using **global numeric hotkeys (Keys 1–7)**.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ SpectraShield 2.0 (Forensic Edition)    [1] Dashboard [2] Forensics [3] Graph [4] Links  │
│ [🟢 Engine Live: Port 8000]                [5] Sentinel  [6] Cases/RBAC [7] Extension Popup │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.1 View 1: Executive SOC Dashboard (`DashboardView`)
**Target Audience:** SOC Leads, Incident Commanders, Executive CISOs.  
**Purpose:** High-level threat intelligence telemetry, real-time volume metrics, and trend monitoring.

#### Key Modules:
1. **Volumetric KPI Scorecards**:
   - Total Monitored Messages (with weekly percentage delta)
   - High-Risk BEC & Phishing Incidents Blocked
   - Average Multi-Hop Relay Latency
   - Active Campaign Clusters
2. **Threat Trends AreaChart (Recharts)**:
   - Stacked volume trends (Malicious vs. Suspicious vs. Clean) across selectable timeframes (`7d`, `30d`, `90d`).
3. **Top Impersonated Brands Bar Chart**:
   - Ranked enterprise targets (Microsoft 365, PayPal, DHL, Google, Amazon, Apple) with risk-level filtering (`all`, `high`, `medium`, `low`).
4. **168-Cell Incident Density Heatmap (7 Days × 24 Hours)**:
   - Interactive matrix displaying incident clustering by day-of-week and hour-of-day, highlighting attacker operational time zones.
5. **Real-Time Forensic Incident Vault Ledger**:
   - Searchable, filterable table of historic scan records with risk badges, sender identity, and 1-click escalation to the Forensic Lab.

---

### 4.2 View 2: Deep Forensic Operations Center (`ForensicOpsView`)
**Target Audience:** Digital Forensics Specialists, Incident Responders, Law Enforcement Officers.  
**Purpose:** Deep technical dissection of raw email payloads, cryptographic protocol verification, and evidentiary dossier compilation.

#### Key Modules:
1. **Multi-Format Ingestion Studio**:
   - Supports raw text/header pasting, `.eml` files, Outlook `.msg` files (OLE decompiler), and `.mbox` archives.
   - Drag-and-drop file zone with immediate SHA-256 pre-hashing.
2. **Earliest Reliable Public Node (ERPN) Isolation**:
   - Automatically filters out internal RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and carrier loopbacks.
   - Flags Tor exit nodes, commercial VPN CIDRs, and bulletproof hosting networks.
3. **Leaflet Cartographic Flight-Path Map (`HopMapVisualizer`)**:
   - Dark-mode vector world map rendering hop-by-hop flight trajectories.
   - Pulsing origin beacon and animated dashed lines connecting intermediate mail transfer agents to the destination server.
4. **Chronological Relay Hop Timeline (`RelayHopTimeline`)**:
   - Chronological MTA relay cards displaying sender, receiver, protocol (ESMTPS), IP address, and transit delay seconds.
   - Highlights "Time Travel" anomalies where hop timestamps move backwards.
5. **Cryptographic Authentication Matrix (`AuthStatusMatrix`)**:
   - Status indicators for **SPF** (`Pass`, `Fail`, `SoftFail`), **DKIM** (selector validation, RSA signature check), and **DMARC** (alignment check, policy enforcement: `reject`, `quarantine`, `none`).
6. **Static Attachment Triage Engine (`AttachmentTriageCard`)**:
   - MIME decompilation, true file type detection via magic bytes, Shannon entropy progress bar (detecting packed/encrypted malware), and Office VBA macro indicators.
7. **Export Modals & Court Dossier Generation**:
   - **Court-Admissible PDF Dossier**: Streams an ISO/IEC 27037 compliant ReportLab PDF with SHA-256 evidence stamps, signature blocks, and optional PII redaction.
   - **STIX 2.1 JSON Bundle (`StixExportModal`)**: Standardized CTI feed for ingestion into Splunk, Microsoft Sentinel, or QRadar.
   - **Defanged CSV Threat Export**: Generates firewall-ready blocking lists of defanged domains, IPs, and hashes.

---

### 4.3 View 3: Threat Attribution Network Graph (`ThreatGraphView`)
**Target Audience:** Threat Intelligence Analysts, Malware Researchers.  
**Purpose:** Visual correlation of shared attack infrastructure across independent phishing incidents.

#### Key Modules:
1. **Force-Directed Graph Canvas (`@xyflow/react`)**:
   - Interactive zoom, pan, and minimap controls.
   - Entity node types with distinctive color schemes and icons:
     - 📧 **Email Incidents** (Cyan)
     - 🌐 **Originating IPs** (Orange / Red for Tor)
     - 🏢 **Autonomous Systems (ASNs)** (Blue)
     - 🔗 **Phishing Domains** (Amber)
     - 🎯 **Threat Campaign Clusters** (Purple with pulsing glow)
2. **Animated Relationship Edges**:
   - Labeled directional edges (`ORIGINATED_FROM`, `USES_DOMAIN`, `HOSTED_BY`, `PART_OF`).
   - Pulsing beam animations representing origin transmission vectors.
3. **Campaign Selector & Louvain Clustering**:
   - Filter graph by campaign identifier (e.g., `CAMP-2026-M365`, `FIN7 Emulation`) or view global enterprise correlation.
4. **Entity Inspection Drawer**:
   - Clicking any node opens a glass drawer detailing entity attributes, first-seen timestamps, associated case numbers, and confidence ratings.

---

### 4.4 View 4: Sandboxed URL Previewer (`LinkPreviewView`)
**Target Audience:** Tier 1/2 SOC Analysts, Threat Hunters.  
**Purpose:** Zero-touch inspection of links discovered in suspicious messages without client-side exploitation risk.

#### Key Modules:
1. **Isolated Preview Frame**:
   - Renders a sandboxed, script-disabled visual snapshot of the destination page.
2. **Live SSL/TLS Certificate Inspector**:
   - Probes destination port 443; displays certificate issuer, validity status, expiration countdown, and Extended Validation (EV) status.
   - Flags untrusted, self-signed, or expired certificates.
3. **WHOIS & RDAP Domain Age Radar**:
   - Evaluates domain registration age.
   - Emits a **Burner Domain** warning (+50% risk modifier) for domains registered < 30 days ago.
4. **Homoglyph & Punycode Visual Diff Chip**:
   - Compares destination domains against enterprise target brands using Levenshtein distance and Cyrillic/Latin homoglyph mapping.
   - Visually highlights character substitutions (e.g., `micrоsoft.com` with Cyrillic `о`).
5. **Multi-Feed External Reputation Hub**:
   - Cross-references VirusTotal v3 cache, OpenPhish feed, Google Safe Browsing, and URLhaus.
6. **Defanged URL Generator**:
   - One-click copy of safe defanged strings (`hxxps[://]attacker[.]com/auth`) for ticket logging.

---

### 4.5 View 5: Sentinel Inboxes & Abuse Mailbox (`SentinelInboxesView`)
**Target Audience:** Enterprise Administrators, Employee Security Awareness Teams.  
**Purpose:** Monitoring end-user email streams and automated enterprise abuse mailbox triage.

#### Key Modules:
1. **Dual Desktop Inbox Simulator**:
   - High-fidelity replicas of **Gmail** and **LinkedIn Messaging** interfaces.
   - Non-intrusive Liquid Threat Badges injected directly beside message subjects.
2. **One-Click SOC Escalation Button**:
   - In-inbox action ("🚨 Escalate to Forensic SOC") that packages raw RFC 5322 headers and passes them directly to View 2 with zero manual copying.
3. **Autonomous Abuse Mailbox Listener (`MailboxPoller`)**:
   - Configurable IMAP/TLS client for enterprise quarantine inboxes (e.g., `phish-report@company.com`).
   - Displays connection health, poller mode (`Live IMAP/TLS` vs. `On-Demand Simulation`), and last poll timestamp.
   - On-demand "Poll Mailbox Now" trigger for automated case ingestion.

---

### 4.6 View 6: Enterprise Identity, RBAC & Case Triage (`CaseManagementView`)
**Target Audience:** SOC Managers, Compliance Auditors, System Administrators.  
**Purpose:** Role-based access control, two-factor authentication, case assignment, and tamper-evident audit logging.

#### Key Modules:
1. **Four-Tier Role-Based Access Control (RBAC)**:
   - **Super Admin**: System configuration, user management, policy rules.
   - **Forensic Analyst**: Full case analysis, evidence modification, report generation.
   - **SOC Operator**: Triage queue, case assignment, status updates.
   - **Auditor**: Read-only access to tamper-evident audit ledgers and sealed evidence.
2. **RFC 6238 TOTP Two-Factor Authentication Modal**:
   - QR code display for Google Authenticator / Authy setup.
   - Six-digit TOTP verification with time-drift tolerance.
3. **Case Lifecycle State Machine**:
   - Smooth status transitions: `NEW` ➔ `IN_PROGRESS` ➔ `ESCALATED` ➔ `RESOLVED` ➔ `CLOSED`.
4. **Analyst Assignment & Notes Thread**:
   - Reassign cases to active investigators; log timestamped analyst investigation notes.
5. **Tamper-Evident SHA-256 Audit Ledger**:
   - Block-linked chronological audit records where each entry includes the previous entry's SHA-256 hash, actor ID, action type, and cryptographic timestamp conforming to ISO/IEC 27037.

---

### 4.7 View 7: Extension Sentinel Popup (`ExtensionPopupView` & Chrome MV3 Extension)
**Target Audience:** All Enterprise Employees, Security Analysts on the Go.  
**Purpose:** Lightweight 400×600px desktop extension for rapid, air-gapped threat evaluations.

#### Key Modules:
1. **Live Backend Health Beacon**:
   - Real-time indicator confirming connectivity with `http://localhost:8000`.
2. **Zero-Trust Input Studio**:
   - Quick-paste inputs for email body/headers, URL, and sender identity.
   - One-click "Load Sample BEC" button for rapid demonstration.
3. **Volumetric Circular SVG Risk Gauge**:
   - Animated SVG stroke calculation displaying composite risk score (0–100%) with dynamic color shifts (Emerald < 35, Amber 35–74, Crimson >= 75).
4. **Vector Breakdown Progress Bars**:
   - Discrete sub-scores for URL Reputation, Linguistic Manipulation, Brand Typosquatting, and Synthetic AI Patterns.
5. **Air-Gapped Private Mode Toggle**:
   - Guarantees zero persistent storage when enabled.
6. **Console Launch Trigger**:
   - Launches the full browser SOC dashboard (`http://localhost:5173/?view=forensics&email_text=...`) with pre-populated case data.

---

## 5. Reusable Liquid Glass Component Blueprint

All components are implemented in React with TypeScript, Tailwind CSS, and Lucide icons.

### 5.1 `LiquidGlassCard.tsx`
*The fundamental surface container providing multi-tier refraction blurs, specular rim highlights, and threat-coded caustic glares.*

```tsx
import React from 'react';

interface LiquidGlassCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  variant?: 'default' | 'elevated' | 'critical' | 'warning' | 'safe' | 'forensics';
  className?: string;
}

export const LiquidGlassCard: React.FC<LiquidGlassCardProps> = ({
  children,
  variant = 'default',
  className = '',
  ...props
}) => {
  const variantStyles = {
    default: 'border-white/10 bg-slate-900/60 shadow-slate-950/50',
    elevated: 'border-white/15 bg-slate-900/80 shadow-slate-950/70',
    critical: 'border-red-500/30 bg-slate-900/70 shadow-red-950/30 before:from-red-500/10',
    warning: 'border-amber-500/30 bg-slate-900/70 shadow-amber-950/30 before:from-amber-500/10',
    safe: 'border-emerald-500/30 bg-slate-900/70 shadow-emerald-950/30 before:from-emerald-500/10',
    forensics: 'border-cyan-500/30 bg-slate-900/70 shadow-cyan-950/30 before:from-cyan-500/10',
  };

  return (
    <div
      className={`relative rounded-2xl border p-6 backdrop-blur-2xl backdrop-saturate-150 transition-all duration-300 ${variantStyles[variant]} ${className}`}
      {...props}
    >
      {/* Specular Top Rim Highlight */}
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/20 to-transparent" />
      {/* Internal Caustic Glare */}
      <div className="pointer-events-none absolute -left-12 -top-12 h-40 w-40 rounded-full bg-cyan-500/5 blur-3xl" />
      <div className="relative z-10">{children}</div>
    </div>
  );
};
```

---

### 5.2 `LiquidMorphButton.tsx`
*High-velocity button featuring fluid elastic compression and an animated diagonal specular sheen wave.*

```tsx
import React from 'react';

interface LiquidMorphButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  children: React.ReactNode;
}

export const LiquidMorphButton: React.FC<LiquidMorphButtonProps> = ({
  variant = 'primary',
  size = 'md',
  loading = false,
  children,
  className = '',
  disabled,
  ...props
}) => {
  const variantStyles = {
    primary: 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-cyan-500/25 border-cyan-400/30 hover:from-cyan-500 hover:to-blue-500',
    secondary: 'bg-slate-800/80 text-slate-200 border-white/10 hover:bg-slate-700/80 shadow-black/40',
    danger: 'bg-gradient-to-r from-red-600 to-rose-700 text-white shadow-red-500/25 border-red-400/30 hover:from-red-500 hover:to-rose-600',
    ghost: 'bg-transparent text-slate-300 border-transparent hover:bg-white/5 hover:text-white',
  };

  const sizeStyles = {
    sm: 'px-3 py-1.5 text-xs rounded-lg',
    md: 'px-4 py-2 text-sm rounded-xl',
    lg: 'px-6 py-3 text-base rounded-2xl font-semibold',
  };

  return (
    <button
      disabled={disabled || loading}
      className={`group relative inline-flex items-center justify-center overflow-hidden border font-medium shadow-lg backdrop-blur-md transition-all duration-200 active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50 ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
      {...props}
    >
      {/* Specular Diagonal Sheen Wave */}
      <span className="pointer-events-none absolute inset-0 -translate-x-full -skew-x-12 bg-gradient-to-r from-transparent via-white/20 to-transparent transition-transform duration-1000 group-hover:translate-x-full" />
      {loading ? (
        <span className="flex items-center gap-2">
          <svg className="h-4 w-4 animate-spin text-current" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
          </svg>
          Processing...
        </span>
      ) : (
        children
      )}
    </button>
  );
};
```

---

### 5.3 `DefangedText.tsx`
*Safely renders potentially malicious URLs, domains, and IP addresses to prevent accidental click-throughs while supporting one-click copying.*

```tsx
import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface DefangedTextProps {
  value: string;
  className?: string;
}

export const DefangedText: React.FC<DefangedTextProps> = ({ value, className = '' }) => {
  const [copied, setCopied] = useState(false);

  // Defang: http -> hxxp, https -> hxxps, . -> [.]
  const defanged = (value || '')
    .replace(/^https?:\/\//i, (match) => match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://')
    .replace(/\./g, '[.]');

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(defanged);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <span className={`inline-flex items-center gap-1.5 font-mono text-xs text-slate-300 ${className}`}>
      <span className="truncate selection:bg-cyan-500/30">{defanged}</span>
      <button
        onClick={handleCopy}
        className="rounded p-1 text-slate-400 transition-colors hover:bg-white/10 hover:text-white"
        title="Copy defanged string"
      >
        {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
      </button>
    </span>
  );
};
```

---

## 6. Backend API Specifications & Integration Contracts

The frontend connects to the following endpoints exposed by `FastAPI` (default `http://localhost:8000`).

### 6.1 Core Threat Engine & Analytics Endpoints

| Method | Path | Description | Key Request / Response Parameters |
| :--- | :--- | :--- | :--- |
| `GET` | `/health`, `/` | Live backend health beacon | Returns `{ status: "healthy", version: "2.0.0-phase3" }`. |
| `POST` | `/analyze` | Multi-vector threat scanner | **Req:** `{ email_text, url, sender_email, private_mode }`<br>**Res:** `{ final_risk, verdict, breakdown, threat_category }`. |
| `GET` | `/history` | Paginated historical scan records | Query params: `?limit=50&risk=all`. Returns array of scan records. |
| `GET` | `/history/count` | Fast total lifetime scan count | Returns `{ total_scans: number }`. |
| `DELETE`| `/history/{id}` | Purge specific scan record | Returns `{ message: "Scan {id} deleted" }`. |
| `GET` | `/dashboard/top-brands` | Aggregated targeted brands | Query params: `?days=30&risk=all`. Returns `{ brands: [...] }`. |
| `GET` | `/dashboard/risk-heatmap`| 168-cell 7x24 risk density matrix | Query params: `?days=7&risk=all`. Returns `{ cells: [...], max_count }`. |

---

### 6.2 Digital Forensics & Case Management Endpoints (`/api/forensics`)

| Method | Path | Description | Key Request / Response Parameters |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/forensics/analyze-email` | Full RFC 5322 forensic dissection | **Req:** `{ raw_eml, email_header, email_text, subject }`<br>**Res:** Full forensic dossier with SHA-256 evidence hash. |
| `POST` | `/api/forensics/upload-eml` | Multipart file upload (`.eml`, `.msg`)| Form data with binary file. Returns sealed forensic case. |
| `GET` | `/api/forensics/cases` | List all forensic cases in vault | Query params: `?limit=50&status=INVESTIGATING`. Returns case list. |
| `GET` | `/api/forensics/cases/{id}` | Full case dossier & audit trail | Returns `{ case, analysis, audit_trail }`. |
| `PATCH`| `/api/forensics/cases/{id}/status` | Case triage status transition | **Req:** `{ status: "IN_PROGRESS", actor, reason }`. |
| `POST` | `/api/forensics/cases/{id}/notes` | Append investigation note | **Req:** `{ text: "Tor exit node verified", author }`. |
| `POST` | `/api/forensics/cases/{id}/assign` | Assign investigator | **Req:** `{ analyst: "Lead SOC Analyst", actor }`. |
| `GET` | `/api/forensics/campaigns/{id}/graph`| Threat attribution graph data | Returns `{ nodes: [...], edges: [...], stats }` for `@xyflow/react`. |
| `GET` | `/api/forensics/export/{id}/pdf` | Stream ISO 27037 PDF dossier | Query param: `?redact_pii=true`. Returns `application/pdf`. |
| `GET` | `/api/forensics/export/{id}/stix` | Export STIX 2.1 CTI bundle | Query param: `?redact_pii=true`. Returns OASIS JSON bundle. |
| `GET` | `/api/forensics/export/{id}/csv` | Export Defanged IOC list | Returns `text/csv` formatted IOC table for firewall rules. |
| `GET` | `/api/forensics/mailbox/status` | Ingestion mailbox poller health | Returns `{ is_configured, mode, host, last_poll_at }`. |
| `POST` | `/api/forensics/mailbox/poll` | Trigger on-demand mailbox poll | Returns `{ status: "success", messages_found, ingested_cases }`. |

---

### 6.3 Authentication & RBAC Endpoints (`/api/auth`)

| Method | Path | Description | Key Request / Response Parameters |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | User login & JWT issuance | **Req:** `{ username, password }`<br>**Res:** `{ access_token, refresh_token, role, user }`. |
| `POST` | `/api/auth/2fa/setup` | Generate TOTP QR code | Returns `{ secret_key, qr_code_data_url }`. |
| `POST` | `/api/auth/2fa/verify` | Verify 6-digit TOTP token | **Req:** `{ code: "123456" }`<br>**Res:** `{ verified: true }`. |

---

## 7. Compliance, Legal Chain-of-Custody & Privacy Engine

SpectraShield 2.0 is built from the ground up for strict evidentiary admissibility in legal proceedings and international data protection compliance.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    REGULATORY COMPLIANCE ARCHITECTURE                       │
├──────────────────────────┬──────────────────────────┬───────────────────────┤
│ ISO/IEC 27037 Standard   │ BNSS Electronic Evidence │ GDPR & India DPDP Act │
├──────────────────────────┼──────────────────────────┼───────────────────────┤
│ SHA-256 pre-hashing      │ Section 65B Certificate  │ Luhn algorithm card   │
│ Block-linked audit trail │ Metadata preservation    │ SSN & Aadhaar masking │
│ Immutable case records   │ Analyst signature blocks │ Toggleable PII reveal │
└──────────────────────────┴──────────────────────────┴───────────────────────┘
```

### 7.1 ISO/IEC 27037 & BNSS Evidence Preservation
- **Immediate Pre-Hashing**: Hashes (SHA-256, SHA-1, MD5) are generated before any parsing or transformation, guaranteeing proof that evidence was not altered in transit.
- **Block-Linked Audit Ledger**: Every action (viewing evidence, appending notes, changing status, exporting dossiers) appends a cryptographic entry referencing the preceding entry's SHA-256 hash.
- **Section 65B Certificate Block**: Generated PDF dossiers contain formal certification blocks detailing the device identifier, operating system, analyst credentials, and cryptographic integrity hashes required by Indian and international courts.

### 7.2 PII Redaction & Data Sanitization Engine (`pii_redactor.py`)
Protects sensitive personal data in exported reports and shared STIX feeds:
- **Credit / Debit Cards**: Identified and validated using the **Luhn Algorithm Checksum**; masked as `[REDACTED_CARD_****1234]`.
- **National Identifiers**: Automated regex sanitization for US Social Security Numbers (SSN), Indian Aadhaar (`[REDACTED_AADHAAR]`), and Indian PAN numbers.
- **Financial Accounts**: International Bank Account Numbers (IBAN) masked to country code and last 4 characters.
- **Credentials & Tokens**: Exposed passwords and API secrets stripped from previews.
- **Toggleable Analyst Authorization**: Authorized Tier 1/2 investigators can toggle between redacted and unredacted views with audit logging.

---

## 8. Implementation Roadmap & Verification Matrix

To bridge the remaining minor gaps identified in `pending-features.md`, the platform follows a structured 4-sprint execution plan.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SPRINT 1: Persistence & CSV Export (1 Day)                                  │
│ - Connect EvidenceVault to persistent MongoDB / PostgreSQL collections.     │
│ - Implement Defanged CSV threat export in StixExportModal.tsx.              │
│ - Add Cyrillic homoglyph visual substitution diff chip.                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ SPRINT 2: Ingestion & Parser Hardening (2 Days)                             │
│ - Integrate `extract_msg` for Outlook .msg files in /upload-eml.            │
│ - Add HTML script/iframe sanitizer and disk .quarantine suffix tagging.     │
│ - Install and configure `pyzbar` C-libraries for inline QR image decoding.  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ SPRINT 3: Identity, RBAC & 2FA TOTP (3 Days)                                │
│ - User accounts, bcrypt password hashing, and JWT token authentication.     │
│ - RFC 6238 TOTP 2FA flow using `pyotp` and Google Authenticator QR codes.   │
│ - Role-based route guards (Super Admin, Analyst, Operator, Auditor).        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ SPRINT 4: External CTI Feeds & Transformer Pipeline (3 Days)                │
│ - Google Safe Browsing v4 & URLhaus API connectors.                         │
│ - Commercial VPN subnet CIDR database & AbuseIPDB client.                   │
│ - Quantized RoBERTa/DeBERTa transformer model pipeline for NLP intent.      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Conclusion

This master specification establishes a complete, cohesive blueprint for **SpectraShield 2.0 (Forensic Edition)**. By uniting the **SIH 26106 AegisMail Forensics** analytical rigor with the **Universal Liquid Glass** optical physics design system, SpectraShield delivers an unmatched, court-admissible forensic intelligence platform that sets a new standard for modern cybersecurity operations centers.
