# SpectraShield 2.0 Forensic Dossier PDF Redesign

## Design Specification & Component Architecture

---

## 1. DESIGN PHILOSOPHY

**The report tells an investigation story:**

```
WHAT DID SPECTRASHIELD FIND?
        ↓
WHY IS IT DANGEROUS?
        ↓
HOW DID THE MESSAGE TRAVEL?
        ↓
WHERE DID THE OBSERVED INFRASTRUCTURE COME FROM?
        ↓
WHAT EVIDENCE SUPPORTS THE VERDICT?
        ↓
WHAT SHOULD THE ANALYST DO NEXT?
```

**First page communicates entire investigation in ~10 seconds.**

---

## 2. VISUAL LANGUAGE

### Color Palette
- **Primary Foundation:** `#0B0F17` (Dark Navy)
- **Accent Cyber:** `#0891B2` (Electric Cyan)
- **Alert Red:** `#DC2626` (Malicious Findings)
- **Warning Amber:** `#F59E0B` (Warning Signals)
- **Safe Green:** `#10B981` (Verified/Pass)
- **Card Background:** `#F8FAFC` (Soft White)
- **Border Grey:** `#CBD5E1` (Subtle Borders)
- **Monospace Metadata:** `#64748B` (Slate Grey)

### Typography
- **Headers:** Helvetica-Bold (18-12px)
- **Body:** Helvetica (8-10px)
- **Monospace:** Courier for forensic metadata
- **Labels:** Helvetica-Bold 8px uppercase

### Visual Elements
- Risk gauge (radial visualization)
- Evidence cards (compact 80x80px)
- Timeline nodes (colored dots with labels)
- Confidence meters (horizontal bars)
- Infrastructure diagram (simple flow)
- Threat DNA fingerprint (5-dot profile)
- Evidence integrity seal (cryptographic visual)

---

## 3. 8-PAGE STRUCTURE

### Page 1: THREAT SNAPSHOT
**Goal:** Show entire investigation at a glance

**Components:**
1. Premium Case Header
   - SPECTRASHIELD 2.0 | THREAT INVESTIGATION
   - Case ID, Timestamp, Investigation Status

2. Central Risk Verdict
   - Large risk gauge (visual ring 0-100)
   - PRIMARY THREAT (e.g., "Business Email Compromise")
   - Confidence/Verdict statement

3. Five Evidence Cards (compact)
   - Identity: Sender/Domain
   - Authentication: SPF/DKIM/DMARC overall status
   - Infrastructure: Origin IP/ASN
   - Anonymization: TOR/VPN/Proxy detected
   - Intelligence: Campaign correlation

4. "Why SpectraShield Flagged This"
   - Top 3 strongest reasons (ranked by severity)
   - Human-readable explanations
   - No technical jargon

---

### Page 2: ATTACK STORY
**Goal:** Show how message traveled through infrastructure

**Components:**
1. "How This Message Traveled"
   - Horizontal timeline visualization
   - Nodes: SENDER → RELAY → MAIL SERVER → RECIPIENT
   - Hop styling: TRUSTED | UNKNOWN | SUSPICIOUS | [ORIGIN]

2. For each hop:
   - HOST / IP
   - LOCATION (City, Country)
   - TIMESTAMP + DELAY
   - Visual distinction (color coding)

3. Analyst Interpretation
   - Natural language explanation (backend evidence only)
   - Geolocation disclaimer
   - No overreach about attacker identity

---

### Page 3: AUTHENTICATION FORENSICS
**Goal:** Display SPF/DKIM/DMARC findings as large forensic cards

**Components:**
1. Three Large Cards (side by side):
   - **SPF Card:**
     - STATUS (PASS/FAIL/NEUTRAL)
     - Domain evaluated
     - What was expected vs observed
     - Security impact explanation

   - **DKIM Card:**
     - STATUS (VERIFIED/INVALID/NONE)
     - Domain evaluated
     - Signature details
     - Verification results

   - **DMARC Card:**
     - STATUS (PASS/FAIL/NEUTRAL)
     - Domain evaluated
     - Alignment results
     - Policy enforcement

2. Authentication Verdict
   - Visual: Identity Trust bar (0-100%)
   - Qualitative language only (no invented scores)

---

### Page 4: INFRASTRUCTURE INTELLIGENCE
**Goal:** Profile observed public infrastructure

**Components:**
1. Infrastructure Profile Card
   - OBSERVED PUBLIC IP: `185.xxx.xxx.xxx`
   - GEOLOCATION: `Frankfurt, Germany`
   - ASN: `AS60729`
   - NETWORK/ISP: `Tor Exit Router Network`
   - ANONYMIZATION: `TOR DETECTED`

2. Visual Relationship Diagram
   ```
   DOMAIN
      ↓
     IP
      ↓
     ASN
      ↓
   NETWORK
      ↓
     TOR
   ```

3. Critical Disclaimer
   - "Geolocation represents observed network infrastructure, NOT attacker physical location"
   - Label: "OBSERVED ORIGIN INFRASTRUCTURE"
   - Clear separation of fact from implication

---

### Page 5: THREAT CAMPAIGN INTELLIGENCE
**Goal:** Show campaign attribution with evidence

**Components:**
1. Campaign Signal
   - CAMPAIGN NAME: e.g., "Targeted European Wire Diversion"
   - CONFIDENCE: 92%
   - Attribution explanation

2. Evidence Lanes (only if backend provides evidence)
   - [ Infrastructure Match ]
   - [ Geographic Pattern ]
   - [ Threat Intelligence ]
   - [ Behavioral Pattern ]

3. Confidence Visualization
   - Horizontal meter (0-100%)
   - Color coded: Red (Low) → Yellow (Medium) → Green (High)

---

### Page 6: EVIDENCE & CHAIN OF CUSTODY
**Goal:** Forensic-grade evidence integrity documentation

**Components:**
1. Evidence Integrity
   - SHA-256 Hash (full value, monospace)
   - Status: TAMPER-EVIDENT / SEALED
   - Timestamp of ingestion

2. Chain of Custody Visual
   ```
   INGESTED
      ↓
   HASHED
      ↓
   ANALYZED
      ↓
   SEALED
      ↓
   VERIFIED
   ```

3. Case Reference Data
   - Case ID
   - Evidence Hash
   - Ingestion Timestamp
   - Investigation Status
   - Analysis Completion Time

4. Legal Notice (no fabrication)
   - Only claim what backend establishes
   - DO NOT add: "Court-admissible" unless backend certified
   - DO NOT invent: Officer signatures, Badge IDs, Certifications

---

### Page 7: THREAT DNA & ANALYST CONCLUSION
**Goal:** Summary fingerprint + recommended next steps

**Components:**
1. Threat DNA Fingerprint
   - Visual: 5 dots (●●●●●) for each dimension
   - AUTHENTICATION (●●●○○)
   - INFRASTRUCTURE (●●●●●)
   - ANONYMIZATION (●●●●○)
   - CAMPAIGN CORRELATION (●●●●○)
   - SOCIAL ENGINEERING (●●●●●)

2. Investigation Conclusion
   - THREAT LEVEL: [HIGH/MEDIUM/LOW]
   - PRIMARY THREAT: [Category from backend]
   - CONFIDENCE: [Backend value]

3. Key Findings
   - Bulleted list of detected facts
   - No speculation

4. Recommended Response
   - Actions supported by backend capabilities only
   - Examples:
     - Quarantine message
     - Investigate related domains
     - Block observed infrastructure
     - Search for related campaign indicators
     - Preserve evidence

5. Clear Separation
   - DETECTED FACTS (confident statements)
   - RECOMMENDED ACTIONS (suggested next steps)

---

## 4. COMPONENT ARCHITECTURE

### Directory Structure
```
backend/app/agents/
  ├── forensic_report_agent.py          (main orchestrator)
  ├── pdf_design_spec.md                (this file)
  ├── pdf/
  │   ├── __init__.py
  │   ├── page_builder.py               (PageBuilder class)
  │   ├── components.py                 (PageComponent classes)
  │   ├── visual_elements.py            (ReportLab drawing utilities)
  │   ├── data_transformer.py           (Backend → PDF data mapping)
  │   ├── validator.py                  (Data consistency checker)
  │   └── translations.py               (Technical → readable terms)
```

### Core Classes

#### 1. **PDFReportBuilder** (orchestrator)
```python
class PDFReportBuilder:
    def __init__(self, case_id, forensic_data, redact_pii=False)
    def build_report(self) -> bytes
    def validate_data_consistency() -> List[Warning]
    def _build_page_1_threat_snapshot()
    def _build_page_2_attack_story()
    def _build_page_3_authentication_forensics()
    def _build_page_4_infrastructure_intelligence()
    def _build_page_5_campaign_intelligence()
    def _build_page_6_evidence_chain_of_custody()
    def _build_page_7_threat_dna_conclusion()
```

#### 2. **PageBuilder** (layout helper)
```python
class PageBuilder:
    def __init__(self, story, styles, colors)
    def add_header(title, subtitle, metadata)
    def add_evidence_cards(cards: List[EvidenceCard])
    def add_timeline(hops: List[Hop])
    def add_forensic_card(title, status, details)
    def add_infrastructure_diagram(data)
    def add_threat_dna(dimensions)
    def page_break()
```

#### 3. **PageComponent** (base class for reusable blocks)
```python
class PageComponent:
    def render(self, story, styles, colors) -> Flowable
    
class RiskGaugeComponent(PageComponent)
class EvidenceCardComponent(PageComponent)
class TimelineComponent(PageComponent)
class InfrastructureFlowComponent(PageComponent)
class ThreatDNAComponent(PageComponent)
class AuthenticationCardComponent(PageComponent)
class EvidenceIntegrityComponent(PageComponent)
```

#### 4. **DataTransformer**
```python
class DataTransformer:
    @staticmethod
    def extract_threat_snapshot(forensic_data) -> ThreatSnapshot
    @staticmethod
    def extract_attack_story(forensic_data) -> AttackStory
    @staticmethod
    def extract_auth_findings(forensic_data) -> AuthFindings
    @staticmethod
    def extract_infrastructure_profile(forensic_data) -> InfraProfile
    @staticmethod
    def extract_campaign_signal(forensic_data) -> CampaignSignal
    @staticmethod
    def extract_evidence_integrity(forensic_data) -> EvidenceRecord
    @staticmethod
    def extract_threat_dna(forensic_data) -> ThreatDNA
```

#### 5. **DataValidator**
```python
class DataValidator:
    def validate_consistency(forensic_data) -> List[Warning]
    def check_summary_vs_detail(summary, detail) -> Conflict[]
    def check_required_fields() -> Missing[]
    def warn_on_placeholder_values() -> Placeholder[]
    def validate_ip_not_bogon(ip) -> bool
    def validate_geolocation_disclaimer_needed() -> bool
```

#### 6. **LanguageTranslator**
```python
class LanguageTranslator:
    TECHNICAL_TO_READABLE = {
        "RFC 5322 Multi-Hop Relay Trajectory": "Message Route",
        "Cryptographic Protocol & Header Validation": "Sender Authentication",
        "Originating Infrastructure & Threat Campaign Attribution": "Threat Infrastructure",
        "Anonymization Flag": "Anonymization Detected",
        "Physical Coordinates": "Observed Infrastructure Location",
    }
    
    @staticmethod
    def translate(technical_term) -> str
    @staticmethod
    def friendly_auth_status(status) -> str
    @staticmethod
    def friendly_threat_level(score) -> str
```

#### 7. **VisualElements** (ReportLab utilities)
```python
class VisualElements:
    @staticmethod
    def draw_risk_gauge(score: float, width, height) -> Drawing
    @staticmethod
    def draw_confidence_meter(confidence: float) -> Table
    @staticmethod
    def draw_threat_dna_profile(dimensions: Dict) -> Drawing
    @staticmethod
    def draw_timeline_node(label, status, x, y) -> Drawing
    @staticmethod
    def draw_infrastructure_flow(domain, ip, asn, network, tor) -> Drawing
```

---

## 5. DATA MODELS (Type Hints)

```python
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class EvidenceCard:
    title: str
    value: str
    detail: Optional[str] = None
    color: str = "#0891B2"

@dataclass
class ThreatSnapshot:
    verdict: str                  # e.g., "HIGH RISK"
    risk_score: float            # 0-100
    primary_threat: str          # e.g., "Business Email Compromise"
    confidence: str              # e.g., "89.5%"
    top_reasons: List[str]       # Top 3 findings
    evidence_cards: List[EvidenceCard]

@dataclass
class AttackStory:
    hops: List[dict]             # relay_path from backend
    origin_ip: Optional[str]
    origin_location: str
    hop_count: int
    interpretation: str          # Natural language

@dataclass
class AuthFindings:
    spf_status: str
    spf_domain: str
    spf_impact: str
    dkim_status: str
    dkim_domain: str
    dkim_impact: str
    dmarc_status: str
    dmarc_domain: str
    dmarc_impact: str
    overall_trust_percentage: float

@dataclass
class InfraProfile:
    origin_ip: str
    origin_ip_defanged: str
    geolocation: str
    asn: str
    network_name: str
    anonymization_type: Optional[str]
    is_tor: bool
    is_vpn: bool
    disclaimer: str

@dataclass
class CampaignSignal:
    name: str
    confidence: float
    evidence_sources: List[str]
    linked_incidents: int

@dataclass
class EvidenceRecord:
    sha256_hash: str
    status: str                  # "SEALED", "TAMPER-EVIDENT"
    ingestion_timestamp: str
    analysis_timestamp: str
    case_id: str

@dataclass
class ThreatDNA:
    authentication: int          # 0-5 dots
    infrastructure: int
    anonymization: int
    campaign_correlation: int
    social_engineering: int
```

---

## 6. DATA CONSISTENCY RULES

### Critical Validation Rules

**Rule 1: No Placeholder Values as Real Findings**
```
IF displayed_value IN ["0.0.0.0", "Unknown", "Unknown ISP", "Unknown Country"]
THEN display "NOT RESOLVED" with disclaimer
ELSE display value normally
```

**Rule 2: Summary ↔ Detail Consistency**
```
IF (summary_says: "SPF PASS") AND (detail_says: "SPF FAILED")
THEN emit DATA_CONSISTENCY_WARNING
DO NOT generate report until resolved
```

**Rule 3: Geolocation Disclaimer**
```
IF (showing_origin_ip OR showing_geolocation)
THEN ALWAYS include disclaimer
"Represents observed network infrastructure, NOT attacker physical location"
```

**Rule 4: Campaign Attribution Confidence**
```
IF (campaign_confidence < 60%)
THEN show as "POSSIBLE CAMPAIGN CORRELATION (Low Confidence)"
IF (campaign_confidence >= 60% AND < 80%)
THEN show as "PROBABLE CAMPAIGN CORRELATION"
IF (campaign_confidence >= 80%)
THEN show as "HIGH CONFIDENCE CAMPAIGN MATCH"
```

**Rule 5: No Invented Forensic Claims**
```
DO NOT fabricate:
  - Officer signatures
  - Badge IDs
  - Court certifications
  - Regulatory compliance claims
  - Legal admissibility statements

ONLY claim what backend explicitly provides.
```

**Rule 6: PII Redaction Consistency**
```
IF (redact_pii == True)
THEN:
  - Mark all pages with "REDACTED EVIDENCE DOSSIER"
  - Preserve SHA-256 evidence integrity
  - Redact personal emails, names, domains
  - Maintain forensic credibility
```

---

## 7. IMPORTANT DISCLAIMERS & LANGUAGE

### For Geolocation
❌ "Attacker's physical location"
✅ "Observed origin infrastructure location"
✅ "Earliest reliable public relay node"

### For IP/ASN Findings
❌ "Identified the attacker at X location"
✅ "Observed infrastructure resolves to X location"
✅ "Infrastructure is associated with X network"

### For Campaign Attribution
❌ "Definitely matches campaign X"
✅ "Infrastructure patterns consistent with campaign X"
✅ "High confidence correlation with campaign X"

### For Authentication Results
❌ "Email is definitely spoofed"
✅ "Sender domain failed SPF/DKIM/DMARC validation"
✅ "Authentication results indicate unauthorized sending infrastructure"

---

## 8. PDF TECHNICAL CONSTRAINTS

### Page Layout
- **Page Size:** Letter (8.5" × 11")
- **Margins:** 36pt (0.5")
- **Usable Area:** 540pt wide × 720pt tall

### Font Sizing Rules
- **Headers (H1):** 18pt (title)
- **Headers (H2):** 12pt (section)
- **Headers (H3):** 10pt (subsection)
- **Body Text:** 8pt
- **Monospace:** 8pt (metadata, hashes)
- **Minimum:** Never go below 8pt

### Table Rules
- **Column Widths:** Never squeeze text
- **Row Height:** Min 18pt
- **Header Row:** Always bold, dark background
- **Content:** Wrap text or use abbreviations
- **Borders:** 0.5pt, subtle grey

### Page Break Rules
- **Never:** Orphan headings (heading without content below)
- **Never:** Split tables across pages without reason
- **Always:** Keep related sections together with KeepTogether()
- **Always:** Add page numbers (bottom right)

### Visual Hierarchy Rules
- **Title:** Single page number line at top
- **Sections:** 12pt bold headers with 6pt spacing
- **Content:** 8pt body with 2-4pt spacing
- **Emphasis:** Color (not ALL CAPS), bold, or boxes

---

## 9. REDACTION MODE BEHAVIOR

### When `redact_pii=True`:

**Page 1 - Threat Snapshot:**
- Show risk score and threat category
- Hide: sender name, domain names
- Use: "[REDACTED: Email Domain]", "[REDACTED: Sender]"

**Page 2 - Attack Story:**
- Show hop counts and timestamps
- Hide: specific IPs (defang instead)
- Use: "185[.]xxx[.]xxx[.]xxx"

**Page 3 - Authentication:**
- Show SPF/DKIM/DMARC status
- Hide: specific domains
- Use: "[REDACTED: Sending Domain]"

**Page 4 - Infrastructure:**
- Show ASN, ISP, anonymization status
- Hide: specific IPs, coordinates
- Use: "Geolocation: [REDACTED]"

**Page 5 - Campaign:**
- Show campaign name, confidence
- Hide: nothing (campaigns are generic)

**Page 6 - Evidence:**
- Show SHA-256, status, timestamps
- Hide: nothing (chain of custody must be preserved)

**Page 7 - Conclusion:**
- Show all findings (no PII in conclusions)

**Header/Footer:**
- Add: "REDACTED EVIDENCE DOSSIER" watermark
- Add: "Personal identifiable information sanitized per GDPR/DPDP"

---

## 10. SUCCESS CRITERIA

✅ **First page communicates entire investigation in ≤10 seconds**

✅ **No dense tables on pages 1-2**

✅ **All technical terms translated to readable language**

✅ **No contradictions between summary and detail**

✅ **All forensic findings sourced from backend (no fabrication)**

✅ **Visual hierarchy: What → Why → How → Where → Evidence → Next Steps**

✅ **PDF looks professional when printed**

✅ **Risk gauge and visual elements communicate information**

✅ **Geolocation has clear disclaimer**

✅ **Redaction mode preserves forensic integrity**

✅ **Evidence integrity block is tamper-evident visual**

✅ **Campaign attribution only shows what backend provides**

---

## 11. IMPLEMENTATION PHASES

### Phase 1: Architecture & Foundation
- [ ] Create modular component classes
- [ ] Implement DataTransformer
- [ ] Implement DataValidator
- [ ] Implement LanguageTranslator
- [ ] Implement VisualElements

### Phase 2: Visual Components
- [ ] Risk gauge drawing
- [ ] Timeline drawing
- [ ] Infrastructure flow diagram
- [ ] Threat DNA fingerprint
- [ ] Confidence meters

### Phase 3: Pages 1-3
- [ ] Page 1 - Threat Snapshot
- [ ] Page 2 - Attack Story
- [ ] Page 3 - Authentication Forensics

### Phase 4: Pages 4-7
- [ ] Page 4 - Infrastructure Intelligence
- [ ] Page 5 - Campaign Intelligence
- [ ] Page 6 - Evidence & Chain of Custody
- [ ] Page 7 - Threat DNA & Conclusion

### Phase 5: Integration & Testing
- [ ] Wire up to forensic_routes.py
- [ ] Generate test PDFs with all data variations
- [ ] Verify redaction mode
- [ ] Verify conflict detection
- [ ] Frontend export button integration

---

## 12. MIGRATION CHECKLIST

From old `forensic_report_agent.py` to new modular system:

- [ ] Preserve all backend data integrity (no lost information)
- [ ] Keep STIX JSON export working
- [ ] Keep IOC CSV export working
- [ ] Maintain PDF streaming to frontend
- [ ] Maintain PII redaction behavior
- [ ] Add new data consistency validation
- [ ] Add new visual components
- [ ] Update API response documentation
- [ ] Create backwards-compat alias functions (if needed)

---

End of Design Specification
