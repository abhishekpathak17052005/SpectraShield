# Software Design Document (SDD) & Technical Specification — Phase 5

**Document Title:** Multi-Format Ingestion Hardening (Outlook .MSG / .MBOX), Payload Quarantine & Quishing QR Engine  
**Project Name:** SpectraShield 2.0 (Forensic Edition)  
**Short Name:** AegisMail Forensics (AegisMail_AI)  
**Phase Identifier:** Phase 5 of Version 2.0 (Sprint 2 Roadmap)  
**SIH Problem Statement ID:** 26106 (AICTE Cyber Security Cell)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  
**Target Beneficiaries:** Enterprise SOC Engineers, Cyber Defense Units, Forensic Lab Operators, Incident First Responders  
**Baseline System State:** SpectraShield 2.0 (Phase 4 Foundation)  
**Date:** September 2026  

---

## 1. Project Overview & Phase 5 Executive Summary

### 1.1 Executive Summary
In enterprise SOC investigations, incoming suspicious emails arrive in diverse file formats beyond standard RFC 5322 text files. The vast majority of corporate workstations utilize Microsoft Outlook, producing proprietary OLE Compound File Binary (`.msg`) containers or multi-message mailbox archives (`.mbox`). Furthermore, attackers frequently conceal malicious payloads inside obfuscated HTML markup (zero-width spaces, hidden frames, executable JavaScript) or inline QR codes (Quishing) that evade standard text-based natural language processing filters.

Currently, SpectraShield 2.0 supports raw `.eml` and text pasting. The `qr_detector.py` module operates in simulation fallback mode due to missing `pyzbar` C-libraries, and uploaded attachments are decomposed in memory without strict disk quarantine isolation or automated script sanitization.

**Phase 5** hardens the ingestion and payload isolation architecture by:
1. **Multi-Format Decompiler (`ING-01`):** Integrating Python `extract_msg` to decompile Microsoft Outlook `.msg` files and adding an `.mbox` stream splitter to unpack bulk email exports directly from drag-and-drop.
2. **HTML Script Sanitizer & Disk Quarantine (`ING-03`):** Implementing strict HTML decoupling that strips dangerous tags (`<script>`, `<iframe>`, `<object>`, `<embed>`, inline event handlers) and writes extracted binary attachments into an isolated, non-executable directory with a `.quarantine` suffix.
3. **Quishing Inline Image QR Decoding Engine:** Fully enabling `pyzbar` QR image decoding for inline CID images and attachments, sandboxing extracted URLs, and feeding them into the threat reputation pipeline.

### 1.2 Phase 5 Mission & Objectives
- **Support Outlook `.msg` & `.mbox`:** Parse Microsoft Outlook Compound Document formats seamlessly in `POST /api/forensics/upload-eml`.
- **Enforce Strict Evidentiary Quarantine:** Deconstruct MIME attachments, compute cryptographic hashes, and isolate physical bytes on disk under a `.quarantine` extension to prevent accidental analyst execution.
- **Automate HTML Payload Sanitization:** Strip active script elements, zero-width characters, and suspicious hidden styling from email body previews while preserving structural layout for forensic inspection.
- **Operationalize Inline Quishing Detection:** Extract and decode QR code matrices from email image parts, displaying the extracted redirect target in the Link Sandbox view.

---

## 2. Tech Stack & Dependencies

### 2.1 Backend Architecture
- **Runtime:** Python 3.11+
- **OLE Compound Document Parser:** `extract-msg` 0.48+ (extracts headers, body, attachments, and RTF from Outlook `.msg` files)
- **Mailbox Archive Parser:** Python standard library `mailbox` (RFC 4155 MBOX parser)
- **HTML Sanitization:** `bleach` 6.1+ or `beautifulsoup4` 4.12+ with `lxml` parser
- **Computer Vision & QR Decoding:**
  - `pyzbar` 0.1.9+ with underlying `libzbar` DLLs
  - `Pillow` (PIL) 10.2+ for image decoding, cropping, and matrix normalization

### 2.2 Frontend Architecture
- **Framework:** React 18, TypeScript, Vite
- **UI Drag-and-Drop:** Native HTML5 Drag and Drop API with expanded MIME/extension filtering (`.eml`, `.msg`, `.mbox`)
- **Universal Liquid Glass Components:** Quishing alert card, Quarantined attachment badges, Sanitized HTML previewer

---

## 3. Core Features & Detailed Specifications

### 3.1 Feature ING-01-EXT: Outlook `.msg` & `.mbox` Ingestion Engine
- **Technical Description:** Enhance `POST /api/forensics/upload-eml` to inspect magic bytes upon upload:
  - **Outlook OLE Binary (`.msg`):** Starts with magic sequence `D0 CF 11 E0 A1 B1 1A E1`. Route to `extract_msg.Message`.
  - **MBOX Archives (`.mbox`):** Starts with `From ` (RFC 4155 mboxrd separator). Route to `mailbox.mbox`.
  - **Standard MIME (`.eml`):** Standard RFC 5322 text. Route to existing email parser.
- **Extracted Fields from `.msg`:**
  - Transport headers (PR_TRANSPORT_MESSAGE_HEADERS)
  - Sender name, sender email (PR_SENDER_EMAIL_ADDRESS)
  - Subject, Date, Body (Plain text and HTML)
  - Attachments (PR_ATTACH_DATA_BIN)
- **Inputs:** Binary file upload via multipart/form-data.
- **Outputs:** Standardized forensic case JSON matching existing RFC 5322 schemas.

### 3.2 Feature ING-03-SAN: HTML Sanitizer & Disk Attachment Quarantine
- **Technical Description:**
  1. **HTML Sanitization Pipeline:**
     - Removes `<script>`, `<style>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`, and `<form>` tags.
     - Strips event attributes: `onload=`, `onerror=`, `onclick=`, `onmouseover=`.
     - Normalizes obfuscated text (strips Unicode zero-width spaces `\u200B`, `\u200C`, `\u200D`, `\uFEFF`).
     - Rewrites dangerous external resource links to use defanged placeholders.
  2. **Disk Quarantine Isolation:**
     - Extracted attachments are saved into `backend/data/quarantine/{case_id}/{sha256}.quarantine`.
     - File permissions are set to read-only (`chmod 0440`).
     - Executable bits are strictly stripped.
     - The database stores the storage path, original filename, MIME type, Shannon entropy, and cryptographic hashes.

### 3.3 Feature QUI-01: Quishing Inline Image QR Code Decoder
- **Technical Description:** Attackers increasingly embed QR codes redirecting victims to credential-harvesting portals to bypass traditional textual spam filters.
- **Inspection Pipeline:**
  1. Scan all inline images (`multipart/related`, `image/png`, `image/jpeg`) and standalone image attachments.
  2. Convert images to grayscale using Pillow (`Image.convert('L')`).
  3. Execute `pyzbar.decode(image)` to locate and read 2D QR matrix symbols.
  4. If a QR code is detected:
     - Extract raw payload string (typically a URL).
     - Defang URL (`hxxps[://]...`).
     - Trigger URL heuristic scoring, WHOIS domain age lookup, and reputation queries.
     - Append a `QuishingEvidence` object to the analysis result.

---

## 4. Architecture & Data Flow

```
                               [ UPLOADED FILE PAYLOAD ]
                                           │
                                           ▼
                     [ MAGIC BYTE INSPECTION & FORMAT ROUTING ]
                                           │
         ┌─────────────────────────────────┼─────────────────────────────────┐
         ▼                                 ▼                                 ▼
   [ OLE .msg Format ]            [ MBOX Archive Format ]           [ Standard .eml MIME ]
   (D0 CF 11 E0 A1 B1...)         (From <separator>...)             (Received: / From:...)
         │                                 │                                 │
         ▼                                 ▼                                 ▼
 [ extract_msg Parser ]           [ mailbox.mbox Splitter ]         [ RFC 5322 Parser ]
         │                                 │                                 │
         └─────────────────────────────────┼─────────────────────────────────┘
                                           │
                                           ▼
                            [ DECOUPLED MIME ARTIFACTS ]
                                           │
         ┌─────────────────────────────────┴─────────────────────────────────┐
         ▼                                                                   ▼
 [ HTML & Text Body ]                                            [ Binary Attachments ]
         │                                                                   │
         ▼                                                                   ▼
 [ bleach / BS4 Sanitizer ]                                      [ Multi-Hash & Entropy ]
 - Strips <script>, <iframe>                                     - SHA-256 / MD5 / SimHash
 - Cleans zero-width chars                                       - Office Macro / Script Probe
         │                                                                   │
         ├─────────────────────────────────┐                                 ▼
         │                                 │                    [ Disk Quarantine Vault ]
         ▼                                 ▼                    - Saved as {sha256}.quarantine
 [ Inline CID Images ]            [ Clean Preview JSON ]         - Read-only, non-executable
         │
         ▼
 [ Pillow & pyzbar Engine ]
 - 2D QR Matrix Decoding
 - Extracts Phishing URL
         │
         ▼
 [ URL Reputation Sandbox ]
```

---

## 5. Database Schemas & Pydantic Models

### 5.1 Pydantic Model Updates (`backend/app/schemas.py`)
```python
class QuishingEvidence(BaseModel):
    has_qr_code: bool
    qr_count: int
    decoded_payloads: List[str]
    defanged_payloads: List[str]
    risk_level: str  # "clean" | "suspicious" | "malicious"
    source_image_filename: Optional[str] = None

class QuarantinedAttachment(BaseModel):
    filename: str
    original_extension: str
    file_size_bytes: int
    sha256: str
    md5: str
    entropy_score: float
    is_macro_enabled: bool
    is_executable: bool
    quarantine_path: str
    is_quarantined: bool = True
```

---

## 6. API Endpoints Specification

### 6.1 `POST /api/forensics/upload-eml` (Hardened)
- **Method:** `POST`
- **Content-Type:** `multipart/form-data`
- **Payload:** `file: UploadFile`
- **Supported Formats:** `.eml`, `.msg`, `.mbox`
- **Response:**
  ```json
  {
    "case_id": "CASE-2026-0906-8A1F",
    "ingestion_format": "OUTLOOK_MSG_OLE",
    "sha256_evidence_hash": "e8e4a726b23...a48c",
    "quarantined_attachments_count": 2,
    "quishing_detected": true,
    "analysis": { ... }
  }
  ```

### 6.2 `GET /api/forensics/cases/{case_id}/quarantine/{sha256}`
- **Method:** `GET`
- **Description:** Download quarantined attachment for safe external dynamic sandboxing (restricted to `SUPER_ADMIN` and `FORENSIC_ANALYST` roles).
- **Response Type:** `application/octet-stream`
- **Headers:** `Content-Disposition: attachment; filename="{sha256}.quarantine"`

---

## 7. Frontend Components & Universal Liquid Glass UI

### 7.1 Enhanced Drag-and-Drop Zone (`ForensicOpsView.tsx`)
- Updated file dropzone accepts `.eml`, `.msg`, `.mbox`.
- Dynamic format badge updates upon drop:
  - 🔵 `.eml` (RFC 5322 Standard)
  - 🟡 `.msg` (Microsoft Outlook OLE Binary)
  - 🟣 `.mbox` (UNIX Mailbox Archive)

### 7.2 Quishing Detection Card (`QuishingPreviewCard.tsx`)
- Specular crimson glare card (`--accent-critical`) displaying decoded QR target.
- One-click defanged copy button.
- Direct quick-link to load the decoded destination URL into the **Sandboxed URL Previewer (`LinkPreviewView`)**.

---

## 8. Annotated File Modification Matrix

```text
SpectraShield/
├── backend/
│   ├── requirements.txt                         # Added: extract-msg, bleach, pyzbar
│   ├── app/
│   │   ├── forensic_routes.py                   # [MODIFY] Added format routing & quarantine downloads
│   │   ├── schemas.py                           # [MODIFY] Added QuishingEvidence & QuarantinedAttachment
│   │   ├── services/
│   │   │   ├── qr_detector.py                   # [MODIFY] Integrated pyzbar QR matrix extractor
│   │   │   └── html_sanitizer.py                # [NEW] HTML script tag & zero-width stripper
│   │   └── agents/
│   │       └── attachment_forensic_agent.py     # [MODIFY] Write quarantined files to disk with .quarantine
│
└── frontend/
    └── src/
        ├── app/
        │   └── components/
        │       └── forensics/
        │           ├── ForensicOpsView.tsx      # [MODIFY] Dropzone accepts .msg & .mbox
        │           ├── QuishingPreviewCard.tsx  # [NEW] QR Code detection display card
        │           └── AttachmentTriageCard.tsx # [MODIFY] Quarantine badge & download trigger
```

---

## 9. Step-by-Step Implementation Roadmap

### Milestone 5.1: Microsoft Outlook `.msg` & `.mbox` Ingestion
- [ ] Add `extract-msg` to `backend/requirements.txt`.
- [ ] Implement format detector in `forensic_routes.py` checking magic bytes `D0 CF 11 E0`.
- [ ] Convert parsed Outlook message into standard RFC dictionary format.
- [ ] Add `.mbox` archive extraction support.

### Milestone 5.2: HTML Body Sanitizer & Attachment Disk Quarantine
- [ ] Create `backend/app/services/html_sanitizer.py` using `bleach` / `BeautifulSoup`.
- [ ] Ensure `<script>`, `<iframe>`, and event attributes are stripped from preview payloads.
- [ ] Update `attachment_forensic_agent.py` to write extracted attachments to `backend/data/quarantine/` with `.quarantine` suffix.

### Milestone 5.3: Quishing Image QR Code Decoder
- [ ] Configure `pyzbar` and DLL loaders in `backend/app/services/qr_detector.py`.
- [ ] Add image decoding loop for embedded CID images and image attachments.
- [ ] Connect decoded URLs to `url_analyzer.py` and threat scoring.
- [ ] Build `QuishingPreviewCard.tsx` in frontend with Universal Liquid Glass aesthetics.

---

## 10. Verification & Quality Gates

1. **Outlook Format Gate:** Upload a sample Microsoft Outlook `.msg` binary file; verify that headers, sender, subject, and attachments extract with 100% fidelity.
2. **Sanitization Gate:** Upload an email containing `<script>alert('xss')</script>` and `<iframe src="..."></iframe>`; verify that the sanitized body preview strips both tags completely.
3. **Quarantine Isolation Gate:** Verify that attachments written to disk have the `.quarantine` suffix and file permissions set to non-executable.
4. **Quishing Gate:** Upload an email with an inline QR code targeting `https://evil-phish.top/login`; verify that `qr_detector.py` decodes the exact payload and defangs it.
5. **Regression & Build Gate:** Run `pytest tests/test_phase5.py tests/test_phase4.py tests/test_forensics.py` (100% pass) and `npm run build` (zero errors).
