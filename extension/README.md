# SpectraShield 1.0 — Chromium Browser Extension (Manifest V3)

The **SpectraShield Browser Extension** provides real-time, zero-touch phishing and social engineering protection directly within webmail and professional messaging platforms (**Gmail** and **LinkedIn**), backed by a standalone quick-scan popup.

Built on Chrome **Manifest V3**, the extension operates under strict privacy-first principles (`private_mode: true`), executing security evaluations in-memory on the local backend without persisting user correspondence.

---

## Capabilities & Platform Modules

### 1. Gmail In-Inbox Protection (`content.js`, `content.css`)
- **Row-Level Inbox Scanning:**
  - Uses `MutationObserver` to track inbox thread rows (`tr.zA`) as the user scrolls or navigates folders.
  - Extracts subject lines, sender addresses, and thread identifiers.
  - Dispatches non-intrusive evaluation requests with `private_mode: true`.
  - Injects dynamic risk badges into the subject line:
    - 🟢 **Safe / Low Risk (< 35%)**
    - 🟡 **Suspicious (35% – 74%)**
    - 🔴 **High Risk / Phishing (≥ 75%)**
- **Opened Email Sentinel:**
  - When an email thread is opened, extracts the full message body, RFC headers, and embedded URLs.
  - Injects a prominent alert banner at the top of high-risk messages, warning users before they click malicious links or reply to impersonation attempts.
  - Caches verdicts by `thread_id` to prevent redundant network requests.

### 2. LinkedIn Sentinel (`content.js`)
- **Direct Message (DM) Threat Detection:**
  - Monitors active LinkedIn conversation threads (`.msg-s-message-list`).
  - Analyzes inbound messages for social engineering, fake job offers, urgency framing, and credential harvesting lures.
  - Identifies embedded hyperlinks, automatically discards internal LinkedIn routes (e.g., `/in/`, `/company/`, `/feed/`), and evaluates external target domains via the backend URL intelligence engine.

### 3. Quick Scan Popup (`popup.html`, `popup.js`, `popup.css`)
- **On-Demand Forensic Sandbox:**
  - Accessible via the browser toolbar icon at any time.
  - Accepts arbitrary email body text, raw headers, and URLs.
  - Features an interactive **Privacy Mode** toggle.
  - Renders an instantaneous risk verdict, confidence rating, and factor breakdown.

### 4. Background Service Worker (`background.js`)
- Handles inter-process communication between content scripts, popup modals, and the local backend API.
- Manages dynamic extension badge states and icons based on active page risk levels.

---

## Directory Structure

```
extension/
├── manifest.json       # Manifest V3 configuration & permission grants
├── background.js       # Background service worker & badge manager
├── content.js          # DOM observers for Gmail and LinkedIn Sentinel
├── content.css         # Injected badge styles, alert ribbons, and modal UI
├── popup.html          # Quick scan interface markup
├── popup.js            # Popup logic and API dispatcher
├── popup.css           # Popup dark-themed styling
└── README.md           # Extension documentation
```

---

## Installation & Setup

### Prerequisites
- Google Chrome, Brave, or any Chromium-compatible browser.
- SpectraShield backend running locally at `http://localhost:8000`.

### Loading the Extension in Developer Mode
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable the **Developer mode** toggle in the top-right corner.
3. Click **Load unpacked** in the top-left toolbar.
4. Select the `extension/` directory from this repository.
5. The **SpectraShield AI** shield icon will now appear in your browser extension tray.

---

## Permissions & Privacy Assurances

| Permission / Match | Purpose | Privacy Impact |
| :--- | :--- | :--- |
| `https://mail.google.com/*` | Inspects inbox rows and opened emails for threats | Scans execute in-memory with `private_mode: true`. Zero message text is persisted to disk or database. |
| `https://www.linkedin.com/*`| Inspects LinkedIn DMs for external phishing links | Evaluates messages locally via the backend; internal LinkedIn paths are discarded. |
| `activeTab` / `storage` | Stores user UI preferences and session cache | Data never leaves the local browser session. |
| `http://localhost:8000/*` | Communicates exclusively with the local SpectraShield backend | No third-party servers or telemetry services are contacted by the extension. |
