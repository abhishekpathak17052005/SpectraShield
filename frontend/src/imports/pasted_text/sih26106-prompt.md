Build a complete, production-quality React 18 + Vite 6 + TypeScript frontend called SpectraShield — an AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform, built for Smart India Hackathon 2026 (Problem Statement SIH26106, theme: Blockchain & Cybersecurity, sponsored by AICTE). This must look like a premium cybersecurity SaaS product (think Vercel, Linear, or CrowdStrike's newer UI), not a generic admin template. Judges will see 50+ dashboards this weekend — this needs to visually stop them.

CORE AESTHETIC DIRECTION: "Liquid Glass Cyber"
Glassmorphism throughout: frosted-glass panels using backdrop-filter: blur(20px), semi-transparent backgrounds (rgba(15, 20, 30, 0.55)), 1px hairline borders with subtle gradient border, soft inner glow on hover.
Dark-mode-only base: deep navy/near-black gradient background (
#05070d to 
#0b0f1a), NOT pure black — add subtle animated noise/grain texture at low opacity.
Accent palette: electric cyan (
#00e5ff) primary, violet (
#7c3aed) secondary, risk-tier colors — emerald 
#10b981 (safe), amber 
#f59e0b (suspicious), red 
#ef4444 (malicious/critical). Use as glowing accents, not fills.
Typography: Space Grotesk or Satoshi for headings, Inter for body. Large confident headline sizing on landing page (clamp(3rem, 8vw, 7rem)).
Every glass panel has a subtle animated gradient border-glow on hover (a "scanning" effect) — this is the signature visual motif.
PRIORITY TIERS (build in this order — do not skip ahead)

TIER 1 — MUST HAVE (build these fully polished first):

Hero 3D globe with threat arcs (landing page)
3D scanning sequence animation (Analyze page, on submit)
Rotating glass risk orb/shield (Analyze results view)
Full glassmorphism design system applied everywhere
All 6 core dashboard pages functional and wired to the real API

TIER 2 — NICE TO HAVE (only after Tier 1 is fully working):
6. 3D force-directed threat graph (instead of flat 2D graph)
7. Floating holographic dashboard mockup in hero section

SKIP ENTIRELY: 3D architecture/server-rack diagrams, heavy WebGL on any page besides the landing page and the scan animation. Keep everything else in lightweight CSS/Framer Motion so the demo never lags on a projector or weak laptop GPU.

3D LANDING PAGE — TIER 1, HIGHEST PRIORITY

Build using React Three Fiber (@react-three/fiber) + @react-three/drei, not a static hero image.

Hero Section:

A rotating, semi-transparent glass globe (wireframe + MeshTransmissionMaterial from drei) as the hero background.
Glowing particle points on the globe (representing malicious IPs) pulse and occasionally send an animated arc/beam across the globe to a "SOC command center" point, then fade — loop continuously and randomly. This directly visualizes the "GeoLocation" part of the product without needing explanation.
Mouse parallax: globe subtly rotates toward cursor position (useFrame + lerp).
Foreground: glass-panel headline card floating above the scene — product name, tagline ("Trace Every Threat. Attribute Every Actor."), two CTA buttons (glass-style, glow-on-hover: "Launch Console" and "View Live Demo").
Scroll-triggered: as user scrolls past hero, the globe smoothly zooms/transitions into a stylized "email packet flowing through a network" scene (use drei's ScrollControls or GSAP ScrollTrigger synced to the canvas camera).
Mobile/low-end fallback: detect WebGL capability; if unavailable or screen is small, replace the 3D scene with a lighter animated CSS gradient + Framer Motion version. Never let the landing page crash or freeze.

Scroll sections below hero (Framer Motion scroll-reveal, staggered):

Problem stats — 3-column glass cards with animated count-up numbers (e.g., "91% of cyberattacks start with email").
How it works — glass node timeline: Email Ingested → NLP + Header Forensics → Geo-Trace & Attribution → Risk Score & Alert → Forensic Report/STIX Export. Connected by animated glowing dashed lines, reveal-on-scroll.
Feature bento-grid — glass cards for: Real-time Phishing Detection, Homoglyph & Zero-Width Unicode Detection, SPF/DKIM/DMARC Validation, IP GeoLocation & Tor/VPN Detection, Campaign Graph Attribution, Tamper-Evident PDF/STIX Export, QR Quishing Detection, PII Redaction & Privacy Mode.
Live threat map teaser — lightweight animated SVG dots (Framer Motion) pulsing on a world map outline, giving a "live system" feel.
Tech stack strip — glass pill badges (FastAPI, PostgreSQL, Neo4j, React, MITRE ATT&CK).
CTA footer — large glass card, "Ready to see it in action?" linking to /dashboard.

Use GSAP + ScrollTrigger for scroll choreography and Lenis (@studio-freight/lenis) for smooth inertia scrolling across the whole page. Add a cursor-follow soft glow blob (blurred div + Framer Motion useSpring) for extra polish.

3D SCANNING SEQUENCE — TIER 1

On the Analyze page, when a user submits an email for scanning (POST /analyze), replace the boring spinner with a stylized 3D envelope/packet object that gets swept by a moving light plane, with small particle bits flying off into labeled bins as each check completes: Parsing Headers → Checking SPF/DKIM/DMARC → NLP Analysis → URL/VT Lookup → Geo-Trace → Computing Risk Score. This animation repeats every time a scan runs, so it needs to feel fast (3-4 seconds) and satisfying, not gimmicky/slow.

ROTATING RISK ORB — TIER 1

Once scan results return, show a 3D glass orb/shield (React Three Fiber) that rotates slowly and shifts color based on risk score — green for safe, amber for suspicious, red for malicious/critical — with a subtle glow-pulse or crack-effect animation on high-risk results. This becomes the product's visual signature.

APPLICATION SHELL (/dashboard/*)
Persistent left sidebar (glass, collapsible): Dashboard, Analyze, Forensic Cases, Threat Graph, Analytics, Settings.
Top bar (glass): live "system status" pill (pulsing green dot, "All Systems Operational"), search, Privacy Mode toggle (maps to the real private_mode API flag — should visually "encrypt"/scramble UI text briefly when toggled on).
Page transitions: fade + slight scale via Framer Motion AnimatePresence.
PAGES — WIRE TO THE REAL BACKEND (base URL http://localhost:8000, via .env as VITE_API_BASE_URL)

1. Analyze (/dashboard/analyze)

Tabbed input: Paste Email Text / Paste URL / Upload .eml File / LinkedIn Message.
POST /analyze with: email_text, email_header, url, urls, sender_email, private_mode, platform, thread_id.
Results: circular animated risk gauge (SVG arc fills on load, color-coded), 4 animated factor bars (Linguistic, Brand, Protocol, URL), verdict badge, confidence level, MITRE ATT&CK trajectory as a horizontal chip stepper, plus the Tier-1 rotating risk orb.

2. Forensic Investigation (/dashboard/forensics/analyze)

Drag-drop glass dropzone for .eml/.msg → POST /api/forensics/upload-eml, or raw paste → POST /api/forensics/analyze-email.
Results: Case ID header (copy-to-clipboard), hash chips (sha256/sha1/md5, monospace), SPF/DKIM/DMARC matrix (3 status pills), relay path as a vertical timeline of hops (IP, hostname, timestamp, latency), campaign correlation badge, MITRE tactic chips.
Buttons: "Export PDF" → GET /api/forensics/export/{case_id}/pdf, "Export STIX" → GET /api/forensics/export/{case_id}/stix.

3. Evidence Vault / Cases (/dashboard/forensics/cases)

GET /api/forensics/cases — paginated glass table/cards, filter by verdict/date, click-through to GET /api/forensics/cases/{case_id} full dossier + chain-of-custody timeline.

4. Threat Graph (/dashboard/forensics/campaigns/:id/graph)

Tier 1: @xyflow/react (React Flow) with custom glass node types (Email/IP/Domain/ASN/Threat Actor, each with a distinct icon) and animated flowing-gradient edges.
Tier 2 (only if time allows): upgrade to react-force-graph-3d for a fully 3D orbitable graph.

5. Analytics / SOC Dashboard (/dashboard/analytics)

GET /analytics — animated count-up KPI cards.
GET /daily-pulse-heatmap — 7×24 heatmap (Recharts or custom CSS grid), glass container, hover tooltips.
GET /dashboard/top-brands, GET /dashboard/risk-heatmap, GET /history (filterable by verdict/channel/time) — sortable glass table.

6. Geo Threat Map (/dashboard/geo)

Full Leaflet map (dark tiles) plotting scan origins from history, animated pulse markers for high-risk origins, distinct styling for Tor/VPN-flagged nodes.
ANIMATION/LIBRARY STACK

framer-motion, @react-three/fiber + @react-three/drei, gsap + ScrollTrigger, @studio-freight/lenis, recharts, @xyflow/react (or react-force-graph-3d for Tier 2), leaflet + react-leaflet, lucide-react, sonner, tailwindcss v4 with custom glass utility classes (.glass-panel, .glass-card, .glow-border).

TECHNICAL REQUIREMENTS
TypeScript throughout, typed API client (/src/lib/api.ts).
@tanstack/react-query for all data fetching — no raw useEffect fetch chains.
Fully responsive; disable heavy 3D on low-end/mobile devices via WebGL capability check.
Glass-shimmer skeleton loaders for every async view — never a blank screen.
Respect prefers-reduced-motion; keyboard-navigable; readable contrast over glass.
.env.example with VITE_API_BASE_URL=http://localhost:8000.
Folder structure: /src/components, /src/pages, /src/lib, /src/hooks, /src/three, /src/styles.
DELIVERABLE

Build Tier 1 completely and polished first — 3D landing page, 3D scan animation, rotating risk orb, glass design system, and all 6 dashboard pages wired to the real API. Only move to Tier 2 items (3D force graph, holographic hero mockup) if Tier 1 is fully done and stable. Handle backend connection failures gracefully with a glass banner ("Backend not reachable — start FastAPI server") rather than crashing. Prioritize visual polish on the landing page and Analyze results view, since that's what judges see in the first 90 seconds of a demo.