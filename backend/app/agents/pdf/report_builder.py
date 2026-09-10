"""
PDFReportBuilder: Generates a professional one-page A4 forensic dossier.

Design philosophy:
- ONE PAGE ONLY — no page breaks, no multi-page output
- All data sourced from backend via DataTransformer
- cursor_y tracker prevents overflow; lower-priority sections truncated first
- Professional forensic document: printable, executive-readable, evidence-driven

Layout (top to bottom):
  Header (logo + case ID + timestamp)
  ├── Risk Summary Panel (left)  |  Email Information Panel (right)
  ├── WHY THIS WAS FLAGGED (full width)
  ├── Risk Factor Table (left)   |  Authentication Matrix (right)
  ├── URL/Domain Intel (left)    |  Infrastructure (right)
  ├── Evidence Block (left)      |  Forensic Assessment (right)
  ├── Final Verdict Bar (full width)
  └── Footer
"""

import io
import math
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import mm, inch

from .data_transformer import DataTransformer
from .validator import DataValidator
from .translations import LanguageTranslator
from .pii_redactor import PIIRedactor

# ── Page constants ────────────────────────────────────────────────────────────
PAGE_W, PAGE_H = A4          # 595.28 x 841.89 pts
MARGIN_X = 26.0              # left / right margin
MARGIN_TOP = 22.0            # top margin
MARGIN_BOT = 20.0            # bottom margin
CONTENT_W = PAGE_W - 2 * MARGIN_X   # usable width

# ── Color palette ─────────────────────────────────────────────────────────────
C_NAVY       = colors.HexColor("#0F172A")   # primary text
C_CYAN       = colors.HexColor("#0891B2")   # accent / headers
C_CYAN_LIGHT = colors.HexColor("#E0F2FE")   # light accent bg
C_BORDER     = colors.HexColor("#CBD5E1")   # borders / dividers
C_BG_CARD    = colors.HexColor("#F8FAFC")   # card background
C_BG_HEADER  = colors.HexColor("#0F172A")   # header bar bg
C_NEUTRAL    = colors.HexColor("#64748B")   # secondary text
C_WHITE      = colors.white

# Risk colours
C_CRITICAL   = colors.HexColor("#7F1D1D")   # dark red bg for CRITICAL
C_HIGH_RED   = colors.HexColor("#DC2626")   # HIGH text/badge
C_HIGH_BG    = colors.HexColor("#FEF2F2")   # HIGH panel bg
C_MED_AMBER  = colors.HexColor("#D97706")   # MEDIUM text/badge
C_MED_BG     = colors.HexColor("#FFFBEB")   # MEDIUM panel bg
C_SAFE_GREEN = colors.HexColor("#16A34A")   # SAFE text/badge
C_SAFE_BG    = colors.HexColor("#F0FDF4")   # SAFE panel bg

# Auth status colours
C_PASS       = colors.HexColor("#16A34A")
C_FAIL       = colors.HexColor("#DC2626")
C_NONE       = colors.HexColor("#64748B")


# ── Helper: safe string ───────────────────────────────────────────────────────
def _s(val: Any, default: str = "—") -> str:
    if val is None or val == "" or val == [] or val == {}:
        return default
    return str(val)


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


# ── Helper: risk colour from score ────────────────────────────────────────────
def _risk_color(score: float) -> colors.HexColor:
    if score >= 80:
        return C_HIGH_RED
    if score >= 55:
        return C_MED_AMBER
    return C_SAFE_GREEN


def _risk_bg(score: float) -> colors.HexColor:
    if score >= 80:
        return C_HIGH_BG
    if score >= 55:
        return C_MED_BG
    return C_SAFE_BG


def _risk_label(score: float) -> str:
    if score >= 80:
        return "HIGH RISK"
    if score >= 55:
        return "SUSPICIOUS"
    return "SAFE"


def _auth_color(status: str) -> colors.HexColor:
    s = (status or "").lower()
    if s in ("pass", "verified"):
        return C_PASS
    if s in ("fail", "failed", "invalid", "reject"):
        return C_FAIL
    return C_NONE


# ── Helper: word-wrap text onto canvas ───────────────────────────────────────
def _draw_wrapped(c: canvas.Canvas, text: str, x: float, y: float,
                  max_w: float, font: str, size: float,
                  color: colors.Color, line_h: float) -> float:
    """Draw text with word-wrapping. Returns the y-position after the last line."""
    c.setFont(font, size)
    c.setFillColor(color)
    words = str(text).split()
    line = ""
    for word in words:
        test = (line + " " + word).strip()
        if c.stringWidth(test, font, size) <= max_w:
            line = test
        else:
            if line:
                c.drawString(x, y, line)
                y -= line_h
            line = word
    if line:
        c.drawString(x, y, line)
        y -= line_h
    return y


# ── Helper: severity badge pill ──────────────────────────────────────────────
def _draw_badge(c: canvas.Canvas, x: float, y: float,
                label: str, bg: colors.Color, text_c: colors.Color = C_WHITE,
                font_size: float = 6.5) -> float:
    """Draw a small colored pill badge. Returns the width of the badge."""
    c.setFont("Helvetica-Bold", font_size)
    w = c.stringWidth(label, "Helvetica-Bold", font_size) + 6
    h = font_size + 4
    c.setFillColor(bg)
    c.roundRect(x, y - h + 2, w, h, 2, fill=True, stroke=False)
    c.setFillColor(text_c)
    c.drawString(x + 3, y - font_size + 2, label)
    return w


# ── Helper: horizontal rule ──────────────────────────────────────────────────
def _hrule(c: canvas.Canvas, x: float, y: float, w: float,
           color: colors.Color = C_BORDER, thickness: float = 0.5) -> None:
    c.setStrokeColor(color)
    c.setLineWidth(thickness)
    c.line(x, y, x + w, y)


# ── Helper: section label ─────────────────────────────────────────────────────
def _section_label(c: canvas.Canvas, x: float, y: float,
                   label: str, color: colors.Color = C_CYAN) -> None:
    c.setFont("Helvetica-Bold", 7)
    c.setFillColor(color)
    c.drawString(x, y, label.upper())


# ── Helper: key-value row ─────────────────────────────────────────────────────
def _kv(c: canvas.Canvas, x: float, y: float,
        key: str, val: str, key_w: float, total_w: float,
        key_size: float = 7.5, val_size: float = 7.5) -> float:
    """Draw key: value. Returns next y."""
    c.setFont("Helvetica-Bold", key_size)
    c.setFillColor(C_NAVY)
    c.drawString(x, y, key + ":")
    c.setFont("Helvetica", val_size)
    c.setFillColor(C_NEUTRAL)
    val_x = x + key_w
    val_w = total_w - key_w
    # truncate if too long
    if c.stringWidth(val, "Helvetica", val_size) > val_w:
        while val and c.stringWidth(val + "...", "Helvetica", val_size) > val_w:
            val = val[:-1]
        val = val + "..."
    c.drawString(val_x, y, val)
    return y - 10.5


# ─────────────────────────────────────────────────────────────────────────────
class PDFReportBuilder:
    """
    Generates a one-page A4 forensic dossier for SpectraShield.

    Data flow:
        Raw forensic data → DataTransformer → _build_pdf_document → canvas → bytes
    """

    def __init__(self, case_id: str, redaction_mode: bool = False,
                 redaction_level: str = "standard"):
        self.case_id = case_id
        self.redaction_mode = redaction_mode
        self.redaction_level = redaction_level
        self.warnings = []
        self.data_transformer = DataTransformer()
        self.translator = LanguageTranslator()
        self.redactor = PIIRedactor(level=redaction_level) if redaction_mode else None

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_pdf(self, forensic_data: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """
        Generate one-page PDF report from forensic data.

        Returns:
            (pdf_bytes, metadata_dict)
        """
        metadata = {
            "case_id": self.case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "error",
            "pages": 0,
            "validation_warnings": [],
            "validation_errors": [],
            "redaction_applied": self.redaction_mode,
            "redaction_level": self.redaction_level if self.redaction_mode else None,
        }

        try:
            if self.redaction_mode and self.redactor:
                forensic_data = self.redactor.redact_forensic_data(forensic_data)

            transformed = self.data_transformer.extract_from_backend(forensic_data)
            warnings = DataValidator.validate_consistency(transformed)
            metadata["validation_warnings"] = [
                {"level": w.level, "category": w.category,
                 "message": w.message, "field": w.affected_field}
                for w in warnings
            ]

            should_proceed, err = DataValidator.should_generate_pdf(warnings)
            if not should_proceed:
                metadata["validation_errors"].append(err)
                metadata["status"] = "blocked_by_validation"
                return self._generate_error_pdf(err), metadata

            pdf_bytes = self._build_pdf_document(transformed)
            metadata["status"] = "success"
            metadata["pages"] = 1
            return pdf_bytes, metadata

        except Exception as e:
            metadata["status"] = "error"
            metadata["validation_errors"].append(str(e))
            return self._generate_error_pdf(f"Report generation failed: {e}"), metadata

    # ── Core builder ──────────────────────────────────────────────────────────

    def _build_pdf_document(self, data: Dict[str, Any]) -> bytes:
        """Render entire dossier onto a single A4 page."""
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        self._build_single_page_dossier(c, data)
        c.save()
        buf.seek(0)
        return buf.getvalue()

    def _build_single_page_dossier(self, c: canvas.Canvas,
                                   data: Dict[str, Any]) -> None:
        """Master renderer: draws all sections onto one A4 page."""
        # White background
        c.setFillColor(C_WHITE)
        c.rect(0, 0, PAGE_W, PAGE_H, fill=True, stroke=False)

        cursor = PAGE_H - MARGIN_TOP

        # 1. HEADER ────────────────────────────────────────────────────────────
        cursor = self._draw_header(c, data, cursor)

        # 2. RISK SUMMARY  |  EMAIL INFO ──────────────────────────────────────
        cursor = self._draw_risk_email_row(c, data, cursor)

        # 3. WHY THIS WAS FLAGGED ─────────────────────────────────────────────
        cursor = self._draw_why_flagged(c, data, cursor)

        # 4. RISK FACTORS  |  AUTHENTICATION ──────────────────────────────────
        cursor = self._draw_risk_auth_row(c, data, cursor)

        # 5. URL INTEL  |  INFRASTRUCTURE ─────────────────────────────────────
        cursor = self._draw_intel_infra_row(c, data, cursor)

        # 6. EVIDENCE  |  FORENSIC ASSESSMENT ────────────────────────────────
        cursor = self._draw_evidence_assessment_row(c, data, cursor)

        # 7. FINAL VERDICT BAR ────────────────────────────────────────────────
        verdict_top = MARGIN_BOT + 18.0   # fixed position from bottom
        self._draw_final_verdict_bar(c, data, verdict_top)

        # 8. FOOTER ───────────────────────────────────────────────────────────
        self._draw_footer(c, data)

        # No showPage() except the implicit one — canvas.save() finalizes

    # ── Section: HEADER ───────────────────────────────────────────────────────

    def _draw_header(self, c: canvas.Canvas, data: Dict[str, Any],
                     top_y: float) -> float:
        """Dark navy header bar with logo, subtitle, and case info."""
        h = 42.0
        # Background bar
        c.setFillColor(C_BG_HEADER)
        c.rect(0, top_y - h, PAGE_W, h, fill=True, stroke=False)

        # Cyan left accent strip
        c.setFillColor(C_CYAN)
        c.rect(0, top_y - h, 4, h, fill=True, stroke=False)

        # Logo text
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(C_WHITE)
        c.drawString(MARGIN_X, top_y - 15, "SPECTRASHIELD")

        # Subtitle
        c.setFont("Helvetica", 7.5)
        c.setFillColor(colors.HexColor("#94A3B8"))
        c.drawString(MARGIN_X, top_y - 27, "EMAIL THREAT FORENSIC DOSSIER")

        # Case ID / timestamp (right-aligned)
        case_id = _s(data.get("case_id"), self.case_id)
        now_str = datetime.now().strftime("%d %b %Y  %H:%M")
        c.setFont("Courier-Bold", 8)
        c.setFillColor(colors.HexColor("#CBD5E1"))
        c.drawRightString(PAGE_W - MARGIN_X, top_y - 14, case_id)
        c.setFont("Helvetica", 7)
        c.setFillColor(colors.HexColor("#94A3B8"))
        c.drawRightString(PAGE_W - MARGIN_X, top_y - 26, f"Generated: {now_str}")

        # Demo watermark if applicable
        verdict = _s(data.get("verdict"), "").upper()
        if "DEMO" in case_id.upper() or "TEST" in case_id.upper():
            c.setFont("Helvetica-Bold", 7)
            c.setFillColor(colors.HexColor("#F59E0B"))
            demo_w = c.stringWidth("  DEMONSTRATION CASE  ", "Helvetica-Bold", 7)
            demo_x = (PAGE_W - demo_w) / 2
            c.setFillColor(colors.HexColor("#78350F"))
            c.rect(demo_x, top_y - 30, demo_w, 12, fill=True, stroke=False)
            c.setFillColor(colors.HexColor("#FDE68A"))
            c.drawString(demo_x + 3, top_y - 22, "DEMONSTRATION CASE")

        return top_y - h - 4

    # ── Section: RISK SUMMARY + EMAIL INFO ───────────────────────────────────

    def _draw_risk_email_row(self, c: canvas.Canvas, data: Dict[str, Any],
                             top_y: float) -> float:
        """Left: Risk panel. Right: Email metadata. Height: ~88pts."""
        _hrule(c, MARGIN_X, top_y, CONTENT_W, C_BORDER, 0.4)
        top_y -= 5
        h = 86.0
        col_w = CONTENT_W / 2 - 4

        # ── LEFT: Risk Summary ───────────────────────────────────────────────
        rx = MARGIN_X
        score = _safe_float(data.get("final_risk"), 0.0)
        verdict = _s(data.get("verdict"), "EVALUATED").upper()
        threat_cat = _s(data.get("threat_category"), "Unknown")
        confidence = _safe_float(data.get("confidence"), 0.0)
        severity = _risk_label(score)
        risk_col = _risk_color(score)
        risk_bg = _risk_bg(score)

        # Card background
        c.setFillColor(risk_bg)
        c.setStrokeColor(risk_col)
        c.setLineWidth(1.2)
        c.roundRect(rx, top_y - h, col_w, h, 4, fill=True, stroke=True)

        # Left cyan accent bar
        c.setFillColor(risk_col)
        c.roundRect(rx, top_y - h, 4, h, 2, fill=True, stroke=False)

        pad = 10
        lx = rx + pad

        # RISK SCORE big number
        c.setFont("Helvetica-Bold", 28)
        c.setFillColor(risk_col)
        score_str = f"{int(score)}"
        c.drawString(lx, top_y - 30, score_str)
        sw = c.stringWidth(score_str, "Helvetica-Bold", 28)
        c.setFont("Helvetica", 10)
        c.setFillColor(C_NEUTRAL)
        c.drawString(lx + sw + 3, top_y - 23, "/ 100")

        # SEVERITY badge
        badge_y = top_y - 46
        _draw_badge(c, lx, badge_y, severity, risk_col, C_WHITE, 8)
        sev_w = c.stringWidth(severity, "Helvetica-Bold", 8) + 8

        # VERDICT
        c.setFont("Helvetica-Bold", 8.5)
        c.setFillColor(C_NAVY)
        c.drawString(lx + sev_w + 5, badge_y - 1, verdict)

        # Threat category
        c.setFont("Helvetica", 7.5)
        c.setFillColor(C_NEUTRAL)
        c.drawString(lx, top_y - 59, threat_cat[:38])

        # Confidence bar
        bar_y = top_y - 73
        bar_w = col_w - pad - 8
        c.setFillColor(colors.HexColor("#E2E8F0"))
        c.roundRect(lx, bar_y, bar_w, 6, 2, fill=True, stroke=False)
        filled = max(0, min(bar_w, bar_w * confidence / 100))
        c.setFillColor(risk_col)
        c.roundRect(lx, bar_y, filled, 6, 2, fill=True, stroke=False)
        c.setFont("Helvetica-Bold", 7)
        c.setFillColor(C_NAVY)
        c.drawString(lx, bar_y - 9, f"CONFIDENCE: {int(confidence)}%")

        # ── RIGHT: Email Info ────────────────────────────────────────────────
        ex = MARGIN_X + col_w + 8
        ew = CONTENT_W - col_w - 8

        c.setFillColor(C_BG_CARD)
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.5)
        c.roundRect(ex, top_y - h, ew, h, 4, fill=True, stroke=True)

        _section_label(c, ex + 8, top_y - 10, "EMAIL")
        _hrule(c, ex + 8, top_y - 14, ew - 16, C_BORDER, 0.3)

        email_meta = data.get("email_metadata") or {}

        # Extract sender intelligently
        sender = email_meta.get("sender") or {}
        if isinstance(sender, dict):
            from_val = sender.get("email") or sender.get("address") or "—"
            from_name = sender.get("name") or ""
        else:
            from_val = _s(sender)
            from_name = ""

        recipient = email_meta.get("recipient") or email_meta.get("to") or "-"
        if isinstance(recipient, dict):
            recipient = recipient.get("email") or recipient.get("address") or "-"
        subject = _s(email_meta.get("subject"), "-")
        ts = _s(email_meta.get("timestamp") or email_meta.get("date"), "-")
        platform = _s(email_meta.get("platform") or email_meta.get("source"), "-")

        ey = top_y - 22
        kw = 38
        ey = _kv(c, ex + 8, ey, "From", _s(from_val), kw, ew - 14)
        ey = _kv(c, ex + 8, ey, "To", _s(recipient), kw, ew - 14)
        ey = _kv(c, ex + 8, ey, "Subject", _s(subject), kw, ew - 14)
        ey = _kv(c, ex + 8, ey, "Received", _s(ts)[:30], kw, ew - 14)
        if platform != "-":
            _kv(c, ex + 8, ey, "Platform", platform, kw, ew - 14)

        return top_y - h - 6

    # ── Section: WHY THIS WAS FLAGGED ─────────────────────────────────────────

    def _draw_why_flagged(self, c: canvas.Canvas, data: Dict[str, Any],
                          top_y: float) -> float:
        """Full-width 'WHY THIS WAS FLAGGED' section with severity rows."""
        _hrule(c, MARGIN_X, top_y, CONTENT_W, C_BORDER, 0.4)
        top_y -= 5

        why_raw = data.get("why_flagged") or []
        # Normalize to list of dicts
        items = self._normalize_why_flagged(why_raw)
        # Cap at 5
        items = items[:5]

        if not items:
            return top_y

        # Section header bar
        c.setFillColor(colors.HexColor("#1E293B"))
        c.rect(MARGIN_X, top_y - 13, CONTENT_W, 13, fill=True, stroke=False)
        c.setFont("Helvetica-Bold", 7.5)
        c.setFillColor(C_WHITE)
        c.drawString(MARGIN_X + 6, top_y - 10, "WHY THIS WAS FLAGGED")

        row_h = 17.5
        section_h = 13 + len(items) * row_h + 4

        # Background
        c.setFillColor(C_BG_CARD)
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.4)
        c.rect(MARGIN_X, top_y - section_h, CONTENT_W, section_h - 13,
               fill=True, stroke=True)

        ry = top_y - 13 - 4

        for i, item in enumerate(items):
            sev = item.get("severity", "MEDIUM").upper()
            cat = item.get("category", "").upper() or item.get("reason", "Unknown").upper()
            explanation = item.get("explanation") or ""
            evidence = item.get("evidence") or ""

            # Severity badge
            if "HIGH" in sev or "CRITICAL" in sev:
                badge_col = C_HIGH_RED
            elif "LOW" in sev:
                badge_col = C_SAFE_GREEN
            else:
                badge_col = C_MED_AMBER

            bx = MARGIN_X + 5
            bw = _draw_badge(c, bx, ry - 1, sev, badge_col, C_WHITE, 6.5)

            # Category
            c.setFont("Helvetica-Bold", 7.5)
            c.setFillColor(C_NAVY)
            c.drawString(bx + bw + 4, ry - 1, cat[:28])

            # Explanation
            if explanation:
                exp_x = bx + bw + 4 + c.stringWidth(cat[:28], "Helvetica-Bold", 7.5) + 6
                c.setFont("Helvetica", 7)
                c.setFillColor(C_NEUTRAL)
                exp_avail = CONTENT_W - (exp_x - MARGIN_X) - 6
                exp_str = str(explanation)
                while exp_str and c.stringWidth(exp_str, "Helvetica", 7) > exp_avail:
                    exp_str = exp_str[:-1]
                if exp_str:
                    c.drawString(exp_x, ry - 1, exp_str + ("..." if len(exp_str) < len(str(explanation)) else ""))

            # Evidence (monospace, truncated)
            if evidence:
                c.setFont("Courier", 6.5)
                c.setFillColor(colors.HexColor("#475569"))
                ev_str = str(evidence)
                ev_avail = CONTENT_W - 30
                while ev_str and c.stringWidth(ev_str, "Courier", 6.5) > ev_avail:
                    ev_str = ev_str[:-1]
                c.drawString(bx + bw + 4, ry - 11, ("Evidence: " + ev_str)[:80])

            ry -= row_h

            # subtle row divider
            if i < len(items) - 1:
                _hrule(c, MARGIN_X + 5, ry + 3, CONTENT_W - 10, C_BORDER, 0.2)

        return top_y - section_h - 4

    # ── Section: RISK FACTORS | AUTHENTICATION ────────────────────────────────

    def _draw_risk_auth_row(self, c: canvas.Canvas, data: Dict[str, Any],
                            top_y: float) -> float:
        """Left: risk factor score table. Right: SPF/DKIM/DMARC matrix."""
        _hrule(c, MARGIN_X, top_y, CONTENT_W, C_BORDER, 0.4)
        top_y -= 5

        col_w = CONTENT_W / 2 - 4
        h = 72.0

        # ── LEFT: Risk Factor Table ──────────────────────────────────────────
        rx = MARGIN_X
        c.setFillColor(C_BG_CARD)
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.5)
        c.roundRect(rx, top_y - h, col_w, h, 3, fill=True, stroke=True)

        _section_label(c, rx + 6, top_y - 9, "RISK FACTOR ANALYSIS")
        _hrule(c, rx + 6, top_y - 12, col_w - 12, C_BORDER, 0.3)

        # Extract risk sub-scores from backend data
        score = _safe_float(data.get("final_risk"), 0.0)
        url_score  = _safe_float(data.get("url_risk_score"), None)
        dom_score  = _safe_float(data.get("domain_risk_score"), None)
        soc_score  = _safe_float(data.get("nlp_score") or data.get("social_engineering_score"), None)
        auth_score = _safe_float(data.get("authentication_risk"), None)
        ssl_score  = data.get("ssl_score")
        vt_score   = data.get("virustotal_score")

        factors = [
            ("URL Analysis",     url_score),
            ("Domain Intel",     dom_score),
            ("Social Engineer.", soc_score),
            ("Authentication",   auth_score),
            ("SSL/TLS",          ssl_score),
            ("VirusTotal",       vt_score),
        ]

        fy = top_y - 21
        col_name_w = 90
        col_bar_w  = col_w - col_name_w - 28
        for name, val in factors:
            c.setFont("Helvetica", 7)
            c.setFillColor(C_NAVY)
            c.drawString(rx + 6, fy, name)

            if val is None:
                c.setFont("Helvetica", 6.5)
                c.setFillColor(C_NEUTRAL)
                c.drawString(rx + col_name_w, fy, "NOT ENRICHED")
            else:
                fval = float(val)
                fc = _risk_color(fval)
                # mini bar
                bar_bg_w = col_bar_w
                c.setFillColor(colors.HexColor("#E2E8F0"))
                c.roundRect(rx + col_name_w, fy - 1, bar_bg_w, 6, 1, fill=True, stroke=False)
                filled = bar_bg_w * fval / 100
                c.setFillColor(fc)
                c.roundRect(rx + col_name_w, fy - 1, filled, 6, 1, fill=True, stroke=False)
                # label
                lbl = f"{int(fval)}"
                c.setFont("Helvetica-Bold", 6.5)
                c.setFillColor(fc)
                c.drawString(rx + col_name_w + bar_bg_w + 3, fy, lbl)

            fy -= 9.5

        # ── RIGHT: Authentication Matrix ─────────────────────────────────────
        ax = MARGIN_X + col_w + 8
        aw = CONTENT_W - col_w - 8

        c.setFillColor(C_BG_CARD)
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.5)
        c.roundRect(ax, top_y - h, aw, h, 3, fill=True, stroke=True)

        _section_label(c, ax + 8, top_y - 9, "AUTHENTICATION")
        _hrule(c, ax + 8, top_y - 12, aw - 16, C_BORDER, 0.3)

        auth = data.get("authentication") or {}
        spf   = auth.get("spf")   or {}
        dkim  = auth.get("dkim")  or {}
        dmarc = auth.get("dmarc") or {}

        protos = [
            ("SPF",   spf.get("status",  "NONE")),
            ("DKIM",  dkim.get("status", "NONE")),
            ("DMARC", dmarc.get("status","NONE")),
        ]

        ay = top_y - 22
        proto_x = ax + 8
        status_x = proto_x + 38

        for proto, status in protos:
            ac = _auth_color(status)

            c.setFont("Helvetica-Bold", 8)
            c.setFillColor(C_NAVY)
            c.drawString(proto_x, ay, proto)

            # Status pill
            s_label = LanguageTranslator.auth_status(status)
            sw = c.stringWidth(s_label, "Helvetica-Bold", 7) + 6
            c.setFillColor(ac)
            c.roundRect(status_x, ay - 1, sw, 10, 2, fill=True, stroke=False)
            c.setFillColor(C_WHITE)
            c.setFont("Helvetica-Bold", 7)
            c.drawString(status_x + 3, ay + 1, s_label)
            ay -= 14

        # Domain details
        auth_domain = (spf.get("domain") or dmarc.get("domain") or
                       dkim.get("domain") or "")
        if auth_domain:
            c.setFont("Helvetica", 6.5)
            c.setFillColor(C_NEUTRAL)
            c.drawString(proto_x, ay - 1, f"Domain: {auth_domain[:30]}")

        return top_y - h - 5

    # ── Section: URL INTEL | INFRASTRUCTURE ───────────────────────────────────

    def _draw_intel_infra_row(self, c: canvas.Canvas, data: Dict[str, Any],
                               top_y: float) -> float:
        """Left: URL/domain intel. Right: origin infrastructure."""
        _hrule(c, MARGIN_X, top_y, CONTENT_W, C_BORDER, 0.4)
        top_y -= 5
        col_w = CONTENT_W / 2 - 4
        h = 68.0

        # ── LEFT: URL / Domain Intelligence ──────────────────────────────────
        ux = MARGIN_X
        c.setFillColor(C_BG_CARD)
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.5)
        c.roundRect(ux, top_y - h, col_w, h, 3, fill=True, stroke=True)

        _section_label(c, ux + 6, top_y - 9, "URL / DOMAIN INTELLIGENCE")
        _hrule(c, ux + 6, top_y - 12, col_w - 12, C_BORDER, 0.3)

        url_data = data.get("url_analysis") or data.get("domain_info") or {}
        origin  = data.get("originating_node") or {}
        auth    = data.get("authentication") or {}
        spf     = auth.get("spf") or {}

        url_val    = _s(url_data.get("url") or url_data.get("primary_url"), "NOT ENRICHED")
        domain_val = (_s(url_data.get("domain") or spf.get("domain") or
                         (auth.get("dmarc") or {}).get("domain"), "NOT ENRICHED"))
        ip_val     = _s(url_data.get("ip") or origin.get("ip"), "NOT ENRICHED")
        asn_val    = _s(url_data.get("asn") or origin.get("asn"), "NOT ENRICHED")
        rep_val    = _s(url_data.get("reputation"), "NOT ENRICHED")

        uy = top_y - 21
        kw = 44
        uy = _kv(c, ux + 6, uy, "URL",    url_val,    kw, col_w - 10, 7, 7)
        uy = _kv(c, ux + 6, uy, "Domain", domain_val, kw, col_w - 10, 7, 7)
        uy = _kv(c, ux + 6, uy, "IP",     ip_val,     kw, col_w - 10, 7, 7)
        uy = _kv(c, ux + 6, uy, "ASN",    asn_val,    kw, col_w - 10, 7, 7)
        if rep_val != "NOT ENRICHED":
            _kv(c, ux + 6, uy, "Rep.",   rep_val, kw, col_w - 10, 7, 7)

        # ── RIGHT: Infrastructure ─────────────────────────────────────────────
        ix = MARGIN_X + col_w + 8
        iw = CONTENT_W - col_w - 8

        c.setFillColor(C_BG_CARD)
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.5)
        c.roundRect(ix, top_y - h, iw, h, 3, fill=True, stroke=True)

        _section_label(c, ix + 8, top_y - 9, "INFRASTRUCTURE")
        _hrule(c, ix + 8, top_y - 12, iw - 16, C_BORDER, 0.3)

        ip    = _s(origin.get("ip") or origin.get("defanged_ip"), "NOT ENRICHED")
        country = _s(origin.get("country") or origin.get("country_code"), "NOT ENRICHED")
        isp   = _s(origin.get("isp") or origin.get("organization"), "NOT ENRICHED")
        asn   = _s(origin.get("asn"), "NOT ENRICHED")
        anon  = origin.get("anonymization_type")
        anon_label = LanguageTranslator.anonymization_type(anon) if anon else "None Detected"
        ssl_tls = _s(data.get("ssl_status") or data.get("tls_status"), "NOT ENRICHED")

        iy = top_y - 21
        kw2 = 44
        iy = _kv(c, ix + 8, iy, "Origin IP", ip, kw2, iw - 14, 7, 7)
        iy = _kv(c, ix + 8, iy, "Country",   country, kw2, iw - 14, 7, 7)
        iy = _kv(c, ix + 8, iy, "ISP",        isp, kw2, iw - 14, 7, 7)
        iy = _kv(c, ix + 8, iy, "ASN",        asn, kw2, iw - 14, 7, 7)
        iy = _kv(c, ix + 8, iy, "Anon",  anon_label, kw2, iw - 14, 7, 7)

        return top_y - h - 5

    # ── Section: EVIDENCE | ASSESSMENT ───────────────────────────────────────

    def _draw_evidence_assessment_row(self, c: canvas.Canvas, data: Dict[str, Any],
                                      top_y: float) -> float:
        """Left: evidence record. Right: forensic assessment text."""
        _hrule(c, MARGIN_X, top_y, CONTENT_W, C_BORDER, 0.4)
        top_y -= 5
        col_w = CONTENT_W * 0.42
        h = 60.0

        # ── LEFT: Evidence Block ──────────────────────────────────────────────
        ex = MARGIN_X
        c.setFillColor(colors.HexColor("#F0FDF4"))
        c.setStrokeColor(colors.HexColor("#86EFAC"))
        c.setLineWidth(0.5)
        c.roundRect(ex, top_y - h, col_w, h, 3, fill=True, stroke=True)

        _section_label(c, ex + 6, top_y - 9, "EVIDENCE", colors.HexColor("#16A34A"))
        _hrule(c, ex + 6, top_y - 12, col_w - 12, colors.HexColor("#86EFAC"), 0.3)

        sha256 = _s(data.get("sha256_evidence_hash"), "NOT COMPUTED")
        # Truncate hash for display
        hash_disp = sha256[:24] + "..." if len(sha256) > 24 else sha256
        case_id = _s(data.get("case_id"), self.case_id)
        ts = _s(data.get("analysis_timestamp") or data.get("ingestion_timestamp"), "-")
        sealed = data.get("is_sealed", False)
        integrity = "SEALED" if sealed else "TAMPER-EVIDENT"

        evy = top_y - 21
        evy = _kv(c, ex + 6, evy, "Case ID",   case_id,    50, col_w - 10, 7, 7)

        c.setFont("Helvetica-Bold", 7)
        c.setFillColor(C_NAVY)
        c.drawString(ex + 6, evy, "SHA-256:")
        c.setFont("Courier", 6.5)
        c.setFillColor(C_NEUTRAL)
        c.drawString(ex + 6 + 40, evy, hash_disp)
        evy -= 10.5

        evy = _kv(c, ex + 6, evy, "Integrity", integrity,  50, col_w - 10, 7, 7)
        _kv(c, ex + 6, evy, "Collected", ts[:20], 50, col_w - 10, 7, 7)

        # ── RIGHT: Forensic Assessment ────────────────────────────────────────
        ax = MARGIN_X + col_w + 6
        aw = CONTENT_W - col_w - 6

        c.setFillColor(C_BG_CARD)
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.5)
        c.roundRect(ax, top_y - h, aw, h, 3, fill=True, stroke=True)

        _section_label(c, ax + 8, top_y - 9, "FORENSIC ASSESSMENT")
        _hrule(c, ax + 8, top_y - 12, aw - 16, C_BORDER, 0.3)

        summary = self._build_assessment_text(data)
        _draw_wrapped(c, summary, ax + 8, top_y - 23, aw - 18,
                      "Helvetica", 7.5, C_NAVY, 11)

        return top_y - h - 5

    # ── Section: FINAL VERDICT BAR ────────────────────────────────────────────

    def _draw_final_verdict_bar(self, c: canvas.Canvas, data: Dict[str, Any],
                                 bottom_y: float) -> None:
        """Bold full-width verdict strip just above the footer."""
        score   = _safe_float(data.get("final_risk"), 0.0)
        verdict = _s(data.get("verdict"), "EVALUATED").upper()
        conf    = _safe_float(data.get("confidence"), 0.0)
        cat     = _s(data.get("threat_category"), "").upper()
        risk_c  = _risk_color(score)

        bar_h = 20.0
        c.setFillColor(risk_c)
        c.rect(MARGIN_X, bottom_y, CONTENT_W, bar_h, fill=True, stroke=False)

        label = f"FINAL VERDICT: {verdict}"
        if cat:
            label += f" - {cat}"

        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(C_WHITE)
        c.drawString(MARGIN_X + 10, bottom_y + 6, label)

        right_text = f"Risk: {int(score)} / 100   Confidence: {int(conf)}%"
        c.setFont("Helvetica-Bold", 8.5)
        c.drawRightString(MARGIN_X + CONTENT_W - 10, bottom_y + 6, right_text)

    # ── Section: FOOTER ───────────────────────────────────────────────────────

    def _draw_footer(self, c: canvas.Canvas, data: Dict[str, Any]) -> None:
        """Minimal footer: brand | case | generated."""
        fy = MARGIN_BOT - 2
        _hrule(c, MARGIN_X, fy + 12, CONTENT_W, C_BORDER, 0.3)

        case_id = _s(data.get("case_id"), self.case_id)
        now_str = datetime.now().strftime("%d %b %Y  %H:%M")

        c.setFont("Helvetica-Bold", 6.5)
        c.setFillColor(C_CYAN)
        c.drawString(MARGIN_X, fy + 4, "SpectraShield")

        c.setFont("Helvetica", 6.5)
        c.setFillColor(C_NEUTRAL)
        c.drawString(MARGIN_X + 55, fy + 4, "Automated Email Forensics")

        right_foot = f"Case: {case_id}   Generated: {now_str}"
        c.setFont("Courier", 6)
        c.setFillColor(C_NEUTRAL)
        c.drawRightString(MARGIN_X + CONTENT_W, fy + 4, right_foot)

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _normalize_why_flagged(self, raw: Any) -> List[Dict[str, Any]]:
        """Normalize why_flagged to list of rich dicts regardless of input format."""
        if not raw:
            return []
        result = []
        for item in raw:
            if isinstance(item, dict):
                # Already rich dict — use as-is, fill missing fields
                result.append({
                    "severity": item.get("severity") or item.get("level") or "MEDIUM",
                    "category": (item.get("category") or
                                 item.get("type") or
                                 item.get("reason") or "Unknown"),
                    "explanation": (item.get("explanation") or
                                    item.get("description") or
                                    item.get("message") or ""),
                    "evidence": item.get("evidence") or item.get("indicator") or "",
                })
            elif isinstance(item, str):
                # String key → expand via translator
                explanation = LanguageTranslator.risk_factor_explanation(item)
                # Guess severity from key name
                sev = "MEDIUM"
                if any(k in item.lower() for k in ("fail", "malicious", "tor", "critical")):
                    sev = "HIGH"
                elif any(k in item.lower() for k in ("warn", "short", "qr")):
                    sev = "LOW"
                result.append({
                    "severity": sev,
                    "category": item.replace("_", " ").upper(),
                    "explanation": explanation,
                    "evidence": "",
                })
        return result

    def _build_assessment_text(self, data: Dict[str, Any]) -> str:
        """Build the 2-3 line forensic assessment from backend data."""
        # Use backend-provided reasoning summary if available
        summary = (data.get("reasoning_summary") or
                   data.get("analysis_summary") or
                   data.get("summary") or "")
        if summary and len(summary) > 20:
            return str(summary)[:300]

        # Auto-generate from available fields
        score   = _safe_float(data.get("final_risk"), 0.0)
        verdict = _s(data.get("verdict"), "evaluated")
        cat     = _s(data.get("threat_category"), "unknown category")
        conf    = _safe_float(data.get("confidence"), 0.0)
        reasons = self._normalize_why_flagged(data.get("why_flagged") or [])
        top     = [r.get("category", "") for r in reasons[:3]]

        signals = ", ".join(t.lower().replace("_", " ") for t in top if t)
        signal_text = f" including {signals}" if signals else ""

        return (
            f"The message exhibits multiple indicators{signal_text}. "
            f"The combined forensic signals result in a "
            f"{_risk_label(score)} classification ({verdict.upper()}) "
            f"with a risk score of {int(score)}/100 and "
            f"{int(conf)}% confidence. "
            f"Threat category: {cat}."
        )

    def _generate_error_pdf(self, message: str) -> bytes:
        """Generate minimal error PDF when main generation fails."""
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        c.setFillColor(colors.HexColor("#0F172A"))
        c.rect(0, 0, PAGE_W, PAGE_H, fill=True, stroke=False)
        c.setFont("Helvetica-Bold", 16)
        c.setFillColor(colors.HexColor("#DC2626"))
        c.drawCentredString(PAGE_W / 2, PAGE_H / 2 + 30, "PDF GENERATION ERROR")
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.white)
        c.drawCentredString(PAGE_W / 2, PAGE_H / 2, message[:80])
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#64748B"))
        c.drawCentredString(PAGE_W / 2, PAGE_H / 2 - 20, f"Case ID: {self.case_id}")
        c.save()
        buf.seek(0)
        return buf.getvalue()
