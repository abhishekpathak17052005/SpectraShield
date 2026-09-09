"""
PDFReportBuilder: Orchestrates end-to-end PDF generation.

Responsibilities:
- Validate data before generation
- Coordinate component rendering
- Manage multi-page document structure
- Handle errors and generate fallback reports
- Return PDF bytes for transmission
"""

import io
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

from .data_transformer import DataTransformer
from .validator import DataValidator, ValidationWarning
from .translations import LanguageTranslator
from .page_builder import PageBuilder
from .components import (
    ComponentRenderContext,
    RiskSnapshot,
    AttackStory,
    AuthenticationForensics,
    InfrastructureProfile,
    CampaignIntelligence,
    EvidenceIntegrity,
    ThreatDNAFingerprint
)
from .visual_elements import VisualElements
from .pii_redactor import PIIRedactor, RedactionValidator


class PDFReportBuilder:
    """
    Orchestrates PDF generation for SpectraShield Forensic Dossier.
    
    Seven-page structure:
    1. Risk Snapshot (executive summary)
    2. Attack Story (email journey)
    3. Authentication Forensics (SPF/DKIM/DMARC)
    4. Infrastructure Intelligence (threat intel)
    5. Campaign Intelligence (campaign correlation)
    6. Evidence & Chain of Custody
    7. Threat DNA & Conclusion
    
    Data Flow:
    Raw forensic data → DataTransformer → Validate → Build components → Render to PDF
    """

    def __init__(self, case_id: str, redaction_mode: bool = False, redaction_level: str = "standard"):
        """
        Initialize report builder.
        
        Args:
            case_id: Case identifier
            redaction_mode: If True, redact PII
            redaction_level: Redaction level (minimal, standard, strict)
        """
        self.case_id = case_id
        self.redaction_mode = redaction_mode
        self.redaction_level = redaction_level
        self.warnings = []
        self.validation_errors = []

        # Initialize components
        self.data_transformer = DataTransformer()
        self.translator = LanguageTranslator()
        self.visual_renderer = VisualElements()
        
        # Initialize redactor if needed
        if self.redaction_mode:
            self.redactor = PIIRedactor(level=redaction_level)
        else:
            self.redactor = None

    def generate_pdf(self, forensic_data: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """
        Generate complete PDF report from forensic data.
        
        Args:
            forensic_data: Raw forensic analysis results from backend
            
        Returns:
            (pdf_bytes, metadata_dict) where metadata contains warnings/errors
        """
        metadata = {
            'case_id': self.case_id,
            'generated_at': datetime.now().isoformat(),
            'status': 'error',
            'pages': 0,
            'validation_warnings': [],
            'validation_errors': [],
            'redaction_applied': self.redaction_mode,
            'redaction_level': self.redaction_level if self.redaction_mode else None,
        }

        try:
            # Step 0: Apply redaction if enabled
            if self.redaction_mode:
                forensic_data = self.redactor.redact_forensic_data(forensic_data)

            # Step 1: Transform data
            transformed_data = self.data_transformer.extract_from_backend(forensic_data)

            # Step 2: Validate data consistency
            warnings = DataValidator.validate_consistency(transformed_data)
            metadata['validation_warnings'] = [
                {
                    'level': w.level,
                    'category': w.category,
                    'message': w.message,
                    'field': w.affected_field
                }
                for w in warnings
            ]

            # Step 3: Check if we should proceed
            should_proceed, error_msg = DataValidator.should_generate_pdf(warnings)
            if not should_proceed:
                metadata['validation_errors'].append(error_msg)
                metadata['status'] = 'blocked_by_validation'
                return self._generate_error_pdf(error_msg), metadata

            # Step 4: Build PDF
            pdf_bytes = self._build_pdf_document(transformed_data)

            metadata['status'] = 'success'
            metadata['pages'] = 7
            return pdf_bytes, metadata

        except Exception as e:
            metadata['status'] = 'error'
            metadata['validation_errors'].append(str(e))
            return self._generate_error_pdf(f"Report generation failed: {str(e)}"), metadata

    def _build_pdf_document(self, forensic_data: Dict[str, Any]) -> bytes:
        """
        Build multi-page PDF document.
        
        Args:
            forensic_data: Transformed forensic data
            
        Returns:
            PDF bytes
        """
        # Create in-memory PDF
        pdf_buffer = io.BytesIO()
        c = canvas.Canvas(pdf_buffer, pagesize=letter)

        # Set up page
        page_width, page_height = letter

        # Add redaction header if needed
        if self.redaction_mode:
            self._add_redaction_header(c, page_width, page_height)
            c.showPage()

        # Page 1: Risk Snapshot
        self._build_page_1_risk_snapshot(c, forensic_data, page_width, page_height)
        c.showPage()

        # Page 2: Attack Story
        self._build_page_2_attack_story(c, forensic_data, page_width, page_height)
        c.showPage()

        # Page 3: Authentication Forensics
        self._build_page_3_authentication_forensics(c, forensic_data, page_width, page_height)
        c.showPage()

        # Page 4: Infrastructure Profile
        self._build_page_4_infrastructure_profile(c, forensic_data, page_width, page_height)
        c.showPage()

        # Page 5: Campaign Intelligence
        self._build_page_5_campaign_intelligence(c, forensic_data, page_width, page_height)
        c.showPage()

        # Page 6: Evidence & Chain of Custody
        self._build_page_6_evidence_integrity(c, forensic_data, page_width, page_height)
        c.showPage()

        # Page 7: Threat DNA & Conclusion
        self._build_page_7_threat_dna(c, forensic_data, page_width, page_height)
        c.showPage()

        # Finalize PDF
        c.save()

        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()

    def _add_redaction_header(self, c: canvas.Canvas, page_width: float, page_height: float) -> None:
        """Add redaction notice page at beginning of PDF."""
        from reportlab.lib import colors
        
        margin = 0.75 * inch
        x_start = margin
        y_start = page_height - margin

        # Warning box
        box_height = 5 * inch
        box_width = page_width - 2 * margin

        # Draw red warning box
        c.setFillColor(colors.HexColor("#FEE2E2"))
        c.setStrokeColor(colors.HexColor("#DC2626"))
        c.setLineWidth(2)
        c.rect(x_start, y_start - box_height, box_width, box_height, fill=True, stroke=True)

        # Redaction notice title
        c.setFont("Helvetica-Bold", 20)
        c.setFillColor(colors.HexColor("#DC2626"))
        c.drawString(x_start + 0.2*inch, y_start - 0.4*inch, "PII REDACTION APPLIED")

        # Redaction details
        current_y = y_start - 0.8*inch
        c.setFont("Helvetica-Bold", 12)
        c.setFillColor(colors.HexColor("#1F2937"))

        redaction_level = self.redaction_level.upper()
        c.drawString(x_start + 0.2*inch, current_y, f"Redaction Level: {redaction_level}")

        current_y -= 0.3*inch
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.HexColor("#4B5563"))

        level_descriptions = {
            "MINIMAL": "Email addresses redacted",
            "STANDARD": "Email addresses, user identifiers, and file paths redacted",
            "STRICT": "Email addresses, domains, IP addresses, and phone numbers redacted"
        }

        description = level_descriptions.get(redaction_level, "PII redacted")
        c.drawString(x_start + 0.2*inch, current_y, f"Redacted Information: {description}")

        current_y -= 0.3*inch
        c.drawString(x_start + 0.2*inch, current_y, "Technical information (hashes, ASNs) preserved for forensic integrity")

        current_y -= 0.4*inch
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor("#6B7280"))

        notice_text = (
            "This report has been processed to remove personally identifiable information (PII). "
            "Redacted values are marked with [REDACTED], [EMAIL], or similar placeholders. "
            "All forensic technical information has been preserved."
        )

        words = notice_text.split()
        line = ""
        for word in words:
            test_line = line + " " + word if line else word
            if c.stringWidth(test_line, "Helvetica", 9) > box_width - 0.4*inch:
                c.drawString(x_start + 0.2*inch, current_y, line)
                current_y -= 0.18*inch
                line = word
            else:
                line = test_line

        if line:
            c.drawString(x_start + 0.2*inch, current_y, line)

        current_y -= 0.4*inch

        # Disclaimer
        c.setFont("Helvetica-BoldOblique", 9)
        c.setFillColor(colors.HexColor("#DC2626"))
        c.drawString(x_start + 0.2*inch, current_y, "Do not distribute beyond authorized recipients.")

    def _build_page_1_risk_snapshot(self, c: canvas.Canvas, forensic_data: Dict[str, Any],
                                    page_width: float, page_height: float) -> None:
        """Build Page 1: Risk Snapshot."""
        margin = 0.75 * inch
        x_start = margin
        y_start = page_height - margin

        # Header
        c.setFont("Helvetica-Bold", 28)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, y_start - 0.4*inch, "Threat Snapshot")

        c.setFont("Helvetica", 12)
        c.setFillColor(VisualElements.COLOR_NEUTRAL)
        c.drawString(x_start, y_start - 0.65*inch, "Executive Summary of Risk Assessment")

        # Separator
        VisualElements.separator_line(c, x_start, y_start - 0.75*inch, page_width - 2*margin)

        # Risk gauge
        final_risk = forensic_data.get('final_risk', 0)
        risk_label = self.translator.threat_level(final_risk)
        gauge_x = x_start + (page_width - 2*margin) / 2
        gauge_y = y_start - 2*inch

        VisualElements.risk_gauge(c, gauge_x, gauge_y, final_risk, risk_label)

        # Verdict
        verdict = forensic_data.get('verdict', 'EVALUATED')
        c.setFont("Helvetica-Bold", 12)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, y_start - 4*inch, f"Verdict: {verdict}")

        # Top reasons
        why_flagged = forensic_data.get('why_flagged', [])
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, y_start - 4.4*inch, "Top Risk Factors:")

        current_y = y_start - 4.7*inch
        for i, reason in enumerate(why_flagged[:3]):
            reason_text = reason if isinstance(reason, str) else reason.get('reason', 'Unknown')
            explanation = self.translator.risk_factor_explanation(reason_text)

            c.setFont("Helvetica", 9)
            c.setFillColor(colors.HexColor("#1F2937"))
            c.drawString(x_start + 0.2*inch, current_y, f"• {explanation[:60]}")
            current_y -= 0.25*inch

        # Disclaimer
        disclaimer_y = 0.75*inch
        VisualElements.disclaimer_box(c, x_start, disclaimer_y + 0.3*inch, page_width - 2*margin, 0.6*inch,
                                      "This assessment is based on automated analysis. Manual review recommended for critical decisions.")

        # Footer
        VisualElements.page_footer(c, x_start, 0.4*inch, self.case_id, 1, 7)

    def _build_page_2_attack_story(self, c: canvas.Canvas, forensic_data: Dict[str, Any],
                                   page_width: float, page_height: float) -> None:
        """Build Page 2: Attack Story."""
        margin = 0.75 * inch
        x_start = margin
        y_start = page_height - margin

        # Header
        c.setFont("Helvetica-Bold", 24)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, y_start - 0.4*inch, "Attack Story")

        c.setFont("Helvetica", 12)
        c.setFillColor(VisualElements.COLOR_NEUTRAL)
        c.drawString(x_start, y_start - 0.65*inch, "Email Journey & Infrastructure Trace")

        # Separator
        VisualElements.separator_line(c, x_start, y_start - 0.75*inch, page_width - 2*margin)

        # Timeline
        relay_hops = forensic_data.get('relay_hops', [])
        current_y = y_start - 1.2*inch

        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, current_y, "Message Route Timeline:")
        current_y -= 0.3*inch

        for i, hop in enumerate(relay_hops):
            org = hop.get('organization', 'Unknown')
            ip = hop.get('ip', 'Not Resolved')
            is_origin = hop.get('is_origin', False)

            # Timeline node
            VisualElements.timeline_node(c, x_start + 0.15*inch, current_y, str(i+1),
                                        severity="critical" if is_origin else "info")

            # Hop details
            c.setFont("Helvetica-Bold", 9)
            c.setFillColor(colors.HexColor("#1F2937"))
            c.drawString(x_start + 0.4*inch, current_y + 0.05*inch, org)

            c.setFont("Helvetica", 8)
            c.setFillColor(colors.HexColor("#6B7280"))
            c.drawString(x_start + 0.4*inch, current_y - 0.15*inch, f"IP: {ip}")

            if is_origin:
                c.setFont("Helvetica", 8)
                c.setFillColor(VisualElements.COLOR_ALERT)
                c.drawString(x_start + 0.4*inch, current_y - 0.3*inch, "[ORIGIN]")

            current_y -= 0.5*inch

        # Infrastructure diagram
        origin_node = forensic_data.get('originating_node', {})
        VisualElements.infrastructure_flow(c, x_start, current_y - 0.5*inch, origin_node)

        # Disclaimer
        disclaimer_y = 0.75*inch
        VisualElements.disclaimer_box(c, x_start, disclaimer_y + 0.3*inch, page_width - 2*margin, 0.6*inch,
                                      "Geographic location indicates where infrastructure is hosted, not attacker location.")

        # Footer
        VisualElements.page_footer(c, x_start, 0.4*inch, self.case_id, 2, 7)

    def _build_page_3_authentication_forensics(self, c: canvas.Canvas, forensic_data: Dict[str, Any],
                                               page_width: float, page_height: float) -> None:
        """Build Page 3: Authentication Forensics."""
        margin = 0.75 * inch
        x_start = margin
        y_start = page_height - margin

        # Header
        c.setFont("Helvetica-Bold", 24)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, y_start - 0.4*inch, "Authentication Forensics")

        c.setFont("Helvetica", 12)
        c.setFillColor(VisualElements.COLOR_NEUTRAL)
        c.drawString(x_start, y_start - 0.65*inch, "Email Authentication Protocol Analysis")

        # Separator
        VisualElements.separator_line(c, x_start, y_start - 0.75*inch, page_width - 2*margin)

        auth = forensic_data.get('authentication', {})
        card_width = (page_width - 2*margin - 0.2*inch) / 2
        card_height = 2*inch
        current_y = y_start - 1.2*inch

        # SPF Card
        spf = auth.get('spf', {})
        spf_status = spf.get('status', 'None')
        spf_color = PageBuilder.get_auth_status_color(spf_status)

        VisualElements.forensic_card(c, x_start, current_y, card_width, card_height,
                                     "SPF Authentication",
                                     {
                                         'Status': self.translator.auth_status(spf_status),
                                         'Policy': spf.get('policy', 'Not found'),
                                         'Details': spf.get('details', '')
                                     },
                                     spf_color)

        # DKIM Card
        dkim = auth.get('dkim', {})
        dkim_status = dkim.get('status', 'None')
        dkim_color = PageBuilder.get_auth_status_color(dkim_status)

        VisualElements.forensic_card(c, x_start + card_width + 0.1*inch, current_y, card_width, card_height,
                                     "DKIM Cryptographic",
                                     {
                                         'Status': self.translator.auth_status(dkim_status),
                                         'Domain': dkim.get('domain', 'Not found'),
                                         'Details': dkim.get('details', '')
                                     },
                                     dkim_color)

        current_y -= card_height + 0.3*inch

        # DMARC Card (full width)
        dmarc = auth.get('dmarc', {})
        dmarc_status = dmarc.get('status', 'None')
        dmarc_color = PageBuilder.get_auth_status_color(dmarc_status)

        VisualElements.forensic_card(c, x_start, current_y, page_width - 2*margin, 1.5*inch,
                                     "DMARC Policy Alignment",
                                     {
                                         'Status': self.translator.auth_status(dmarc_status),
                                         'Domain': dmarc.get('domain', 'Not found'),
                                         'Policy': dmarc.get('policy', 'Not found'),
                                         'Details': dmarc.get('details', '')
                                     },
                                     dmarc_color)

        # Disclaimer
        disclaimer_y = 0.75*inch
        VisualElements.disclaimer_box(c, x_start, disclaimer_y + 0.3*inch, page_width - 2*margin, 0.6*inch,
                                      "Authentication failures indicate potential spoofing. Verify sender legitimacy.")

        # Footer
        VisualElements.page_footer(c, x_start, 0.4*inch, self.case_id, 3, 7)

    def _build_page_4_infrastructure_profile(self, c: canvas.Canvas, forensic_data: Dict[str, Any],
                                             page_width: float, page_height: float) -> None:
        """Build Page 4: Infrastructure Profile."""
        margin = 0.75 * inch
        x_start = margin
        y_start = page_height - margin

        # Header
        c.setFont("Helvetica-Bold", 24)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, y_start - 0.4*inch, "Infrastructure Intelligence")

        c.setFont("Helvetica", 12)
        c.setFillColor(VisualElements.COLOR_NEUTRAL)
        c.drawString(x_start, y_start - 0.65*inch, "Network & Threat Intelligence Analysis")

        # Separator
        VisualElements.separator_line(c, x_start, y_start - 0.75*inch, page_width - 2*margin)

        origin_node = forensic_data.get('originating_node', {})
        current_y = y_start - 1.2*inch

        # Key-value details
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, current_y, "Origin Infrastructure Details:")
        current_y -= 0.3*inch

        ti_details = {
            'IP Address': origin_node.get('ip', 'Not Resolved'),
            'Organization': origin_node.get('organization', 'Unknown'),
            'ASN': origin_node.get('asn', 'Not Found'),
            'Country': origin_node.get('country', 'Unknown'),
            'AbuseIPDB Confidence': f"{origin_node.get('abuse_confidence', 'N/A')}%",
            'Anonymization Type': self.translator.anonymization_type(origin_node.get('anonymization_type')),
        }

        for key, value in ti_details.items():
            c.setFont("Helvetica-Bold", 9)
            c.setFillColor(colors.HexColor("#1F2937"))
            c.drawString(x_start, current_y, f"{key}:")

            c.setFont("Helvetica", 9)
            c.setFillColor(colors.HexColor("#6B7280"))
            c.drawString(x_start + 2*inch, current_y, str(value)[:50])

            current_y -= 0.25*inch

        # Campaign correlation
        campaign = forensic_data.get('campaign', {})
        if campaign.get('id'):
            current_y -= 0.2*inch
            c.setFont("Helvetica-Bold", 10)
            c.setFillColor(VisualElements.COLOR_ACCENT)
            c.drawString(x_start, current_y, "Campaign Correlation:")
            current_y -= 0.25*inch

            c.setFont("Helvetica", 9)
            c.setFillColor(colors.HexColor("#6B7280"))
            c.drawString(x_start + 0.2*inch, current_y, f"Campaign: {campaign.get('name', 'Unknown')}")
            current_y -= 0.2*inch
            c.drawString(x_start + 0.2*inch, current_y, f"Confidence: {self.translator.campaign_attribution_label(campaign.get('attribution_confidence'))}")

        # Disclaimer
        disclaimer_y = 0.75*inch
        VisualElements.disclaimer_box(c, x_start, disclaimer_y + 0.3*inch, page_width - 2*margin, 0.6*inch,
                                      "Threat intelligence data may lag real-time events. Verify with current threat feeds.")

        # Footer
        VisualElements.page_footer(c, x_start, 0.4*inch, self.case_id, 4, 7)

    def _build_page_5_campaign_intelligence(self, c: canvas.Canvas, forensic_data: Dict[str, Any],
                                            page_width: float, page_height: float) -> None:
        """Build Page 5: Campaign Intelligence."""
        margin = 0.75 * inch
        x_start = margin
        y_start = page_height - margin

        # Header
        c.setFont("Helvetica-Bold", 24)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, y_start - 0.4*inch, "Campaign Intelligence")

        c.setFont("Helvetica", 12)
        c.setFillColor(VisualElements.COLOR_NEUTRAL)
        c.drawString(x_start, y_start - 0.65*inch, "Threat Group & Campaign Correlation")

        # Separator
        VisualElements.separator_line(c, x_start, y_start - 0.75*inch, page_width - 2*margin)

        campaign = forensic_data.get('campaign', {})

        if not campaign or not campaign.get('id'):
            c.setFont("Helvetica", 11)
            c.setFillColor(colors.HexColor("#6B7280"))
            c.drawString(x_start, y_start - 1.2*inch, "No campaign correlation identified for this email.")
        else:
            current_y = y_start - 1.2*inch

            # Campaign name
            c.setFont("Helvetica-Bold", 14)
            c.setFillColor(VisualElements.COLOR_ACCENT)
            c.drawString(x_start, current_y, campaign.get('name', 'Unknown Campaign'))
            current_y -= 0.4*inch

            # Campaign details
            c.setFont("Helvetica-Bold", 10)
            c.setFillColor(colors.HexColor("#1F2937"))
            c.drawString(x_start, current_y, "Campaign ID:")
            c.setFont("Helvetica", 10)
            c.drawString(x_start + 1.5*inch, current_y, campaign.get('id', 'Unknown'))
            current_y -= 0.25*inch

            c.setFont("Helvetica-Bold", 10)
            c.setFillColor(colors.HexColor("#1F2937"))
            c.drawString(x_start, current_y, "Confidence:")
            c.setFont("Helvetica", 10)
            c.drawString(x_start + 1.5*inch, current_y, self.translator.campaign_attribution_label(campaign.get('attribution_confidence')))
            current_y -= 0.25*inch

            # TTPs
            ttps = campaign.get('ttps', [])
            if ttps:
                current_y -= 0.2*inch
                c.setFont("Helvetica-Bold", 10)
                c.setFillColor(VisualElements.COLOR_ACCENT)
                c.drawString(x_start, current_y, "Attack Techniques:")
                current_y -= 0.25*inch

                for ttp in ttps[:5]:
                    c.setFont("Helvetica", 9)
                    c.setFillColor(colors.HexColor("#6B7280"))
                    c.drawString(x_start + 0.2*inch, current_y, f"• {ttp}")
                    current_y -= 0.2*inch

        # Disclaimer
        disclaimer_y = 0.75*inch
        VisualElements.disclaimer_box(c, x_start, disclaimer_y + 0.3*inch, page_width - 2*margin, 0.6*inch,
                                      "Campaign correlations are based on patterns and historical analysis. Manual verification recommended.")

        # Footer
        VisualElements.page_footer(c, x_start, 0.4*inch, self.case_id, 5, 7)

    def _build_page_6_evidence_integrity(self, c: canvas.Canvas, forensic_data: Dict[str, Any],
                                         page_width: float, page_height: float) -> None:
        """Build Page 6: Evidence & Chain of Custody."""
        margin = 0.75 * inch
        x_start = margin
        y_start = page_height - margin

        # Header
        c.setFont("Helvetica-Bold", 24)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, y_start - 0.4*inch, "Evidence & Chain of Custody")

        c.setFont("Helvetica", 12)
        c.setFillColor(VisualElements.COLOR_NEUTRAL)
        c.drawString(x_start, y_start - 0.65*inch, "Data Integrity & Forensic Preservation")

        # Separator
        VisualElements.separator_line(c, x_start, y_start - 0.75*inch, page_width - 2*margin)

        current_y = y_start - 1.2*inch

        # Data integrity
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, current_y, "Data Integrity Information:")
        current_y -= 0.3*inch

        email_meta = forensic_data.get('email_metadata', {})
        integrity_details = {
            'Message ID': email_meta.get('message_id', 'Not Available'),
            'Content Hash (SHA256)': email_meta.get('hash_sha256', 'Not Computed')[:32] + '...' if email_meta.get('hash_sha256') else 'Not Computed',
            'Analysis Timestamp': forensic_data.get('analysis_timestamp', 'Not Recorded'),
            'Forensic Tool': 'SpectraShield 2.0 Forensic Agent v2.0'
        }

        for key, value in integrity_details.items():
            c.setFont("Helvetica-Bold", 9)
            c.setFillColor(colors.HexColor("#1F2937"))
            c.drawString(x_start, current_y, f"{key}:")

            c.setFont("Helvetica", 9)
            c.setFillColor(colors.HexColor("#6B7280"))
            c.drawString(x_start + 2*inch, current_y, str(value)[:50])

            current_y -= 0.25*inch

        # Preservation statement
        current_y -= 0.2*inch
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, current_y, "Forensic Preservation Statement")
        current_y -= 0.25*inch

        preservation_text = (
            "This email and associated metadata have been preserved in their original state "
            "for forensic analysis. No modification, deletion, or alteration has been performed. "
            "Data is maintained in accordance with chain of custody protocols."
        )

        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor("#1F2937"))

        # Word wrap
        words = preservation_text.split()
        line = ""
        for word in words:
            test_line = line + " " + word if line else word
            if c.stringWidth(test_line, "Helvetica", 9) > page_width - 2*margin - 0.2*inch:
                c.drawString(x_start + 0.2*inch, current_y, line)
                current_y -= 0.2*inch
                line = word
            else:
                line = test_line

        if line:
            c.drawString(x_start + 0.2*inch, current_y, line)

        # Disclaimer
        disclaimer_y = 0.75*inch
        VisualElements.disclaimer_box(c, x_start, disclaimer_y + 0.3*inch, page_width - 2*margin, 0.6*inch,
                                      "Original email files remain in secure storage with full audit logging.")

        # Footer
        VisualElements.page_footer(c, x_start, 0.4*inch, self.case_id, 6, 7)

    def _build_page_7_threat_dna(self, c: canvas.Canvas, forensic_data: Dict[str, Any],
                                 page_width: float, page_height: float) -> None:
        """Build Page 7: Threat DNA & Conclusion."""
        margin = 0.75 * inch
        x_start = margin
        y_start = page_height - margin

        # Header
        c.setFont("Helvetica-Bold", 24)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, y_start - 0.4*inch, "Threat DNA & Conclusion")

        c.setFont("Helvetica", 12)
        c.setFillColor(VisualElements.COLOR_NEUTRAL)
        c.drawString(x_start, y_start - 0.65*inch, "Behavioral Fingerprint & Assessment Summary")

        # Separator
        VisualElements.separator_line(c, x_start, y_start - 0.75*inch, page_width - 2*margin)

        current_y = y_start - 1.2*inch

        # Executive summary
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, current_y, "Executive Summary")
        current_y -= 0.3*inch

        final_risk = forensic_data.get('final_risk', 0)
        verdict = forensic_data.get('verdict', 'EVALUATED')
        threat_cat = forensic_data.get('threat_category', 'Unknown')
        confidence = forensic_data.get('confidence')

        summary = (
            f"Overall threat assessment: {verdict} | "
            f"Risk Score: {int(final_risk)}/100 | "
            f"Category: {threat_cat}"
        )

        if confidence:
            summary += f" | Confidence: {int(confidence)}%"

        c.setFont("Helvetica", 10)
        c.setFillColor(colors.HexColor("#1F2937"))

        # Word wrap
        words = summary.split()
        line = ""
        for word in words:
            test_line = line + " " + word if line else word
            if c.stringWidth(test_line, "Helvetica", 10) > page_width - 2*margin - 0.2*inch:
                c.drawString(x_start, current_y, line)
                current_y -= 0.25*inch
                line = word
            else:
                line = test_line

        if line:
            c.drawString(x_start, current_y, line)

        current_y -= 0.4*inch

        # Recommended actions
        why_flagged = forensic_data.get('why_flagged', [])
        if why_flagged:
            c.setFont("Helvetica-Bold", 10)
            c.setFillColor(VisualElements.COLOR_ACCENT)
            c.drawString(x_start, current_y, "Recommended Actions:")
            current_y -= 0.25*inch

            for reason in why_flagged[:3]:
                reason_text = reason if isinstance(reason, str) else reason.get('reason', 'Unknown')
                recommendation = self.translator.create_recommendation(reason_text)

                if recommendation:
                    c.setFont("Helvetica", 9)
                    c.setFillColor(colors.HexColor("#1F2937"))
                    c.drawString(x_start + 0.2*inch, current_y, f"• {recommendation[:70]}")
                    current_y -= 0.2*inch

        current_y -= 0.2*inch

        # Report metadata
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(VisualElements.COLOR_ACCENT)
        c.drawString(x_start, current_y, "Report Information")
        current_y -= 0.25*inch

        metadata_details = {
            'Case ID': forensic_data.get('case_id', 'Not Available'),
            'Analysis Date': forensic_data.get('analysis_timestamp', 'Not Recorded'),
            'Report Version': 'SpectraShield 2.0',
            'Analyzer': 'Forensic Agent v2.0'
        }

        for key, value in metadata_details.items():
            c.setFont("Helvetica-Bold", 9)
            c.setFillColor(colors.HexColor("#1F2937"))
            c.drawString(x_start + 0.2*inch, current_y, f"{key}:")

            c.setFont("Helvetica", 9)
            c.setFillColor(colors.HexColor("#6B7280"))
            c.drawString(x_start + 1.8*inch, current_y, str(value))

            current_y -= 0.2*inch

        # Disclaimer
        disclaimer_y = 0.75*inch
        VisualElements.disclaimer_box(c, x_start, disclaimer_y + 0.3*inch, page_width - 2*margin, 0.6*inch,
                                      "Manual review recommended before taking action. This assessment is provided for informational purposes.")

        # Footer
        VisualElements.page_footer(c, x_start, 0.4*inch, self.case_id, 7, 7)

    def _generate_error_pdf(self, error_message: str) -> bytes:
        """
        Generate single-page error PDF.
        
        Args:
            error_message: Error message to display
            
        Returns:
            PDF bytes
        """
        pdf_buffer = io.BytesIO()
        c = canvas.Canvas(pdf_buffer, pagesize=letter)
        page_width, page_height = letter
        margin = 0.75 * inch

        # Title
        c.setFont("Helvetica-Bold", 24)
        c.setFillColor(VisualElements.COLOR_ALERT)
        c.drawString(margin, page_height - margin, "Report Generation Error")

        # Message
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.HexColor("#1F2937"))

        y_pos = page_height - margin - 0.5*inch
        words = error_message.split()
        line = ""

        for word in words:
            test_line = line + " " + word if line else word
            if c.stringWidth(test_line, "Helvetica", 11) > page_width - 2*margin:
                c.drawString(margin, y_pos, line)
                y_pos -= 0.25*inch
                line = word
            else:
                line = test_line

        if line:
            c.drawString(margin, y_pos, line)

        c.save()
        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()


# Import colors for use in this module
from reportlab.lib import colors
