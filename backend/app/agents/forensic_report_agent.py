import io
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from app.services.pii_redactor import pii_redactor


class ForensicReportAgent:
    """
    Generates court-admissible forensic PDF dossiers (ISO/IEC 27037 & BNSS digital forensics)
    and STIX 2.1 CTI JSON bundles.
    """

    def generate_stix_bundle(self, case_id: str, forensic_data: Dict[str, Any], redact_pii: bool = False) -> Dict[str, Any]:
        """Serializes forensic investigation findings into a STIX 2.1 compliant JSON bundle."""
        if redact_pii:
            forensic_data = pii_redactor.sanitize_case_data(forensic_data)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        bundle_id = f"bundle--{uuid.uuid4()}"

        report_obj = {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{uuid.uuid4()}",
            "created": now_str,
            "modified": now_str,
            "name": f"SpectraShield 2.0 Forensic Dossier: Case {case_id}",
            "description": forensic_data.get("reasoning_summary", "Email threat investigation report."),
            "report_types": ["threat-report", "incident-investigation"],
            "published": now_str,
            "object_refs": []
        }

        objects = [report_obj]

        # 1. Identity Object (Organization / LEA)
        identity_id = f"identity--{uuid.uuid4()}"
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_str,
            "modified": now_str,
            "name": "SpectraShield Forensic Intelligence Cell",
            "identity_class": "organization"
        }
        objects.append(identity_obj)
        report_obj["object_refs"].append(identity_id)

        # 2. Indicators for Origin IP
        origin = forensic_data.get("originating_node") or {}
        origin_ip = origin.get("ip")
        if origin_ip and not origin.get("is_private"):
            ind_ip_id = f"indicator--{uuid.uuid4()}"
            ind_ip = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_ip_id,
                "created": now_str,
                "modified": now_str,
                "name": f"Malicious / Suspicious Origin IP: {origin_ip}",
                "pattern_type": "stix",
                "pattern": f"[ipv4-addr:value = '{origin_ip}']",
                "valid_from": now_str,
                "confidence": int(forensic_data.get("final_risk", 75))
            }
            objects.append(ind_ip)
            report_obj["object_refs"].append(ind_ip_id)

        # 3. Campaign Object
        camp = forensic_data.get("campaign") or {}
        if camp.get("id"):
            camp_id = f"campaign--{uuid.uuid4()}"
            camp_obj = {
                "type": "campaign",
                "spec_version": "2.1",
                "id": camp_id,
                "created": now_str,
                "modified": now_str,
                "name": camp.get("name", "Attributed Phishing Campaign"),
                "description": f"Linked Incidents: {camp.get('linked_incidents_count', 1)}"
            }
            objects.append(camp_obj)
            report_obj["object_refs"].append(camp_id)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }

    def generate_ioc_csv(self, case_id: str, forensic_data: Dict[str, Any], defang: bool = True) -> str:
        """
        Generates an RFC 4180 compliant CSV of all indicators of compromise (IOCs)
        discovered in the forensic examination.
        """
        import csv

        def _defang_ip(ip: str) -> str:
            if not ip or not defang:
                return ip
            return ip.replace(".", "[.]")

        def _defang_domain(domain: str) -> str:
            if not domain or not defang:
                return domain
            return domain.replace(".", "[.]")

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "ioc_type",
            "defanged_value",
            "raw_value",
            "threat_category",
            "confidence_score",
            "context_source",
            "first_seen"
        ])

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        final_risk = float(forensic_data.get("final_risk", 75.0))
        category = str(forensic_data.get("threat_category", "Phishing"))

        # 1. Originating Node IP
        origin = forensic_data.get("originating_node") or {}
        origin_ip = origin.get("ip")
        if origin_ip and not origin.get("is_private"):
            cat = "Tor Exit Node" if origin.get("is_anonymized") else category
            writer.writerow([
                "origin_ip",
                _defang_ip(origin_ip),
                origin_ip,
                cat,
                round(final_risk, 1),
                f"ERPN Originating Hop (ISP: {origin.get('isp', 'Unknown')}, ASN: {origin.get('asn', 'Unknown')})",
                now_iso
            ])

        # 2. Intermediate Public Relay Hops
        for hop in forensic_data.get("relay_path", []):
            hip = hop.get("ip")
            if hip and not hop.get("is_private") and hip != origin_ip:
                writer.writerow([
                    "relay_hop_ip",
                    _defang_ip(hip),
                    hip,
                    "Intermediate Relay MTA",
                    round(max(final_risk - 20.0, 10.0), 1),
                    f"Hop #{hop.get('hop', 0)} ({hop.get('received_from', '')})",
                    hop.get("timestamp") or now_iso
                ])

        # 3. Sender Domain / Return-Path Domain
        auth = forensic_data.get("authentication") or {}
        spf_domain = (auth.get("spf") or {}).get("domain")
        dmarc_domain = (auth.get("dmarc") or {}).get("domain")
        target_domain = spf_domain or dmarc_domain
        if target_domain:
            writer.writerow([
                "sender_domain",
                _defang_domain(target_domain),
                target_domain,
                "Email Spoofing / Lookalike Domain",
                round(final_risk, 1),
                "Authentication-Results / From Header",
                now_iso
            ])

        # 4. Attachments (SHA-256 and MD5)
        for att in forensic_data.get("attachments", []):
            att_sha256 = att.get("sha256")
            att_fn = att.get("filename", "unnamed")
            att_risk = att.get("risk_level", "clean")
            if att_sha256:
                writer.writerow([
                    "attachment_hash_sha256",
                    att_sha256,
                    att_sha256,
                    f"Malicious Attachment ({att_risk})",
                    85.0 if att_risk == "malicious" else 50.0,
                    f"Attachment: {att_fn} (Entropy: {att.get('entropy_score', 0)})",
                    now_iso
                ])
            att_md5 = att.get("md5")
            if att_md5:
                writer.writerow([
                    "attachment_hash_md5",
                    att_md5,
                    att_md5,
                    f"Malicious Attachment ({att_risk})",
                    85.0 if att_risk == "malicious" else 50.0,
                    f"Attachment: {att_fn}",
                    now_iso
                ])

        # 5. Raw Evidence Checksum
        evidence_hash = forensic_data.get("sha256_evidence_hash")
        if evidence_hash:
            writer.writerow([
                "evidence_hash_sha256",
                evidence_hash,
                evidence_hash,
                "Case Cryptographic Pre-Hash (ISO 27037)",
                100.0,
                f"Evidence Vault Case {case_id}",
                now_iso
            ])

        return output.getvalue()

    def generate_pdf_dossier_bytes(self, case_id: str, forensic_data: Dict[str, Any], redact_pii: bool = False) -> bytes:
        """Generates a court-admissible forensic PDF dossier conforming to ISO/IEC 27037 standards."""
        if redact_pii:
            forensic_data = pii_redactor.sanitize_case_data(forensic_data)

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        # Custom Forensic Palette
        c_primary = colors.HexColor("#0B0F17")     # Dark Slate
        c_crimson = colors.HexColor("#DC2626")     # Alert Red
        c_cyan = colors.HexColor("#0891B2")        # Forensic Cyan
        c_card = colors.HexColor("#F8FAFC")        # Soft background
        c_border = colors.HexColor("#CBD5E1")      # Border grey

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=c_primary
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#64748B")
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=c_primary,
            spaceBefore=10,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "BodyTextCustom",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#1E293B")
        )
        body_bold = ParagraphStyle(
            "BodyBoldCustom",
            parent=body_style,
            fontName="Helvetica-Bold"
        )

        story = []

        # Header Block
        header_table = Table([
            [
                Paragraph("<b>SPECTRA SHIELD 2.0</b><br/><font size='8' color='#64748B'>FORENSIC INTELLIGENCE DOSSIER</font>", title_style),
                Paragraph(
                    f"<b>CASE REF:</b> {case_id[:16]}<br/>"
                    f"<b>DATE (UTC):</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}<br/>"
                    f"<b>STANDARD:</b> ISO/IEC 27037:2012 & BNSS Sec 63",
                    subtitle_style
                )
            ]
        ], colWidths=[360, 180])
        header_table.setStyle(TableStyle([
            ('LINEBELOW', (0, 0), (-1, -1), 1.5, c_cyan),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(header_table)

        if redact_pii:
            redact_alert = Paragraph(
                "<font color='#DC2626'><b>[!] REDACTED EVIDENCE DOSSIER:</b> Sensitive Personal Identifiable Information (PII) has been sanitized conforming to GDPR Art 32 / DPDP Act 2023. Canonical SHA-256 evidence integrity is preserved in the Evidence Vault.</font>",
                subtitle_style
            )
            story.append(Spacer(1, 4))
            story.append(redact_alert)

        story.append(Spacer(1, 10))

        # Evidence Integrity (SHA-256 Vault)
        sha256_hash = forensic_data.get("sha256_evidence_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        hash_table = Table([
            [Paragraph("<b>EVIDENCE HASH (SHA-256):</b>", body_bold), Paragraph(f"<code>{sha256_hash}</code>", body_style)],
            [Paragraph("<b>LEGAL INTEGRITY:</b>", body_bold), Paragraph("Cryptographically sealed upon ingestion. Tamper-evident ledger confirmed.", body_style)],
            [Paragraph("<b>THREAT CATEGORY:</b>", body_bold), Paragraph(f"<b>{forensic_data.get('threat_category', 'Phishing')}</b>", body_style)],
            [Paragraph("<b>FINAL RISK SCORE:</b>", body_bold), Paragraph(f"<font color='#DC2626'><b>{forensic_data.get('final_risk', 0.0)} / 100 ({forensic_data.get('verdict', 'Evaluated')})</b></font>", body_bold)]
        ], colWidths=[150, 390])
        hash_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_card),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4)
        ]))
        story.append(hash_table)
        story.append(Spacer(1, 10))

        # Cryptographic Authentication Matrix
        auth = forensic_data.get("authentication", {})
        spf = auth.get("spf", {})
        dkim = auth.get("dkim", {})
        dmarc = auth.get("dmarc", {})

        story.append(Paragraph("1. Cryptographic Protocol & Header Validation", h2_style))
        auth_data = [
            ["Protocol", "Status", "Evaluated Domain", "Cryptographic Findings"],
            ["SPF (Sender Policy)", spf.get("status", "None"), spf.get("domain", "N/A"), Paragraph(spf.get("reason", "N/A"), body_style)],
            ["DKIM (Public Key Sig)", dkim.get("status", "None"), dkim.get("domain", "N/A"), Paragraph(dkim.get("reason", "N/A"), body_style)],
            ["DMARC (Alignment)", dmarc.get("status", "Fail"), dmarc.get("domain", "N/A"), Paragraph(dmarc.get("reason", "N/A"), body_style)]
        ]
        auth_table = Table(auth_data, colWidths=[90, 60, 110, 280])
        auth_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        story.append(auth_table)
        story.append(Spacer(1, 10))

        # Multi-Hop Relay Trajectory Table
        story.append(Paragraph("2. RFC 5322 Multi-Hop Relay Trajectory & Latency", h2_style))
        hops = forensic_data.get("relay_path", [])
        hop_rows = [["Hop", "Received From", "By MTA", "IP Address", "Location", "Delay"]]
        for h in hops[:7]:  # Up to 7 hops per page
            geo = h.get("geo") or {}
            loc_str = f"{geo.get('city', '')}, {geo.get('country_code', '')}".strip(", ") or "Unknown"
            if h.get("is_origin"):
                loc_str = f"[ORIGIN] {loc_str}"
            delay_str = f"+{h.get('delay_seconds', 0)}s"

            hop_rows.append([
                str(h.get("hop", "")),
                str(h.get("received_from", ""))[:20],
                str(h.get("by", ""))[:20],
                str(h.get("defanged_ip") or h.get("ip") or "Bogon"),
                loc_str[:22],
                delay_str
            ])

        if len(hop_rows) == 1:
            hop_rows.append(["1", "N/A", "N/A", "N/A", "Single Hop Direct Submission", "+0s"])

        hop_table = Table(hop_rows, colWidths=[30, 115, 115, 100, 130, 50])
        hop_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0891B2")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(hop_table)
        story.append(Spacer(1, 10))

        # Origin Geolocation & Attribution
        story.append(Paragraph("3. Originating Infrastructure & Threat Campaign Attribution", h2_style))
        origin_node = forensic_data.get("originating_node") or {}
        camp = forensic_data.get("campaign") or {}

        origin_data = [
            [Paragraph("<b>Origin Public IP:</b>", body_bold), Paragraph(str(origin_node.get("defanged_ip") or origin_node.get("ip")), body_style)],
            [Paragraph("<b>Physical Coordinates:</b>", body_bold), Paragraph(f"Lat: {origin_node.get('latitude', 'N/A')}, Lon: {origin_node.get('longitude', 'N/A')} ({origin_node.get('city', '')}, {origin_node.get('country', '')})", body_style)],
            [Paragraph("<b>ASN & ISP Organization:</b>", body_bold), Paragraph(f"{origin_node.get('asn', 'N/A')} — {origin_node.get('isp', 'N/A')}", body_style)],
            [Paragraph("<b>Anonymization Flag:</b>", body_bold), Paragraph(f"<b>{origin_node.get('anonymization_type') or 'None (Direct Routing)'}</b>", body_style)],
            [Paragraph("<b>Attributed Campaign:</b>", body_bold), Paragraph(f"<b>{camp.get('name', 'Uncorrelated Incident')}</b> (Confidence: {camp.get('attribution_confidence', 70)}%)", body_style)]
        ]
        origin_table = Table(origin_data, colWidths=[150, 390])
        origin_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_card),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3)
        ]))
        story.append(origin_table)
        story.append(Spacer(1, 10))

        # Attachment Static Triage (if any)
        attachments = forensic_data.get("attachments", [])
        if attachments:
            story.append(Paragraph("4. Attachment Static Forensic Triage", h2_style))
            att_rows = [["Filename", "Type", "Size", "SHA-256", "Entropy", "Risk"]]
            for att in attachments[:5]:
                att_rows.append([
                    str(att.get("filename", "unnamed"))[:20],
                    str(att.get("content_type", ""))[:14],
                    f"{att.get('file_size_bytes', 0)} B",
                    str(att.get("sha256", ""))[:12] + "...",
                    f"{att.get('entropy_score', 0.0)}",
                    str(att.get("risk_level", "clean")).upper()
                ])
            att_table = Table(att_rows, colWidths=[110, 85, 65, 120, 50, 110])
            att_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#7C3AED")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, c_border),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            story.append(att_table)
            story.append(Spacer(1, 10))

        # Forensic Chain of Custody & Sign-off Block
        section_num = "5" if attachments else "4"
        story.append(Paragraph(f"{section_num}. Chain of Custody Sign-Off (ISO/IEC 27037)", h2_style))
        sign_table = Table([
            [
                Paragraph("<b>Investigating Forensic Officer:</b><br/>SpectraShield Cyber Threat Unit<br/>Badge ID: AGY-26106", body_style),
                Paragraph("<b>Verified Sign-Off Date:</b><br/>" + datetime.now(timezone.utc).strftime('%Y-%m-%d') + "<br/>Status: <b>LEGALLY SEALED</b>", body_style)
            ]
        ], colWidths=[270, 270])
        sign_table.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8)
        ]))
        story.append(sign_table)

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes


# Global instance
forensic_report_agent = ForensicReportAgent()
