"""
PageComponent: Abstract base and concrete implementations for PDF page sections.

Each page component encapsulates rendering logic for a specific section:
- RiskSnapshot (page 1)
- AttackStory (page 2)
- AuthenticationForensics (page 3)
- InfrastructureProfile (page 4)
- CampaignIntelligence (page 5)
- EvidenceIntegrity (page 6)
- ThreatDNAFingerprint (page 7)
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class ComponentRenderContext:
    """Context for rendering components."""
    page_builder: Any  # PageBuilder instance
    forensic_data: Dict[str, Any]
    translator: Any  # LanguageTranslator instance
    visual_renderer: Any  # VisualElements instance


class PageComponent(ABC):
    """
    Abstract base for PDF page components.
    
    Each component:
    - Extracts relevant data
    - Validates data consistency
    - Renders to page via PageBuilder
    - Handles missing data gracefully
    """

    def __init__(self, component_id: str):
        self.component_id = component_id
        self.warnings = []

    @abstractmethod
    def render(self, context: ComponentRenderContext) -> None:
        """Render component to PDF page."""
        pass

    def _handle_missing_field(self, field_path: str) -> None:
        """Record missing field as warning."""
        self.warnings.append({
            'type': 'missing_field',
            'field': field_path,
            'message': f"Field not found: {field_path}"
        })


class RiskSnapshot(PageComponent):
    """
    Page 1: Risk Snapshot
    
    Displays:
    - Large risk gauge with score and label
    - Evidence cards (top 3 risk factors)
    - Verdict statement
    - Recommended actions
    """

    def __init__(self):
        super().__init__("risk_snapshot")

    def render(self, context: ComponentRenderContext) -> None:
        """Render risk snapshot page."""
        pb = context.page_builder
        fd = context.forensic_data
        trans = context.translator

        # Header
        pb.add_header("Threat Snapshot", "Executive Summary of Risk Assessment")

        # Risk gauge
        final_risk = fd.get('final_risk', 0)
        risk_label = trans.threat_level(final_risk)
        pb.add_risk_gauge(final_risk, risk_label)

        pb.add_spacer(0.3)

        # Verdict box
        verdict = fd.get('verdict', 'EVALUATED')
        pb.add_paragraph(
            f"<b>Verdict:</b> {verdict}",
            style='emphasis'
        )

        pb.add_spacer(0.2)

        # Top reasons (evidence cards)
        why_flagged = fd.get('why_flagged', [])
        evidence_items = []

        for i, reason in enumerate(why_flagged[:3]):
            reason_text = reason if isinstance(reason, str) else reason.get('reason', 'Unknown')
            evidence_items.append({
                'title': f"Risk Factor {i+1}",
                'value': trans.risk_factor_explanation(reason_text),
                'icon': '⚠',
                'color': '#DC2626'
            })

        if evidence_items:
            pb.add_evidence_cards(evidence_items, columns=3)

        pb.add_spacer(0.3)

        # Threat category
        threat_cat = fd.get('threat_category', 'Unknown')
        pb.add_paragraph(
            f"<b>Threat Category:</b> {threat_cat}",
            style='normal'
        )

        pb.add_spacer(0.3)

        # Confidence
        confidence = fd.get('confidence')
        if confidence is not None:
            conf_label = trans.confidence_label(confidence)
            pb.add_confidence_meter("Analysis Confidence", confidence)

        pb.add_spacer(0.5)

        # Disclaimer
        pb.add_disclaimer(
            "This assessment is based on automated analysis. "
            "Manual review recommended for critical decisions. "
            "See Evidence page for data sources and confidence intervals."
        )


class AttackStory(PageComponent):
    """
    Page 2: Attack Story
    
    Displays:
    - Chronological message route timeline
    - Relay hops with IPs and organizations
    - Originating infrastructure highlight
    - Geographic trace visualization
    """

    def __init__(self):
        super().__init__("attack_story")

    def render(self, context: ComponentRenderContext) -> None:
        """Render attack story page."""
        pb = context.page_builder
        fd = context.forensic_data
        trans = context.translator

        # Header
        pb.add_header("Attack Story", "Email Journey & Infrastructure Trace")

        # Timeline events
        events = []
        relay_hops = fd.get('relay_hops', [])

        for i, hop in enumerate(relay_hops):
            timestamp = hop.get('timestamp')
            ip = hop.get('ip', 'Not Resolved')
            org = hop.get('organization', 'Unknown')
            is_origin = hop.get('is_origin', False)

            severity = "critical" if is_origin else "info"

            events.append({
                'timestamp': timestamp or f"Hop {i+1}",
                'label': f"Relay: {org}",
                'description': f"IP: {ip}",
                'severity': severity
            })

        if events:
            pb.add_timeline(events, layout="vertical")

        pb.add_spacer(0.3)

        # Origin infrastructure highlight
        origin_node = fd.get('originating_node', {})
        origin_ip = origin_node.get('ip')

        if origin_ip and origin_ip not in ["0.0.0.0", "127.0.0.1"]:
            pb.add_section_header("Originating Infrastructure")
            pb.add_key_value_section({
                'IP Address': origin_ip,
                'Organization': origin_node.get('organization', 'Unknown'),
                'Location': origin_node.get('city') + ", " + origin_node.get('country')
                if origin_node.get('city') and origin_node.get('country')
                else 'Not Resolved',
                'Anonymization': trans.anonymization_type(origin_node.get('anonymization_type'))
            })
        else:
            pb.add_section_header("Originating Infrastructure")
            pb.add_paragraph(
                "No publicly routable originating IP was identified. "
                "Infrastructure cannot be traced.",
                style='warning'
            )

        pb.add_spacer(0.2)

        # Geolocation disclaimer
        pb.add_disclaimer(
            "Geographic location indicates where infrastructure is hosted, "
            "not where attacker is physically located. VPN/proxy services may mask true origin."
        )


class AuthenticationForensics(PageComponent):
    """
    Page 3: Authentication Forensics
    
    Displays:
    - Large forensic cards for SPF, DKIM, DMARC
    - Detailed findings per protocol
    - Pass/fail indicators
    - Recommendations
    """

    def __init__(self):
        super().__init__("authentication_forensics")

    def render(self, context: ComponentRenderContext) -> None:
        """Render authentication forensics page."""
        pb = context.page_builder
        fd = context.forensic_data
        trans = context.translator

        # Header
        pb.add_header("Authentication Forensics", "Email Authentication Protocol Analysis")

        auth = fd.get('authentication', {})

        # SPF Card
        spf = auth.get('spf', {})
        spf_status = spf.get('status', 'None')
        pb.add_forensic_card(
            title=trans.header_field_name("SPF"),
            findings={
                'Status': trans.auth_status(spf_status),
                'Policy': spf.get('policy', 'Not found'),
                'Authorized IPs': spf.get('authorized_ips', 'None'),
                'Details': spf.get('details', 'No additional details')
            },
            background_color=trans.get_auth_status_color(spf_status)
        )

        pb.add_spacer(0.3)

        # DKIM Card
        dkim = auth.get('dkim', {})
        dkim_status = dkim.get('status', 'None')
        pb.add_forensic_card(
            title=trans.header_field_name("DKIM"),
            findings={
                'Status': trans.auth_status(dkim_status),
                'Domain': dkim.get('domain', 'Not found'),
                'Selector': dkim.get('selector', 'Not found'),
                'Public Key': dkim.get('public_key_id', 'Not found'),
                'Details': dkim.get('details', 'No additional details')
            },
            background_color=trans.get_auth_status_color(dkim_status)
        )

        pb.add_spacer(0.3)

        # DMARC Card
        dmarc = auth.get('dmarc', {})
        dmarc_status = dmarc.get('status', 'None')
        pb.add_forensic_card(
            title=trans.header_field_name("DMARC"),
            findings={
                'Status': trans.auth_status(dmarc_status),
                'Policy': dmarc.get('policy', 'Not found'),
                'Domain': dmarc.get('domain', 'Not found'),
                'Alignment': dmarc.get('alignment', 'Not found'),
                'Details': dmarc.get('details', 'No additional details')
            },
            background_color=trans.get_auth_status_color(dmarc_status)
        )

        pb.add_spacer(0.5)

        # Recommendations
        pb.add_section_header("Authentication Recommendations")
        pb.add_paragraph(
            "If authentication failures are detected, verify sender domain legitimacy. "
            "Spoofed emails may lack cryptographic signatures. "
            "Consider implementing strict DMARC policies.",
            style='normal'
        )


class InfrastructureProfile(PageComponent):
    """
    Page 4: Infrastructure Intelligence
    
    Displays:
    - Infrastructure diagram/flow
    - ASN and network details
    - Threat intelligence (AbuseIPDB)
    - Campaign infrastructure correlation
    """

    def __init__(self):
        super().__init__("infrastructure_profile")

    def render(self, context: ComponentRenderContext) -> None:
        """Render infrastructure page."""
        pb = context.page_builder
        fd = context.forensic_data
        trans = context.translator

        # Header
        pb.add_header("Infrastructure Intelligence", "Network & Threat Intelligence Analysis")

        origin_node = fd.get('originating_node', {})

        # Infrastructure diagram
        pb.add_infrastructure_diagram(origin_node)

        pb.add_spacer(0.3)

        # Threat intel details
        pb.add_section_header("Threat Intelligence Results")

        ti_results = {
            'IP Address': origin_node.get('ip', 'Not Resolved'),
            'ASN': origin_node.get('asn', 'Not Found'),
            'Network Organization': origin_node.get('organization', 'Unknown'),
            'AbuseIPDB Confidence': f"{origin_node.get('abuse_confidence', 'N/A')}%",
            'Anonymization Type': trans.anonymization_type(origin_node.get('anonymization_type')),
            'VPN Provider': origin_node.get('vpn_provider', 'Not Detected')
        }

        pb.add_key_value_section(ti_results)

        pb.add_spacer(0.3)

        # Campaign correlation
        campaign = fd.get('campaign', {})
        if campaign.get('id'):
            pb.add_section_header("Campaign Infrastructure Correlation")
            pb.add_paragraph(
                f"<b>Campaign:</b> {campaign.get('name', 'Unknown')}",
                style='emphasis'
            )
            pb.add_paragraph(
                f"<b>Confidence:</b> {trans.campaign_attribution_label(campaign.get('attribution_confidence'))}",
                style='normal'
            )

        pb.add_spacer(0.2)

        pb.add_disclaimer(
            "Threat intelligence data is sourced from AbuseIPDB and campaign correlation databases. "
            "Data may lag real-time events by hours or days."
        )


class CampaignIntelligence(PageComponent):
    """
    Page 5: Campaign Threat Intelligence
    
    Displays:
    - Known campaign indicators
    - Historical correlations
    - TTPs (Tactics, Techniques, Procedures)
    - Threat group attribution
    """

    def __init__(self):
        super().__init__("campaign_intelligence")

    def render(self, context: ComponentRenderContext) -> None:
        """Render campaign intelligence page."""
        pb = context.page_builder
        fd = context.forensic_data
        trans = context.translator

        # Header
        pb.add_header("Campaign Intelligence", "Threat Group & Campaign Correlation")

        campaign = fd.get('campaign', {})

        if not campaign or not campaign.get('id'):
            pb.add_paragraph(
                "No campaign correlation identified for this email.",
                style='normal'
            )
            return

        # Campaign details
        pb.add_section_header(campaign.get('name', 'Unknown Campaign'))

        pb.add_key_value_section({
            'Campaign ID': campaign.get('id', 'Unknown'),
            'Confidence Level': trans.campaign_attribution_label(campaign.get('attribution_confidence')),
            'Historical Incidents': campaign.get('historical_count', '0'),
            'Active Since': campaign.get('first_seen', 'Unknown')
        })

        pb.add_spacer(0.3)

        # TTPs
        ttps = campaign.get('ttps', [])
        if ttps:
            pb.add_section_header("Attack Techniques (TTPs)")
            for ttp in ttps[:5]:  # Limit to 5
                pb.add_paragraph(f"• {ttp}", style='normal')

        pb.add_spacer(0.3)

        # Related indicators
        indicators = campaign.get('related_indicators', [])
        if indicators:
            pb.add_section_header("Related Indicators")
            for ind in indicators[:5]:  # Limit to 5
                pb.add_paragraph(f"• {ind}", style='mono')

        pb.add_spacer(0.2)

        pb.add_disclaimer(
            "Campaign correlations are based on infrastructure, tactics, and historical patterns. "
            "Confidence levels may vary. Manual verification recommended."
        )


class EvidenceIntegrity(PageComponent):
    """
    Page 6: Evidence & Chain of Custody
    
    Displays:
    - Evidence records with timestamps
    - Data integrity hashes
    - Forensic preservation notes
    - Audit trail
    """

    def __init__(self):
        super().__init__("evidence_integrity")

    def render(self, context: ComponentRenderContext) -> None:
        """Render evidence integrity page."""
        pb = context.page_builder
        fd = context.forensic_data

        # Header
        pb.add_header("Evidence & Chain of Custody", "Data Integrity & Forensic Preservation")

        # Evidence records
        evidence_records = fd.get('evidence', [])

        if evidence_records:
            pb.add_evidence_chain(evidence_records)

        pb.add_spacer(0.3)

        # Hash/integrity info
        email_meta = fd.get('email_metadata', {})
        pb.add_section_header("Data Integrity")
        pb.add_key_value_section({
            'Message ID': email_meta.get('message_id', 'Not Available'),
            'Content Hash': email_meta.get('hash_sha256', 'Not Computed'),
            'Analysis Timestamp': fd.get('analysis_timestamp', 'Not Recorded'),
            'Forensic Tool': 'SpectraShield 2.0 Forensic Agent'
        })

        pb.add_spacer(0.3)

        # Preservation statement
        pb.add_section_header("Forensic Preservation Statement")
        pb.add_paragraph(
            "This email and associated metadata have been preserved in their original state "
            "for forensic analysis. No modification, deletion, or alteration has been performed. "
            "Data is maintained in accordance with chain of custody protocols.",
            style='disclaimer'
        )

        pb.add_spacer(0.2)

        pb.add_disclaimer(
            "This report documents the forensic analysis performed. "
            "Original email files remain in secure storage with full audit logging."
        )


class ThreatDNAFingerprint(PageComponent):
    """
    Page 7: Threat DNA & Conclusion
    
    Displays:
    - Threat DNA visualization (behavioral fingerprint)
    - Confidence intervals
    - Executive summary
    - Next recommended actions
    - Report metadata
    """

    def __init__(self):
        super().__init__("threat_dna_fingerprint")

    def render(self, context: ComponentRenderContext) -> None:
        """Render threat DNA page."""
        pb = context.page_builder
        fd = context.forensic_data
        trans = context.translator

        # Header
        pb.add_header("Threat DNA & Conclusion", "Behavioral Fingerprint & Assessment Summary")

        # Threat DNA visualization
        threat_dna = fd.get('threat_dna', {})
        pb.add_threat_dna_profile(threat_dna)

        pb.add_spacer(0.3)

        # Executive summary
        pb.add_section_header("Executive Summary")
        final_risk = fd.get('final_risk', 0)
        verdict = fd.get('verdict', 'EVALUATED')
        threat_cat = fd.get('threat_category', 'Unknown')

        pb.add_paragraph(
            f"Overall threat assessment: <b>{verdict}</b> | "
            f"Risk Score: <b>{final_risk}/100</b> | "
            f"Category: <b>{threat_cat}</b>",
            style='emphasis'
        )

        pb.add_spacer(0.2)

        # Recommendations
        why_flagged = fd.get('why_flagged', [])
        if why_flagged:
            pb.add_section_header("Recommended Actions")
            for reason in why_flagged[:3]:
                reason_text = reason if isinstance(reason, str) else reason.get('reason', 'Unknown')
                recommendation = trans.create_recommendation(reason_text)
                if recommendation:
                    pb.add_paragraph(f"• {recommendation}", style='normal')

        pb.add_spacer(0.3)

        # Report metadata
        pb.add_section_header("Report Information")
        pb.add_key_value_section({
            'Case ID': fd.get('case_id', 'Not Available'),
            'Analysis Date': fd.get('analysis_timestamp', 'Not Recorded'),
            'Report Version': 'SpectraShield 2.0',
            'Analyzer': 'Forensic Agent v2.0'
        })

        pb.add_spacer(0.2)

        pb.add_disclaimer(
            "This forensic assessment is provided for informational purposes. "
            "Manual review and expert judgment recommended before taking action. "
            "See Evidence page for detailed methodology and data sources."
        )
