"""
DataTransformer: Maps backend forensic data to PDF-friendly data models.

Extracts relevant sections from the backend analysis result and transforms them
into structured data that pages/components can consume without modification.
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class EvidenceCard:
    """Compact evidence summary for display."""
    title: str
    value: str
    detail: Optional[str] = None
    color: str = "#0891B2"
    status: Optional[str] = None  # "PASS", "FAIL", "WARNING"


@dataclass
class ThreatSnapshot:
    """Page 1 - Threat Snapshot data."""
    verdict: str  # e.g., "HIGH RISK"
    risk_score: float  # 0-100
    primary_threat: str  # e.g., "Business Email Compromise"
    confidence: str  # e.g., "89.5%"
    top_reasons: List[str]  # Top 3 findings
    evidence_cards: List[EvidenceCard]


@dataclass
class RelayHop:
    """Single hop in message relay path."""
    hop_number: int
    received_from: str
    by_mta: str
    ip: str
    defanged_ip: str
    is_private: bool
    is_origin: bool
    location: str  # "City, Country"
    timestamp: Optional[str]
    delay_seconds: int
    status: str  # "TRUSTED", "UNKNOWN", "SUSPICIOUS", "ORIGIN"


@dataclass
class AttackStory:
    """Page 2 - Attack Story data."""
    hops: List[RelayHop]
    origin_ip: Optional[str]
    origin_location: str
    hop_count: int
    interpretation: str  # Natural language explanation


@dataclass
class AuthenticationFindings:
    """Page 3 - Authentication Findings."""
    spf_status: str  # "PASS", "FAIL", "NEUTRAL", "NONE"
    spf_domain: str
    spf_expected: str
    spf_observed: str
    spf_impact: str

    dkim_status: str
    dkim_domain: str
    dkim_expected: str
    dkim_observed: str
    dkim_impact: str

    dmarc_status: str
    dmarc_domain: str
    dmarc_expected: str
    dmarc_observed: str
    dmarc_impact: str

    overall_trust_percentage: float  # 0-100


@dataclass
class InfrastructureProfile:
    """Page 4 - Infrastructure Intelligence."""
    origin_ip: str
    origin_ip_defanged: str
    is_ip_resolved: bool  # False if 0.0.0.0 or NOT RESOLVED
    geolocation: str
    asn: str
    network_name: str
    anonymization_type: Optional[str]  # "TOR", "VPN", "PROXY", etc.
    is_tor: bool
    is_vpn: bool
    disclaimer: str  # Always include


@dataclass
class CampaignSignal:
    """Page 5 - Campaign Signal."""
    name: str
    confidence_percentage: float  # 0-100
    confidence_label: str  # "LOW", "POSSIBLE", "PROBABLE", "HIGH"
    evidence_sources: List[str]
    linked_incidents_count: int


@dataclass
class EvidenceRecord:
    """Page 6 - Evidence & Chain of Custody."""
    case_id: str
    sha256_hash: str
    hash_status: str  # "SEALED", "TAMPER-EVIDENT"
    ingestion_timestamp: str
    analysis_completion_timestamp: str
    analysis_status: str  # "COMPLETED", "IN_PROGRESS", "PENDING"


@dataclass
class ThreatDNAProfile:
    """Page 7 - Threat DNA fingerprint (0-5 dots each)."""
    authentication: int  # 0-5
    infrastructure: int  # 0-5
    anonymization: int  # 0-5
    campaign_correlation: int  # 0-5
    social_engineering: int  # 0-5


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely converts numeric or qualitative string values (e.g. 'Moderate Confidence') to float."""
    if val is None:
        return default
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        clean = val.replace("%", "").strip()
        try:
            return float(clean)
        except ValueError:
            low = val.lower()
            if "very high" in low:
                return 95.0
            elif "high" in low:
                return 85.0
            elif "moderate" in low or "medium" in low or "probable" in low:
                return 70.0
            elif "low" in low or "possible" in low:
                return 40.0
            elif "critical" in low:
                return 90.0
            elif "safe" in low:
                return 15.0
            return default
    return default


class DataTransformer:
    """
    Transforms raw backend forensic data into structured page-component models.
    
    Each method extracts a specific section and validates that required fields exist.
    Missing fields are handled gracefully with sensible defaults.
    """

    @staticmethod
    def extract_from_backend(forensic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master extraction method that normalizes backend data for PDF generation.
        
        This method ensures all data is in the expected format for the report builder.
        It handles different backend schemas and provides sensible defaults.
        
        Args:
            forensic_data: Raw forensic data from backend
            
        Returns:
            Normalized forensic data dict ready for PDF generation
        """
        # Ensure required top-level fields exist
        normalized = {
            'case_id': forensic_data.get('case_id', 'CASE-UNKNOWN'),
            'threat_category': forensic_data.get('threat_category', 'Unknown'),
            'final_risk': _safe_float(forensic_data.get('final_risk', 0), 0.0),
            'verdict': forensic_data.get('verdict', 'EVALUATED'),
            'confidence': _safe_float(forensic_data.get('confidence', 50), 70.0),
            'analysis_timestamp': forensic_data.get('analysis_timestamp', ''),
            'why_flagged': forensic_data.get('why_flagged', []),
            'email_metadata': forensic_data.get('email_metadata', {}),
            'authentication': forensic_data.get('authentication', {}),
            'relay_hops': forensic_data.get('relay_hops', []),
            'originating_node': forensic_data.get('originating_node', {}),
            'campaign': forensic_data.get('campaign', {}),
            'evidence': forensic_data.get('evidence', []),
            'threat_dna': forensic_data.get('threat_dna', {}),
        }
        
        # Normalize authentication status values
        if 'authentication' in normalized:
            auth = normalized['authentication']
            for proto in ['spf', 'dkim', 'dmarc']:
                if proto in auth and isinstance(auth[proto], dict):
                    status = auth[proto].get('status', '').lower()
                    # Standardize to: pass, fail, neutral, none
                    if status in ['pass', 'passed', 'verified', 'success']:
                        auth[proto]['status'] = 'pass'
                    elif status in ['fail', 'failed', 'invalid', 'reject']:
                        auth[proto]['status'] = 'fail'
                    elif status in ['neutral', 'none', 'unknown']:
                        auth[proto]['status'] = 'none'
        
        # Ensure relay hops is a list
        if not isinstance(normalized.get('relay_hops'), list):
            normalized['relay_hops'] = []
        
        # Normalize relay hop IPs (defang if needed)
        for hop in normalized['relay_hops']:
            if 'ip' in hop and not 'defanged_ip' in hop:
                ip = hop['ip']
                if ip and not ip.startswith('['):
                    hop['defanged_ip'] = ip.replace('.', '[.]')
                else:
                    hop['defanged_ip'] = ip
        
        # Ensure originating_node is a dict
        if not isinstance(normalized.get('originating_node'), dict):
            normalized['originating_node'] = {}
        
        # Ensure campaign is a dict
        if not isinstance(normalized.get('campaign'), dict):
            normalized['campaign'] = {}
        
        # Ensure evidence is a list
        if not isinstance(normalized.get('evidence'), list):
            normalized['evidence'] = []
        
        return normalized

    @staticmethod
    def extract_threat_snapshot(forensic_data: Dict[str, Any]) -> ThreatSnapshot:
        """Extract Page 1 data from backend analysis."""
        
        risk_score = _safe_float(forensic_data.get("final_risk", 0.0), 0.0)
        verdict = forensic_data.get("verdict", "EVALUATED")
        primary_threat = forensic_data.get("threat_category", "Security Threat")
        
        # Confidence as percentage string
        confidence = forensic_data.get("confidence", 70)
        if isinstance(confidence, (int, float)):
            confidence_str = f"{int(confidence)}%"
        elif isinstance(confidence, str):
            confidence_str = confidence if ("%" in confidence or "Confidence" in confidence) else f"{confidence}%"
        else:
            confidence_str = str(confidence)
        
        # Top 3 reasons from why_flagged
        top_reasons = []
        why_flagged = forensic_data.get("why_flagged", [])
        for item in why_flagged[:3]:
            if isinstance(item, dict):
                explanation = item.get("explanation", "")
                if explanation:
                    top_reasons.append(explanation)
            elif isinstance(item, str):
                top_reasons.append(item)
        
        if len(top_reasons) < 3:
            top_reasons.append("Investigation completed without additional critical signals.")
        
        # Evidence cards: Identity, Auth, Infrastructure, Anonymization, Intelligence
        evidence_cards = []
        
        # 1. Identity Card
        sender_email = forensic_data.get("email_metadata", {}).get("sender", {}).get("email", "Unknown")
        evidence_cards.append(EvidenceCard(
            title="Identity",
            value=sender_email[:20] + ("..." if len(sender_email) > 20 else ""),
            detail="Sender / Domain",
            color="#3B82F6",
            status="FLAGGED"
        ))
        
        # 2. Authentication Card
        auth = forensic_data.get("authentication", {})
        spf_status = auth.get("spf", {}).get("status", "Unknown")
        dkim_status = auth.get("dkim", {}).get("status", "Unknown")
        dmarc_status = auth.get("dmarc", {}).get("status", "Unknown")
        auth_status = "PASS" if all(s == "Pass" for s in [spf_status, dkim_status, dmarc_status]) else "FAIL"
        evidence_cards.append(EvidenceCard(
            title="Authentication",
            value=auth_status,
            detail="SPF / DKIM / DMARC",
            color="#10B981" if auth_status == "PASS" else "#DC2626",
            status=auth_status
        ))
        
        # 3. Infrastructure Card
        origin_node = forensic_data.get("originating_node", {})
        origin_ip = origin_node.get("defanged_ip") or origin_node.get("ip") or "NOT RESOLVED"
        evidence_cards.append(EvidenceCard(
            title="Infrastructure",
            value=origin_ip[:15] + ("..." if len(origin_ip) > 15 else ""),
            detail="Origin IP / ASN",
            color="#0891B2"
        ))
        
        # 4. Anonymization Card
        is_anon = origin_node.get("is_anonymized", False)
        anon_type = origin_node.get("anonymization_type", "None")
        evidence_cards.append(EvidenceCard(
            title="Anonymization",
            value=anon_type if is_anon else "None",
            detail="TOR / VPN / Proxy",
            color="#F59E0B" if is_anon else "#10B981",
            status="DETECTED" if is_anon else "CLEAN"
        ))
        
        # 5. Intelligence Card
        campaign = forensic_data.get("campaign", {})
        camp_name = campaign.get("name", "Uncorrelated")
        evidence_cards.append(EvidenceCard(
            title="Intelligence",
            value=camp_name[:15] + ("..." if len(camp_name) > 15 else ""),
            detail="Campaign / CTI",
            color="#8B5CF6"
        ))
        
        return ThreatSnapshot(
            verdict=f"{verdict.upper()} {risk_score:.1f}/100",
            risk_score=risk_score,
            primary_threat=primary_threat,
            confidence=confidence_str,
            top_reasons=top_reasons,
            evidence_cards=evidence_cards
        )

    @staticmethod
    def extract_attack_story(forensic_data: Dict[str, Any]) -> AttackStory:
        """Extract Page 2 data - message relay path."""
        
        relay_path = forensic_data.get("relay_path", [])
        hops = []
        origin_ip = None
        origin_location = "Unknown"
        
        for hop_data in relay_path:
            hop_num = hop_data.get("hop", 0)
            ip = hop_data.get("ip", "")
            defanged_ip = hop_data.get("defanged_ip") or (ip.replace(".", "[.]") if ip else "")
            is_private = hop_data.get("is_private", True)
            is_origin = hop_data.get("is_origin", False)
            
            # Determine hop status
            if is_origin:
                status = "ORIGIN"
                if not origin_ip:
                    origin_ip = ip
            elif is_private:
                status = "TRUSTED"
            else:
                status = "UNKNOWN"
            
            # Geolocation
            geo = hop_data.get("geo", {})
            city = geo.get("city", "")
            country = geo.get("country_code", "")
            location = f"{city}, {country}".strip(", ") or "Unknown"
            
            if is_origin:
                origin_location = location
            
            hops.append(RelayHop(
                hop_number=hop_num,
                received_from=hop_data.get("received_from", "Unknown")[:20],
                by_mta=hop_data.get("by", "Unknown")[:20],
                ip=ip,
                defanged_ip=defanged_ip,
                is_private=is_private,
                is_origin=is_origin,
                location=location,
                timestamp=hop_data.get("timestamp"),
                delay_seconds=hop_data.get("delay_seconds", 0),
                status=status
            ))
        
        # Natural language interpretation
        interpretation = "Message was submitted through standard email relay infrastructure."
        if origin_ip and not any(h.is_private for h in hops if h.is_origin):
            interpretation = f"Earliest publicly routable infrastructure observed in headers resolves to {origin_location}."
        
        return AttackStory(
            hops=hops,
            origin_ip=origin_ip,
            origin_location=origin_location,
            hop_count=len(hops),
            interpretation=interpretation
        )

    @staticmethod
    def extract_authentication_findings(forensic_data: Dict[str, Any]) -> AuthenticationFindings:
        """Extract Page 3 data - SPF/DKIM/DMARC forensics."""
        
        auth = forensic_data.get("authentication", {})
        spf = auth.get("spf", {})
        dkim = auth.get("dkim", {})
        dmarc = auth.get("dmarc", {})
        
        # Calculate overall trust
        spf_pass = spf.get("status", "").lower() == "pass"
        dkim_pass = dkim.get("status", "").lower() in ["pass", "verified"]
        dmarc_pass = dmarc.get("status", "").lower() == "pass"
        passes = sum([spf_pass, dkim_pass, dmarc_pass])
        overall_trust = (passes / 3.0) * 100.0
        
        return AuthenticationFindings(
            spf_status=spf.get("status", "None").upper(),
            spf_domain=spf.get("domain", "N/A"),
            spf_expected="IP authorized by SPF record",
            spf_observed=spf.get("reason", "Not evaluated"),
            spf_impact="SPF validation determines if sending IP is authorized to send on behalf of domain",

            dkim_status=dkim.get("status", "None").upper(),
            dkim_domain=dkim.get("domain", "N/A"),
            dkim_expected="Valid cryptographic DKIM signature present",
            dkim_observed=dkim.get("reason", "Not evaluated"),
            dkim_impact="DKIM signature proves message originated from domain and was not tampered with",

            dmarc_status=dmarc.get("status", "Fail").upper(),
            dmarc_domain=dmarc.get("domain", "N/A"),
            dmarc_expected="SPF and DKIM alignments pass",
            dmarc_observed=dmarc.get("reason", "Alignment failed"),
            dmarc_impact="DMARC policy aligns SPF/DKIM to prevent spoofing",

            overall_trust_percentage=overall_trust
        )

    @staticmethod
    def extract_infrastructure_profile(forensic_data: Dict[str, Any]) -> InfrastructureProfile:
        """Extract Page 4 data - infrastructure intelligence."""
        
        origin_node = forensic_data.get("originating_node", {})
        origin_ip = origin_node.get("ip")
        
        # Check if IP is resolved
        is_resolved = (
            origin_ip and 
            origin_ip not in ["0.0.0.0", None, ""] and 
            not origin_node.get("is_private", True)
        )
        
        origin_ip_display = origin_node.get("defanged_ip") or (origin_ip.replace(".", "[.]") if origin_ip else "NOT RESOLVED")
        
        geolocation = f"{origin_node.get('city', '')}, {origin_node.get('country', '')}".strip(", ") or "Not Resolved"
        
        asn = origin_node.get("asn", "N/A")
        network_name = origin_node.get("isp", "Unknown Network")
        
        anon_type = origin_node.get("anonymization_type")
        is_tor = anon_type and "tor" in anon_type.lower()
        is_vpn = anon_type and "vpn" in anon_type.lower()
        
        disclaimer = "Geolocation represents observed network infrastructure, not necessarily attacker physical location."
        
        return InfrastructureProfile(
            origin_ip=origin_ip or "NOT RESOLVED",
            origin_ip_defanged=origin_ip_display,
            is_ip_resolved=is_resolved,
            geolocation=geolocation,
            asn=asn,
            network_name=network_name,
            anonymization_type=anon_type,
            is_tor=is_tor,
            is_vpn=is_vpn,
            disclaimer=disclaimer
        )

    @staticmethod
    def extract_campaign_signal(forensic_data: Dict[str, Any]) -> Optional[CampaignSignal]:
        """Extract Page 5 data - campaign attribution."""
        
        campaign = forensic_data.get("campaign", {})
        if not campaign.get("id"):
            return None
        
        confidence = _safe_float(campaign.get("attribution_confidence", 70), 70.0)
        
        # Label based on confidence
        if confidence < 60:
            label = "LOW (Possible)"
        elif confidence < 80:
            label = "PROBABLE"
        else:
            label = "HIGH CONFIDENCE"
        
        return CampaignSignal(
            name=campaign.get("name", "Unknown Campaign"),
            confidence_percentage=confidence,
            confidence_label=label,
            evidence_sources=campaign.get("evidence_sources", []),
            linked_incidents_count=campaign.get("linked_incidents_count", 1)
        )

    @staticmethod
    def extract_evidence_record(case_id: str, forensic_data: Dict[str, Any]) -> EvidenceRecord:
        """Extract Page 6 data - evidence integrity."""
        
        sha256 = forensic_data.get("sha256_evidence_hash", "")
        status = "SEALED" if forensic_data.get("is_sealed", False) else "TAMPER-EVIDENT"
        
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        
        return EvidenceRecord(
            case_id=case_id,
            sha256_hash=sha256 or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            hash_status=status,
            ingestion_timestamp=forensic_data.get("ingestion_timestamp", now),
            analysis_completion_timestamp=now,
            analysis_status="COMPLETED"
        )

    @staticmethod
    def extract_threat_dna(forensic_data: Dict[str, Any]) -> ThreatDNAProfile:
        """Extract Page 7 data - threat fingerprint (5-dot profile)."""
        
        # Authentication: based on SPF/DKIM/DMARC
        auth = forensic_data.get("authentication", {})
        auth_pass = sum([
            auth.get("spf", {}).get("status", "").lower() == "pass",
            auth.get("dkim", {}).get("status", "").lower() in ["pass", "verified"],
            auth.get("dmarc", {}).get("status", "").lower() == "pass"
        ])
        authentication_dots = min(5, auth_pass + 1)  # 1-5 dots
        
        # Infrastructure: based on public IP and ASN reputation
        origin_node = forensic_data.get("originating_node", {})
        has_public_ip = origin_node.get("ip") and not origin_node.get("is_private", True)
        infrastructure_dots = 5 if has_public_ip else 2
        
        # Anonymization: TOR/VPN detected
        is_anon = origin_node.get("is_anonymized", False)
        anonymization_dots = 5 if is_anon else 1
        
        # Campaign Correlation: confidence level
        campaign = forensic_data.get("campaign", {})
        if campaign.get("id"):
            confidence = _safe_float(campaign.get("attribution_confidence", 70), 70.0)
            campaign_dots = min(5, max(1, int(confidence / 20)))
        else:
            campaign_dots = 0
        
        # Social Engineering: from threat category and why_flagged
        threat_cat = forensic_data.get("threat_category", "").lower()
        has_urgency_signals = any("urgent" in str(r).lower() for r in forensic_data.get("why_flagged", []))
        social_eng_dots = 4 if (has_urgency_signals or "bec" in threat_cat or "phishing" in threat_cat) else 2
        
        return ThreatDNAProfile(
            authentication=authentication_dots,
            infrastructure=infrastructure_dots,
            anonymization=anonymization_dots,
            campaign_correlation=campaign_dots,
            social_engineering=social_eng_dots
        )
