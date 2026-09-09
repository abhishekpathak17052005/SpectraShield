"""
LanguageTranslator: Converts technical terms to user-friendly language.

Maps cryptic RFC/security terminology to readable explanations that don't
sacrifice technical accuracy.
"""

from typing import Dict, Optional


class LanguageTranslator:
    """
    Translates technical security terms into user-friendly language.
    
    Examples:
    - "RFC 5322 Multi-Hop Relay Trajectory" → "Message Route"
    - "Cryptographic Protocol & Header Validation" → "Sender Authentication"
    - "Physical Coordinates" → "Observed Infrastructure Location"
    """

    # Technical section headers → readable titles
    SECTION_HEADERS = {
        "RFC 5322 Multi-Hop Relay Trajectory & Latency": "Message Route",
        "Cryptographic Protocol & Header Validation": "Sender Authentication",
        "Originating Infrastructure & Threat Campaign Attribution": "Threat Infrastructure",
        "Attachment Static Forensic Triage": "Attachment Analysis",
        "Chain of Custody Sign-Off (ISO/IEC 27037)": "Evidence Integrity",
    }

    # Authentication status translations
    AUTH_STATUS_LABELS = {
        "pass": "PASS",
        "fail": "FAIL",
        "neutral": "NEUTRAL",
        "none": "NONE",
        "verified": "VERIFIED",
        "invalid": "INVALID",
        "unknown": "UNKNOWN",
    }

    # Threat level → readable description
    THREAT_LEVEL_LABELS = {
        0: "Safe",
        1: "Safe",
        10: "Low Risk",
        20: "Low Risk",
        30: "Moderate Risk",
        40: "Moderate Risk",
        50: "Moderate Risk",
        60: "Elevated Risk",
        70: "High Risk",
        80: "High Risk",
        90: "Critical Risk",
        100: "Critical Risk",
    }

    # Anonymization types
    ANONYMIZATION_LABELS = {
        "tor": "Tor Exit Node",
        "vpn": "Commercial VPN",
        "proxy": "Proxy Service",
        "socks": "SOCKS Proxy",
        "datacenter": "Datacenter IP",
        "residential": "Residential Proxy",
    }

    # Risk factors → readable explanations
    RISK_FACTOR_EXPLANATIONS = {
        "spf_fail": "Sending IP is not authorized by the domain's SPF record",
        "dkim_fail": "Email lacks valid DKIM cryptographic signature",
        "dmarc_fail": "Domain authentication failed DMARC policy alignment",
        "homoglyph": "Sender domain uses lookalike characters (homoglyph attack)",
        "tor_detected": "Originating infrastructure is a known Tor exit node",
        "vpn_detected": "Originating infrastructure is a commercial VPN service",
        "urgency_trigger": "Email uses psychological urgency phrases",
        "brand_impersonation": "Email impersonates recognized enterprise brand",
        "qr_code": "Email contains QR code (common in phishing)",
        "request_credentials": "Email requests authentication credentials or sensitive data",
        "suspicious_link": "Email contains link to known malicious domain",
        "attachment_malicious": "Attachment flagged as potentially malicious",
        "no_received_headers": "Email lacks standard Received headers (suspicious)",
        "short_lifespan": "Sender domain registered recently (burner domain indicator)",
    }

    @staticmethod
    def section_header(technical_title: str) -> str:
        """
        Translate section header from technical to readable.
        Falls back to original if no translation exists.
        """
        return LanguageTranslator.SECTION_HEADERS.get(technical_title, technical_title)

    @staticmethod
    def auth_status(status: str) -> str:
        """
        Translate authentication status to consistent format.
        
        Examples:
        - "Pass" → "PASS"
        - "FAIL" → "FAIL"
        - "verified" → "VERIFIED"
        """
        if not status:
            return "UNKNOWN"
        
        normalized = status.lower().strip()
        return LanguageTranslator.AUTH_STATUS_LABELS.get(normalized, status.upper())

    @staticmethod
    def threat_level(score: float) -> str:
        """
        Convert numeric threat score to readable threat level.
        
        Examples:
        - 0-20 → "Low Risk"
        - 65 → "Elevated Risk"
        - 92 → "Critical Risk"
        """
        if score is None:
            return "Unknown"
        
        try:
            score_int = int(float(score))
        except (TypeError, ValueError):
            return "Unknown"
        
        # Find closest bracket
        brackets = sorted(LanguageTranslator.THREAT_LEVEL_LABELS.keys())
        for bracket in brackets:
            if score_int <= bracket:
                return LanguageTranslator.THREAT_LEVEL_LABELS[bracket]
        
        return LanguageTranslator.THREAT_LEVEL_LABELS[100]

    @staticmethod
    def anonymization_type(anon_type: Optional[str]) -> str:
        """
        Translate anonymization type to readable label.
        
        Examples:
        - "tor" → "Tor Exit Node"
        - "VPN" → "Commercial VPN"
        - "datacenter" → "Datacenter IP"
        """
        if not anon_type:
            return "None Detected"
        
        normalized = anon_type.lower().strip()
        
        # Check for exact match or substring match
        for key, label in LanguageTranslator.ANONYMIZATION_LABELS.items():
            if key in normalized or normalized in key:
                return label
        
        return anon_type.capitalize()

    @staticmethod
    def risk_factor_explanation(factor_key: str) -> str:
        """
        Get human-readable explanation for a risk factor.
        
        Examples:
        - "spf_fail" → "Sending IP is not authorized by the domain's SPF record"
        - "tor_detected" → "Originating infrastructure is a known Tor exit node"
        """
        normalized = factor_key.lower().replace(" ", "_").strip()
        
        explanation = LanguageTranslator.RISK_FACTOR_EXPLANATIONS.get(
            normalized,
            f"Risk factor: {factor_key}"
        )
        
        return explanation

    @staticmethod
    def confidence_label(confidence_percent: float) -> str:
        """
        Convert numeric confidence to qualitative label.
        
        Examples:
        - 30 → "Low Confidence"
        - 60 → "Probable"
        - 85 → "High Confidence"
        """
        if confidence_percent is None:
            return "Unknown"
        
        try:
            conf = float(confidence_percent)
        except (TypeError, ValueError):
            return "Unknown"
        
        if conf < 40:
            return "Low Confidence"
        elif conf < 60:
            return "Possible"
        elif conf < 75:
            return "Probable"
        elif conf < 90:
            return "High Confidence"
        else:
            return "Very High Confidence"

    @staticmethod
    def verdict_interpretation(verdict: str, score: float) -> str:
        """
        Create readable interpretation of verdict.
        
        Examples:
        - ("MALICIOUS", 92) → "Highly suspicious communication detected"
        - ("SAFE", 15) → "No significant security indicators detected"
        """
        if not verdict:
            verdict = "EVALUATED"
        
        verdict_upper = verdict.upper().strip()
        
        interpretation_map = {
            "MALICIOUS": "Highly suspicious communication detected",
            "SUSPICIOUS": "Communication exhibits warning signs",
            "EVALUATED": "Communication analyzed and scored",
            "SAFE": "No significant security indicators detected",
            "CLEAN": "Message appears legitimate",
        }
        
        base_interpretation = interpretation_map.get(verdict_upper, f"Verdict: {verdict}")
        
        # Add score context
        if score is not None:
            try:
                score_float = float(score)
                if score_float >= 80:
                    context = " (High severity)"
                elif score_float >= 60:
                    context = " (Moderate severity)"
                elif score_float >= 40:
                    context = " (Low severity)"
                else:
                    context = " (Minimal risk)"
                return base_interpretation + context
            except (TypeError, ValueError):
                pass
        
        return base_interpretation

    @staticmethod
    def header_field_name(technical_name: str) -> str:
        """
        Translate email header field names to readable format.
        
        Examples:
        - "RFC 5322" → "Standard Email Format"
        - "DKIM" → "Email Signature"
        - "SPF" → "Sender Policy"
        """
        mapping = {
            "rfc 5322": "Standard Email Format",
            "dkim": "Email Signature Verification",
            "spf": "Sender Authorization",
            "dmarc": "Domain Alignment Policy",
            "mime": "Message Format",
            "tls": "Encryption",
            "return-path": "Bounce Address",
            "received": "Relay Chain",
        }
        
        normalized = technical_name.lower()
        return mapping.get(normalized, technical_name)

    @staticmethod
    def hop_role(hop_type: str) -> str:
        """
        Translate hop type/role to readable description.
        
        Examples:
        - "mta" → "Mail Server"
        - "relay" → "Relay Service"
        - "client" → "Sending Client"
        """
        mapping = {
            "mta": "Mail Transfer Agent",
            "relay": "Relay Service",
            "client": "Sending Client",
            "submission": "Client Submission",
            "gateway": "Email Gateway",
            "filter": "Spam Filter",
            "antivirus": "Antivirus Gateway",
        }
        
        normalized = hop_type.lower().strip()
        return mapping.get(normalized, hop_type.capitalize())

    @staticmethod
    def geolocation_label(location: str) -> str:
        """
        Add context to geolocation (not attacker location).
        
        Example output: "Frankfurt, Germany (Observed Infrastructure Location)"
        """
        if not location:
            return "Not Resolved"
        
        return f"{location}"  # Disclaimer handled separately

    @staticmethod
    def attachment_risk_label(risk_level: str) -> str:
        """
        Translate attachment risk level.
        
        Examples:
        - "malicious" → "Flagged as Malicious"
        - "suspicious" → "Suspicious"
        - "clean" → "Safe"
        """
        mapping = {
            "malicious": "Flagged as Malicious",
            "suspicious": "Suspicious",
            "clean": "Safe",
            "unknown": "Unknown",
            "quarantined": "Quarantined",
        }
        
        normalized = (risk_level or "unknown").lower().strip()
        return mapping.get(normalized, risk_level.capitalize())

    @staticmethod
    def campaign_attribution_label(confidence: float) -> str:
        """
        Create readable campaign attribution label.
        
        Examples:
        - 35 → "POSSIBLE CAMPAIGN CORRELATION (Low Confidence)"
        - 75 → "PROBABLE CAMPAIGN CORRELATION (High Confidence)"
        - 92 → "HIGH CONFIDENCE CAMPAIGN MATCH"
        """
        try:
            conf = float(confidence)
        except (TypeError, ValueError):
            return "Uncorrelated"
        
        if conf < 40:
            return f"POSSIBLE CORRELATION ({LanguageTranslator.confidence_label(conf)})"
        elif conf < 70:
            return f"PROBABLE CORRELATION ({LanguageTranslator.confidence_label(conf)})"
        else:
            return f"HIGH CONFIDENCE MATCH ({LanguageTranslator.confidence_label(conf)})"

    @staticmethod
    def create_recommendation(finding_type: str) -> Optional[str]:
        """
        Generate actionable recommendation based on finding type.
        Only returns recommendations backed by backend analysis.
        
        Examples:
        - "spf_fail" → "Verify sender domain is not spoofed"
        - "tor_detected" → "Consider blocking messages from Tor networks"
        """
        recommendations = {
            "spf_fail": "Verify sender domain is legitimate and not spoofed",
            "dkim_fail": "Confirm email has not been modified in transit",
            "dmarc_fail": "Domain authentication failed; exercise caution with sender",
            "tor_detected": "Consider blocking or quarantining messages from Tor infrastructure",
            "vpn_detected": "Evaluate legitimacy of VPN-sourced communication",
            "urgency_trigger": "Review for social engineering tactics",
            "brand_impersonation": "Investigate brand impersonation and report to affected organization",
            "request_credentials": "Alert recipient; never provide credentials via email",
            "suspicious_link": "Do not click links; verify sender through alternative channel",
            "attachment_malicious": "Do not open attachment; isolate message",
            "campaign_correlated": "Search for related indicators in historical email logs",
            "short_lifespan_domain": "Monitor for additional emails from this domain",
        }
        
        normalized = (finding_type or "").lower().replace(" ", "_")
        return recommendations.get(normalized)
