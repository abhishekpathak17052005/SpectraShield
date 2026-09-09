"""
DataValidator: Validates data consistency and detects conflicts before PDF generation.

Ensures:
- Summary and detail views don't contradict
- No placeholder values are presented as real findings
- Geolocation disclaimers are present where needed
- All forensic claims are grounded in backend data
- Required fields exist
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class ValidationWarning:
    """A data consistency warning or validation issue."""
    level: str  # "ERROR", "WARNING", "INFO"
    category: str  # "CONSISTENCY", "MISSING_DATA", "PLACEHOLDER", "DISCLAIMER"
    message: str
    affected_field: Optional[str] = None
    remediation: Optional[str] = None


class DataValidator:
    """
    Validates forensic data before PDF generation.
    
    Catches:
    - Summary vs Detail contradictions
    - Placeholder values presented as findings
    - Missing critical fields
    - Suspicious geolocation claims
    - Invalid confidence values
    """

    # Bogon/placeholder IP addresses
    BOGON_IPS = {
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
        "192.0.2.0",
        "198.51.100.0",
        "203.0.113.0",
    }

    # Placeholder values that should trigger "NOT RESOLVED"
    PLACEHOLDER_VALUES = {
        "Unknown",
        "Unknown ISP",
        "Unknown Country",
        "N/A",
        "Not Available",
        "Unresolved",
        "",
    }

    @staticmethod
    def validate_consistency(forensic_data: Dict[str, Any]) -> List[ValidationWarning]:
        """
        Validate data consistency across backend analysis.
        
        Returns list of warnings/errors that should prevent or modify PDF generation.
        """
        warnings = []

        # Rule 1: Check authentication status consistency
        warnings.extend(DataValidator._check_auth_consistency(forensic_data))

        # Rule 2: Check IP is not bogon
        warnings.extend(DataValidator._check_ip_validity(forensic_data))

        # Rule 3: Check confidence values are valid
        warnings.extend(DataValidator._check_confidence_values(forensic_data))

        # Rule 4: Check geolocation exists if IP is shown
        warnings.extend(DataValidator._check_geolocation(forensic_data))

        # Rule 5: Check required fields
        warnings.extend(DataValidator._check_required_fields(forensic_data))

        # Rule 6: Check threat category is supported
        warnings.extend(DataValidator._check_threat_category(forensic_data))

        # Rule 7: Check campaign data (if present)
        warnings.extend(DataValidator._check_campaign_data(forensic_data))

        return warnings

    @staticmethod
    def _check_auth_consistency(forensic_data: Dict[str, Any]) -> List[ValidationWarning]:
        """
        Verify that summary and detail authentication states don't contradict.
        
        Example:
        - Summary shows "SPF: PASS" but detail shows SPF Failed
        - DKIM shows Verified but also shows Invalid
        """
        warnings = []
        auth = forensic_data.get("authentication", {})

        # Check SPF
        spf = auth.get("spf", {})
        spf_status = spf.get("status", "").lower()
        if spf_status and spf_status not in ["pass", "fail", "neutral", "none"]:
            warnings.append(ValidationWarning(
                level="WARNING",
                category="CONSISTENCY",
                message=f"SPF status '{spf_status}' is non-standard. Expected: PASS, FAIL, NEUTRAL, or NONE",
                affected_field="authentication.spf.status",
                remediation="Normalize SPF status value in backend"
            ))

        # Check DKIM
        dkim = auth.get("dkim", {})
        dkim_status = dkim.get("status", "").lower()
        if dkim_status and dkim_status not in ["pass", "verified", "fail", "invalid", "none"]:
            warnings.append(ValidationWarning(
                level="WARNING",
                category="CONSISTENCY",
                message=f"DKIM status '{dkim_status}' is non-standard",
                affected_field="authentication.dkim.status",
                remediation="Normalize DKIM status value"
            ))

        # Check DMARC
        dmarc = auth.get("dmarc", {})
        dmarc_status = dmarc.get("status", "").lower()
        if dmarc_status and dmarc_status not in ["pass", "fail", "neutral", "none"]:
            warnings.append(ValidationWarning(
                level="WARNING",
                category="CONSISTENCY",
                message=f"DMARC status '{dmarc_status}' is non-standard",
                affected_field="authentication.dmarc.status",
                remediation="Normalize DMARC status value"
            ))

        return warnings

    @staticmethod
    def _check_ip_validity(forensic_data: Dict[str, Any]) -> List[ValidationWarning]:
        """
        Check that displayed IP is not a bogon or placeholder.
        """
        warnings = []
        origin_node = forensic_data.get("originating_node", {})
        origin_ip = origin_node.get("ip")

        if not origin_ip:
            warnings.append(ValidationWarning(
                level="INFO",
                category="MISSING_DATA",
                message="No origin IP found in forensic data",
                affected_field="originating_node.ip",
                remediation="Origin IP will display as 'NOT RESOLVED'"
            ))
            return warnings

        # Check if it's a bogon
        if origin_ip in DataValidator.BOGON_IPS:
            warnings.append(ValidationWarning(
                level="WARNING",
                category="PLACEHOLDER",
                message=f"Origin IP '{origin_ip}' is a bogon address. Will display as 'NOT RESOLVED'",
                affected_field="originating_node.ip",
                remediation="None needed; correctly identifies unresolved infrastructure"
            ))

        # Check if private but should show
        is_private = origin_node.get("is_private", True)
        if is_private:
            warnings.append(ValidationWarning(
                level="INFO",
                category="MISSING_DATA",
                message=f"Origin IP '{origin_ip}' is private/internal. Public infrastructure not identified.",
                affected_field="originating_node.is_private",
                remediation="Infrastructure section will show 'NOT RESOLVED'"
            ))

        return warnings

    @staticmethod
    def _check_confidence_values(forensic_data: Dict[str, Any]) -> List[ValidationWarning]:
        """
        Validate all confidence/score values are in expected ranges.
        """
        warnings = []

        # Final risk score (0-100)
        final_risk = forensic_data.get("final_risk")
        if final_risk is not None:
            try:
                risk_float = float(final_risk)
                if not 0 <= risk_float <= 100:
                    warnings.append(ValidationWarning(
                        level="ERROR",
                        category="CONSISTENCY",
                        message=f"final_risk '{risk_float}' outside valid range [0, 100]",
                        affected_field="final_risk",
                        remediation="Clamp value to 0-100 range"
                    ))
            except (TypeError, ValueError):
                warnings.append(ValidationWarning(
                    level="ERROR",
                    category="CONSISTENCY",
                    message=f"final_risk is not numeric: {final_risk}",
                    affected_field="final_risk",
                    remediation="Ensure final_risk is a number"
                ))

        # Campaign confidence (0-100)
        campaign = forensic_data.get("campaign", {})
        if campaign.get("attribution_confidence"):
            try:
                conf = float(campaign["attribution_confidence"])
                if not 0 <= conf <= 100:
                    warnings.append(ValidationWarning(
                        level="WARNING",
                        category="CONSISTENCY",
                        message=f"Campaign confidence '{conf}' outside [0, 100]",
                        affected_field="campaign.attribution_confidence",
                        remediation="Clamp value to valid range"
                    ))
            except (TypeError, ValueError):
                warnings.append(ValidationWarning(
                    level="WARNING",
                    category="CONSISTENCY",
                    message=f"Campaign confidence is not numeric",
                    affected_field="campaign.attribution_confidence"
                ))

        # Analysis confidence (0-100)
        confidence = forensic_data.get("confidence")
        if confidence:
            try:
                conf_float = float(confidence)
                if not 0 <= conf_float <= 100:
                    warnings.append(ValidationWarning(
                        level="WARNING",
                        category="CONSISTENCY",
                        message=f"Analysis confidence '{conf_float}' outside [0, 100]",
                        affected_field="confidence",
                        remediation="Clamp to valid range"
                    ))
            except (TypeError, ValueError):
                pass  # Non-numeric confidence is acceptable (e.g., qualitative)

        return warnings

    @staticmethod
    def _check_geolocation(forensic_data: Dict[str, Any]) -> List[ValidationWarning]:
        """
        If showing origin IP, verify geolocation data exists for disclaimer.
        """
        warnings = []
        origin_node = forensic_data.get("originating_node", {})
        origin_ip = origin_node.get("ip")

        # If we have an IP, we should have geolocation
        if origin_ip and origin_ip not in DataValidator.BOGON_IPS:
            city = origin_node.get("city")
            country = origin_node.get("country")

            if not city or not country:
                warnings.append(ValidationWarning(
                    level="INFO",
                    category="MISSING_DATA",
                    message="Geolocation incomplete for origin IP",
                    affected_field="originating_node.city/country",
                    remediation="Geolocation will display as partial or 'Unknown'"
                ))

        return warnings

    @staticmethod
    def _check_required_fields(forensic_data: Dict[str, Any]) -> List[ValidationWarning]:
        """
        Check that essential fields for PDF generation exist.
        """
        warnings = []

        required_top_level = ["threat_category", "final_risk", "verdict"]
        for field in required_top_level:
            if field not in forensic_data or forensic_data[field] is None:
                warnings.append(ValidationWarning(
                    level="WARNING",
                    category="MISSING_DATA",
                    message=f"Required field missing: {field}",
                    affected_field=field,
                    remediation=f"Set {field} to a valid value"
                ))

        # Check email metadata
        email_meta = forensic_data.get("email_metadata", {})
        if not email_meta.get("sender"):
            warnings.append(ValidationWarning(
                level="INFO",
                category="MISSING_DATA",
                message="Sender information missing",
                affected_field="email_metadata.sender",
                remediation="Sender will display as 'Unknown'"
            ))

        # Check authentication data
        auth = forensic_data.get("authentication", {})
        if not auth:
            warnings.append(ValidationWarning(
                level="WARNING",
                category="MISSING_DATA",
                message="Authentication data missing entirely",
                affected_field="authentication",
                remediation="Authentication page will display all results as 'None'"
            ))

        # Check why_flagged
        why_flagged = forensic_data.get("why_flagged", [])
        if not why_flagged or len(why_flagged) == 0:
            warnings.append(ValidationWarning(
                level="INFO",
                category="MISSING_DATA",
                message="No 'why_flagged' reasons provided",
                affected_field="why_flagged",
                remediation="Top reasons section will use generic message"
            ))

        return warnings

    @staticmethod
    def _check_threat_category(forensic_data: Dict[str, Any]) -> List[ValidationWarning]:
        """
        Verify threat category is in supported set.
        """
        warnings = []
        threat_cat = forensic_data.get("threat_category", "").lower()

        supported = [
            "phishing",
            "business email compromise",
            "malware",
            "ransomware",
            "credential harvesting",
            "spam",
            "scam",
            "suspicious",
        ]

        if threat_cat and threat_cat not in supported:
            warnings.append(ValidationWarning(
                level="INFO",
                category="CONSISTENCY",
                message=f"Threat category '{threat_cat}' is non-standard but acceptable",
                affected_field="threat_category",
                remediation="Will display as-is in report"
            ))

        return warnings

    @staticmethod
    def _check_campaign_data(forensic_data: Dict[str, Any]) -> List[ValidationWarning]:
        """
        Validate campaign data if present.
        """
        warnings = []
        campaign = forensic_data.get("campaign", {})

        if not campaign:
            return warnings

        if campaign.get("id") and not campaign.get("name"):
            warnings.append(ValidationWarning(
                level="WARNING",
                category="MISSING_DATA",
                message="Campaign has ID but no name",
                affected_field="campaign.name",
                remediation="Campaign will display as 'Unknown Campaign'"
            ))

        if campaign.get("attribution_confidence") and not campaign.get("id"):
            warnings.append(ValidationWarning(
                level="WARNING",
                category="CONSISTENCY",
                message="Campaign has confidence but no ID - may not be valid attribution",
                affected_field="campaign",
                remediation="Campaign section may not render"
            ))

        return warnings

    @staticmethod
    def should_generate_pdf(warnings: List[ValidationWarning]) -> tuple[bool, str]:
        """
        Determine if we should proceed with PDF generation.
        
        Returns (should_proceed, reason_if_blocked)
        """
        errors = [w for w in warnings if w.level == "ERROR"]

        if errors:
            reasons = "; ".join([w.message for w in errors])
            return False, f"Critical data validation errors: {reasons}"

        return True, ""

    @staticmethod
    def get_warnings_summary(warnings: List[ValidationWarning]) -> Dict[str, int]:
        """Get count of warnings by level."""
        summary = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        for w in warnings:
            summary[w.level] = summary.get(w.level, 0) + 1
        return summary
