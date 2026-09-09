"""
CSV Exporter: Extracts defanged IOCs in RFC 4180 CSV format for SIEM/firewall deployment.

Columns:
- IOC_Type: domain, email, ipv4, hash, url, asn
- IOC_Value: Defanged indicator value
- Threat_Level: critical, high, medium, low
- Risk_Score: 0-100 assessment score
- Case_ID: Source case identifier
- Threat_Category: Type of threat (phishing, malware, etc.)
- Confidence: 0-100 confidence in finding
- First_Seen: When this IOC was first identified
- Last_Seen: When this IOC was last seen
- Description: Human-readable description
"""

import csv
import io
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone


class CSVExporter:
    """Exports forensic findings to CSV IOC format."""

    def __init__(self, case_id: str, forensic_data: Dict[str, Any], defang: bool = True):
        """
        Initialize CSV exporter.
        
        Args:
            case_id: Case identifier
            forensic_data: Forensic analysis data
            defang: If True, defang IOCs (e.g., example.com → example[.]com)
        """
        self.case_id = case_id
        self.forensic_data = forensic_data
        self.defang = defang
        self.iocs = []

    def generate_csv(self) -> str:
        """
        Generate CSV content.
        
        Returns:
            CSV-formatted string
        """
        # Extract IOCs
        self._extract_iocs()

        # Build CSV
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                'IOC_Type', 'IOC_Value', 'Threat_Level', 'Risk_Score',
                'Case_ID', 'Threat_Category', 'Confidence',
                'First_Seen', 'Last_Seen', 'Description'
            ]
        )

        writer.writeheader()
        writer.writerows(self.iocs)

        return output.getvalue()

    def _extract_iocs(self) -> None:
        """Extract IOCs from forensic data."""
        # Campaign indicators
        self._extract_campaign_indicators()

        # Email indicators
        self._extract_email_indicators()

        # Infrastructure indicators
        self._extract_infrastructure_indicators()

        # Authentication indicators
        self._extract_auth_indicators()

    def _extract_campaign_indicators(self) -> None:
        """Extract campaign-related IOCs."""
        campaign = self.forensic_data.get('campaign', {})

        if not campaign.get('related_indicators'):
            return

        threat_level = self._calculate_threat_level(
            self.forensic_data.get('final_risk', 50)
        )

        for indicator in campaign['related_indicators'][:10]:  # Limit to 10
            ioc_type, ioc_value = self._parse_ioc(indicator)

            if not ioc_value:
                continue

            self.iocs.append({
                'IOC_Type': ioc_type,
                'IOC_Value': ioc_value,
                'Threat_Level': threat_level,
                'Risk_Score': int(self.forensic_data.get('final_risk', 50)),
                'Case_ID': self.case_id,
                'Threat_Category': self.forensic_data.get('threat_category', 'Unknown'),
                'Confidence': int(campaign.get('attribution_confidence', 70)),
                'First_Seen': campaign.get('first_seen', datetime.now(timezone.utc).isoformat()),
                'Last_Seen': campaign.get('last_seen', datetime.now(timezone.utc).isoformat()),
                'Description': f"Indicator from campaign: {campaign.get('name', 'Unknown')}"
            })

    def _extract_email_indicators(self) -> None:
        """Extract email-based IOCs."""
        email_meta = self.forensic_data.get('email_metadata', {})

        if not email_meta.get('sender'):
            return

        # Extract domain from sender
        sender = email_meta['sender']
        if '@' in sender:
            domain = sender.split('@')[1]
            ioc_value = self._defang_value(domain) if self.defang else domain

            self.iocs.append({
                'IOC_Type': 'domain',
                'IOC_Value': ioc_value,
                'Threat_Level': self._calculate_threat_level(
                    self.forensic_data.get('final_risk', 50)
                ),
                'Risk_Score': int(self.forensic_data.get('final_risk', 50)),
                'Case_ID': self.case_id,
                'Threat_Category': self.forensic_data.get('threat_category', 'Unknown'),
                'Confidence': int(self.forensic_data.get('confidence', 70)),
                'First_Seen': email_meta.get('timestamp', datetime.now(timezone.utc).isoformat()),
                'Last_Seen': email_meta.get('timestamp', datetime.now(timezone.utc).isoformat()),
                'Description': f"Domain from sender email: {sender}"
            })

    def _extract_infrastructure_indicators(self) -> None:
        """Extract infrastructure-based IOCs."""
        origin_node = self.forensic_data.get('originating_node', {})

        if not origin_node.get('ip'):
            return

        # IP Address
        ip = origin_node['ip']
        ioc_value = self._defang_value(ip) if self.defang else ip

        self.iocs.append({
            'IOC_Type': 'ipv4',
            'IOC_Value': ioc_value,
            'Threat_Level': 'critical' if origin_node.get('abuse_confidence', 0) > 80 else 'high',
            'Risk_Score': int(origin_node.get('abuse_confidence', 50)),
            'Case_ID': self.case_id,
            'Threat_Category': self.forensic_data.get('threat_category', 'Unknown'),
            'Confidence': int(origin_node.get('abuse_confidence', 70)),
            'First_Seen': datetime.now(timezone.utc).isoformat(),
            'Last_Seen': datetime.now(timezone.utc).isoformat(),
            'Description': f"Origin IP: {origin_node.get('organization', 'Unknown')} ({origin_node.get('country', 'Unknown')})"
        })

        # ASN
        asn = origin_node.get('asn')
        if asn:
            self.iocs.append({
                'IOC_Type': 'asn',
                'IOC_Value': asn,
                'Threat_Level': 'high',
                'Risk_Score': int(origin_node.get('abuse_confidence', 50)),
                'Case_ID': self.case_id,
                'Threat_Category': self.forensic_data.get('threat_category', 'Unknown'),
                'Confidence': 80,
                'First_Seen': datetime.now(timezone.utc).isoformat(),
                'Last_Seen': datetime.now(timezone.utc).isoformat(),
                'Description': f"Malicious ASN: {origin_node.get('organization', 'Unknown')}"
            })

    def _extract_auth_indicators(self) -> None:
        """Extract authentication-based IOCs (spoofed domains)."""
        auth = self.forensic_data.get('authentication', {})

        # Spoofed domain from SPF/DKIM/DMARC
        for proto, details in auth.items():
            if isinstance(details, dict) and details.get('domain'):
                domain = details['domain']
                ioc_value = self._defang_value(domain) if self.defang else domain

                # Only add if authentication failed
                if details.get('status', '').lower() in ['fail', 'invalid', 'none']:
                    self.iocs.append({
                        'IOC_Type': 'domain',
                        'IOC_Value': ioc_value,
                        'Threat_Level': 'high',
                        'Risk_Score': 85,
                        'Case_ID': self.case_id,
                        'Threat_Category': 'Spoofing',
                        'Confidence': 95,
                        'First_Seen': datetime.now(timezone.utc).isoformat(),
                        'Last_Seen': datetime.now(timezone.utc).isoformat(),
                        'Description': f"Spoofed domain: {proto} authentication failed"
                    })

    @staticmethod
    def _parse_ioc(indicator: str) -> Tuple[str, str]:
        """
        Parse IOC and determine type.
        
        Args:
            indicator: IOC string
            
        Returns:
            (type, value) tuple
        """
        if not indicator:
            return ('unknown', '')

        indicator = indicator.strip()

        # Email
        if '@' in indicator and '.' in indicator:
            return ('email', indicator)

        # URL
        if indicator.startswith('http://') or indicator.startswith('https://'):
            return ('url', indicator)

        # IPv4
        if all(c.isdigit() or c == '.' for c in indicator) and len(indicator.split('.')) == 4:
            return ('ipv4', indicator)

        # SHA256
        if len(indicator) == 64 and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return ('hash', indicator)

        # Domain (or defanged domain)
        if '.' in indicator or '[.]' in indicator:
            return ('domain', indicator)

        # ASN
        if indicator.startswith('AS'):
            return ('asn', indicator)

        return ('unknown', indicator)

    @staticmethod
    def _defang_value(value: str) -> str:
        """
        Defang an IOC to prevent accidental clicks.
        
        Args:
            value: IOC value
            
        Returns:
            Defanged value
        """
        if not value:
            return value

        # Defang domain dots
        if '.' in value and '[.]' not in value:
            value = value.replace('.', '[.]')

        # Defang slashes
        if '://' in value:
            value = value.replace('://', '[://]')

        # Defang IPv4 dots
        if all(c.isdigit() or c == '.' for c in value):
            parts = value.split('.')
            if len(parts) == 4:
                value = '[.]'.join(parts)

        return value

    @staticmethod
    def _calculate_threat_level(risk_score: float) -> str:
        """
        Calculate threat level from risk score.
        
        Args:
            risk_score: 0-100 risk score
            
        Returns:
            Threat level: critical, high, medium, low
        """
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'


def export_forensic_to_csv(case_id: str, forensic_data: Dict[str, Any], defang: bool = True) -> str:
    """
    Export forensic findings to CSV IOC format.
    
    Args:
        case_id: Case identifier
        forensic_data: Forensic analysis data
        defang: If True, defang IOCs
        
    Returns:
        CSV string with IOCs
    """
    exporter = CSVExporter(case_id, forensic_data, defang=defang)
    return exporter.generate_csv()
