"""
STIX 2.1 Exporter: Converts forensic findings to STIX bundle for SIEM/SOAR.

Generates STIX 2.1 compliant JSON that includes:
- Campaign objects
- Infrastructure profiles
- Malware/tools
- Attack patterns (MITRE ATT&CK)
- Indicators (IOCs)
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from enum import Enum


class STIXExporter:
    """Exports forensic findings to STIX 2.1 JSON bundle."""

    # STIX Bundle metadata
    STIX_VERSION = "2.1"
    PRODUCER = "SpectraShield-2.0-Forensic-Agent"

    def __init__(self, case_id: str, forensic_data: Dict[str, Any]):
        """
        Initialize STIX exporter.
        
        Args:
            case_id: Case identifier
            forensic_data: Forensic analysis data
        """
        self.case_id = case_id
        self.forensic_data = forensic_data
        self.objects = []
        self.relationships = []

    def generate_bundle(self) -> Dict[str, Any]:
        """
        Generate complete STIX bundle.
        
        Returns:
            STIX 2.1 bundle JSON
        """
        # Create initial objects from forensic data
        self._extract_campaign()
        self._extract_infrastructure()
        self._extract_indicators()
        self._extract_attack_patterns()
        self._extract_identity()

        # Create relationships
        self._create_relationships()

        # Build bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": self.objects,
            "created": datetime.now(timezone.utc).isoformat()
        }

        return bundle

    def _extract_campaign(self) -> None:
        """Extract campaign object from forensic data."""
        campaign = self.forensic_data.get('campaign', {})

        if not campaign.get('id'):
            return

        campaign_obj = {
            "type": "campaign",
            "id": f"campaign--{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": campaign.get('name', 'Unknown Campaign'),
            "description": campaign.get('description', ''),
            "created_by_ref": f"identity--{self.case_id}",
            "x_forensic_case_id": self.case_id,
            "x_confidence": int(campaign.get('attribution_confidence', 70))
        }

        # Add aliases if campaign has other names
        if campaign.get('aliases'):
            campaign_obj['aliases'] = campaign['aliases']

        self.objects.append(campaign_obj)
        self.campaign_id = campaign_obj['id']

    def _extract_infrastructure(self) -> None:
        """Extract infrastructure objects (IP, ASN, etc.)."""
        origin_node = self.forensic_data.get('originating_node', {})

        if not origin_node.get('ip'):
            return

        # IP Address object
        ip = origin_node.get('ip')
        ip_obj = {
            "type": "ipv4-addr",
            "id": f"ipv4-addr--{uuid.uuid4()}",
            "value": ip,
            "x_abuse_confidence": origin_node.get('abuse_confidence', 0),
            "x_threat_reports": origin_node.get('threat_reports', 0)
        }

        self.objects.append(ip_obj)
        self.ip_id = ip_obj['id']

        # Autonomous System object
        asn = origin_node.get('asn')
        if asn:
            asn_obj = {
                "type": "autonomous-system",
                "id": f"autonomous-system--{uuid.uuid4()}",
                "number": int(asn.replace('AS', '')) if asn.startswith('AS') else 0,
                "x_asn_string": asn,
                "x_organization": origin_node.get('organization', '')
            }
            self.objects.append(asn_obj)
            self.asn_id = asn_obj['id']

    def _extract_indicators(self) -> None:
        """Extract indicators (IOCs) from findings."""
        indicators = []

        # Campaign indicators
        campaign = self.forensic_data.get('campaign', {})
        for indicator in campaign.get('related_indicators', []):
            indicator_obj = self._create_indicator(indicator)
            if indicator_obj:
                indicators.append(indicator_obj)

        # Email indicators
        email_meta = self.forensic_data.get('email_metadata', {})
        sender_val = email_meta.get('sender')
        if isinstance(sender_val, dict):
            sender_val = sender_val.get('email')
        if sender_val and isinstance(sender_val, str):
            sender_ind = self._create_indicator(sender_val)
            if sender_ind:
                indicators.append(sender_ind)

        # Authentication domain indicators
        auth = self.forensic_data.get('authentication', {})
        for proto, details in auth.items():
            if isinstance(details, dict) and details.get('domain'):
                domain_ind = self._create_indicator(details['domain'])
                if domain_ind:
                    indicators.append(domain_ind)

        self.objects.extend(indicators)

    def _create_indicator(self, value: str) -> Dict[str, Any]:
        """
        Create STIX indicator from value.
        
        Args:
            value: IOC value (domain, email, IP, hash)
            
        Returns:
            STIX indicator object or None
        """
        if not value:
            return None

        indicator_obj = {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "pattern": self._create_pattern(value),
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "labels": ["malicious-activity"],
            "x_forensic_case_id": self.case_id
        }

        return indicator_obj

    @staticmethod
    def _create_pattern(value: str) -> str:
        """
        Create STIX pattern from IOC value.
        
        Args:
            value: IOC value
            
        Returns:
            STIX pattern string
        """
        # Detect type
        if '@' in value and '.' in value:
            # Email
            return f"[email-addr:value = '{value}']"
        elif value.startswith('http'):
            # URL
            return f"[url:value = '{value}']"
        elif all(c.isdigit() or c == '.' for c in value) and len(value.split('.')) == 4:
            # IPv4
            return f"[ipv4-addr:value = '{value}']"
        elif '.' in value and all(c.isalnum() or c in '.-' for c in value):
            # Domain
            return f"[domain-name:value = '{value}']"
        elif len(value) == 64 and all(c in '0123456789abcdefABCDEF' for c in value):
            # SHA256
            return f"[file:hashes.SHA-256 = '{value.lower()}']"
        else:
            # Generic
            return f"[x-custom:value = '{value}']"

    def _extract_attack_patterns(self) -> None:
        """Extract attack patterns (MITRE ATT&CK) from campaign."""
        campaign = self.forensic_data.get('campaign', {})
        ttps = campaign.get('ttps', [])

        for ttp in ttps:
            # Parse MITRE ATT&CK ID
            if 'T' in ttp and ':' in ttp:
                ttp_id, ttp_name = ttp.split(':', 1)
                ttp_id = ttp_id.strip()
                ttp_name = ttp_name.strip()
            else:
                ttp_id = ttp
                ttp_name = ttp

            pattern_obj = {
                "type": "attack-pattern",
                "id": f"attack-pattern--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": ttp_name,
                "x_mitre_id": ttp_id if ttp_id.startswith('T') else None,
                "x_forensic_case_id": self.case_id
            }

            self.objects.append(pattern_obj)

    def _extract_identity(self) -> None:
        """Create identity object for this analysis."""
        identity_obj = {
            "type": "identity",
            "id": f"identity--{self.case_id}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": f"SpectraShield Case {self.case_id}",
            "identity_class": "organization",
            "x_threat_assessment": {
                "verdict": self.forensic_data.get('verdict', 'EVALUATED'),
                "risk_score": self.forensic_data.get('final_risk', 0),
                "confidence": self.forensic_data.get('confidence', 0),
                "threat_category": self.forensic_data.get('threat_category', 'Unknown')
            }
        }

        self.objects.append(identity_obj)

    def _create_relationships(self) -> None:
        """Create relationship objects between STIX objects."""
        # Campaign to infrastructure
        if hasattr(self, 'campaign_id') and hasattr(self, 'ip_id'):
            rel = {
                "type": "relationship",
                "id": f"relationship--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "relationship_type": "uses",
                "source_ref": self.campaign_id,
                "target_ref": self.ip_id
            }
            self.objects.append(rel)


def export_forensic_to_stix(case_id: str, forensic_data: Dict[str, Any]) -> str:
    """
    Export forensic findings to STIX 2.1 JSON.
    
    Args:
        case_id: Case identifier
        forensic_data: Forensic analysis data
        
    Returns:
        JSON string containing STIX bundle
    """
    exporter = STIXExporter(case_id, forensic_data)
    bundle = exporter.generate_bundle()

    return json.dumps(bundle, indent=2)
