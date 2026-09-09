"""
Individual page testing and validation.

Tests each of the 7 pages with different data scenarios to ensure
proper rendering and data presentation.
"""

import io
import json
from typing import Dict, Any

from .report_builder import PDFReportBuilder


def create_phishing_case() -> Dict[str, Any]:
    """Phishing with SPF/DKIM failures and Tor detection."""
    return {
        'case_id': 'CASE-2024-PHISHING-001',
        'threat_category': 'Phishing',
        'final_risk': 92,
        'verdict': 'MALICIOUS',
        'confidence': 95,
        'analysis_timestamp': '2024-01-15T14:32:00Z',
        'why_flagged': [
            'spf_fail',
            'dkim_fail',
            'tor_detected',
            'urgency_trigger',
            'request_credentials'
        ],
        'email_metadata': {
            'sender': 'admin@bank-security.com',
            'recipient': 'user@company.com',
            'subject': 'URGENT: Verify Your Account Now',
            'timestamp': '2024-01-15T14:32:00Z',
            'message_id': '<20240115143200.ABC@bank-security.com>',
            'hash_sha256': 'cf270edc59dafa6d10c184e07be53d4c27c9918bdcbfdbb84dfe0e68d1dbb082'
        },
        'authentication': {
            'spf': {
                'status': 'fail',
                'policy': 'v=spf1 include:_spf.bank.com ~all',
                'authorized_ips': '192.0.2.0/24',
                'details': 'Sending IP 198.51.100.88 not in SPF record'
            },
            'dkim': {
                'status': 'invalid',
                'domain': 'bank-security.com',
                'selector': 'default',
                'public_key_id': 'unknown',
                'details': 'DKIM signature missing or invalid'
            },
            'dmarc': {
                'status': 'fail',
                'policy': 'p=quarantine',
                'domain': 'bank-security.com',
                'alignment': 'fail',
                'details': 'DMARC alignment failed: SPF and DKIM did not align'
            }
        },
        'relay_hops': [
            {
                'hop_number': 1,
                'timestamp': '2024-01-15T14:31:00Z',
                'ip': '203.0.113.100',
                'organization': 'AttackerISP',
                'country': 'Russia',
                'city': 'Moscow',
                'is_private': False,
                'is_origin': False
            },
            {
                'hop_number': 2,
                'timestamp': '2024-01-15T14:31:30Z',
                'ip': '198.51.100.88',
                'organization': 'Tor Exit Node',
                'country': 'Netherlands',
                'city': 'Amsterdam',
                'is_private': False,
                'is_origin': True,
                'anonymization_type': 'tor'
            },
            {
                'hop_number': 3,
                'timestamp': '2024-01-15T14:32:00Z',
                'ip': '192.0.2.50',
                'organization': 'Company Mail Gateway',
                'country': 'United States',
                'city': 'New York',
                'is_private': False,
                'is_origin': False
            }
        ],
        'originating_node': {
            'ip': '198.51.100.88',
            'organization': 'Tor Exit Node',
            'asn': 'AS3352',
            'country': 'Netherlands',
            'city': 'Amsterdam',
            'is_private': False,
            'anonymization_type': 'tor',
            'vpn_provider': 'Tor Network',
            'abuse_confidence': 98,
            'threat_reports': 342
        },
        'campaign': {
            'id': 'CAMPAIGN-2024-PHISH-BANK-001',
            'name': 'Banking Credential Harvesting Campaign',
            'description': 'Widespread phishing targeting financial institution customers',
            'attribution_confidence': 87,
            'first_seen': '2024-01-01',
            'last_seen': '2024-01-15',
            'historical_count': 5234,
            'ttps': [
                'T1566.002: Phishing - Spearphishing Link',
                'T1598.003: Phishing for Information',
                'T1110.004: Brute Force - Credential Stuffing'
            ]
        },
        'evidence': [
            {
                'type': 'email_header',
                'timestamp': '2024-01-15T14:32:00Z',
                'description': 'Original email headers',
                'hash': 'cf270edc59dafa6d10c184e07be53d4c27c9918bdcbfdbb84dfe0e68d1dbb082',
                'preserved': True
            },
            {
                'type': 'threat_intelligence',
                'timestamp': '2024-01-15T14:32:20Z',
                'description': 'Tor exit node correlation',
                'status': 'recorded',
                'preserved': True
            }
        ],
        'threat_dna': {
            'attributes': {
                'urgency_language': 0.95,
                'credential_request': 0.92,
                'brand_impersonation': 0.88,
                'suspicious_infrastructure': 0.98,
                'malware_indicators': 0.10,
                'data_exfiltration': 0.05
            },
            'patterns': [
                'High urgency language',
                'Explicit credential request',
                'Brand spoofing',
                'Tor exit node infrastructure',
                'Campaign correlation'
            ]
        }
    }


def create_bec_case() -> Dict[str, Any]:
    """Business Email Compromise with clean auth but suspicious content."""
    return {
        'case_id': 'CASE-2024-BEC-001',
        'threat_category': 'Business Email Compromise',
        'final_risk': 72,
        'verdict': 'SUSPICIOUS',
        'confidence': 78,
        'analysis_timestamp': '2024-01-16T09:15:00Z',
        'why_flagged': [
            'urgency_trigger',
            'request_credentials',
            'unusual_sender_domain'
        ],
        'email_metadata': {
            'sender': 'cfo@legitimate-company.com',
            'recipient': 'accounts@payroll.company.com',
            'subject': 'Urgent wire transfer needed - process immediately',
            'timestamp': '2024-01-16T09:15:00Z',
            'message_id': '<20240116091500.XYZ@legitimate-company.com>',
            'hash_sha256': 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
        },
        'authentication': {
            'spf': {
                'status': 'pass',
                'policy': 'v=spf1 ip4:192.0.2.0/24 ~all',
                'authorized_ips': '192.0.2.5',
                'details': 'SPF check passed'
            },
            'dkim': {
                'status': 'pass',
                'domain': 'legitimate-company.com',
                'selector': 'default',
                'public_key_id': 'rsa.dkim.2024',
                'details': 'Valid DKIM signature present'
            },
            'dmarc': {
                'status': 'pass',
                'policy': 'p=reject',
                'domain': 'legitimate-company.com',
                'alignment': 'pass',
                'details': 'DMARC check passed'
            }
        },
        'relay_hops': [
            {
                'hop_number': 1,
                'timestamp': '2024-01-16T09:14:30Z',
                'ip': '192.0.2.5',
                'organization': 'Legitimate Company',
                'country': 'United States',
                'city': 'New York',
                'is_private': False,
                'is_origin': True
            },
            {
                'hop_number': 2,
                'timestamp': '2024-01-16T09:15:00Z',
                'ip': '192.0.2.10',
                'organization': 'Company Mail Gateway',
                'country': 'United States',
                'city': 'New York',
                'is_private': False,
                'is_origin': False
            }
        ],
        'originating_node': {
            'ip': '192.0.2.5',
            'organization': 'Legitimate Company',
            'asn': 'AS64496',
            'country': 'United States',
            'city': 'New York',
            'is_private': False,
            'anonymization_type': None,
            'vpn_provider': None,
            'abuse_confidence': 2,
            'threat_reports': 0
        },
        'campaign': {
            'id': 'CAMPAIGN-2024-BEC-001',
            'name': 'Wire Transfer Fraud Campaign',
            'attribution_confidence': 65,
            'first_seen': '2024-01-10',
            'last_seen': '2024-01-16',
            'historical_count': 127
        },
        'evidence': [
            {
                'type': 'email_header',
                'timestamp': '2024-01-16T09:15:00Z',
                'description': 'Original email headers',
                'hash': 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
                'preserved': True
            }
        ],
        'threat_dna': {
            'attributes': {
                'urgency_language': 0.88,
                'credential_request': 0.45,
                'brand_impersonation': 0.10,
                'suspicious_infrastructure': 0.15,
                'malware_indicators': 0.05,
                'data_exfiltration': 0.75
            },
            'patterns': [
                'Urgency and time pressure',
                'Financial transaction request',
                'Unusual sender behavior',
                'Campaign correlation',
                'Data exfiltration attempt'
            ]
        }
    }


def create_malware_case() -> Dict[str, Any]:
    """Malware with attachment."""
    return {
        'case_id': 'CASE-2024-MALWARE-001',
        'threat_category': 'Malware',
        'final_risk': 95,
        'verdict': 'MALICIOUS',
        'confidence': 99,
        'analysis_timestamp': '2024-01-17T11:22:00Z',
        'why_flagged': [
            'attachment_malicious',
            'suspicious_link',
            'dkim_fail',
            'vpn_detected'
        ],
        'email_metadata': {
            'sender': 'noreply@service-update.com',
            'recipient': 'user@company.com',
            'subject': 'Software Update Required - Click Here',
            'timestamp': '2024-01-17T11:22:00Z',
            'message_id': '<20240117112200.MAL@service-update.com>',
            'hash_sha256': 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
        },
        'authentication': {
            'spf': {
                'status': 'none',
                'policy': 'Not found',
                'authorized_ips': 'None',
                'details': 'Domain has no SPF record'
            },
            'dkim': {
                'status': 'fail',
                'domain': 'service-update.com',
                'selector': 'unknown',
                'public_key_id': 'not_found',
                'details': 'DKIM public key not found'
            },
            'dmarc': {
                'status': 'none',
                'policy': 'Not found',
                'domain': 'service-update.com',
                'alignment': 'fail',
                'details': 'No DMARC policy configured'
            }
        },
        'relay_hops': [
            {
                'hop_number': 1,
                'timestamp': '2024-01-17T11:21:00Z',
                'ip': '45.142.120.50',
                'organization': 'Suspicious Hosting',
                'country': 'Romania',
                'city': 'Bucharest',
                'is_private': False,
                'is_origin': True
            },
            {
                'hop_number': 2,
                'timestamp': '2024-01-17T11:22:00Z',
                'ip': '192.0.2.20',
                'organization': 'Company Mail Gateway',
                'country': 'United States',
                'city': 'New York',
                'is_private': False,
                'is_origin': False
            }
        ],
        'originating_node': {
            'ip': '45.142.120.50',
            'organization': 'HostEurope Malware',
            'asn': 'AS201814',
            'country': 'Romania',
            'city': 'Bucharest',
            'is_private': False,
            'anonymization_type': 'vpn',
            'vpn_provider': 'Commercial VPN',
            'abuse_confidence': 87,
            'threat_reports': 156
        },
        'campaign': {
            'id': 'CAMPAIGN-2024-MAL-DIST-001',
            'name': 'Trojan Distribution Campaign',
            'attribution_confidence': 92,
            'first_seen': '2024-01-10',
            'last_seen': '2024-01-17',
            'historical_count': 8934
        },
        'evidence': [
            {
                'type': 'email_header',
                'timestamp': '2024-01-17T11:22:00Z',
                'description': 'Original email headers',
                'hash': 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
                'preserved': True
            },
            {
                'type': 'malware_analysis',
                'timestamp': '2024-01-17T11:22:30Z',
                'description': 'Attachment flagged as malware',
                'status': 'quarantined',
                'preserved': True
            }
        ],
        'threat_dna': {
            'attributes': {
                'urgency_language': 0.75,
                'credential_request': 0.15,
                'brand_impersonation': 0.70,
                'suspicious_infrastructure': 0.92,
                'malware_indicators': 0.98,
                'data_exfiltration': 0.45
            },
            'patterns': [
                'Malware attachment detected',
                'Suspicious hosting infrastructure',
                'VPN obfuscation',
                'Software impersonation',
                'Campaign correlation'
            ]
        }
    }


def create_safe_case() -> Dict[str, Any]:
    """Legitimate email - passes all authentication checks."""
    return {
        'case_id': 'CASE-2024-SAFE-001',
        'threat_category': 'Legitimate',
        'final_risk': 8,
        'verdict': 'SAFE',
        'confidence': 98,
        'analysis_timestamp': '2024-01-18T16:45:00Z',
        'why_flagged': [],
        'email_metadata': {
            'sender': 'newsletter@microsoft.com',
            'recipient': 'user@company.com',
            'subject': 'Security Update: January 2024',
            'timestamp': '2024-01-18T16:45:00Z',
            'message_id': '<20240118164500.SAFE@microsoft.com>',
            'hash_sha256': 'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe'
        },
        'authentication': {
            'spf': {
                'status': 'pass',
                'policy': 'v=spf1 ip4:198.51.100.0/24 ~all',
                'authorized_ips': '198.51.100.10',
                'details': 'SPF check passed'
            },
            'dkim': {
                'status': 'pass',
                'domain': 'microsoft.com',
                'selector': 'selector1',
                'public_key_id': 'rsa.dkim.2024',
                'details': 'Valid DKIM signature verified'
            },
            'dmarc': {
                'status': 'pass',
                'policy': 'p=reject',
                'domain': 'microsoft.com',
                'alignment': 'pass',
                'details': 'DMARC policy alignment verified'
            }
        },
        'relay_hops': [
            {
                'hop_number': 1,
                'timestamp': '2024-01-18T16:44:00Z',
                'ip': '198.51.100.10',
                'organization': 'Microsoft',
                'country': 'United States',
                'city': 'Seattle',
                'is_private': False,
                'is_origin': True
            },
            {
                'hop_number': 2,
                'timestamp': '2024-01-18T16:45:00Z',
                'ip': '192.0.2.25',
                'organization': 'Company Mail Gateway',
                'country': 'United States',
                'city': 'New York',
                'is_private': False,
                'is_origin': False
            }
        ],
        'originating_node': {
            'ip': '198.51.100.10',
            'organization': 'Microsoft',
            'asn': 'AS8075',
            'country': 'United States',
            'city': 'Seattle',
            'is_private': False,
            'anonymization_type': None,
            'vpn_provider': None,
            'abuse_confidence': 0,
            'threat_reports': 0
        },
        'campaign': {},
        'evidence': [
            {
                'type': 'email_header',
                'timestamp': '2024-01-18T16:45:00Z',
                'description': 'Original email headers',
                'hash': 'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe',
                'preserved': True
            }
        ],
        'threat_dna': {
            'attributes': {
                'urgency_language': 0.05,
                'credential_request': 0.00,
                'brand_impersonation': 0.00,
                'suspicious_infrastructure': 0.00,
                'malware_indicators': 0.00,
                'data_exfiltration': 0.00
            },
            'patterns': [
                'Legitimate sender domain',
                'Authentication passed',
                'No suspicious indicators'
            ]
        }
    }


def test_page_rendering(case_name: str, forensic_data: Dict[str, Any]) -> bool:
    """
    Test PDF generation for a specific case.
    
    Returns True if successful, False otherwise.
    """
    builder = PDFReportBuilder(case_id=forensic_data['case_id'])

    try:
        pdf_bytes, metadata = builder.generate_pdf(forensic_data)

        print(f"\n✓ {case_name}")
        print(f"  Status: {metadata['status']}")
        print(f"  Pages: {metadata['pages']}")
        print(f"  Size: {len(pdf_bytes) / 1024:.1f} KB")
        print(f"  Warnings: {len(metadata['validation_warnings'])}")

        # Verify PDF is valid
        if not pdf_bytes.startswith(b'%PDF'):
            print(f"  ✗ Invalid PDF header")
            return False

        return metadata['status'] == 'success'

    except Exception as e:
        print(f"\n✗ {case_name}")
        print(f"  Error: {str(e)[:100]}")
        return False


def run_page_tests():
    """Run comprehensive page rendering tests."""
    print("\n" + "="*60)
    print("SpectraShield 2.0 - Page Rendering Tests")
    print("="*60)

    test_cases = [
        ("Phishing Attack", create_phishing_case()),
        ("Business Email Compromise", create_bec_case()),
        ("Malware Distribution", create_malware_case()),
        ("Legitimate Email", create_safe_case()),
    ]

    passed = 0
    failed = 0

    for case_name, forensic_data in test_cases:
        if test_page_rendering(case_name, forensic_data):
            passed += 1
        else:
            failed += 1

    print("\n" + "="*60)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*60)

    return failed == 0


if __name__ == '__main__':
    success = run_page_tests()
    exit(0 if success else 1)
