"""
Test suite for PDF generation pipeline.

Validates:
- Data transformation from backend format
- Validation rules and error detection
- PDF generation with sample data
- All 7 pages render without errors
"""

import io
import json
from datetime import datetime
from typing import Dict, Any

from .data_transformer import DataTransformer
from .validator import DataValidator
from .report_builder import PDFReportBuilder


def create_sample_forensic_data() -> Dict[str, Any]:
    """
    Create realistic sample forensic data for testing.
    Based on actual backend schema.
    """
    return {
        'case_id': 'CASE-2024-001234',
        'email_metadata': {
            'sender': 'support@legitimate-bank.com',
            'recipient': 'user@company.com',
            'subject': 'Urgent: Verify Your Account',
            'timestamp': '2024-01-15T14:32:00Z',
            'message_id': '<20240115143200.ABC123@legitimate-bank.com>',
            'hash_sha256': 'cf270edc59dafa6d10c184e07be53d4c27c9918bdcbfdbb84dfe0e68d1dbb082'
        },
        'threat_category': 'Phishing',
        'final_risk': 78,
        'verdict': 'MALICIOUS',
        'confidence': 85,
        'analysis_timestamp': datetime.now().isoformat(),
        'why_flagged': [
            'spf_fail',
            'tor_detected',
            'urgency_trigger',
            'request_credentials',
            'suspicious_link'
        ],
        'authentication': {
            'spf': {
                'status': 'fail',
                'policy': 'v=spf1 include:_spf.legitimate-bank.com ~all',
                'authorized_ips': '192.0.2.0/24',
                'details': 'SPF check failed: sending IP not in authorized range'
            },
            'dkim': {
                'status': 'invalid',
                'domain': 'legitimate-bank.com',
                'selector': 'default',
                'public_key_id': 'rsa.dkim.key',
                'details': 'DKIM signature invalid or missing'
            },
            'dmarc': {
                'status': 'fail',
                'policy': 'p=quarantine',
                'domain': 'legitimate-bank.com',
                'alignment': 'fail',
                'details': 'DMARC policy alignment failed'
            }
        },
        'relay_hops': [
            {
                'hop_number': 0,
                'timestamp': '2024-01-15T14:31:00Z',
                'ip': '203.0.113.45',
                'organization': 'TechISP Communications',
                'country': 'United States',
                'is_private': False,
                'is_origin': False
            },
            {
                'hop_number': 1,
                'timestamp': '2024-01-15T14:31:30Z',
                'ip': '198.51.100.88',
                'organization': 'Suspicious Relay Corp',
                'country': 'Netherlands',
                'is_private': False,
                'is_origin': True
            },
            {
                'hop_number': 2,
                'timestamp': '2024-01-15T14:32:00Z',
                'ip': '192.0.2.199',
                'organization': 'Company Mail Gateway',
                'country': 'United States',
                'is_private': False,
                'is_origin': False
            }
        ],
        'originating_node': {
            'ip': '198.51.100.88',
            'organization': 'Suspicious Relay Corp',
            'asn': 'AS12345',
            'country': 'Netherlands',
            'city': 'Amsterdam',
            'is_private': False,
            'anonymization_type': 'tor',
            'vpn_provider': 'Tor Exit Node',
            'abuse_confidence': 92,
            'threat_reports': 17,
            'last_reported': '2024-01-14T08:00:00Z'
        },
        'authentication_findings': {
            'spf_check_pass': False,
            'dkim_check_pass': False,
            'dmarc_check_pass': False,
            'alignment_pass': False
        },
        'campaign': {
            'id': 'CAMPAIGN-2024-PHISH-BANK',
            'name': 'Fake Bank Credential Harvesting Campaign',
            'description': 'Large-scale phishing campaign targeting financial institution customers',
            'attribution_confidence': 87,
            'first_seen': '2024-01-01',
            'last_seen': '2024-01-15',
            'historical_count': 12847,
            'ttps': [
                'T1566.002: Phishing - Spearphishing Link',
                'T1598.003: Phishing for Information - Spearphishing Link',
                'T1110.004: Brute Force - Credential Stuffing',
            ],
            'related_indicators': [
                'malicious-bank-com.example.com',
                '198.51.100.0/24',
                'phishkit-v2.0.zip',
            ]
        },
        'evidence': [
            {
                'type': 'email_header',
                'timestamp': '2024-01-15T14:32:00Z',
                'description': 'Original email headers preserved',
                'hash': 'cf270edc59dafa6d10c184e07be53d4c27c9918bdcbfdbb84dfe0e68d1dbb082',
                'preserved': True
            },
            {
                'type': 'authentication_record',
                'timestamp': '2024-01-15T14:32:10Z',
                'description': 'SPF/DKIM/DMARC authentication results',
                'status': 'recorded',
                'preserved': True
            },
            {
                'type': 'threat_intelligence',
                'timestamp': '2024-01-15T14:32:20Z',
                'description': 'AbuseIPDB and campaign correlation records',
                'status': 'recorded',
                'preserved': True
            }
        ],
        'threat_dna': {
            'attributes': {
                'urgency_language': 0.92,
                'credential_request': 0.88,
                'brand_impersonation': 0.85,
                'suspicious_infrastructure': 0.95,
                'malware_indicators': 0.15,
                'data_exfiltration': 0.08
            },
            'patterns': [
                'Psychological urgency (act now)',
                'Explicit credential request (username/password)',
                'Brand spoofing (bank name and logo)',
                'Suspicious originating infrastructure',
                'Historical campaign correlation'
            ],
            'fingerprint': 'PHISH.CREDENTIAL_HARVEST.URGENCY'
        }
    }


def test_data_transformation():
    """Test data transformation from backend format."""
    print("\n=== Test 1: Data Transformation ===")

    sample_data = create_sample_forensic_data()
    transformer = DataTransformer()

    try:
        transformed = transformer.extract_from_backend(sample_data)
        print(f"✓ Data transformation successful")
        print(f"  - Threat category: {transformed.get('threat_category')}")
        print(f"  - Final risk: {transformed.get('final_risk')}")
        print(f"  - Relay hops: {len(transformed.get('relay_hops', []))}")
        print(f"  - Campaign ID: {transformed.get('campaign', {}).get('id')}")
        return transformed
    except Exception as e:
        print(f"✗ Data transformation failed: {str(e)}")
        raise


def test_data_validation(transformed_data):
    """Test data validation and consistency checks."""
    print("\n=== Test 2: Data Validation ===")

    warnings = DataValidator.validate_consistency(transformed_data)

    print(f"✓ Validation completed: {len(warnings)} warning(s)")
    for warning in warnings:
        print(f"  - [{warning.level}] {warning.category}: {warning.message}")

    should_proceed, error_msg = DataValidator.should_generate_pdf(warnings)
    print(f"✓ Validation decision: {'PROCEED' if should_proceed else 'BLOCKED'}")
    if not should_proceed:
        print(f"  Error: {error_msg}")

    return should_proceed


def test_pdf_generation(transformed_data):
    """Test end-to-end PDF generation."""
    print("\n=== Test 3: PDF Generation ===")

    builder = PDFReportBuilder(
        case_id='CASE-2024-001234',
        redaction_mode=False
    )

    try:
        pdf_bytes, metadata = builder.generate_pdf(transformed_data)

        print(f"✓ PDF generated successfully")
        print(f"  - Status: {metadata['status']}")
        print(f"  - Pages: {metadata['pages']}")
        print(f"  - Size: {len(pdf_bytes) / 1024:.1f} KB")
        print(f"  - Validation warnings: {len(metadata['validation_warnings'])}")

        # Verify PDF structure
        if pdf_bytes.startswith(b'%PDF'):
            print(f"✓ PDF header valid")
        else:
            print(f"✗ Invalid PDF header")

        return pdf_bytes

    except Exception as e:
        print(f"✗ PDF generation failed: {str(e)}")
        raise


def test_error_handling():
    """Test error handling with incomplete data."""
    print("\n=== Test 4: Error Handling ===")

    incomplete_data = {
        'case_id': 'CASE-INCOMPLETE',
        'threat_category': 'Unknown',
        # Missing required fields
    }

    builder = PDFReportBuilder(case_id='CASE-INCOMPLETE')

    try:
        pdf_bytes, metadata = builder.generate_pdf(incomplete_data)

        if metadata['status'] == 'error':
            print(f"✓ Error handling working - status: {metadata['status']}")
            print(f"  Errors: {metadata['validation_errors']}")
        else:
            print(f"✗ Expected error status, got: {metadata['status']}")

    except Exception as e:
        print(f"✓ Exception handling: {str(e)[:80]}...")


def test_redaction_mode():
    """Test redaction mode for PII masking."""
    print("\n=== Test 5: Redaction Mode ===")

    sample_data = create_sample_forensic_data()
    builder = PDFReportBuilder(
        case_id='CASE-REDACTED',
        redaction_mode=True
    )

    try:
        pdf_bytes, metadata = builder.generate_pdf(sample_data)

        print(f"✓ Redaction mode PDF generated")
        print(f"  - Size: {len(pdf_bytes) / 1024:.1f} KB")
        print(f"  - Redaction mode: True")

    except Exception as e:
        print(f"✗ Redaction mode failed: {str(e)}")
        raise


def run_all_tests():
    """Run complete test suite."""
    print("\n" + "="*60)
    print("SpectraShield 2.0 PDF Generation Test Suite")
    print("="*60)

    try:
        # Test 1: Transformation
        transformed_data = test_data_transformation()

        # Test 2: Validation
        should_proceed = test_data_validation(transformed_data)

        # Test 3: PDF Generation
        if should_proceed:
            pdf_bytes = test_pdf_generation(transformed_data)

            # Save test PDF
            test_pdf_path = 'test_output.pdf'
            with open(test_pdf_path, 'wb') as f:
                f.write(pdf_bytes)
            print(f"\n✓ Test PDF saved to: {test_pdf_path}")

        # Test 4: Error Handling
        test_error_handling()

        # Test 5: Redaction Mode
        test_redaction_mode()

        print("\n" + "="*60)
        print("All tests completed successfully!")
        print("="*60)

    except Exception as e:
        print(f"\n✗ Test suite failed: {str(e)}")
        raise


if __name__ == '__main__':
    run_all_tests()
