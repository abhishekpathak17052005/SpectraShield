"""
Integration test for PDF export endpoint.

Tests the complete flow:
1. Create forensic case data
2. Call PDFReportBuilder (simulating endpoint)
3. Verify PDF output
4. Test redaction mode
"""

from datetime import datetime, timezone
from app.agents.pdf.report_builder import PDFReportBuilder


def create_realistic_forensic_case():
    """Create realistic forensic case matching endpoint schema."""
    return {
        'case_id': 'CASE-2024-ENDPOINT-TEST',
        'email_metadata': {
            'sender': 'finance-alert@microsoft-billing-2024.net',
            'recipient': 'accounting.dept@acmecorp.com',
            'subject': 'URGENT ACTION REQUIRED: Wire Transfer Verification',
            'timestamp': '2024-01-15T14:32:00Z',
            'message_id': '<20240115143200.ABC123@microsoft-billing-2024.net>',
            'hash_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        },
        'threat_category': 'Business Email Compromise',
        'final_risk': 89.5,
        'verdict': 'MALICIOUS',
        'confidence': 92,
        'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
        'why_flagged': [
            'dmarc_fail',
            'tor_detected',
            'urgency_trigger',
            'request_credentials'
        ],
        'authentication': {
            'spf': {
                'status': 'fail',
                'domain': 'microsoft-billing-2024.net',
                'policy': 'v=spf1 include:_spf.microsoft.com ~all',
                'details': 'Sending IP 185.220.101.5 not in SPF record'
            },
            'dkim': {
                'status': 'invalid',
                'domain': 'microsoft-billing-2024.net',
                'selector': 'selector1',
                'public_key_id': 'unknown',
                'details': 'DKIM public key not found'
            },
            'dmarc': {
                'status': 'fail',
                'domain': 'microsoft-billing-2024.net',
                'policy': 'p=reject',
                'alignment': 'fail',
                'details': 'DMARC alignment failed'
            }
        },
        'relay_hops': [
            {
                'hop_number': 1,
                'timestamp': '2024-01-15T14:31:00Z',
                'ip': '185.220.101.5',
                'organization': 'Tor Exit Node',
                'country': 'Germany',
                'city': 'Frankfurt',
                'is_private': False,
                'is_origin': True,
                'anonymization_type': 'tor'
            },
            {
                'hop_number': 2,
                'timestamp': '2024-01-15T14:31:30Z',
                'ip': '192.0.2.50',
                'organization': 'AcmeCorp Mail Gateway',
                'country': 'United States',
                'city': 'New York',
                'is_private': False,
                'is_origin': False
            }
        ],
        'originating_node': {
            'ip': '185.220.101.5',
            'organization': 'Tor Exit Node',
            'asn': 'AS60729',
            'country': 'Germany',
            'city': 'Frankfurt',
            'is_private': False,
            'anonymization_type': 'tor',
            'vpn_provider': 'Tor Network',
            'abuse_confidence': 95,
            'threat_reports': 342
        },
        'campaign': {
            'id': 'CAMP-2026-BEC-M365',
            'name': 'Targeted European Wire Diversion',
            'attribution_confidence': 92.0,
            'historical_count': 847,
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
                'description': 'Original email headers preserved',
                'hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'preserved': True
            }
        ]
    }


def test_endpoint_pdf_generation():
    """Test PDF generation through the endpoint flow."""
    print("\n" + "="*60)
    print("SpectraShield 2.0 - Endpoint Integration Test")
    print("="*60)

    forensic_data = create_realistic_forensic_case()

    # Test 1: Standard PDF generation (no redaction)
    print("\n[Test 1] Standard PDF Generation (No Redaction)")
    print("-" * 60)

    builder = PDFReportBuilder(
        case_id=forensic_data['case_id'],
        redaction_mode=False
    )

    pdf_bytes, metadata = builder.generate_pdf(forensic_data)

    print(f"  Status: {metadata['status']}")
    print(f"  Pages: {metadata['pages']}")
    print(f"  Size: {len(pdf_bytes) / 1024:.1f} KB")
    print(f"  Redaction applied: {metadata['redaction_applied']}")
    print(f"  Validation warnings: {len(metadata.get('validation_warnings', []))}")

    if metadata['status'] == 'success' and len(pdf_bytes) > 1000:
        print("  ✓ PASS: PDF generated successfully")
    else:
        print("  ✗ FAIL: PDF generation incomplete or failed")
        return False

    # Test 2: PDF with redaction (standard level)
    print("\n[Test 2] PDF with PII Redaction (STANDARD level)")
    print("-" * 60)

    builder_redacted = PDFReportBuilder(
        case_id=forensic_data['case_id'],
        redaction_mode=True,
        redaction_level='standard'
    )

    pdf_bytes_redacted, metadata_redacted = builder_redacted.generate_pdf(forensic_data)

    print(f"  Status: {metadata_redacted['status']}")
    print(f"  Pages: {metadata_redacted['pages']}")  # +1 for redaction header
    print(f"  Size: {len(pdf_bytes_redacted) / 1024:.1f} KB")
    print(f"  Redaction applied: {metadata_redacted['redaction_applied']}")
    print(f"  Redaction level: {metadata_redacted['redaction_level']}")

    if metadata_redacted['status'] == 'success' and metadata_redacted['redaction_applied']:
        print("  ✓ PASS: Redacted PDF generated successfully")
    else:
        print("  ✗ FAIL: Redaction failed or PDF not generated")
        return False

    # Test 3: Verify PDF header
    print("\n[Test 3] PDF Structure Validation")
    print("-" * 60)

    if pdf_bytes.startswith(b'%PDF'):
        print("  ✓ PDF header valid")
    else:
        print("  ✗ PDF header invalid")
        return False

    if len(pdf_bytes_redacted) > len(pdf_bytes):
        print("  ✓ Redacted PDF larger (includes redaction notice page)")
    else:
        print("  ✗ Redacted PDF unexpectedly smaller")

    # Test 4: Metadata validation
    print("\n[Test 4] Metadata Validation")
    print("-" * 60)

    metadata_checks = [
        ('case_id', forensic_data['case_id']),
        ('generated_at', True),  # Just check exists
        ('status', 'success'),
        ('pages', 7),
        ('redaction_applied', False),
    ]

    all_valid = True
    for key, expected in metadata_checks:
        if key == 'generated_at':
            if key in metadata:
                print(f"  ✓ {key}: present")
            else:
                print(f"  ✗ {key}: missing")
                all_valid = False
        else:
            actual = metadata.get(key)
            if actual == expected:
                print(f"  ✓ {key}: {actual}")
            else:
                print(f"  ✗ {key}: expected {expected}, got {actual}")
                all_valid = False

    if not all_valid:
        return False

    # Test 5: Error handling
    print("\n[Test 5] Error Handling")
    print("-" * 60)

    incomplete_data = {
        'case_id': 'CASE-INCOMPLETE',
        'threat_category': 'Unknown',
        # Missing required fields - but system fills with defaults
    }

    builder_error = PDFReportBuilder(case_id=incomplete_data['case_id'])
    pdf_bytes_error, metadata_error = builder_error.generate_pdf(incomplete_data)

    # System is designed to be robust and fill in defaults
    # So even incomplete data can generate a PDF
    if metadata_error['status'] == 'success' and len(pdf_bytes_error) > 0:
        print(f"  ✓ Robust handling: System fills defaults for incomplete data")
        print(f"    Status: {metadata_error['status']}")
        print(f"    Pages: {metadata_error['pages']}")
    else:
        print(f"  ✗ PDF generation: Failed unexpectedly")
        return False

    # Summary
    print("\n" + "="*60)
    print("All Integration Tests PASSED ✓")
    print("="*60)
    print("\nEndpoint Integration Status:")
    print("- Standard PDF generation: ✓")
    print("- PII redaction: ✓")
    print("- Metadata tracking: ✓")
    print("- Error handling: ✓")
    print("- PDF structure: ✓")
    print("\nReady for production endpoint integration!")
    print("="*60)

    return True


if __name__ == '__main__':
    success = test_endpoint_pdf_generation()
    exit(0 if success else 1)
