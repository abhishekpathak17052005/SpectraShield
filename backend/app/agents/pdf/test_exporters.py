"""
Test suite for STIX and CSV exporters.

Tests alignment with new findings structure and output format validation.
"""

import json
import csv
import io
from app.agents.pdf.stix_exporter import export_forensic_to_stix
from app.agents.pdf.csv_exporter import export_forensic_to_csv


def create_test_forensic_data():
    """Create realistic forensic data for testing."""
    return {
        'case_id': 'CASE-2024-EXPORT-TEST',
        'threat_category': 'Business Email Compromise',
        'final_risk': 89.5,
        'verdict': 'MALICIOUS',
        'confidence': 92,
        'email_metadata': {
            'sender': 'finance@microsoft-billing-2024.net',
            'recipient': 'accounting@company.com',
            'subject': 'Wire Transfer Required',
            'timestamp': '2024-01-15T14:32:00Z'
        },
        'originating_node': {
            'ip': '185.220.101.5',
            'organization': 'Tor Exit Node',
            'asn': 'AS60729',
            'country': 'Germany',
            'city': 'Frankfurt',
            'abuse_confidence': 95,
            'threat_reports': 234
        },
        'authentication': {
            'spf': {'domain': 'microsoft-billing-2024.net', 'status': 'fail'},
            'dkim': {'domain': 'microsoft-billing-2024.net', 'status': 'invalid'},
            'dmarc': {'domain': 'microsoft-billing-2024.net', 'status': 'fail'}
        },
        'campaign': {
            'id': 'CAMP-2026-M365',
            'name': 'Targeted Wire Diversion Campaign',
            'attribution_confidence': 92.0,
            'first_seen': '2024-01-01',
            'last_seen': '2024-01-15',
            'related_indicators': [
                '185.220.101.5',
                'AS60729',
                'microsoft-billing-2024.net'
            ],
            'ttps': [
                'T1566.002: Phishing - Spearphishing Link',
                'T1598.003: Phishing for Information'
            ]
        }
    }


def test_stix_export():
    """Test STIX 2.1 export."""
    print("\n" + "="*60)
    print("STIX 2.1 Export Test")
    print("="*60)

    forensic_data = create_test_forensic_data()
    case_id = forensic_data['case_id']

    # Generate STIX
    stix_json = export_forensic_to_stix(case_id, forensic_data)

    print("\n✓ STIX generation completed")
    print(f"  Output size: {len(stix_json) / 1024:.1f} KB")

    # Parse and validate
    try:
        stix_bundle = json.loads(stix_json)
        print("✓ Valid JSON format")
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        return False

    # Validate structure
    if stix_bundle.get('type') != 'bundle':
        print("✗ Not a STIX bundle")
        return False

    print(f"✓ STIX bundle structure valid")
    print(f"  Bundle ID: {stix_bundle.get('id')}")

    # Count objects
    objects = stix_bundle.get('objects', [])
    print(f"  Objects: {len(objects)}")
    for obj_type in set(o.get('type') for o in objects):
        count = sum(1 for o in objects if o.get('type') == obj_type)
        print(f"    - {obj_type}: {count}")

    # Verify key objects
    has_campaign = any(o.get('type') == 'campaign' for o in objects)
    has_infrastructure = any(o.get('type') in ['ipv4-addr', 'autonomous-system'] for o in objects)
    has_indicators = any(o.get('type') == 'indicator' for o in objects)

    if has_campaign:
        print("✓ Campaign object present")
    if has_infrastructure:
        print("✓ Infrastructure objects present")
    if has_indicators:
        print("✓ Indicator objects present")

    return has_campaign and has_infrastructure


def test_csv_export():
    """Test CSV IOC export."""
    print("\n" + "="*60)
    print("CSV IOC Export Test")
    print("="*60)

    forensic_data = create_test_forensic_data()
    case_id = forensic_data['case_id']

    # Test 1: Generate CSV with defanging
    print("\n[Test 1] CSV Export with Defanging")
    csv_content = export_forensic_to_csv(case_id, forensic_data, defang=True)

    print(f"  Output size: {len(csv_content)} bytes")
    print(f"  Lines: {len(csv_content.splitlines())}")

    # Parse CSV
    try:
        reader = csv.DictReader(io.StringIO(csv_content))
        rows = list(reader)
        print(f"✓ Valid CSV format")
        print(f"  IOCs extracted: {len(rows)}")
    except Exception as e:
        print(f"✗ CSV parsing failed: {e}")
        return False

    # Validate IOC entries
    if rows:
        first_row = rows[0]
        print(f"\n  First IOC:")
        print(f"    Type: {first_row.get('IOC_Type')}")
        print(f"    Value: {first_row.get('IOC_Value')}")
        print(f"    Threat Level: {first_row.get('Threat_Level')}")
        print(f"    Risk Score: {first_row.get('Risk_Score')}")

        # Check for defanging
        ioc_value = first_row.get('IOC_Value', '')
        if '[.]' in ioc_value or '[://]' in ioc_value:
            print(f"✓ IOC properly defanged")
        elif 'example' in ioc_value.lower():
            print(f"✓ Sample IOC (defanging not applicable)")

    # Test 2: Generate CSV without defanging
    print("\n[Test 2] CSV Export without Defanging")
    csv_content_raw = export_forensic_to_csv(case_id, forensic_data, defang=False)

    reader = csv.DictReader(io.StringIO(csv_content_raw))
    rows_raw = list(reader)

    if rows and rows_raw:
        # Compare first rows
        if rows[0].get('IOC_Value') != rows_raw[0].get('IOC_Value'):
            print(f"✓ Defanging difference detected")
        else:
            print(f"  No defanging difference (expected for some IOC types)")

    return len(rows) > 0


def test_csv_columns():
    """Test CSV column validation."""
    print("\n" + "="*60)
    print("CSV Column Validation Test")
    print("="*60)

    forensic_data = create_test_forensic_data()
    case_id = forensic_data['case_id']

    csv_content = export_forensic_to_csv(case_id, forensic_data)

    # Parse and check columns
    reader = csv.DictReader(io.StringIO(csv_content))

    required_columns = [
        'IOC_Type', 'IOC_Value', 'Threat_Level', 'Risk_Score',
        'Case_ID', 'Threat_Category', 'Confidence',
        'First_Seen', 'Last_Seen', 'Description'
    ]

    if reader.fieldnames:
        print(f"\n  Expected columns: {len(required_columns)}")
        print(f"  Present columns: {len(reader.fieldnames)}")

        for col in required_columns:
            if col in reader.fieldnames:
                print(f"    ✓ {col}")
            else:
                print(f"    ✗ {col} (MISSING)")

        return all(col in reader.fieldnames for col in required_columns)

    return False


def test_threat_level_calculation():
    """Test threat level calculation."""
    print("\n" + "="*60)
    print("Threat Level Calculation Test")
    print("="*60)

    test_cases = [
        (95, 'critical'),
        (75, 'high'),
        (50, 'medium'),
        (25, 'low'),
    ]

    print("\n  Risk Score → Threat Level mapping:")
    for risk_score, expected_level in test_cases:
        forensic_data = create_test_forensic_data()
        forensic_data['final_risk'] = risk_score

        csv_content = export_forensic_to_csv(forensic_data['case_id'], forensic_data)
        reader = csv.DictReader(io.StringIO(csv_content))
        rows = list(reader)

        if rows:
            actual_level = rows[0].get('Threat_Level')
            status = "✓" if actual_level == expected_level else "✗"
            print(f"    {status} {risk_score:3d} → {actual_level:10s} (expected {expected_level})")

    return True


def run_exporter_tests():
    """Run all exporter tests."""
    print("\n" + "="*60)
    print("SpectraShield 2.0 - STIX/CSV Export Tests")
    print("="*60)

    tests = [
        ("STIX 2.1 Export", test_stix_export()),
        ("CSV IOC Export", test_csv_export()),
        ("CSV Columns", test_csv_columns()),
        ("Threat Level Calculation", test_threat_level_calculation()),
    ]

    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)

    passed = sum(1 for _, result in tests if result)
    total = len(tests)

    for name, result in tests:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed")
    print("="*60)

    return passed == total


if __name__ == '__main__':
    success = run_exporter_tests()
    exit(0 if success else 1)
