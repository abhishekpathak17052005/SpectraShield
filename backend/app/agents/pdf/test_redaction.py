"""
Test suite for PII redaction functionality.

Tests:
- Email redaction
- Path redaction
- Domain redaction
- IP redaction
- Forensic data redaction
- PDF generation with redaction
- Redaction validation
"""

from typing import Dict, Any

from .pii_redactor import PIIRedactor, RedactionValidator, PIIRedactor
from .test_pages import create_phishing_case, create_bec_case
from .report_builder import PDFReportBuilder


def test_email_redaction():
    """Test email address redaction."""
    print("\n=== Test: Email Redaction ===")

    redactor = PIIRedactor(level=PIIRedactor.LEVEL_MINIMAL)

    test_cases = [
        ("user@example.com", "u***@[REDACTED]"),
        ("john.doe@company.com", "j***@[REDACTED]"),
        ("a@test.org", "a***@[REDACTED]"),
    ]

    for email, expected_pattern in test_cases:
        result = redactor.redact_text(email)
        print(f"  {email} → {result}")

        # Check that it was redacted (domain should be REDACTED)
        if "[REDACTED]" in result:
            print(f"    ✓ Email redacted")
        else:
            print(f"    ✗ Email not fully redacted")


def test_path_redaction():
    """Test file path redaction."""
    print("\n=== Test: Path Redaction ===")

    redactor = PIIRedactor(level=PIIRedactor.LEVEL_STANDARD)

    test_cases = [
        "C:\\Users\\JohnDoe\\Documents\\file.txt",
        "/home/user/sensitive/data.txt",
        "C:\\Users\\Administrator\\AppData\\Local\\Temp\\temp.bin",
    ]

    for path in test_cases:
        result = redactor.redact_text(path)
        print(f"  {path}")
        print(f"    → {result}")

        if "REDACTED" in result:
            print(f"    ✓ Path redacted")
        else:
            print(f"    ? Path unchanged (may be acceptable)")


def test_domain_redaction():
    """Test domain name redaction (STRICT mode)."""
    print("\n=== Test: Domain Redaction ===")

    redactor = PIIRedactor(level=PIIRedactor.LEVEL_STRICT)

    test_cases = [
        "example.com",
        "mail.company.org",
        "secure-bank-online.co.uk",
    ]

    for domain in test_cases:
        result = redactor.redact_text(domain)
        print(f"  {domain} → {result}")


def test_ip_redaction():
    """Test IP address redaction (STRICT mode)."""
    print("\n=== Test: IP Redaction ===")

    redactor = PIIRedactor(level=PIIRedactor.LEVEL_STRICT)

    test_cases = [
        "203.0.113.50",
        "192.168.1.1",
        "10.0.0.5",
    ]

    for ip in test_cases:
        result = redactor.redact_text(ip)
        print(f"  {ip} → {result}")


def test_forensic_data_redaction():
    """Test redaction of complete forensic data."""
    print("\n=== Test: Forensic Data Redaction ===")

    # Create sample case
    forensic_data = create_phishing_case()

    # Redact with STANDARD level
    redactor = PIIRedactor(level=PIIRedactor.LEVEL_STANDARD)
    redacted = redactor.redact_forensic_data(forensic_data)

    print(f"  Original sender: {forensic_data['email_metadata']['sender']}")
    print(f"  Redacted sender: {redacted['email_metadata']['sender']}")

    print(f"  Original subject: {forensic_data['email_metadata']['subject']}")
    print(f"  Redacted subject: {redacted['email_metadata']['subject']}")

    # Verify case_id and analysis_timestamp NOT redacted
    if redacted['case_id'] == forensic_data['case_id']:
        print(f"  ✓ Case ID preserved: {redacted['case_id']}")
    else:
        print(f"  ✗ Case ID changed!")

    if redacted['analysis_timestamp'] == forensic_data['analysis_timestamp']:
        print(f"  ✓ Analysis timestamp preserved")
    else:
        print(f"  ✗ Analysis timestamp changed!")


def test_redaction_validation():
    """Test redaction validation."""
    print("\n=== Test: Redaction Validation ===")

    # Text with unredacted email
    unredacted = "Contact user@example.com for more info"
    valid, issues = RedactionValidator.validate_redaction(unredacted)
    print(f"  Unredacted text: {unredacted}")
    print(f"    Valid: {valid}, Issues: {issues}")

    # Text with redacted email
    redacted = "Contact u***@[REDACTED] for more info"
    valid, issues = RedactionValidator.validate_redaction(redacted)
    print(f"  Redacted text: {redacted}")
    print(f"    Valid: {valid}, Issues: {issues}")


def test_pdf_with_redaction():
    """Test PDF generation with redaction mode enabled."""
    print("\n=== Test: PDF Generation with Redaction ===")

    forensic_data = create_phishing_case()

    # Generate PDF with redaction
    builder = PDFReportBuilder(
        case_id=forensic_data['case_id'],
        redaction_mode=True,
        redaction_level=PIIRedactor.LEVEL_STANDARD
    )

    pdf_bytes, metadata = builder.generate_pdf(forensic_data)

    print(f"  Status: {metadata['status']}")
    print(f"  Pages: {metadata['pages']}")
    print(f"  Size: {len(pdf_bytes) / 1024:.1f} KB")
    print(f"  Redaction applied: {metadata['redaction_applied']}")
    print(f"  Redaction level: {metadata['redaction_level']}")

    if metadata['status'] == 'success' and len(pdf_bytes) > 0:
        print(f"  ✓ PDF generated successfully with redaction")
    else:
        print(f"  ✗ PDF generation failed")


def test_pdf_without_redaction():
    """Test PDF generation without redaction for comparison."""
    print("\n=== Test: PDF Generation without Redaction ===")

    forensic_data = create_bec_case()

    # Generate PDF without redaction
    builder = PDFReportBuilder(
        case_id=forensic_data['case_id'],
        redaction_mode=False
    )

    pdf_bytes, metadata = builder.generate_pdf(forensic_data)

    print(f"  Status: {metadata['status']}")
    print(f"  Pages: {metadata['pages']}")
    print(f"  Size: {len(pdf_bytes) / 1024:.1f} KB")
    print(f"  Redaction applied: {metadata['redaction_applied']}")

    if metadata['status'] == 'success' and len(pdf_bytes) > 0:
        print(f"  ✓ PDF generated successfully without redaction")
    else:
        print(f"  ✗ PDF generation failed")


def run_redaction_tests():
    """Run all redaction tests."""
    print("\n" + "="*60)
    print("SpectraShield 2.0 - PII Redaction Test Suite")
    print("="*60)

    test_email_redaction()
    test_path_redaction()
    test_domain_redaction()
    test_ip_redaction()
    test_forensic_data_redaction()
    test_redaction_validation()
    test_pdf_with_redaction()
    test_pdf_without_redaction()

    print("\n" + "="*60)
    print("All redaction tests completed!")
    print("="*60)


if __name__ == '__main__':
    run_redaction_tests()
