import pytest
from app.agents.attachment_forensic_agent import AttachmentForensicAgent, compute_shannon_entropy, compute_fuzzy_simhash
from app.services.pii_redactor import PiiRedactor, luhn_validate
from app.storage import evidence_vault


def test_attachment_forensic_agent():
    agent = AttachmentForensicAgent()

    # 1. Test PDF with embedded JavaScript
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('pwned');) >> >>\nendobj\n"
    res_pdf = agent.inspect_attachment_bytes("invoice_details.pdf", "application/pdf", pdf_bytes)
    assert res_pdf["has_embedded_scripts"] is True
    assert res_pdf["risk_level"] == "malicious"
    assert any("JavaScript" in r for r in res_pdf["risk_reasons"])
    assert len(res_pdf["sha256"]) == 64
    assert len(res_pdf["fuzzy_hash"]) == 16

    # 2. Test Deceptive Double Extension
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    res_exe = agent.inspect_attachment_bytes("salary_review.docx.exe", "application/x-msdownload", fake_exe)
    assert res_exe["is_executable_or_script"] is True
    assert res_exe["risk_level"] == "malicious"
    assert any("double-extension" in r for r in res_exe["risk_reasons"])

    # 3. Test Safe Attachment
    safe_txt = b"Hello, please find the minutes of yesterday's meeting attached."
    res_txt = agent.inspect_attachment_bytes("meeting_notes.txt", "text/plain", safe_txt)
    assert res_txt["risk_level"] == "clean"
    assert res_txt["is_executable_or_script"] is False
    assert res_txt["has_macros"] is False


def test_pii_redactor():
    redactor = PiiRedactor()

    # Test Luhn credit card validation
    # Visa test card: 4532 0151 1283 0366
    valid_card = "4532015112830366"
    assert luhn_validate(valid_card) is True
    assert luhn_validate("1234567812345678") is False

    test_text = (
        "Customer card: 4532015112830366. "
        "Account IBAN: DE89370400440532013000. "
        "User SSN: 123-45-6789. "
        "Emergency phone: 415-555-2671. "
        "Database password=SuperSecretToken123;"
    )

    sanitized, manifest = redactor.redact_text(test_text)

    assert "4532015112830366" not in sanitized
    assert "[REDACTED_CARD_****0366]" in sanitized
    assert "DE89370400440532013000" not in sanitized
    assert "[REDACTED_IBAN_DE****3000]" in sanitized
    assert "123-45-6789" not in sanitized
    assert "[REDACTED_SSN_***-**-****]" in sanitized
    assert "SuperSecretToken123" not in sanitized
    assert "[REDACTED_CREDENTIAL]" in sanitized
    assert len(manifest) >= 4


def test_case_management_and_notes():
    # 1. Create a case
    case = evidence_vault.create_case(
        raw_payload="From: attacker@malicious.com\nSubject: Wire Transfer Urgent\n\nTransfer $50,000",
        title="Suspicious Wire Transfer Request",
        threat_category="Business Email Compromise",
        severity="CRITICAL",
        overall_risk_score=92.5,
        analyst="Analyst Alice"
    )
    case_id = case["id"]
    assert case["status"] == "NEW"

    # 2. Transition status
    updated = evidence_vault.update_case_status(case_id, "INVESTIGATING", actor="Analyst Bob", reason="Assigned for deep triage")
    assert updated["status"] == "INVESTIGATING"

    # 3. Add notes
    note = evidence_vault.add_case_note(case_id, "Confirmed sender domain was registered 2 days ago.", author="Analyst Bob")
    assert note["author"] == "Analyst Bob"
    case_updated = evidence_vault.get_case(case_id)
    assert len(case_updated["notes"]) >= 1
    assert case_updated["notes"][0]["text"] == "Confirmed sender domain was registered 2 days ago."

    # 4. Assign investigator
    assigned = evidence_vault.assign_case(case_id, "Senior Officer Carlos", actor="Admin")
    assert assigned["assigned_analyst"] == "Senior Officer Carlos"

    # 5. Check audit trail link
    audit = evidence_vault.get_audit_trail(case_id)
    assert len(audit) >= 4
    # Ensure block hashing links previous_hash
    for i in range(1, len(audit)):
        assert audit[i]["previous_hash"] is not None


def test_phase3_api_endpoints():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)

    # Test analyze email with MIME attachment
    mime_with_att = (
        'From: "HR" <hr@company-update.top>\n'
        'To: employee@corp.com\n'
        'Subject: Employee Bonus List.pdf\n'
        'MIME-Version: 1.0\n'
        'Content-Type: multipart/mixed; boundary="====BOUNDARY===="\n\n'
        '--====BOUNDARY====\n'
        'Content-Type: text/plain; charset="utf-8"\n\n'
        'Please review your bonus details in the attached PDF.\n\n'
        '--====BOUNDARY====\n'
        'Content-Type: application/pdf; name="bonus.pdf.exe"\n'
        'Content-Disposition: attachment; filename="bonus.pdf.exe"\n'
        'Content-Transfer-Encoding: base64\n\n'
        'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\n'
        '--====BOUNDARY====--\n'
    )

    resp = client.post("/api/forensics/analyze-email", json={"raw_eml": mime_with_att})
    assert resp.status_code == 200
    data = resp.json()
    assert "attachments" in data
    assert len(data["attachments"]) >= 1
    assert data["attachments"][0]["is_executable_or_script"] is True
    assert data["final_risk"] >= 80.0

    case_id = data["case_id"]

    # Test Case Status Update API
    status_resp = client.patch(f"/api/forensics/cases/{case_id}/status", json={"status": "ESCALATED", "reason": "Malicious payload detected"})
    assert status_resp.status_code == 200
    assert status_resp.json()["case"]["status"] == "ESCALATED"

    # Test Case Add Note API
    note_resp = client.post(f"/api/forensics/cases/{case_id}/notes", json={"text": "Escalated to CIRT team for host isolation."})
    assert note_resp.status_code == 200
    assert "note" in note_resp.json()

    # Test Redacted PDF Export
    pdf_resp = client.get(f"/api/forensics/export/{case_id}/pdf?redact_pii=true")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"

    # Test Redacted STIX Export
    stix_resp = client.get(f"/api/forensics/export/{case_id}/stix?redact_pii=true")
    assert stix_resp.status_code == 200
    assert stix_resp.json()["type"] == "bundle"

    # Test Mailbox Poller Status
    mb_resp = client.get("/api/forensics/mailbox/status")
    assert mb_resp.status_code == 200
    assert "mode" in mb_resp.json()
