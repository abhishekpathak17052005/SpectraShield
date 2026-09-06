import io
import os
import stat
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.html_sanitizer import html_sanitizer
from app.services.qr_detector import qr_detector
from app.agents.attachment_forensic_agent import attachment_forensic_agent
from app.storage import evidence_vault

client = TestClient(app)


def safe_rmtree(path: str):
    """Safely removes directory on Windows even if files have read-only attributes."""
    if os.path.exists(path):
        for root, dirs, files in os.walk(path):
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), stat.S_IWRITE)
                except Exception:
                    pass
        shutil.rmtree(path, ignore_errors=True)


def test_html_sanitizer_active_scripts():
    """Verify HTML script and zero-width evasion sanitizer."""
    malicious_html = """
    <html>
      <body>
        <h2>Account Verification Required</h2>
        <p>Please log in immediately to confirm your identity\u200B\u200C.</p>
        <script>window.location="http://evil-phish.top/cookie-steal";</script>
        <iframe src="http://credential-grabber.net/login" width="400" height="300"></iframe>
        <a href="javascript:alert('XSS')" onclick="doMalicious()">Click here to verify</a>
      </body>
    </html>
    """
    res = html_sanitizer.sanitize(malicious_html)

    # 1. Verification of stripped tags
    assert "<script>" not in res["sanitized_html"]
    assert "<iframe" not in res["sanitized_html"]
    assert "onclick=" not in res["sanitized_html"]
    assert "javascript:" not in res["sanitized_html"]

    # 2. Verification of zero-width character removal
    assert res["zero_width_chars_removed"] == 2

    # 3. Verification of forensic threat cues
    assert res["has_hidden_scripts"] is True
    assert len(res["script_cues"]) >= 2
    assert "script" in res["dangerous_tags_stripped"]
    assert "iframe" in res["dangerous_tags_stripped"]

    # 4. Clean text extraction preserved
    assert "Account Verification Required" in res["clean_text"]


def test_quishing_qr_detection():
    """Verify Quishing (QR Phishing) detector and URL defanging."""
    import qrcode

    # Generate a real QR code targeting a credential lure
    test_target_url = "https://secure-login.micr0soft.com/adfs/ls"
    qr_img = qrcode.make(test_target_url)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    img_bytes = buf.getvalue()

    # 1. Scan direct image bytes
    decoded = qr_detector.scan_image_bytes(img_bytes)
    assert len(decoded) > 0
    assert decoded[0] == test_target_url

    # 2. Comprehensive Quishing analysis
    quishing_res = qr_detector.analyze_quishing(
        attachments=[{
            "filename": "urgent_invoice_qr.png",
            "content_type": "image/png",
            "raw_bytes": img_bytes
        }],
        html_body="<p>Scan the attached QR code to pay your invoice</p>"
    )

    assert quishing_res["has_qr_code"] is True
    assert quishing_res["qr_count"] == 1
    assert quishing_res["risk_level"] == "malicious"
    assert quishing_res["source_image_filename"] == "urgent_invoice_qr.png"
    assert "hxxps[://]" in quishing_res["defanged_payloads"][0]
    assert "[.]" in quishing_res["defanged_payloads"][0]


def test_attachment_quarantine_isolation():
    """Verify physical attachment quarantine on disk under .quarantine with read-only permissions."""
    case_id = "CASE-TEST-QUARANTINE-001"
    sample_payload = b"MZ\x90\x00\x03\x00\x00\x00ExecutableWindowsBinaryContent"

    evidence = attachment_forensic_agent.inspect_attachment_bytes(
        filename="bonus_payout.exe",
        content_type="application/x-dosexec",
        data=sample_payload,
        case_id=case_id
    )

    assert evidence["is_executable_or_script"] is True
    assert evidence["is_quarantined"] is True
    assert evidence["quarantine_path"] is not None
    assert evidence["quarantine_path"].endswith(".quarantine")

    # Verify physical file existence and content fidelity
    base_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "quarantine", case_id
    )
    expected_file = os.path.join(base_dir, f"{evidence['sha256']}.quarantine")
    assert os.path.exists(expected_file)

    with open(expected_file, "rb") as f:
        stored_bytes = f.read()
    assert stored_bytes == sample_payload

    # Cleanup test quarantine dir
    safe_rmtree(base_dir)


def test_mbox_archive_ingestion():
    """Verify UNIX MBOX archive ingestion format parsing."""
    mbox_content = (
        "From test@attacker.org Mon Sep 07 00:00:00 2026\n"
        "From: ceo@micro-soft-billing.top\n"
        "To: cfo@victim-corp.com\n"
        "Subject: Mbox Archive Urgent Transfer\n"
        "Date: Mon, 07 Sep 2026 00:00:00 +0000\n\n"
        "Please transfer $50,000 to the attached escrow account.\n"
    ).encode("utf-8")

    response = client.post(
        "/api/forensics/upload-eml",
        files={"file": ("archive.mbox", mbox_content, "application/mbox")}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ingestion_format"] == "MBOX_ARCHIVE"
    assert data["case_id"] is not None


def test_outlook_msg_magic_byte_detection():
    """Verify Outlook .msg magic byte detection and ingestion routing."""
    # Synthetic OLE Header: D0 CF 11 E0 A1 B1 1A E1
    msg_bytes = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 504 + b"From: ceo@micro-soft-billing.top\nSubject: Outlook Wire\n\nTransfer immediately."

    response = client.post(
        "/api/forensics/upload-eml",
        files={"file": ("urgent_executive_memo.msg", msg_bytes, "application/vnd.ms-outlook")}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ingestion_format"] == "OUTLOOK_MSG_OLE"
    assert data["case_id"] is not None


def test_quarantine_download_endpoint():
    """Verify GET /api/forensics/cases/{case_id}/quarantine/{sha256}."""
    case_id = "CASE-TEST-DOWNLOAD-002"
    sample_data = b"PAYLOAD_STATIC_ANALYSIS_ONLY"
    ev = attachment_forensic_agent.inspect_attachment_bytes(
        filename="payload.bin",
        content_type="application/octet-stream",
        data=sample_data,
        case_id=case_id
    )
    sha256 = ev["sha256"]

    # 1. Download valid quarantine file
    resp = client.get(f"/api/forensics/cases/{case_id}/quarantine/{sha256}")
    assert resp.status_code == 200
    assert resp.content == sample_data
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert f"{sha256}.quarantine" in resp.headers.get("content-disposition", "")

    # 2. Non-existent file returns 404
    missing_resp = client.get(f"/api/forensics/cases/{case_id}/quarantine/nonexistenthash123456789")
    assert missing_resp.status_code == 404

    # Cleanup
    base_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "quarantine", case_id
    )
    safe_rmtree(base_dir)


def test_full_pipeline_with_quishing_and_html_sanitizing():
    """Verify end-to-end upload with inline HTML zero-width spaces and attached QR matrix."""
    import qrcode

    qr_img = qrcode.make("https://portal-login-banking.top/auth")
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    # Build a multipart MIME email with both an HTML part and a PNG attachment
    import email.mime.multipart
    import email.mime.text
    import email.mime.image

    msg = email.mime.multipart.MIMEMultipart("mixed")
    msg["From"] = "ceo@micro-soft-billing.top"
    msg["To"] = "cfo@victim-corp.com"
    msg["Subject"] = "URGENT: Executive Wire Transfer Authorization"

    html_part = email.mime.text.MIMEText(
        "<p>Please review\u200B the invoice immediately.</p><script>evil()</script>",
        "html"
    )
    msg.attach(html_part)

    img_part = email.mime.image.MIMEImage(png_bytes, _subtype="png")
    img_part.add_header("Content-Disposition", "attachment", filename="auth_qr_code.png")
    msg.attach(img_part)

    raw_eml_bytes = msg.as_bytes()

    response = client.post(
        "/api/forensics/upload-eml",
        files={"file": ("incident.eml", raw_eml_bytes, "message/rfc822")}
    )

    assert response.status_code == 200
    data = response.json()

    # Check Ingestion & Sanitization
    assert data["ingestion_format"] == "STANDARD_RFC5322_EML"
    assert "<script>" not in (data.get("sanitized_html") or "")
    assert len(data.get("script_cues", [])) > 0

    # Check Quishing Detection
    quishing = data.get("quishing_evidence")
    assert quishing is not None
    assert quishing["has_qr_code"] is True
    assert quishing["risk_level"] == "malicious"
    assert len(quishing["defanged_payloads"]) > 0

    # Check Attachment Quarantine
    assert len(data.get("attachments", [])) >= 1
    att = data["attachments"][0]
    assert att["is_quarantined"] is True
    assert att["quarantine_path"] is not None

    # Check overall verdict reflects high threat
    assert data["final_risk"] >= 80.0
    assert data["verdict"] == "High Risk / Malicious"
