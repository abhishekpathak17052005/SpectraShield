import pytest
from app.services.brand_detector import analyze_homoglyphs, known_brands
from app.agents.forensic_report_agent import forensic_report_agent
from app.storage import evidence_vault


def test_evidence_vault_persistence():
    # 1. Create a case
    case = evidence_vault.create_case(
        raw_payload="From: attacker@evil-homoglyph.top\nSubject: Critical Security Notification\n\nPlease confirm credentials.",
        title="Homoglyph Spoofing Incident",
        threat_category="Homoglyph Domain Spoofing",
        severity="HIGH",
        overall_risk_score=84.0,
        analyst="Forensic Lead"
    )
    case_id = case["id"]
    assert case["status"] == "NEW"
    assert case["sha256_evidence_hash"] is not None

    # 2. Store full analysis
    analysis_data = {
        "final_risk": 84.0,
        "verdict": "High Risk / Malicious",
        "threat_category": "Homoglyph Domain Spoofing",
        "originating_node": {"ip": "185.220.101.5", "is_private": False},
        "relay_path": [{"hop": 1, "ip": "185.220.101.5", "is_private": False}]
    }
    evidence_vault.store_analysis(case_id, analysis_data)

    # 3. Retrieve analysis and audit trail
    fetched_analysis = evidence_vault.get_analysis(case_id)
    assert fetched_analysis is not None
    assert fetched_analysis["final_risk"] == 84.0

    # 4. Status update and notes
    evidence_vault.update_case_status(case_id, "INVESTIGATING", actor="Analyst Dave")
    evidence_vault.add_case_note(case_id, "Punycode & Cyrillic character confirmed in sender address.", author="Analyst Dave")

    updated_case = evidence_vault.get_case(case_id)
    assert updated_case["status"] == "INVESTIGATING"
    assert len(updated_case["notes"]) >= 1

    # 5. Verify audit ledger chain
    audit = evidence_vault.get_audit_trail(case_id)
    assert len(audit) >= 3
    for i in range(1, len(audit)):
        assert audit[i]["previous_hash"] == audit[i - 1]["current_hash"]


def test_defanged_csv_export():
    sample_analysis = {
        "case_id": "test-case-1234",
        "sha256_evidence_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "final_risk": 91.0,
        "threat_category": "Business Email Compromise (BEC)",
        "originating_node": {
            "ip": "185.220.101.5",
            "isp": "Tor Exit Router Network",
            "asn": "AS60729",
            "is_anonymized": True,
            "is_private": False
        },
        "authentication": {
            "spf": {"domain": "micro-soft-billing.top"}
        },
        "relay_path": [
            {"hop": 1, "ip": "185.220.101.5", "is_private": False},
            {"hop": 2, "ip": "172.217.194.27", "is_private": False, "received_from": "relay.google.com"}
        ],
        "attachments": [
            {
                "filename": "invoice_revised.pdf.exe",
                "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "md5": "5d41402abc4b2a76b9719d911017c592",
                "entropy_score": 7.82,
                "risk_level": "malicious"
            }
        ]
    }

    csv_out = forensic_report_agent.generate_ioc_csv("test-case-1234", sample_analysis, defang=True)
    assert "ioc_type,defanged_value,raw_value,threat_category,confidence_score,context_source,first_seen" in csv_out
    # Check defanged items
    assert "185[.]220[.]101[.]5" in csv_out
    assert "micro-soft-billing[.]top" in csv_out
    assert "172[.]217[.]194[.]27" in csv_out
    # Check hashes are present
    assert "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" in csv_out
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in csv_out


def test_homoglyph_detection():
    # 1. Cyrillic lookalike: 'micrоsoft.com' where 'о' is \u043E (Cyrillic Small Letter O)
    spoofed_domain = "micr\u043Esoft.com"
    res = analyze_homoglyphs(spoofed_domain)
    assert res["has_homoglyphs"] is True
    assert res["target_brand"] == "microsoft"
    assert len(res["substituted_characters"]) == 1
    assert res["substituted_characters"][0]["unicode_hex"] == "U+043E"
    assert res["substituted_characters"][0]["lookalike_char"] == "o"
    assert res["substituted_characters"][0]["script"] == "Cyrillic"
    assert res["risk_score_modifier"] >= 40.0

    # 2. Cyrillic lookalike: 'pаypal.com' where 'а' is \u0430 (Cyrillic Small Letter A)
    spoofed_paypal = "p\u0430ypal.com"
    res_pp = analyze_homoglyphs(spoofed_paypal)
    assert res_pp["has_homoglyphs"] is True
    assert res_pp["target_brand"] == "paypal"
    assert res_pp["substituted_characters"][0]["unicode_hex"] == "U+0430"

    # 3. Clean domain
    clean_res = analyze_homoglyphs("microsoft.com")
    assert clean_res["has_homoglyphs"] is False
    assert len(clean_res["substituted_characters"]) == 0
    assert clean_res["risk_score_modifier"] == 0.0

    # 4. Punycode input
    punycode_res = analyze_homoglyphs("xn--micrsoft-37g.com")
    assert punycode_res["is_punycode"] is True


def test_phase4_api_endpoints():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)

    # 1. Test CSV IOC Export API
    csv_resp = client.get("/api/forensics/export/sample-phase4-case/csv?defang=true")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "attachment; filename=" in csv_resp.headers["content-disposition"]
    csv_text = csv_resp.text
    assert "IOC_Type,IOC_Value" in csv_text or "ioc_type,defanged_value" in csv_text
    assert "185[.]220[.]101[.]5" in csv_text

    # 2. Test analyze-email with homoglyph sender
    homoglyph_eml = (
        'From: "IT Support" <admin@micr\u043Esoft.com>\n'
        'To: user@victim.com\n'
        'Subject: Urgent Password Expiration Notice\n\n'
        'Your Microsoft account password expires in 2 hours. Reset immediately.'
    )

    resp = client.post("/api/forensics/analyze-email", json={"raw_eml": homoglyph_eml})
    assert resp.status_code == 200
    data = resp.json()
    assert "homoglyph_analysis" in data
    assert data["homoglyph_analysis"] is not None
    assert data["homoglyph_analysis"]["has_homoglyphs"] is True
    assert data["homoglyph_analysis"]["target_brand"] == "microsoft"
    assert data["final_risk"] >= 80.0
    assert any("Homoglyph" in a for a in data["anomalies"])
