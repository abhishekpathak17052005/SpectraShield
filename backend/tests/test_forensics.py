import pytest
from app.agents.header_forensic_agent import HeaderForensicAgent
from app.agents.geo_trace_agent import GeoTraceAgent
from app.agents.nlp_threat_agent import NLPThreatAgent
from app.agents.graph_attribution_agent import graph_attribution_agent
from app.agents.forensic_report_agent import forensic_report_agent
from app.storage import evidence_vault

SAMPLE_RAW_EMAIL = """Received: from mail-relay.target.com (mx.target.com [172.217.194.27])
    by mx.google.com with ESMTPS id abc123xyz
    for <victim@target.com>; Wed, 02 Sep 2026 10:14:04 -0700 (PDT)
Received: from client-node.local (tor-relay.exit.org [185.220.101.5])
    by mail-relay.target.com with ESMTP id 987zyx
    for <victim@target.com>; Wed, 02 Sep 2026 10:14:02 -0700 (PDT)
From: "CEO John Doe" <ceo@micro-soft-billing.top>
To: <victim@target.com>
Subject: Urgent: Overdue wire transfer invoice payment requested
Date: Wed, 02 Sep 2026 10:14:00 -0700
Message-ID: <9827341.20260902@micro-soft-billing.top>
Return-Path: <bounce@attacker-spoof.com>

Please find the attached invoice. Are you at your desk? I need an urgent wire transfer to our new vendor before end of day.
Keep this strictly confidential.
"""


def test_header_forensic_agent():
    agent = HeaderForensicAgent()
    result = agent.analyze_raw_headers(SAMPLE_RAW_EMAIL)

    assert result["subject"] == "Urgent: Overdue wire transfer invoice payment requested"
    assert "micro-soft-billing.top" in result["header_from"]
    assert len(result["relay_hops"]) >= 2

    # Verify chronological order: Hop 1 should be the bottom-most hop (tor-relay 185.220.101.5)
    first_hop = result["relay_hops"][0]
    assert first_hop["hop"] == 1
    assert first_hop["ip"] == "185.220.101.5"
    assert first_hop["is_origin"] is True

    # Check anomalies: Return-Path mismatch with From
    assert any("Return-Path mismatch" in a for a in result["anomalies"])
    assert result["header_score"] > 0


def test_geo_trace_agent():
    agent = GeoTraceAgent()
    # Test Tor exit node
    tor_record = agent.resolve_ip("185.220.101.5")
    assert tor_record["is_anonymized"] is True
    assert tor_record["anonymization_type"] == "TOR"
    assert tor_record["country"] == "Germany"

    # Test Bogon / Private IP
    bogon_record = agent.resolve_ip("192.168.1.50")
    assert bogon_record["is_private"] is True
    assert bogon_record["is_bogon"] is True


def test_nlp_threat_agent():
    agent = NLPThreatAgent()
    text = "Are you at your desk? I need an urgent wire transfer to our new vendor. Keep this strictly confidential."
    result = agent.analyze_content(text=text, subject="Urgent wire transfer")

    assert result["financial_intent"] is True
    assert result["executive_impersonation"] is True
    assert result["bec_score"] >= 0.75
    assert "BEC" in result["threat_category"] or "Wire Diversion" in result["threat_category"]


def test_graph_attribution_agent():
    result = graph_attribution_agent.correlate_incident(
        email_hash="aabbcc1122334455",
        subject="Urgent wire transfer invoice",
        body_text="Wire transfer payment instructions for new vendor.",
        origin_ip="185.220.101.5",
        country="Germany",
        sender_domain="micro-soft-billing.top",
        asn_number="AS60729",
        isp_name="Tor Exit Network",
        threat_category="Business Email Compromise (BEC)",
        is_tor=True
    )

    assert "campaign_id" in result
    assert result["attribution_confidence"] > 50.0


def test_forensic_report_agent_and_vault():
    vault = evidence_vault
    hashes = vault.compute_hashes(SAMPLE_RAW_EMAIL)
    assert len(hashes["sha256"]) == 64

    case = vault.create_case(
        raw_payload=SAMPLE_RAW_EMAIL,
        title="Test Wire Diversion Case",
        threat_category="Business Email Compromise (BEC)",
        severity="CRITICAL",
        overall_risk_score=94.5
    )
    assert case["id"] is not None
    assert case["sha256_evidence_hash"] == hashes["sha256"]

    # Test PDF generation
    sample_data = {
        "case_id": case["id"],
        "sha256_evidence_hash": hashes["sha256"],
        "final_risk": 94.5,
        "verdict": "High Risk / Malicious",
        "threat_category": "Business Email Compromise (BEC)",
        "authentication": {
            "spf": {"status": "Fail", "domain": "micro-soft-billing.top", "reason": "Origin IP not authorized"},
            "dkim": {"status": "Fail", "domain": "micro-soft-billing.top", "reason": "No public key"},
            "dmarc": {"status": "Fail", "domain": "micro-soft-billing.top", "reason": "Unaligned"}
        },
        "originating_node": {
            "ip": "185.220.101.5",
            "defanged_ip": "185[.]220[.]101[.]5",
            "country": "Germany",
            "city": "Frankfurt",
            "asn": "AS60729",
            "isp": "Tor Exit Network",
            "is_anonymized": True,
            "anonymization_type": "TOR"
        },
        "relay_path": [
            {
                "hop": 1,
                "received_from": "client-node.local",
                "by": "mail-relay.target.com",
                "defanged_ip": "185[.]220[.]101[.]5",
                "is_origin": True,
                "geo": {"city": "Frankfurt", "country_code": "DE"},
                "delay_seconds": 0
            }
        ],
        "campaign": {
            "id": "CAMP-2026-BEC",
            "name": "European Executive Wire Diversion",
            "attribution_confidence": 91.0
        }
    }

    pdf_bytes = forensic_report_agent.generate_pdf_dossier_bytes(case["id"], sample_data)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")

    # Test STIX 2.1 Bundle
    stix = forensic_report_agent.generate_stix_bundle(case["id"], sample_data)
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) >= 2


def test_forensics_api_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    response = client.post(
        "/api/forensics/analyze-email",
        json={
            "raw_eml": SAMPLE_RAW_EMAIL,
            "subject": "Urgent: Overdue wire transfer invoice payment requested",
            "sender_email": "ceo@micro-soft-billing.top"
        }
    )

    assert response.status_code == 200
    data = response.json()
    assert "case_id" in data
    assert "sha256_evidence_hash" in data
    assert data["final_risk"] >= 75.0
    assert data["originating_node"]["country"] == "Germany"
    assert data["originating_node"]["is_anonymized"] is True
    assert len(data["relay_path"]) >= 2

    # Test Graph endpoint
    graph_resp = client.get(f"/api/forensics/campaigns/{data['campaign']['id']}/graph")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert len(graph_data["nodes"]) >= 1

    # Test PDF Export endpoint
    pdf_resp = client.get(f"/api/forensics/export/{data['case_id']}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 1000

    # Test STIX Export endpoint
    stix_resp = client.get(f"/api/forensics/export/{data['case_id']}/stix")
    assert stix_resp.status_code == 200
    assert stix_resp.json()["type"] == "bundle"
