import base64
import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.main import app
from app.services.vpn_matcher import vpn_matcher
from app.services.cti_service import cti_service
from app.services.dkim_verifier import dkim_verifier
from app.services.transformer_classifier import (
    transformer_classifier,
    VECTOR_FINANCIAL_WIRE_FRAUD,
    VECTOR_CREDENTIAL_HARVESTING,
    VECTOR_INVOICE_SUPPLIER_FRAUD,
    VECTOR_EXTORTION_BLACKMAIL,
    VECTOR_CLEAN_BENIGN,
)
from app.graph_db import threat_graph_manager
from app.security import create_access_token, ROLE_SUPER_ADMIN


@pytest.fixture
def client():
    return TestClient(app)


def test_commercial_vpn_matcher():
    """Validates high-speed CIDR matching for Tor and commercial VPN subnets."""
    # 1. Tor Exit Node
    tor_match = vpn_matcher.match_ip("185.220.101.5")
    assert tor_match["is_vpn"] is True
    assert tor_match["anonymization_type"] == "TOR"

    # 2. NordVPN
    nord_match = vpn_matcher.match_ip("185.246.188.10")
    assert nord_match["is_vpn"] is True
    assert nord_match["provider"] == "NordVPN"

    # 3. ExpressVPN
    express_match = vpn_matcher.match_ip("45.142.214.12")
    assert express_match["is_vpn"] is True
    assert express_match["provider"] == "ExpressVPN"

    # 4. Private Bogon IP
    private_match = vpn_matcher.match_ip("192.168.1.100")
    assert private_match["is_vpn"] is False
    assert private_match["is_private"] is True

    # 5. Clean benign IP
    clean_match = vpn_matcher.match_ip("8.8.8.8")
    assert clean_match["is_vpn"] is False


@pytest.mark.anyio
async def test_cti_service_safe_browsing_and_urlhaus():
    """Validates multi-feed threat intelligence queries."""
    # 1. Google Safe Browsing test indicator
    gsb_res = await cti_service.check_url_safe_browsing("http://malware.testing.google.test/testing/malware/")
    assert gsb_res["is_malicious"] is True
    assert gsb_res["source"] == "Google Safe Browsing"

    # 2. URLhaus test indicator
    urlhaus_res = await cti_service.check_urlhaus("http://micro-soft-billing.top/invoice.exe")
    assert urlhaus_res["is_malicious"] is True
    assert urlhaus_res["source"] == "abuse.ch URLhaus"

    # 3. Benign URL
    benign_res = await cti_service.check_url_safe_browsing("https://example.com/index.html")
    assert benign_res["is_malicious"] is False

    # 4. Consolidated multi-feed check
    all_feeds = await cti_service.query_all_threat_feeds(
        urls=["http://malware.testing.google.test/"],
        origin_ip="185.220.101.5"
    )
    assert len(all_feeds) >= 3
    assert any(f["is_malicious"] for f in all_feeds)


def test_dkim_standalone_verifier():
    """Validates DKIM body canonicalization and RSA mathematical signature verification."""
    # 1. Relaxed body canonicalization
    body = "  Please find the invoice attached.   \n\nWire $50,000 immediately.  \n\n\n"
    canonical = dkim_verifier.canonicalize_body_relaxed(body)
    assert canonical.endswith(b"\r\n")
    assert b"   " not in canonical

    # 2. Cryptographic RSA Math Signature Test
    # Generate temporary RSA-2048 keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pub_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    p_b64 = base64.b64encode(pub_der).decode('utf-8')

    # Mock DNS lookup to return our generated public key
    orig_query = dkim_verifier.query_dns_public_key
    dkim_verifier.query_dns_public_key = lambda d, s: (True, p_b64, f"v=DKIM1; p={p_b64}")

    try:
        sample_body = "Urgent wire transfer required."
        sample_canonical = dkim_verifier.canonicalize_body_relaxed(sample_body)
        bh_val = base64.b64encode(hashes.Hash(hashes.SHA256()).finalize() if False else __import__('hashlib').sha256(sample_canonical).digest()).decode('utf-8')

        # Sign test headers
        headers_dict = {"from": "ceo@test-domain.com", "subject": "Wire Transfer"}
        header_str = "from:ceo@test-domain.com\r\nsubject:Wire Transfer\r\ndkim-signature:v=1; a=rsa-sha256; d=test-domain.com; s=s1; h=from:subject; bh=" + bh_val + "; b="
        header_data = header_str.encode('utf-8')

        sig_bytes = private_key.sign(header_data, padding.PKCS1v15(), hashes.SHA256())
        b_val = base64.b64encode(sig_bytes).decode('utf-8')

        dkim_header_str = f"v=1; a=rsa-sha256; d=test-domain.com; s=s1; h=from:subject; bh={bh_val}; b={b_val}"
        res = dkim_verifier.verify_dkim(dkim_header_str, body_text=sample_body, headers_dict=headers_dict)

        assert res["verification_status"] == "PASS"
        assert res["body_hash_valid"] is True
        assert res["signature_math_valid"] is True
        assert res["key_length_bits"] == 2048
    finally:
        dkim_verifier.query_dns_public_key = orig_query


def test_deep_transformer_nlp_intent_classifier():
    """Validates 6-vector intent probability distributions."""
    # 1. Financial wire transfer
    wire_text = "Urgent: Complete the wire transfer of $250,000 for the ongoing European acquisition. Routing and SWIFT details attached."
    wire_res = transformer_classifier.classify_intent(wire_text, subject="Acquisition Escrow Payment")
    assert wire_res["predicted_category"] == VECTOR_FINANCIAL_WIRE_FRAUD
    assert wire_res["confidence"] > 0.4
    assert sum(wire_res["category_probabilities"].values()) == pytest.approx(1.0, rel=1e-2)

    # 2. Credential harvesting
    cred_text = "Your Microsoft 365 password expires today. Reset your password immediately via the security portal."
    cred_res = transformer_classifier.classify_intent(cred_text, subject="Password Expiration Warning")
    assert cred_res["predicted_category"] == VECTOR_CREDENTIAL_HARVESTING

    # 3. Clean benign email
    clean_text = "Hi team, please find the minutes from our Monday morning sync attached. See you at lunch."
    clean_res = transformer_classifier.classify_intent(clean_text, subject="Weekly Sync Notes")
    assert clean_res["predicted_category"] == VECTOR_CLEAN_BENIGN


def test_vip_roster_executive_impersonation():
    """Validates detection of executive display names sent from unauthorized domains."""
    # Impersonation attempt: Satya Nadella sent from @gmail.com
    spoofed = "Satya Nadella <ceo-corporate-exec@gmail.com>"
    res = transformer_classifier.check_vip_impersonation(spoofed, body_text="Are you at your desk?")
    assert res["is_vip_impersonation"] is True
    assert res["matched_vip"] == "Satya Nadella"
    assert "Executive Display Name Spoofing Detected" in res["warning"]

    # Legitimate attempt: Satya Nadella sent from @microsoft.com
    legit = "Satya Nadella <satya@microsoft.com>"
    legit_res = transformer_classifier.check_vip_impersonation(legit)
    assert legit_res["is_vip_impersonation"] is False


def test_louvain_community_modularity_clustering():
    """Validates Louvain modularity clustering and syndicate partitioning."""
    comm_data = threat_graph_manager.get_louvain_communities()
    assert comm_data["community_count"] >= 2
    assert comm_data["modularity_score"] >= 0.50
    assert len(comm_data["nodes"]) >= 4
    assert len(comm_data["edges"]) >= 3

    # Check that communities have colors and syndicate names
    for comm in comm_data["communities"]:
        assert comm["community_id"].startswith("comm-")
        assert comm["syndicate_name"].startswith("SYNDICATE-")
        assert comm["color"].startswith("#")


def test_phase7_api_endpoints(client):
    """Tests Phase 7 CTI lookup, graph communities, and VIP roster endpoints."""
    # 1. CTI lookup endpoint
    cti_res = client.get("/api/forensics/cti/lookup?query=185.220.101.5")
    assert cti_res.status_code == 200
    cti_data = cti_res.json()
    assert cti_data["is_malicious"] is True
    assert cti_data["verdict"] == "MALICIOUS"
    assert len(cti_data["records"]) >= 2

    # 2. Campaign communities endpoint
    comm_res = client.get("/api/forensics/campaigns/communities")
    assert comm_res.status_code == 200
    comm_data = comm_res.json()
    assert comm_data["community_count"] >= 2
    assert "modularity_score" in comm_data

    # 3. VIP roster read endpoint
    roster_res = client.get("/api/forensics/vip-roster")
    assert roster_res.status_code == 200
    assert roster_res.json()["count"] >= 4

    # 4. VIP roster add endpoint (Requires Admin or Analyst)
    admin_token = create_access_token({"sub": "usr-admin", "role": ROLE_SUPER_ADMIN})
    add_res = client.post(
        "/api/forensics/vip-roster",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Elon Musk",
            "title": "Chief Executive Officer",
            "trusted_domains": ["tesla.com", "x.com"],
            "is_active": True
        }
    )
    assert add_res.status_code == 200
    assert "Elon Musk" in add_res.json()["message"]
