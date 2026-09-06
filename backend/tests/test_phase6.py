import pytest
from fastapi.testclient import TestClient
import pyotp

from app.main import app
from app.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_totp_secret,
    generate_totp_uri,
    generate_totp_qr_base64,
    verify_totp_code,
    ROLE_SUPER_ADMIN,
    ROLE_FORENSIC_ANALYST,
    ROLE_SOC_OPERATOR,
    ROLE_AUDITOR,
    ROLE_PERMISSIONS,
)
from app.storage import user_store, evidence_vault


@pytest.fixture
def client():
    return TestClient(app)


def test_password_hashing():
    """Validates bcrypt password hashing and verification."""
    password = "TestPassword@2026!"
    hashed = hash_password(password)
    assert hashed != password
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_lifecycle():
    """Validates JWT creation, decoding, and type differentiation."""
    access_token = create_access_token({"sub": "usr-test", "role": ROLE_FORENSIC_ANALYST})
    payload = decode_token(access_token)
    assert payload is not None
    assert payload.get("sub") == "usr-test"
    assert payload.get("role") == ROLE_FORENSIC_ANALYST
    assert payload.get("type") == "access"

    refresh_token = create_refresh_token({"sub": "usr-test", "role": ROLE_FORENSIC_ANALYST})
    ref_payload = decode_token(refresh_token)
    assert ref_payload is not None
    assert ref_payload.get("type") == "refresh"

    # Invalid token handling
    assert decode_token("invalid.token.structure") is None


def test_rfc6238_totp_engine():
    """Validates RFC 6238 TOTP generation, QR rendering, and validation."""
    secret = generate_totp_secret()
    assert len(secret) == 32
    
    uri = generate_totp_uri(secret, "analyst@spectrashield.soc")
    assert uri.startswith("otpauth://totp/SpectraShield%20SOC:analyst")
    assert "secret=" in uri

    qr_base64 = generate_totp_qr_base64(secret, "analyst@spectrashield.soc")
    assert qr_base64.startswith("data:image/png;base64,")

    # Generate current TOTP code using pyotp
    totp = pyotp.TOTP(secret)
    current_code = totp.now()

    assert verify_totp_code(secret, current_code) is True
    assert verify_totp_code(secret, "000000") is False
    assert verify_totp_code(secret, "invalid") is False
    assert verify_totp_code(secret, "123") is False


def test_auth_login_endpoint(client):
    """Tests password login endpoint with seeded credentials."""
    # 1. Success login for Analyst
    res = client.post("/api/auth/login", json={
        "email": "analyst@spectrashield.soc",
        "password": "Analyst@Spectra2026!"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["role"] == ROLE_FORENSIC_ANALYST
    assert "cases:write" in data["permissions"]

    # 2. Failed login with bad password
    bad_res = client.post("/api/auth/login", json={
        "email": "analyst@spectrashield.soc",
        "password": "WrongPassword!"
    })
    assert bad_res.status_code == 401


def test_role_simulation_endpoint(client):
    """Tests the 1-click role simulation helper."""
    for role in [ROLE_SUPER_ADMIN, ROLE_FORENSIC_ANALYST, ROLE_SOC_OPERATOR, ROLE_AUDITOR]:
        res = client.post("/api/auth/simulate-role", json={"role": role})
        assert res.status_code == 200
        data = res.json()
        assert data["simulated_role"] == role
        assert data["user"]["role"] == role
        assert "access_token" in data

    # Invalid role rejection
    bad_role_res = client.post("/api/auth/simulate-role", json={"role": "ILLEGAL_ROLE"})
    assert bad_role_res.status_code == 400


def test_2fa_setup_and_verify_flow(client):
    """Tests 2FA setup, verification, and subsequent 2FA challenge login."""
    # 1. Login to get token for Operator
    login_res = client.post("/api/auth/login", json={
        "email": "operator@spectrashield.soc",
        "password": "Operator@Spectra2026!"
    })
    token = login_res.json()["access_token"]

    # 2. Setup 2FA
    setup_res = client.post("/api/auth/2fa/setup", headers={"Authorization": f"Bearer {token}"})
    assert setup_res.status_code == 200
    setup_data = setup_res.json()
    secret = setup_data["secret"]
    assert setup_data["qr_code_base64"].startswith("data:image/png;base64,")

    # 3. Verify & Enable 2FA
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    verify_res = client.post(
        "/api/auth/2fa/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": valid_code, "secret": secret}
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["totp_enabled"] is True

    # 4. Attempt login now that 2FA is required
    login_2fa = client.post("/api/auth/login", json={
        "email": "operator@spectrashield.soc",
        "password": "Operator@Spectra2026!"
    })
    assert login_2fa.status_code == 200
    login_2fa_data = login_2fa.json()
    assert login_2fa_data.get("requires_2fa") is True
    temp_token = login_2fa_data["temp_token"]

    # 5. Complete 2FA login challenge with temp_token
    code_for_login = pyotp.TOTP(secret).now()
    challenge_res = client.post("/api/auth/2fa/verify", json={
        "code": code_for_login,
        "temp_token": temp_token
    })
    assert challenge_res.status_code == 200
    assert "access_token" in challenge_res.json()
    assert challenge_res.json()["user"]["role"] == ROLE_SOC_OPERATOR

    # Clean up: disable 2FA for operator to keep test idempotency
    disable_code = pyotp.TOTP(secret).now()
    client.post(
        "/api/auth/2fa/disable",
        headers={"Authorization": f"Bearer {challenge_res.json()['access_token']}"},
        json={"code": disable_code}
    )


def test_4tier_rbac_route_enforcement(client):
    """
    Verifies that RBAC guards strictly reject unauthorized tiers (403 Forbidden).
    Specifically, SOC_OPERATOR cannot update case status, while FORENSIC_ANALYST and SUPER_ADMIN can.
    """
    # Create or get a test case
    cases = evidence_vault.list_cases(limit=1)
    assert len(cases) > 0
    case_id = cases[0]["id"]

    # 1. Get SOC_OPERATOR token via simulate-role
    op_res = client.post("/api/auth/simulate-role", json={"role": ROLE_SOC_OPERATOR})
    op_token = op_res.json()["access_token"]

    # 2. Attempt case status update as SOC_OPERATOR -> Must return 403 Forbidden
    op_update = client.patch(
        f"/api/forensics/cases/{case_id}/status",
        headers={"Authorization": f"Bearer {op_token}"},
        json={"status": "INVESTIGATING", "reason": "Operator test"}
    )
    assert op_update.status_code == 403
    assert "Forbidden" in op_update.json()["detail"]["error"]

    # 3. Get FORENSIC_ANALYST token via simulate-role
    analyst_res = client.post("/api/auth/simulate-role", json={"role": ROLE_FORENSIC_ANALYST})
    analyst_token = analyst_res.json()["access_token"]

    # 4. Attempt case status update as FORENSIC_ANALYST -> Must succeed 200 OK
    analyst_update = client.patch(
        f"/api/forensics/cases/{case_id}/status",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"status": "INVESTIGATING", "reason": "Analyst triage"}
    )
    assert analyst_update.status_code == 200
    assert analyst_update.json()["case"]["status"] == "INVESTIGATING"

    # 5. User Directory RBAC check:
    # AUDITOR can list users (200)
    auditor_res = client.post("/api/auth/simulate-role", json={"role": ROLE_AUDITOR})
    auditor_token = auditor_res.json()["access_token"]
    user_list_res = client.get("/api/auth/users", headers={"Authorization": f"Bearer {auditor_token}"})
    assert user_list_res.status_code == 200
    assert user_list_res.json()["count"] >= 4

    # SOC_OPERATOR cannot list users (403 Forbidden)
    op_user_list = client.get("/api/auth/users", headers={"Authorization": f"Bearer {op_token}"})
    assert op_user_list.status_code == 403
