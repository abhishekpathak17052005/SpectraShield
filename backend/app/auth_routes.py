import logging
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

from app.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    create_temp_token,
    decode_token,
    generate_totp_secret,
    generate_totp_uri,
    generate_totp_qr_base64,
    verify_totp_code,
    get_current_user,
    require_role,
    ROLE_SUPER_ADMIN,
    ROLE_FORENSIC_ANALYST,
    ROLE_SOC_OPERATOR,
    ROLE_AUDITOR,
    VALID_ROLES,
    ROLE_PERMISSIONS,
)
from app.storage import user_store, evidence_vault

logger = logging.getLogger("spectrashield.auth")
auth_router = APIRouter(prefix="/api/auth", tags=["Enterprise Identity & RBAC"])


# Request & Response Schemas
class LoginRequest(BaseModel):
    email: str
    password: str


class Setup2FARequest(BaseModel):
    pass


class Verify2FARequest(BaseModel):
    code: str
    secret: Optional[str] = None
    temp_token: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class RoleSimulationRequest(BaseModel):
    role: Optional[str] = None
    simulated_role: Optional[str] = None


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    password: Optional[str] = None


# Endpoints
@auth_router.post("/login")
async def login(req: LoginRequest):
    """
    Enterprise login endpoint.
    Verifies Bcrypt password hash and checks 2FA requirements.
    """
    user = user_store.get_user_by_email(req.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    if not verify_password(req.password, user.get("hashed_password", "")):
        evidence_vault.append_audit_log(
            case_id="SECURITY",
            action="LOGIN_FAILED",
            actor=req.email,
            metadata={"reason": "bad_password"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # If 2FA TOTP is enabled, challenge user for 6-digit code
    if user.get("totp_enabled"):
        temp_token = create_temp_token({
            "sub": user["id"],
            "email": user["email"],
            "role": user["role"]
        })
        return {
            "status": "2FA_REQUIRED",
            "requires_2fa": True,
            "temp_token": temp_token,
            "user_id": user["id"],
            "message": "Two-factor authentication code required"
        }

    # Issue access and refresh tokens
    access_token = create_access_token({
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"]
    })
    refresh_token = create_refresh_token({
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"]
    })

    user_store.record_login(user["id"])

    evidence_vault.append_audit_log(
        case_id="SECURITY",
        action="USER_LOGIN",
        actor=user["email"],
        metadata={"role": user["role"], "2fa_used": False}
    )

    safe_user = dict(user)
    safe_user.pop("hashed_password", None)
    safe_user.pop("totp_secret", None)

    return {
        "status": "SUCCESS",
        "requires_2fa": False,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": safe_user,
        "permissions": ROLE_PERMISSIONS.get(user["role"], [])
    }


@auth_router.post("/2fa/setup")
async def setup_2fa(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Initiates RFC 6238 2FA setup.
    Generates a 32-character base32 secret and scannable QR code PNG Base64 data URL.
    """
    secret = generate_totp_secret()
    qr_code_base64 = generate_totp_qr_base64(secret, current_user["email"])
    provisioning_uri = generate_totp_uri(secret, current_user["email"])

    return {
        "secret": secret,
        "qr_code_base64": qr_code_base64,
        "provisioning_uri": provisioning_uri,
        "manual_entry_key": secret,
        "user_email": current_user["email"],
        "message": "Scan the QR code with Google Authenticator or enter the manual secret key."
    }


@auth_router.post("/2fa/verify")
async def verify_2fa(req: Verify2FARequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Verifies a 6-digit TOTP code.
    Handles both 2FA activation on an account and 2FA challenge login completion.
    """
    # Scenario 1: Completing login challenge via temp_token
    if req.temp_token:
        payload = decode_token(req.temp_token)
        if not payload or payload.get("type") != "2fa_challenge":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired 2FA session token"
            )
        user_id = payload.get("sub")
        user = user_store.get_user_by_id(user_id) if user_id else None
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        secret = user.get("totp_secret")
        if not secret or not verify_totp_code(secret, req.code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid 6-digit authentication code"
            )

        access_token = create_access_token({
            "sub": user["id"],
            "email": user["email"],
            "role": user["role"]
        })
        refresh_token = create_refresh_token({
            "sub": user["id"],
            "email": user["email"],
            "role": user["role"]
        })

        user_store.record_login(user["id"])

        evidence_vault.append_audit_log(
            case_id="SECURITY",
            action="2FA_LOGIN_SUCCESS",
            actor=user["email"],
            metadata={"role": user["role"], "2fa_used": True}
        )

        safe_user = dict(user)
        safe_user.pop("hashed_password", None)
        safe_user.pop("totp_secret", None)

        return {
            "status": "SUCCESS",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": safe_user,
            "permissions": ROLE_PERMISSIONS.get(user["role"], [])
        }

    # Scenario 2: Enabling 2FA on authenticated account with setup secret
    user = user_store.get_user_by_id(current_user["id"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Authenticated user record not found"
        )

    verification_secret = req.secret or user.get("totp_secret")
    if not verification_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP secret missing. Call /api/auth/2fa/setup first."
        )

    if not verify_totp_code(verification_secret, req.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 6-digit authentication code. Please try again."
        )

    user_store.update_user_totp(user["id"], verification_secret, enabled=True)

    evidence_vault.append_audit_log(
        case_id="SECURITY",
        action="2FA_ENABLED",
        actor=user["email"],
        metadata={"role": user["role"]}
    )

    return {
        "status": "2FA_ENABLED",
        "message": "Two-factor authentication successfully verified and activated.",
        "totp_enabled": True
    }


@auth_router.post("/2fa/disable")
async def disable_2fa(
    req: Verify2FARequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Disables 2FA on user account after verifying current TOTP code."""
    user = user_store.get_user_by_id(current_user["id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = user.get("totp_secret")
    if user.get("totp_enabled") and secret:
        if not verify_totp_code(secret, req.code):
            raise HTTPException(status_code=400, detail="Invalid 6-digit code")

    user_store.update_user(user["id"], {"totp_enabled": False})

    evidence_vault.append_audit_log(
        case_id="SECURITY",
        action="2FA_DISABLED",
        actor=user["email"],
        metadata={"role": user["role"]}
    )

    return {
        "status": "2FA_DISABLED",
        "message": "Two-factor authentication has been disabled.",
        "totp_enabled": False
    }


@auth_router.get("/me")
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns the authenticated profile, active role, and permission matrix."""
    return {
        "user": current_user,
        "role": current_user.get("role"),
        "permissions": ROLE_PERMISSIONS.get(current_user.get("role"), []),
        "is_demo_fallback": current_user.get("is_demo_fallback", False)
    }


@auth_router.post("/refresh")
async def refresh_access_token(req: RefreshTokenRequest):
    """Exchanges a valid refresh token for a new short-lived access token."""
    payload = decode_token(req.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    user_id = payload.get("sub")
    user = user_store.get_user_by_id(user_id) if user_id else None
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    access_token = create_access_token({
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"]
    })

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@auth_router.post("/simulate-role")
@auth_router.post("/role-simulation")
async def simulate_role(req: RoleSimulationRequest):
    """
    Seamless 1-click role simulation for demo, evaluation, and security auditing.
    Switches active identity to one of the 4 enterprise roles instantly.
    """
    raw_role = req.role or req.simulated_role or ""
    role_upper = raw_role.strip().upper()
    if role_upper not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Allowed roles: {', '.join(VALID_ROLES)}"
        )

    role_to_email = {
        ROLE_SUPER_ADMIN: "admin@spectrashield.soc",
        ROLE_FORENSIC_ANALYST: "analyst@spectrashield.soc",
        ROLE_SOC_OPERATOR: "operator@spectrashield.soc",
        ROLE_AUDITOR: "auditor@spectrashield.soc",
    }

    email = role_to_email[role_upper]
    user = user_store.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="Simulated role user record not found")

    access_token = create_access_token({
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"]
    })
    refresh_token = create_refresh_token({
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"]
    })

    evidence_vault.append_audit_log(
        case_id="SECURITY",
        action="ROLE_SIMULATION",
        actor=user["email"],
        metadata={"simulated_role": role_upper}
    )

    safe_user = dict(user)
    safe_user.pop("hashed_password", None)
    safe_user.pop("totp_secret", None)

    return {
        "status": "SUCCESS",
        "role": role_upper,
        "simulated_role": role_upper,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": safe_user,
        "permissions": ROLE_PERMISSIONS.get(role_upper, [])
    }


@auth_router.get("/users")
async def list_enterprise_users(
    current_user: Dict[str, Any] = Depends(require_role([ROLE_SUPER_ADMIN, ROLE_AUDITOR]))
):
    """
    Lists enterprise directory users.
    Restricted to SUPER_ADMIN and AUDITOR roles.
    """
    users = user_store.list_users()
    return {
        "count": len(users),
        "users": users
    }


@auth_router.post("/logout")
async def logout(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Terminates session and records audit non-repudiation log."""
    evidence_vault.append_audit_log(
        case_id="SECURITY",
        action="USER_LOGOUT",
        actor=current_user.get("email", "unknown"),
        metadata={"role": current_user.get("role")}
    )
    return {
        "status": "LOGGED_OUT",
        "message": "User logged out successfully"
    }
