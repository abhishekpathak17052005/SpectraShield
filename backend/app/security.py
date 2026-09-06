import base64
import io
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any

import bcrypt
from dotenv import load_dotenv
import pyotp
import qrcode
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

load_dotenv()

# Secret configuration with sensible fallbacks
DEFAULT_INSECURE_SECRET = "spectrashield_jwt_secret_key_sec02_20260907_984123"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", DEFAULT_INSECURE_SECRET)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
TEMP_TOKEN_EXPIRE_MINUTES = 5
ALLOW_DEMO_FALLBACK = os.getenv("ALLOW_DEMO_FALLBACK", "True").strip().lower() in ("true", "1", "yes")

ENVIRONMENT = (os.getenv("ENVIRONMENT") or os.getenv("ENV") or "development").strip().lower()
if ENVIRONMENT == "production":
    if not os.getenv("JWT_SECRET_KEY") or os.getenv("JWT_SECRET_KEY") == DEFAULT_INSECURE_SECRET:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: SpectraShield is running in production mode, "
            "but JWT_SECRET_KEY is using the default insecure fallback key or is unset. "
            "Configure a secure 256-bit secret in .env before starting."
        )

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# 4-Tier RBAC Definitions
ROLE_SUPER_ADMIN = "SUPER_ADMIN"
ROLE_FORENSIC_ANALYST = "FORENSIC_ANALYST"
ROLE_SOC_OPERATOR = "SOC_OPERATOR"
ROLE_AUDITOR = "AUDITOR"

VALID_ROLES = [
    ROLE_SUPER_ADMIN,
    ROLE_FORENSIC_ANALYST,
    ROLE_SOC_OPERATOR,
    ROLE_AUDITOR,
]

ROLE_PERMISSIONS = {
    ROLE_SUPER_ADMIN: [
        "cases:read", "cases:write", "cases:assign", "cases:status", "cases:delete",
        "analysis:execute", "sandbox:execute", "reports:generate", "audit:read",
        "users:manage", "settings:manage", "rbac:admin"
    ],
    ROLE_FORENSIC_ANALYST: [
        "cases:read", "cases:write", "cases:assign", "cases:status",
        "analysis:execute", "sandbox:execute", "reports:generate", "audit:read"
    ],
    ROLE_SOC_OPERATOR: [
        "cases:read", "analysis:execute", "sandbox:execute", "reports:read"
    ],
    ROLE_AUDITOR: [
        "cases:read", "audit:read", "reports:read", "users:read"
    ]
}


def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt with work factor 12."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Issues a short-lived signed JWT access token (default 15 minutes)."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": "access"
    })
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Issues a long-lived signed JWT refresh token (default 7 days)."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": "refresh"
    })
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_temp_token(data: Dict[str, Any]) -> str:
    """Issues a temporary signed JWT for 2FA challenge completion (5 minutes)."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=TEMP_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": "2fa_challenge"
    })
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT token signature and expiration."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


# RFC 6238 TOTP Helpers
def generate_totp_secret() -> str:
    """Generates a 32-character base32 secret conforming to RFC 6238."""
    return pyotp.random_base32(length=32)


def generate_totp_uri(secret: str, user_email: str, issuer_name: str = "SpectraShield SOC") -> str:
    """Generates the standard otpauth URI for Google Authenticator / Authy."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=user_email, issuer_name=issuer_name)


def generate_totp_qr_base64(secret: str, user_email: str, issuer_name: str = "SpectraShield SOC") -> str:
    """Generates a scannable QR Code PNG Base64 data URL for instant 2FA onboarding."""
    uri = generate_totp_uri(secret, user_email, issuer_name)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_bytes = buffered.getvalue()
    b64 = base64.b64encode(img_bytes).decode("utf-8")
    return f"data:image/png;base64,{b64}"


def verify_totp_code(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verifies a 6-digit TOTP code against secret allowing +-1 time drift window."""
    if not secret or not code:
        return False
    # Strip spaces or hyphens if entered by user
    clean_code = str(code).replace(" ", "").replace("-", "").strip()
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(clean_code, valid_window=valid_window)


# Dependency injection
async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """
    Extracts and verifies the current authenticated user from Bearer token.
    Falls back gracefully to default SOC Analyst for developer/demo continuity
    if unauthenticated and demo mode is active.
    """
    from app.storage import user_store

    if token:
        payload = decode_token(token)
        if payload and payload.get("type") == "access":
            user_id = payload.get("sub")
            if user_id:
                user = user_store.get_user_by_id(user_id)
                if user:
                    user_copy = dict(user)
                    user_copy.pop("hashed_password", None)
                    user_copy.pop("totp_secret", None)
                    return user_copy

    # Strict production enforcement: if demo fallback is disabled, reject unauthenticated calls
    if not ALLOW_DEMO_FALLBACK:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided or have expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Graceful fallback: return default Analyst with is_demo_fallback=True
    # This prevents legacy UI workflows, scans, or automated test runners from crashing
    default_user = user_store.get_user_by_email("analyst@spectrashield.soc")
    if default_user:
        safe_user = dict(default_user)
        safe_user.pop("hashed_password", None)
        safe_user.pop("totp_secret", None)
        safe_user["is_demo_fallback"] = True
        return safe_user

    return {
        "id": "usr-default-analyst",
        "email": "analyst@spectrashield.soc",
        "name": "Forensic SOC Analyst",
        "role": ROLE_FORENSIC_ANALYST,
        "permissions": ROLE_PERMISSIONS[ROLE_FORENSIC_ANALYST],
        "is_demo_fallback": True
    }


def require_role(allowed_roles: List[str]):
    """
    Enforces 4-tier Role-Based Access Control on endpoint routes.
    Rejects unauthorized roles with HTTP 403 Forbidden.
    """
    async def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = current_user.get("role", ROLE_SOC_OPERATOR)
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Forbidden: Insufficient privileges",
                    "user_role": user_role,
                    "required_roles": allowed_roles,
                    "message": f"Action requires one of: {', '.join(allowed_roles)}"
                }
            )
        return current_user

    return role_checker
