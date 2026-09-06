# Software Design Document (SDD) & Technical Specification — Phase 6

**Document Title:** Enterprise Identity, 4-Tier Role-Based Access Control (RBAC) & RFC 6238 2FA TOTP Authentication  
**Project Name:** SpectraShield 2.0 (Forensic Edition)  
**Short Name:** AegisMail Forensics (AegisMail_AI)  
**Phase Identifier:** Phase 6 of Version 2.0 (Sprint 3 Roadmap)  
**SIH Problem Statement ID:** 26106 (AICTE Cyber Security Cell)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  
**Target Beneficiaries:** Enterprise Security Administrators, SOC Directors, Compliance Officers, Digital Forensics Analysts  
**Baseline System State:** SpectraShield 2.0 (Phase 5 Foundation)  
**Date:** September 2026  

---

## 1. Project Overview & Phase 6 Executive Summary

### 1.1 Executive Summary
Digital forensics platforms ingest and store highly sensitive enterprise communications, executive correspondence, financial records, and unredacted evidentiary artifacts. Regulatory standards such as **ISO/IEC 27037**, **GDPR Article 32**, and the **Indian Bharatiya Nagarik Suraksha Sanhita (BNSS)** mandate strict non-repudiation, tamper resistance, and identity-bound access control. In a legitimate SOC deployment, an open, unauthenticated dashboard is inadmissible in court and poses catastrophic insider threat risks.

Currently, SpectraShield operates as an open internal SOC console. Case assignment fields accept analyst names, and roles are displayed cosmetically, but there is no cryptographic authentication barrier, user database, JWT token validation, or multi-factor authentication.

**Phase 6** establishes enterprise identity security across the platform by implementing:
1. **User Identity & Password Cryptography (`SEC-02`):** Secure database user models, salt-hashed passwords using `bcrypt` (work factor 12), and short-lived JWT access tokens with secure refresh tokens.
2. **RFC 6238 TOTP Two-Factor Authentication:** Cryptographic time-based one-time password (TOTP) enforcement via `pyotp`, generating scannable QR code setup matrices for Google Authenticator, Microsoft Authenticator, and Authy.
3. **4-Tier Role-Based Access Control (RBAC):** Strict FastAPI dependency route guards enforcing organizational boundaries:
   - **`SUPER_ADMIN`**: Full administrative rights, API key rotation, user provisioning, evidence purging.
   - **`FORENSIC_ANALYST`**: Full evidentiary access, raw byte-stream inspection, note taking, ISO PDF dossier generation.
   - **`SOC_OPERATOR`**: Triage incoming emails, run automated scans, escalate cases (view-only raw evidence).
   - **`AUDITOR`**: Read-only inspection of completed cases and immutable chain-of-custody audit ledgers.
4. **Universal Liquid Glass Authentication Interface:** Stunning, refractive login portal with fluid glass cards, TOTP QR setup modal, active session profile drawer, and instant analyst role switching for testing.

### 1.2 Phase 6 Mission & Objectives
- **Secure API Attack Surface:** Protect all `/api/forensics/*` mutation endpoints behind verified JWT bearer authorization tokens.
- **Enforce Mandatory Multi-Factor Authentication:** Ensure investigators must pass both password authentication and RFC 6238 TOTP verification before accessing sensitive case files.
- **Implement Granular RBAC Permissions:** Prevent unauthorized modification of case status, deletion of scan history, or unredacted PII export by unauthorized tiers.
- **Seamless SOC User Experience:** Provide a smooth, fluid login flow with graceful offline demo modes and mock bypass switches for rapid local demonstration.

---

## 2. Tech Stack & Dependencies

### 2.1 Backend Architecture
- **Runtime:** Python 3.11+
- **Password Hashing:** `passlib[bcrypt]` 1.7+ (Bcrypt salt generation & hashing)
- **Token Cryptography:** `python-jose[cryptography]` 3.3+ (JWT encoding, decoding, HMAC-SHA256 signing)
- **Two-Factor Authentication (TOTP):**
  - `pyotp` 2.9+ (RFC 6238 Time-Based One-Time Password generator & validator)
  - `qrcode[pil]` 7.4+ (Generates base64 data URLs for Google Authenticator QR setup)
- **FastAPI Security:** `fastapi.security.OAuth2PasswordBearer`, `fastapi.Depends`

### 2.2 Frontend Architecture
- **Framework:** React 18, TypeScript, Vite
- **State Management:** Reactive user session store in `frontend/src/app/store/authStore.ts`
- **UI Architecture:** Universal Liquid Glass login portal, 6-digit TOTP input boxes with auto-advance, profile header chip with role indicator badge

---

## 3. Core Features & Detailed Specifications

### 3.1 Feature SEC-02-AUTH: JWT Identity & Token Lifecycle
- **Technical Description:** User authentication pipeline issuing dual cryptographic tokens:
  - **Access Token:** Short-lived (15 minutes), payload containing `sub` (user_id), `role`, `email`, and `session_id`. Signed with `JWT_SECRET_KEY` using `HS256`.
  - **Refresh Token:** Long-lived (7 days), stored in encrypted database store or secure `httpOnly` cookie.
- **Endpoints:**
  - `POST /api/auth/register` (Super Admin or initial setup)
  - `POST /api/auth/login` (Returns temporary 2FA ticket or tokens if 2FA disabled)
  - `POST /api/auth/refresh` (Rotates access token)
  - `GET /api/auth/me` (Returns verified current user profile)
  - `POST /api/auth/logout` (Revokes refresh token)

### 3.2 Feature SEC-02-TOTP: RFC 6238 Multi-Factor Authentication
- **Technical Description:** Standards-compliant TOTP engine using a 32-character base32 secret key.
- **Enrollment Flow:**
  1. Investigator triggers `POST /api/auth/2fa/setup`.
  2. Backend generates secret `pyotp.random_base32()` and otpauth URI (`otpauth://totp/SpectraShield:{email}?secret={secret}&issuer=SpectraShield`).
  3. Backend renders a PNG QR code encoded as a Base64 data URL (`data:image/png;base64,...`).
  4. Investigator scans the QR code in Google Authenticator or Authy.
  5. Investigator submits the first 6-digit token to `POST /api/auth/2fa/verify`.
  6. Backend confirms validity (`totp.verify(code, valid_window=1)`), marks `two_factor_enabled = true`, and issues recovery codes.
- **Authentication Flow:**
  1. Login with username/password returns `{ require_2fa: true, temp_session_token: "..." }`.
  2. User enters 6-digit code.
  3. Backend validates code against user's secret key and issues full JWT tokens.

### 3.3 Feature SEC-02-RBAC: 4-Tier Role-Based Access Control
- **Role Permission Matrix:**

| Capability / Endpoint | `SUPER_ADMIN` | `FORENSIC_ANALYST` | `SOC_OPERATOR` | `AUDITOR` |
| :--- | :---: | :---: | :---: | :---: |
| Ingest & Scan Emails (`POST /analyze`, `upload-eml`) | ✅ | ✅ | ✅ | ❌ |
| View Forensic Dashboard & Metrics | ✅ | ✅ | ✅ | ✅ |
| View Threat Graph & Geolocation Map | ✅ | ✅ | ✅ | ✅ |
| View Raw RFC 5322 Headers & Attachment Hashes | ✅ | ✅ | ⚠️ Redacted | ✅ |
| Change Case Status (`PATCH /cases/{id}/status`) | ✅ | ✅ | ⚠️ Escalate Only | ❌ |
| Add Investigation Notes (`POST /cases/{id}/notes`) | ✅ | ✅ | ❌ | ❌ |
| Assign Lead Investigator (`POST /cases/{id}/assign`)| ✅ | ✅ | ❌ | ❌ |
| Export ISO 27037 Court PDF Dossier | ✅ | ✅ | ❌ | ✅ |
| Export Defanged CSV / STIX 2.1 CTI Feed | ✅ | ✅ | ✅ | ✅ |
| Unredacted PII View (De-mask SSN / Credit Cards) | ✅ | ⚠️ Audit Logged | ❌ | ❌ |
| User Provisioning & System Settings | ✅ | ❌ | ❌ | ❌ |

---

## 4. Architecture & Security Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          USER AUTHENTICATION FLOW                           │
└─────────────────────────────────────────────────────────────────────────────┘
  [ Client Browser ]                              [ FastAPI Auth Controller ]
          │                                                    │
          │ 1. POST /api/auth/login (email, password)          │
          ├───────────────────────────────────────────────────►│
          │                                                    │ Verify bcrypt hash
          │                                                    │ Check 2FA requirement
          │ 2. Return { require_2fa: true, temp_token }        │
          │◄───────────────────────────────────────────────────┤
          │                                                    │
          │ 3. User scans QR code / opens Authenticator app    │
          │                                                    │
          │ 4. POST /api/auth/2fa/verify (code: "829104")      │
          ├───────────────────────────────────────────────────►│
          │                                                    │ pyotp.verify(code)
          │                                                    │ Sign HS256 JWT
          │ 5. Return { access_token, role, user }             │
          │◄───────────────────────────────────────────────────┤
          │                                                    │
          │ 6. Subsequent API Calls (Bearer <access_token>)    │
          ├───────────────────────────────────────────────────►│
                                                               │ Depends(require_role)
                                                               │ Check Permissions
                                                               │ Execute Operation
```

---

## 5. Database Schemas & Pydantic Models

### 5.1 MongoDB / PostgreSQL User Schema
```json
{
  "_id": "USR-2026-001",
  "email": "analyst@spectrashield.soc",
  "name": "Alex Chen",
  "password_hash": "$2b$12$e8e4a726b23...hashed",
  "role": "FORENSIC_ANALYST",
  "two_factor_enabled": true,
  "two_factor_secret": "JBSWY3DPEHPK3PXP",
  "recovery_codes": ["a1b2c3d4", "e5f6g7h8"],
  "created_at": "2026-09-01T10:00:00Z",
  "last_login": "2026-09-06T14:20:00Z",
  "is_active": true
}
```

### 5.2 Pydantic Schemas (`backend/app/schemas.py`)
```python
class UserRole(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    FORENSIC_ANALYST = "FORENSIC_ANALYST"
    SOC_OPERATOR = "SOC_OPERATOR"
    AUDITOR = "AUDITOR"

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole
    name: str
    email: str

class TwoFactorSetupResponse(BaseModel):
    secret_key: str
    otpauth_url: str
    qr_code_data_url: str

class TwoFactorVerifyRequest(BaseModel):
    temp_token: Optional[str] = None
    code: str
```

---

## 6. API Endpoints Specification

### 6.1 Authentication Endpoints (`/api/auth`)
- `POST /api/auth/login` – Validate credentials; returns JWT or requests 2FA code.
- `POST /api/auth/2fa/setup` – Generate new TOTP secret & QR code data URL.
- `POST /api/auth/2fa/verify` – Verify 6-digit TOTP token; issues active session tokens.
- `GET  /api/auth/me` – Retrieve active user profile and roles.
- `POST /api/auth/refresh` – Exchange refresh token for fresh access token.

---

## 7. Frontend Components & Universal Liquid Glass UI

### 7.1 Liquid Glass Login Portal (`LoginModal.tsx` / `AuthView.tsx`)
- Specular rim-highlighted card (`backdrop-blur-3xl`, `backdrop-saturate-200`).
- Fluid tab control: **Sign In** | **Role Simulator / Quick Switch (Demo Mode)**.
- 6-digit split input boxes with smooth auto-focus for TOTP code entry.
- Floating biometric / authenticator badge with pulsing cyan glow.

### 7.2 Header User Profile & Role Switcher
- AppHeader displays authenticated user chip with role-colored badge:
  - 🔴 `SUPER_ADMIN` (Crimson)
  - 🔵 `FORENSIC_ANALYST` (Cyan)
  - 🟡 `SOC_OPERATOR` (Amber)
  - 🟣 `AUDITOR` (Purple)
- 1-click dropdown to simulate different roles for testing permissions.

---

## 8. Annotated File Modification Matrix

```text
SpectraShield/
├── backend/
│   ├── requirements.txt                         # Added: passlib[bcrypt], python-jose, pyotp, qrcode[pil]
│   ├── app/
│   │   ├── auth_routes.py                       # [NEW] /api/auth login, 2fa, and user endpoints
│   │   ├── security.py                          # [NEW] JWT validation & require_role() dependencies
│   │   ├── main.py                              # [MODIFY] Mounted auth_routes router
│   │   ├── forensic_routes.py                   # [MODIFY] Protected endpoints with Depends(require_role)
│   │   └── storage.py                           # [MODIFY] Added users collection & authentication checks
│
└── frontend/
    └── src/
        ├── app/
        │   ├── store/
        │   │   └── authStore.ts                 # [NEW] Zustand auth & session store
        │   ├── api.ts                           # [MODIFY] Added auth headers & token interceptors
        │   ├── App.tsx                          # [MODIFY] Added auth gate & header user chip
        │   └── components/
        │       └── auth/
        │           ├── LoginModal.tsx           # [NEW] Liquid Glass login & TOTP dialog
        │           └── UserProfileDrawer.tsx    # [NEW] Analyst session profile & role switcher
```

---

## 9. Step-by-Step Implementation Roadmap

### Milestone 6.1: Backend Security Infrastructure & JWT
- [ ] Add `passlib[bcrypt]`, `python-jose`, `pyotp`, and `qrcode` to `backend/requirements.txt`.
- [ ] Implement password hashing and JWT token generator in `backend/app/security.py`.
- [ ] Implement user repository and seed default accounts in `backend/app/storage.py`.
- [ ] Create `backend/app/auth_routes.py` with `/login`, `/refresh`, and `/me`.

### Milestone 6.2: RFC 6238 TOTP 2FA Engine
- [ ] Implement `/api/auth/2fa/setup` generating TOTP secret and QR code PNG data URL.
- [ ] Implement `/api/auth/2fa/verify` validating submitted tokens with window tolerance.
- [ ] Protect sensitive administrative operations with 2FA enforcement flags.

### Milestone 6.3: Role Guards & Route Protection
- [ ] Implement `require_role(allowed_roles: List[UserRole])` FastAPI dependency.
- [ ] Apply `require_role` guards across `/api/forensics/cases/*` routes.
- [ ] Write unit tests for RBAC rejection (`403 Forbidden`) in `backend/tests/test_phase6.py`.

### Milestone 6.4: Frontend Authentication & Liquid Glass UI
- [ ] Build `authStore.ts` storing JWT tokens and user metadata with localStorage persistence.
- [ ] Build `LoginModal.tsx` and `UserProfileDrawer.tsx` adhering to Universal Liquid Glass styling.
- [ ] Add authenticated Bearer header to `frontend/src/app/api.ts` requests.
- [ ] Add quick-role switching bar for instant SOC evaluation during demonstrations.

---

## 10. Verification & Quality Gates

1. **Password Security Gate:** Verify that passwords in the database are stored as salt-hashed strings and never logged in plaintext.
2. **TOTP Verification Gate:** Scan generated QR code in Google Authenticator; confirm that the generated 6-digit code grants access while invalid codes return `401 Unauthorized`.
3. **RBAC Isolation Gate:** Make a request as `SOC_OPERATOR` to delete a case or change status to `RESOLVED`; verify that the backend returns `403 Forbidden`.
4. **Token Expiration Gate:** Verify that expired access tokens trigger the `/refresh` endpoint automatically without disrupting active investigations.
5. **Test Suite & Build Gate:** Run `pytest tests/test_phase6.py tests/test_phase5.py tests/test_phase4.py` (100% pass) and `npm run build` (zero errors).
