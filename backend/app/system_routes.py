from __future__ import annotations

import os
import time
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel

from app.database import (
    scans_collection,
    threat_feed_collection,
    vt_cache_collection,
    get_db_status,
)
from app.services.threat_intel import sync_openphish
from app.services.cti_service import cti_service

logger = logging.getLogger("spectrashield.system_routes")
system_router = APIRouter(prefix="/api/system", tags=["System & Integrations"])

_backend_env_path = Path(__file__).resolve().parent.parent / ".env"
_root_env_path = Path(__file__).resolve().parent.parent.parent / ".env"


def _mask_key(key: Optional[str]) -> Optional[str]:
    if not key or not key.strip():
        return None
    k = key.strip()
    if len(k) <= 8:
        return "••••••••"
    return f"{k[:4]}••••••••••••••••••••••••{k[-4:]}"


def _persist_env_var(var_name: str, var_value: str) -> None:
    """Safely updates or appends an environment variable in backend/.env and root .env."""
    targets = [_backend_env_path]
    if _root_env_path.is_file():
        targets.append(_root_env_path)

    for path in targets:
        lines: list[str] = []
        found = False
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")
                lines = content.splitlines()
            except Exception as e:
                logger.warning("Could not read %s: %s", path, e)
                lines = []

        new_lines: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(f"{var_name}=") or stripped.startswith(f"{var_name} ="):
                new_lines.append(f"{var_name}={var_value}")
                found = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.append(f"{var_name}={var_value}")

        try:
            path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            logger.info("Persisted %s to %s", var_name, path)
        except Exception as e:
            logger.error("Failed to write to %s: %s", path, e)


class TestIntegrationRequest(BaseModel):
    service: str


class UpdateKeyRequest(BaseModel):
    service: str
    api_key: str


@system_router.get("/integrations")
async def get_system_integrations() -> Dict[str, Any]:
    """Returns live configuration, status, cache, and telemetry for threat intelligence feeds."""
    vt_key = os.getenv("VT_API_KEY", "").strip()
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    # Query counts safely
    try:
        vt_cached_count = vt_cache_collection.count_documents({})
    except Exception:
        vt_cached_count = len(vt_cache_collection.find({}))

    try:
        openphish_count = threat_feed_collection.count_documents({})
    except Exception:
        openphish_count = len(threat_feed_collection.find({}))

    try:
        scans_count = scans_collection.count_documents({})
    except Exception:
        scans_count = len(scans_collection.find({}))

    db_status = get_db_status()

    return {
        "virustotal": {
            "name": "VirusTotal Intelligence",
            "service_id": "virustotal",
            "configured": bool(vt_key),
            "status": "operational" if vt_key else "not_configured",
            "key_masked": _mask_key(vt_key),
            "cache_entries": vt_cached_count,
            "rate_limit": "4 req / min (Public API)",
            "description": "Multi-engine antivirus heuristic analysis & threat telemetry",
        },
        "openphish": {
            "name": "OpenPhish Global Feed",
            "service_id": "openphish",
            "configured": True,
            "status": "operational",
            "key_masked": None,
            "indicators_count": openphish_count,
            "feed_url": "https://openphish.com/feed.txt",
            "sync_interval": "24h Automated Pulse",
            "description": "Autonomous zero-day targeted phishing URL telemetry",
        },
        "google_safe_browsing": {
            "name": "Google Safe Browsing v4",
            "service_id": "google_safe_browsing",
            "configured": bool(gsb_key),
            "status": "operational" if gsb_key else "not_configured",
            "key_masked": _mask_key(gsb_key),
            "rate_limit": "10,000 queries / day",
            "version": "v4 (Lookup API)",
            "description": "Google malware, social engineering, and unwanted software intel",
        },
        "abuseipdb": {
            "name": "AbuseIPDB Network",
            "service_id": "abuseipdb",
            "configured": bool(abuse_key),
            "status": "operational" if abuse_key else "not_configured",
            "key_masked": _mask_key(abuse_key),
            "rate_limit": "1,000 checks / day",
            "description": "Crowdsourced IP reputation and brute-force telemetry database",
        },
        "database": {
            "name": "Evidence Vault Database",
            "service_id": "database",
            "provider": db_status.get("provider", "In-Memory Vault"),
            "backend": db_status.get("backend", "in-memory"),
            "is_connected": db_status.get("is_connected", False),
            "records_count": scans_count,
            "status": "operational" if db_status.get("is_connected", False) else "fallback_vault",
            "description": "Forensic audit ledger, cases, and scan artifacts persistence",
        },
        "detection_engine": {
            "name": "SpectraShield Consensus Core",
            "status": "operational",
            "version": "2.0.0-phase3",
            "active_scanners": [
                "Hybrid Consensus Scanner",
                "AI Linguistic NLP Detector",
                "Brand Impersonation Classifier",
                "OpenPhish Feed Sync",
                "DKIM / SPF Forensic Parser",
            ],
        },
    }


@system_router.post("/integrations/test")
async def test_integration(req: TestIntegrationRequest) -> Dict[str, Any]:
    """Runs a real live ping with latency measurement to test connectivity with an external service."""
    service = (req.service or "").strip().lower()
    t0 = time.perf_counter()

    if service == "virustotal":
        api_key = os.getenv("VT_API_KEY", "").strip()
        if not api_key:
            return {
                "success": False,
                "service": "virustotal",
                "latency_ms": 0,
                "message": "VirusTotal API Key is not configured in backend environment.",
                "details": {"status": "missing_key"},
            }
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(
                    "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                    headers={"x-apikey": api_key},
                )
            latency_ms = int((time.perf_counter() - t0) * 1000)
            if resp.status_code in (200, 429):
                # 429 is rate-limited but means the key is authenticated
                return {
                    "success": True,
                    "service": "virustotal",
                    "latency_ms": latency_ms,
                    "message": "VirusTotal API connected successfully.",
                    "details": {"status_code": resp.status_code, "quota_status": "ok" if resp.status_code == 200 else "rate_limited"},
                }
            elif resp.status_code in (401, 403):
                return {
                    "success": False,
                    "service": "virustotal",
                    "latency_ms": latency_ms,
                    "message": "Authentication failed. VirusTotal API Key is invalid or rejected.",
                    "details": {"status_code": resp.status_code},
                }
            else:
                return {
                    "success": False,
                    "service": "virustotal",
                    "latency_ms": latency_ms,
                    "message": f"VirusTotal returned unexpected HTTP {resp.status_code}.",
                    "details": {"status_code": resp.status_code},
                }
        except Exception as e:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return {
                "success": False,
                "service": "virustotal",
                "latency_ms": latency_ms,
                "message": f"Network ping failed: {str(e)}",
                "details": {"error": str(e)},
            }

    elif service == "openphish":
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                resp = await client.head("https://openphish.com/feed.txt")
            latency_ms = int((time.perf_counter() - t0) * 1000)
            indicators = threat_feed_collection.count_documents({})
            if resp.status_code in (200, 301, 302):
                return {
                    "success": True,
                    "service": "openphish",
                    "latency_ms": latency_ms,
                    "message": f"OpenPhish feed reachable. {indicators} local threat indicators active.",
                    "details": {"status_code": resp.status_code, "indicators_count": indicators},
                }
            return {
                "success": False,
                "service": "openphish",
                "latency_ms": latency_ms,
                "message": f"OpenPhish feed returned HTTP {resp.status_code}.",
                "details": {"status_code": resp.status_code},
            }
        except Exception as e:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return {
                "success": False,
                "service": "openphish",
                "latency_ms": latency_ms,
                "message": f"Could not reach OpenPhish feed: {str(e)}",
                "details": {"error": str(e)},
            }

    elif service in ("google_safe_browsing", "gsb"):
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        if not api_key:
            return {
                "success": False,
                "service": "google_safe_browsing",
                "latency_ms": 0,
                "message": "Google Safe Browsing API Key is not configured.",
                "details": {"status": "missing_key"},
            }
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            payload = {
                "client": {"clientId": "spectrashield-test", "clientVersion": "2.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": "http://malware.testing.google.test/testing/malware/"}],
                },
            }
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(endpoint, json=payload)
            latency_ms = int((time.perf_counter() - t0) * 1000)
            if resp.status_code == 200:
                data = resp.json()
                matches = len(data.get("matches", []))
                return {
                    "success": True,
                    "service": "google_safe_browsing",
                    "latency_ms": latency_ms,
                    "message": f"Google Safe Browsing v4 active. Threat test pattern confirmed ({matches} match returned).",
                    "details": {"status_code": resp.status_code, "matches": matches},
                }
            elif resp.status_code in (400, 403):
                return {
                    "success": False,
                    "service": "google_safe_browsing",
                    "latency_ms": latency_ms,
                    "message": f"Google Safe Browsing authentication error (HTTP {resp.status_code}). Check API key validity & billing.",
                    "details": {"status_code": resp.status_code, "body": resp.text[:200]},
                }
            else:
                return {
                    "success": False,
                    "service": "google_safe_browsing",
                    "latency_ms": latency_ms,
                    "message": f"Unexpected HTTP response {resp.status_code}.",
                    "details": {"status_code": resp.status_code},
                }
        except Exception as e:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return {
                "success": False,
                "service": "google_safe_browsing",
                "latency_ms": latency_ms,
                "message": f"Network ping failed: {str(e)}",
                "details": {"error": str(e)},
            }

    elif service == "abuseipdb":
        api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        if not api_key:
            return {
                "success": False,
                "service": "abuseipdb",
                "latency_ms": 0,
                "message": "AbuseIPDB API Key is not configured.",
                "details": {"status": "missing_key"},
            }
        try:
            url = "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90"
            headers = {"Key": api_key, "Accept": "application/json"}
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, headers=headers)
            latency_ms = int((time.perf_counter() - t0) * 1000)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "success": True,
                    "service": "abuseipdb",
                    "latency_ms": latency_ms,
                    "message": f"AbuseIPDB connection operational (IP: 8.8.8.8, Abuse Confidence: {data.get('abuseConfidenceScore', 0)}%).",
                    "details": {"status_code": 200, "data": data},
                }
            else:
                return {
                    "success": False,
                    "service": "abuseipdb",
                    "latency_ms": latency_ms,
                    "message": f"AbuseIPDB returned HTTP {resp.status_code}.",
                    "details": {"status_code": resp.status_code, "body": resp.text[:200]},
                }
        except Exception as e:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return {
                "success": False,
                "service": "abuseipdb",
                "latency_ms": latency_ms,
                "message": f"Network ping failed: {str(e)}",
                "details": {"error": str(e)},
            }

    elif service in ("database", "db"):
        try:
            db_status = get_db_status()
            count = scans_collection.count_documents({})
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return {
                "success": True,
                "service": "database",
                "latency_ms": latency_ms,
                "message": f"Database connected: {db_status.get('provider')} with {count} scan records.",
                "details": db_status,
            }
        except Exception as e:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return {
                "success": False,
                "service": "database",
                "latency_ms": latency_ms,
                "message": f"Database error: {str(e)}",
                "details": {"error": str(e)},
            }

    else:
        raise HTTPException(status_code=400, detail=f"Unknown service '{service}'")


@system_router.post("/integrations/sync-openphish")
async def trigger_openphish_sync() -> Dict[str, Any]:
    """Manually triggers an immediate synchronization of the OpenPhish community threat feed."""
    try:
        result = await sync_openphish()
        total_indicators = threat_feed_collection.count_documents({})
        return {
            "success": True,
            "message": f"OpenPhish feed synchronized: {result.get('fetched', 0)} fetched, {result.get('upserted', 0)} new indicators added.",
            "total_indicators": total_indicators,
            "details": result,
        }
    except Exception as e:
        logger.exception("Failed to sync OpenPhish feed")
        raise HTTPException(status_code=500, detail=f"Failed to sync OpenPhish feed: {str(e)}")


@system_router.post("/integrations/update-key")
async def update_integration_key(req: UpdateKeyRequest) -> Dict[str, Any]:
    """Updates and securely persists API keys in the environment for an integration."""
    service_map = {
        "virustotal": "VT_API_KEY",
        "google_safe_browsing": "GOOGLE_SAFE_BROWSING_API_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
    }
    env_var = service_map.get(req.service.strip().lower())
    if not env_var:
        raise HTTPException(status_code=400, detail=f"Unsupported service for key update: '{req.service}'")

    cleaned_key = req.api_key.strip()
    os.environ[env_var] = cleaned_key

    # Update runtime service instances if applicable
    if env_var == "GOOGLE_SAFE_BROWSING_API_KEY":
        cti_service.gsb_api_key = cleaned_key
    elif env_var == "ABUSEIPDB_API_KEY":
        cti_service.abuseipdb_api_key = cleaned_key

    # Persist to disk
    _persist_env_var(env_var, cleaned_key)

    return {
        "success": True,
        "service": req.service,
        "message": f"{req.service} API key successfully updated and saved.",
        "key_masked": _mask_key(cleaned_key),
    }
