import asyncio
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.database import scans_collection, threat_feed_collection, vt_cache_collection
from app.routes import router
from app.scanner import HybridConsensusScanner, analyze_linkedin_message, compute_mail_severity
from app.services.ai_pattern_detector import detect_ai_pattern
from app.services.attack_simulator import generate_attack_simulation
from app.services.brand_detector import detect_brand_impersonation
from app.services.header_analyzer import analyze_email_header
from app.services.manipulation_detector import calculate_manipulation_score
from app.services.threat_category import build_reasoning_summary, get_threat_category
from app.services.threat_intel import analyze_threat_intel
from app.services.threat_intel import sync_openphish

logger = logging.getLogger("spectrashield.daily_pulse")
hybrid_scanner = HybridConsensusScanner(threat_feed_collection, vt_cache_collection=vt_cache_collection)

app = FastAPI(
    title="SpectraShield AI",
    description="Threat Intelligence Platform (phishing detection + explainable URL intel)",
    version="1.0.0",
    debug=True
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    class Config:
        extra = "allow"

    email_text: str = ""
    email_header: Optional[str] = None
    url: Optional[str] = None
    urls: Optional[list[str]] = None
    sender_email: Optional[str] = None
    private_mode: Optional[bool] = False
    thread_id: Optional[str] = None
    platform: Optional[str] = None
    link_pairs: Optional[list[dict]] = None
    opened_mail_body: Optional[str] = None
    opened_mail_urls: Optional[list[str]] = None


def _serialize_attack_simulation(final_risk: float) -> list[dict]:
    raw_steps = generate_attack_simulation(final_risk)
    serialized = []
    for step in raw_steps or []:
        if hasattr(step, "model_dump"):
            serialized.append(step.model_dump())
        else:
            serialized.append(step)
    return serialized


def _score_to_verdict(score: float) -> str:
    if score >= 75:
        return "High Risk"
    if score >= 35:
        return "Medium Risk"
    return "Low Risk"


def _score_to_confidence(score: float) -> str:
    if score >= 75:
        return "Very High Confidence"
    if score >= 50:
        return "High Confidence"
    if score >= 35:
        return "Moderate Confidence"
    return "Low Confidence"


def _extract_urls_from_text(text: str) -> set[str]:
    if not text:
        return set()
    extracted = set()
    matches = re.findall(r'https?://[^\s\]\)\"\'<>]+', text, flags=re.IGNORECASE)
    for u in matches:
        cleaned_u = u.rstrip(']>).\'"')
        if cleaned_u:
            extracted.add(cleaned_u)
    return extracted


def _vt_link_score_from_stats(malicious: int, total: int) -> float:
    if malicious >= 5:
        return 100.0
    if malicious >= 3:
        return 90.0
    if malicious >= 1:
        return 70.0
    if total > 0:
        ratio = malicious / max(total, 1)
        return float(round(min(30.0, ratio * 100.0), 2))
    return 0.0


def _ssl_risk_boost_for_url(url: str) -> tuple[float, bool]:
    raw = (url or "").strip()
    if not raw:
        return 0.0, True

    try:
        parsed = urlparse(raw if raw.startswith(("http://", "https://")) else f"https://{raw}")
    except Exception:
        return 10.0, False

    host = (parsed.hostname or "").strip().lower()
    scheme = (parsed.scheme or "").strip().lower()
    if not host:
        return 10.0, False

    boost = 0.0
    # Non-HTTPS links are an immediate risk signal.
    if scheme and scheme != "https":
        boost += 20.0

    ssl_info = hybrid_scanner._ssl_details(host)
    ssl_valid = bool(ssl_info.get("is_valid"))
    if not ssl_valid:
        boost += 20.0

    return min(40.0, boost), ssl_valid


def _domain_age_profile(domain_age_days: Optional[int]) -> dict:
    if domain_age_days is None:
        return {
            "bucket": "unknown",
            "label": "Unknown",
            "color": "neutral",
            "message": "Domain age could not be verified.",
            "risk_modifier_pct": 0,
        }

    days = max(int(domain_age_days), 0)
    if days <= 30:
        return {
            "bucket": "burner_domain",
            "label": "Burner Domain",
            "color": "red",
            "message": "Extreme Risk: This domain was created in the last month. Common in phishing.",
            "risk_modifier_pct": 50,
        }
    if days <= 180:
        return {
            "bucket": "new_entity",
            "label": "New Entity",
            "color": "orange",
            "message": "High Risk: Relatively new domain. Proceed with caution.",
            "risk_modifier_pct": 25,
        }
    if days <= 1095:
        return {
            "bucket": "emerging",
            "label": "Emerging",
            "color": "yellow",
            "message": "Moderate: Established for over 6 months but lacks a long-term reputation.",
            "risk_modifier_pct": 0,
        }
    if days <= 3650:
        return {
            "bucket": "verified_legacy",
            "label": "Verified Legacy",
            "color": "green",
            "message": "Safe: Stable domain with over 3 years of active history.",
            "risk_modifier_pct": -15,
        }
    return {
        "bucket": "institutional",
        "label": "Institutional",
        "color": "cyan",
        "message": "Trusted: Highly established domain (10+ years). Extremely low risk.",
        "risk_modifier_pct": -30,
    }


def _apply_domain_age_adjustment(url_score: float, domain_age_days: Optional[int]) -> tuple[float, float, dict]:
    context = _domain_age_profile(domain_age_days)
    modifier = float(context.get("risk_modifier_pct") or 0.0)

    # High-age domains can still host phishing: limit negative discount on high-risk URLs.
    effective_modifier = modifier
    if modifier < 0:
        if url_score >= 85:
            effective_modifier = 0.0
        elif url_score >= 70:
            effective_modifier = max(modifier, -10.0)

    adjusted = min(100.0, max(0.0, float(url_score) + effective_modifier))
    context["risk_modifier_pct"] = int(effective_modifier)
    return adjusted, effective_modifier, context


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _ssl_status_profile(ssl_status: dict, has_urls: bool) -> dict:
    if not has_urls:
        return {
            "bucket": "not_applicable",
            "label": "Not Scanned",
            "badge": "NO SSL DATA",
            "severity": "neutral",
            "color": "neutral",
            "symbol": "N/A",
            "message": "No URL available for SSL inspection.",
            "risk_modifier_pct": 0,
        }

    is_valid = bool((ssl_status or {}).get("is_valid"))
    issuer = str((ssl_status or {}).get("issuer") or "")
    subject_org = str((ssl_status or {}).get("subject_organization") or "")
    validation_error = str((ssl_status or {}).get("validation_error") or "").lower()
    is_self_signed = bool((ssl_status or {}).get("is_self_signed"))
    expiry_dt = _parse_iso_datetime((ssl_status or {}).get("expiry_date"))
    now_utc = datetime.now(timezone.utc)

    if is_valid and expiry_dt is not None:
        days_to_expiry = max(0, int((expiry_dt - now_utc).total_seconds() // 86400))
        if days_to_expiry < 7:
            return {
                "bucket": "expiring_soon",
                "label": "Expiring Soon",
                "badge": "SSL WARNING",
                "severity": "warning",
                "color": "amber",
                "symbol": "~!",
                "message": "Certificate expires in under 7 days. Revalidation risk is elevated.",
                "risk_modifier_pct": 15,
            }

    if is_valid:
        issuer_lower = issuer.lower()
        org_lower = subject_org.lower()
        ev_like = any(
            marker in f"{issuer_lower} {org_lower}"
            for marker in ["extended validation", "ev ssl"]
        )
        if ev_like:
            return {
                "bucket": "ev",
                "label": "EV Certificate",
                "badge": "ULTRA SAFE",
                "severity": "safe",
                "color": "emerald",
                "symbol": "EV+",
                "message": "Extended Validation certificate detected. Strong ownership signal.",
                "risk_modifier_pct": -40,
            }
        return {
            "bucket": "valid_ov_dv",
            "label": "Valid OV/DV",
            "badge": "NEUTRAL",
            "severity": "neutral",
            "color": "cyan",
            "symbol": "DV/OV",
            "message": "Certificate is valid. SSL alone does not imply trustworthiness.",
            "risk_modifier_pct": 0,
        }

    mismatch_markers = ["hostname", "doesn't match", "does not match", "name mismatch"]
    if any(marker in validation_error for marker in mismatch_markers):
        return {
            "bucket": "name_mismatch",
            "label": "Name Mismatch",
            "badge": "CRITICAL",
            "severity": "critical",
            "color": "red",
            "symbol": "CN!",
            "message": "Certificate hostname mismatch. This is a high-confidence phishing indicator.",
            "risk_modifier_pct": 80,
        }

    self_signed_markers = ["self signed", "unknown ca", "unable to get local issuer", "self-signed"]
    if is_self_signed or any(marker in validation_error for marker in self_signed_markers):
        return {
            "bucket": "self_signed_untrusted",
            "label": "Self-Signed / Untrusted",
            "badge": "CRITICAL",
            "severity": "critical",
            "color": "orange",
            "symbol": "CA!",
            "message": "Certificate is self-signed or untrusted by the browser trust chain.",
            "risk_modifier_pct": 50,
        }

    if expiry_dt is not None and expiry_dt <= now_utc:
        return {
            "bucket": "expired",
            "label": "Expired",
            "badge": "CRITICAL",
            "severity": "critical",
            "color": "red",
            "symbol": "EXP!",
            "message": "Certificate has expired and no longer provides valid transport assurance.",
            "risk_modifier_pct": 60,
        }

    return {
        "bucket": "self_signed_untrusted",
        "label": "Untrusted SSL",
        "badge": "CRITICAL",
        "severity": "critical",
        "color": "orange",
        "symbol": "TLS!",
        "message": "SSL validation failed. Treat this destination as unsafe until verified.",
        "risk_modifier_pct": 50,
    }


def _is_linkedin_internal_url(url: str) -> bool:
    raw = (url or "").strip()
    if not raw:
        return True
    try:
        parsed = urlparse(raw if raw.startswith(("http://", "https://")) else f"https://{raw}")
    except Exception:
        return True

    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()

    is_linkedin_host = host == "linkedin.com" or host == "www.linkedin.com" or host.endswith(".linkedin.com")
    if not is_linkedin_host:
        return False

    internal_prefixes = (
        "/in/",
        "/company/",
        "/school/",
        "/pub/",
        "/feed/",
        "/messaging/",
        "/posts/",
        "/groups/",
        "/jobs/",
    )
    if path.startswith(internal_prefixes):
        return True

    # Treat remaining LinkedIn URLs as internal by default for this flow.
    return True


@app.post("/analyze")
def analyze_email(data: AnalyzeRequest):
    platform = (data.platform or "gmail").strip().lower()
    now_utc = datetime.now(timezone.utc)
    base_email_text = data.email_text or ""
    opened_mail_body = data.opened_mail_body or ""
    effective_email_text = "\n".join([t for t in [base_email_text, opened_mail_body] if t]).strip()

    if data.thread_id:
        cache_filter = {"thread_id": data.thread_id}
        if platform == "linkedin":
            cache_filter = {"linkedin_thread_id": data.thread_id}

        cached = scans_collection.find_one(
            {
                **cache_filter,
                "confidence_level": {"$in": ["High Confidence", "Very High Confidence", "Moderate Confidence"]},
            },
            {"_id": 0},
        )
        if cached:
            cached["cached"] = True
            return cached

    gathered_urls: set[str] = set()
    if data.url:
        gathered_urls.add(data.url)
    if data.urls:
        gathered_urls.update([u for u in data.urls if u])
    if data.opened_mail_urls:
        gathered_urls.update([u for u in data.opened_mail_urls if u])
    if data.link_pairs:
        for pair in data.link_pairs:
            href = (pair or {}).get("href")
            if href:
                gathered_urls.add(href)

    gathered_urls.update(_extract_urls_from_text(effective_email_text))

    if platform == "linkedin":
        linkedin_links = []
        if data.link_pairs:
            for pair in data.link_pairs:
                if not isinstance(pair, dict):
                    continue
                href = (pair.get("href") or "").strip()
                text = (pair.get("text") or "").strip()
                if href:
                    linkedin_links.append({"text": text, "href": href})
        if not linkedin_links:
            linkedin_links = [{"text": "", "href": u} for u in sorted(gathered_urls)]

        linkedin_result = analyze_linkedin_message(effective_email_text, linkedin_links)

        manipulation_score, flagged_phrases, psychological_index = calculate_manipulation_score(effective_email_text or "")
        ai_generated_score = float(detect_ai_pattern(effective_email_text or ""))
        brand_impersonation_score = float(detect_brand_impersonation(effective_email_text or "", data.sender_email or ""))

        vt_link_scans = []
        max_vt_link_score = 0.0
        max_ssl_risk_boost = 0.0
        for link in linkedin_links:
            href = (link or {}).get("href")
            if not href:
                continue
            if _is_linkedin_internal_url(href):
                continue
            vt_stats = hybrid_scanner.engine.get_vt_stats(href)
            malicious = int(vt_stats.get("malicious", 0) or 0)
            total = int(vt_stats.get("total", 70) or 70)
            vt_score = _vt_link_score_from_stats(malicious, total)
            ssl_risk_boost, ssl_valid = _ssl_risk_boost_for_url(href)
            corrected_url_score = min(100.0, vt_score + ssl_risk_boost)
            max_vt_link_score = max(max_vt_link_score, vt_score)
            max_ssl_risk_boost = max(max_ssl_risk_boost, ssl_risk_boost)

            verdict = "Safe"
            if corrected_url_score > 70:
                verdict = "Hard"
            elif corrected_url_score >= 31:
                verdict = "Moderate"

            vt_link_scans.append(
                {
                    "url": href,
                    "malicious_engines": malicious,
                    "total_engines": total,
                    "vt_score": vt_score,
                    "ssl_valid": ssl_valid,
                    "ssl_risk_boost": round(ssl_risk_boost, 2),
                    "corrected_url_score": round(corrected_url_score, 2),
                    "verdict": verdict,
                }
            )

        max_corrected_url_score = 0.0
        for item in vt_link_scans:
            max_corrected_url_score = max(max_corrected_url_score, float(item.get("corrected_url_score") or 0.0))

        content_score = float(linkedin_result.get("final_risk") or 0)
        if vt_link_scans:
            # Links use VirusTotal-only scoring; content remains backend analysis.
            final_risk = round(min(100.0, (0.65 * max_corrected_url_score) + (0.35 * content_score)), 2)
        else:
            final_risk = round(content_score, 2)

        if final_risk <= 30:
            level = "Safe"
        elif final_risk <= 70:
            level = "Moderate"
        else:
            level = "Hard"

        confidence = _score_to_confidence(final_risk)
        attack_simulation = _serialize_attack_simulation(final_risk)

        sentinel = linkedin_result.get("linkedin_sentinel") or {}
        sentinel["vt_link_scan"] = {
            "max_vt_score": round(max_vt_link_score, 2),
            "max_corrected_url_score": round(max_corrected_url_score, 2),
            "max_ssl_risk_boost": round(max_ssl_risk_boost, 2),
            "links": vt_link_scans,
            "scanned_count": len(vt_link_scans),
        }

        risk_breakdown = linkedin_result.get("risk_breakdown") or {}
        risk_breakdown["content_score"] = round(content_score, 2)
        risk_breakdown["vt_link_score"] = round(max_vt_link_score, 2)
        risk_breakdown["url_score"] = round(max_corrected_url_score, 2)
        risk_breakdown["ssl_risk_boost"] = round(max_ssl_risk_boost, 2)

        threat_category = get_threat_category(
            float(manipulation_score or 0),
            float(max_corrected_url_score or 0),
            float(brand_impersonation_score or 0),
            0.0,
            flagged_phrases or [],
        )

        reasoning_summary = build_reasoning_summary(
            float(manipulation_score or 0),
            float(max_corrected_url_score or 0),
            float(brand_impersonation_score or 0),
            0.0,
            flagged_phrases or [],
            None,
            _score_to_verdict(final_risk),
        )

        response_payload = {
            "platform": "linkedin",
            "thread_id": data.thread_id,
            "linkedin_thread_id": data.thread_id,
            "final_risk": final_risk,
            "final_score": final_risk,
            "level": level,
            "verdict": _score_to_verdict(final_risk),
            "confidence_level": confidence,
            "reasoning_summary": reasoning_summary,
            "threat_category": threat_category,
            "risk_breakdown": risk_breakdown,
            "linkedin_sentinel": sentinel,
            "breakdown": {
                "manipulation_score": float(manipulation_score or 0),
                "url_score": float(round(max_corrected_url_score, 2)),
                "ai_generated_score": float(ai_generated_score or 0),
                "brand_impersonation_score": float(brand_impersonation_score or 0),
                "header_score": 0.0,
            },
            "psychological_index": psychological_index or {},
            "highlighted_phrases": flagged_phrases or [],
            "header_analysis": None,
            "attack_simulation": attack_simulation,
            "urls": sorted(gathered_urls),
            "timestamp": now_utc.isoformat(),
        }

        if data.thread_id:
            scans_collection.update_one(
                {"linkedin_thread_id": data.thread_id},
                {
                    "$set": {
                        **response_payload,
                        "updated_at": now_utc,
                    },
                    "$setOnInsert": {
                        "id": str(uuid.uuid4())[:8],
                        "created_at": now_utc,
                    },
                },
                upsert=True,
            )
        elif not data.private_mode:
            scans_collection.insert_one(
                {
                    "id": str(uuid.uuid4())[:8],
                    **response_payload,
                    "created_at": now_utc,
                }
            )

        response_payload["cached"] = False
        return response_payload

    hybrid = hybrid_scanner.scan(
        email_text=effective_email_text,
        sender_email=data.sender_email,
        urls=list(gathered_urls),
    )

    intelligence_profile = hybrid.get("intelligence_profile") or {}
    technical_details = intelligence_profile.get("advanced_technical_details") or {}
    url_findings = hybrid.get("url_findings") or []
    url_score = float(hybrid.get("external_score") or 0)
    domain_age_days = technical_details.get("domain_age_days")

    header_score, header_details = analyze_email_header(data.email_header)
    threat_score, threat_details = analyze_threat_intel(data.email_header)

    mail_url_summary = compute_mail_severity(url_findings)
    mail_severity_score = float(mail_url_summary.get("mail_severity_score") or 0)
    ssl_status = intelligence_profile.get("ssl_status") or {}
    ssl_context = _ssl_status_profile(ssl_status, bool(gathered_urls))
    ssl_modifier = float(ssl_context.get("risk_modifier_pct") or 0.0)
    if ssl_modifier < 0:
        if url_score >= 70:
            ssl_modifier = 0.0
        elif url_score >= 55:
            ssl_modifier = max(ssl_modifier, -10.0)
    ssl_context["risk_modifier_pct"] = int(ssl_modifier)

    ssl_corrected_url_score = min(100.0, max(0.0, url_score + ssl_modifier))
    corrected_url_score, domain_age_modifier, domain_age_context = _apply_domain_age_adjustment(
        ssl_corrected_url_score,
        domain_age_days,
    )

    local_score = float(hybrid.get("local_score") or 0)
    ssl_age_score = float(hybrid.get("ssl_age_score") or 0)
    fusion_score = (0.35 * local_score) + (0.55 * corrected_url_score) + (0.10 * ssl_age_score)
    final_risk = round(min(100.0, max(fusion_score, mail_severity_score)), 2)
    verdict = _score_to_verdict(final_risk)
    confidence = _score_to_confidence(final_risk)

    attack_simulation = _serialize_attack_simulation(final_risk)

    threat_category = get_threat_category(
        local_score,
        corrected_url_score,
        100.0 if hybrid.get("detected_brand") else 0.0,
        header_score,
        hybrid.get("flagged_phrases") or [],
    )

    reasoning_summary = build_reasoning_summary(
        local_score,
        corrected_url_score,
        100.0 if hybrid.get("detected_brand") else 0.0,
        header_score,
        hybrid.get("flagged_phrases") or [],
        domain_age_days,
        verdict,
    )

    mail_reason = mail_url_summary.get("summary_reason")
    if mail_reason:
        reasoning_summary = f"{reasoning_summary} {mail_reason}".strip()

    response_payload = {
        "thread_id": data.thread_id,
        "final_risk": final_risk,
        "unified_severity_score": final_risk,
        "mail_severity_score": mail_severity_score,
        "verdict": verdict,
        "confidence_level": confidence,
        "threat_category": threat_category,
        "reasoning_summary": reasoning_summary,
        "consensus_mode": hybrid.get("consensus_mode"),
        "intelligence_profile": intelligence_profile,
        "threat_array": intelligence_profile.get("threat_array") or [],
        "open_mail_summary": {
            "malicious_links": mail_url_summary.get("malicious_links", 0),
            "suspicious_links": mail_url_summary.get("suspicious_links", 0),
            "safe_links": mail_url_summary.get("safe_links", 0),
            "most_dangerous_link": mail_url_summary.get("most_dangerous_link"),
            "reason": mail_reason,
        },
        "risk_breakdown": {
            "brand_match": hybrid.get("detected_brand") or "None",
            "logic_flags": hybrid.get("logic_flags") or [],
            "global_reputation": {
                "flagged": int(hybrid.get("vt_malicious_engines") or 0),
                "total": int(hybrid.get("vt_total_engines") or 70),
            },
            "local_score": local_score,
            "external_score": corrected_url_score,
            "ssl_age_score": ssl_age_score,
            "ssl_risk_boost": ssl_modifier,
            "domain_age_risk_modifier": float(domain_age_modifier),
        },
        "url_intelligence": (url_findings[0] if url_findings else None),
        "body_url_intelligence": url_findings,
        "breakdown": {
            "manipulation_score": float(hybrid.get("local_score") or 0),
            "url_score": corrected_url_score,
            "ai_generated_score": 0,
            "brand_impersonation_score": 100.0 if hybrid.get("detected_brand") else 0.0,
            "header_score": header_score,
        },
        "psychological_index": hybrid.get("psychological_index") or {},
        "highlighted_phrases": hybrid.get("flagged_phrases") or [],
        "domain_age_days": domain_age_days,
        "domain_age_context": domain_age_context,
        "ssl_context": ssl_context,
        "header_analysis": header_details,
        "threat_intel": threat_details,
        "attack_simulation": attack_simulation,
        "timestamp": now_utc.isoformat(),
    }

    if data.thread_id:
        scans_collection.update_one(
            {"thread_id": data.thread_id},
            {
                "$set": {
                    **response_payload,
                    "updated_at": now_utc,
                },
                "$setOnInsert": {
                    "id": str(uuid.uuid4())[:8],
                    "created_at": now_utc,
                },
            },
            upsert=True,
        )
    elif not data.private_mode:
        scans_collection.insert_one({
            "id": str(uuid.uuid4())[:8],
            **response_payload,
            "created_at": now_utc,
        })

    response_payload["cached"] = False
    return response_payload


app.include_router(router)


async def _daily_pulse_loop():
    while True:
        try:
            result = await sync_openphish()
            logger.info("OpenPhish sync complete: %s", result)
        except Exception:
            logger.exception("OpenPhish sync failed")
        await asyncio.sleep(24 * 60 * 60)


@app.on_event("startup")
async def start_daily_pulse():
    asyncio.create_task(_daily_pulse_loop())
