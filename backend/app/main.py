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
    ssl_invalid_boost = 12.0 if gathered_urls and not bool(ssl_status.get("is_valid")) else 0.0
    corrected_url_score = min(100.0, url_score + ssl_invalid_boost)
    final_risk = round(min(100.0, max(float(hybrid.get("unified_score") or 0) + ssl_invalid_boost, mail_severity_score)), 2)
    verdict = _score_to_verdict(final_risk)
    confidence = _score_to_confidence(final_risk)

    attack_simulation = _serialize_attack_simulation(final_risk)

    threat_category = get_threat_category(
        float(hybrid.get("local_score") or 0),
        url_score,
        100.0 if hybrid.get("detected_brand") else 0.0,
        header_score,
        hybrid.get("flagged_phrases") or [],
    )

    reasoning_summary = build_reasoning_summary(
        float(hybrid.get("local_score") or 0),
        url_score,
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
            "local_score": float(hybrid.get("local_score") or 0),
            "external_score": corrected_url_score,
            "ssl_age_score": float(hybrid.get("ssl_age_score") or 0),
            "ssl_risk_boost": ssl_invalid_boost,
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
