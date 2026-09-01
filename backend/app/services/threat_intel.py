from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from app.database import threat_feed_collection


OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"


async def sync_openphish() -> dict[str, Any]:
    """
    Fetch the OpenPhish plain-text feed and upsert into `threat_feed`.
    """
    now = datetime.now(timezone.utc)

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        res = await client.get(OPENPHISH_FEED_URL, headers={"User-Agent": "SpectraShield-AI/1.0"})
        res.raise_for_status()
        text = res.text

    urls: list[str] = []
    for line in text.splitlines():
        u = (line or "").strip()
        if not u:
            continue
        # OpenPhish feed is URL-per-line; keep it as-is (trimmed)
        urls.append(u)

    if not urls:
        return {"source": "openphish", "fetched": 0, "upserted": 0}

    upserted = 0
    for u in urls:
        result = threat_feed_collection.update_one(
            {"url": u},
            {
                "$setOnInsert": {"url": u, "first_seen": now, "source": "openphish"},
                "$set": {"last_seen": now},
            },
            upsert=True,
        )
        if getattr(result, "upserted_id", None):
            upserted += 1

    return {"source": "openphish", "fetched": len(urls), "upserted": upserted}


def analyze_threat_intel(header_text: str):
    """
    Header-level intel (placeholder). Kept for backward compatibility with existing frontend fields.
    """
    if not header_text:
        return 0, {
            "ip_reputation": "Unknown",
            "country": "Unknown",
            "blacklisted": False
        }

    header_lower = header_text.lower()
    score = 0

    # Fake suspicious IP detection
    suspicious_ips = ["185.", "103.", "45."]

    ip_reputation = "Clean"
    country = "Safe Region"
    blacklisted = False

    for ip_prefix in suspicious_ips:
        if ip_prefix in header_lower:
            ip_reputation = "Suspicious"
            country = "High-Risk Region"
            blacklisted = True
            score += 40
            break

    return score, {
        "ip_reputation": ip_reputation,
        "country": country,
        "blacklisted": blacklisted
    }