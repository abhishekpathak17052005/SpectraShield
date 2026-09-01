from __future__ import annotations

"""One-time migration from local MongoDB to Supabase PostgreSQL.

This script copies the current SpectraShield collections into the new PostgreSQL
schema used by the backend compatibility layer.

Usage:
    cd backend
    python scripts/migrate_mongo_to_postgres.py

Required env vars:
    MONGO_URI, MONGO_DB_NAME, DATABASE_URL
"""

from datetime import datetime, timezone
import os

from dotenv import load_dotenv
from pymongo import MongoClient
import psycopg2
from psycopg2.extras import Json, RealDictCursor


load_dotenv()


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "spectrashield_db")
DATABASE_URL = os.getenv("DATABASE_URL", "")

if not DATABASE_URL:
    raise SystemExit("DATABASE_URL is required")


def _normalize(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def main() -> None:
    mongo = MongoClient(MONGO_URI)
    mongo_db = mongo[MONGO_DB_NAME]

    pg = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    pg.autocommit = True

    with pg.cursor() as cur:
        cur.execute("SELECT 1")

    counts = {}

    with pg.cursor() as cur:
        for doc in mongo_db["scans"].find({}):
            doc = _normalize(dict(doc))
            scan_id = doc.get("id")
            if not scan_id:
                continue

            payload = dict(doc)
            payload.pop("_id", None)
            payload.pop("id", None)
            cur.execute(
                """
                INSERT INTO scans (id, thread_id, linkedin_thread_id, created_at, updated_at, payload)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE
                SET thread_id = EXCLUDED.thread_id,
                    linkedin_thread_id = EXCLUDED.linkedin_thread_id,
                    created_at = EXCLUDED.created_at,
                    updated_at = EXCLUDED.updated_at,
                    payload = EXCLUDED.payload
                """,
                (
                    scan_id,
                    doc.get("thread_id"),
                    doc.get("linkedin_thread_id"),
                    doc.get("created_at"),
                    doc.get("updated_at"),
                    Json(payload),
                ),
            )
        counts["scans"] = mongo_db["scans"].count_documents({})

        for doc in mongo_db["threat_feed"].find({}):
            doc = _normalize(dict(doc))
            url = doc.get("url")
            if not url:
                continue
            payload = dict(doc)
            payload.pop("_id", None)
            payload.pop("url", None)
            cur.execute(
                """
                INSERT INTO threat_feed (url, first_seen, last_seen, payload)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (url) DO UPDATE
                SET first_seen = COALESCE(threat_feed.first_seen, EXCLUDED.first_seen),
                    last_seen = EXCLUDED.last_seen,
                    payload = EXCLUDED.payload
                """,
                (url, doc.get("first_seen"), doc.get("last_seen"), Json(payload)),
            )
        counts["threat_feed"] = mongo_db["threat_feed"].count_documents({})

        for doc in mongo_db["vt_url_cache"].find({}):
            doc = _normalize(dict(doc))
            url = doc.get("url")
            if not url:
                continue
            payload = dict(doc)
            payload.pop("_id", None)
            payload.pop("url", None)
            cur.execute(
                """
                INSERT INTO vt_url_cache (url, fetched_at, payload)
                VALUES (%s, %s, %s)
                ON CONFLICT (url) DO UPDATE
                SET fetched_at = EXCLUDED.fetched_at,
                    payload = EXCLUDED.payload
                """,
                (url, doc.get("fetched_at"), Json(payload)),
            )
        counts["vt_url_cache"] = mongo_db["vt_url_cache"].count_documents({})

    print("Migration complete")
    for name, count in counts.items():
        print(f"{name}: {count}")


if __name__ == "__main__":
    main()
