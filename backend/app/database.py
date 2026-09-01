from __future__ import annotations

import os

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor
from pymongo import ASCENDING, MongoClient

from app.pg_collection import PostgresCollection


load_dotenv()


def _postgres_url() -> str:
	return (
		os.getenv("DATABASE_URL")
		or os.getenv("SUPABASE_DB_URL")
		or os.getenv("POSTGRES_URL")
		or ""
	).strip()


def _db_backend() -> str:
	configured = (os.getenv("DB_BACKEND") or "").strip().lower()
	if configured in {"postgres", "mongo"}:
		return configured
	return "postgres" if _postgres_url() else "mongo"


def _setup_postgres_schema(conn) -> None:
	statements = [
		"""
		CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			thread_id TEXT UNIQUE,
			linkedin_thread_id TEXT UNIQUE,
			created_at TIMESTAMPTZ NULL,
			updated_at TIMESTAMPTZ NULL,
			payload JSONB NOT NULL DEFAULT '{}'::jsonb
		)
		""",
		"CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_scans_updated_at ON scans(updated_at)",
		"""
		CREATE TABLE IF NOT EXISTS threat_feed (
			url TEXT PRIMARY KEY,
			first_seen TIMESTAMPTZ NULL,
			last_seen TIMESTAMPTZ NULL,
			payload JSONB NOT NULL DEFAULT '{}'::jsonb
		)
		""",
		"CREATE INDEX IF NOT EXISTS idx_threat_feed_last_seen ON threat_feed(last_seen)",
		"""
		CREATE TABLE IF NOT EXISTS vt_url_cache (
			url TEXT PRIMARY KEY,
			fetched_at TIMESTAMPTZ NULL,
			payload JSONB NOT NULL DEFAULT '{}'::jsonb
		)
		""",
		"CREATE INDEX IF NOT EXISTS idx_vt_cache_fetched_at ON vt_url_cache(fetched_at)",
	]

	with conn.cursor() as cur:
		for stmt in statements:
			cur.execute(stmt)


backend = _db_backend()

if backend == "postgres":
	conn = psycopg2.connect(_postgres_url(), cursor_factory=RealDictCursor)
	conn.autocommit = True
	_setup_postgres_schema(conn)

	scans_collection = PostgresCollection(
		connection=conn,
		table_name="scans",
		key_column="id",
		key_field="id",
		extra_columns=["thread_id", "linkedin_thread_id", "created_at", "updated_at"],
	)
	threat_feed_collection = PostgresCollection(
		connection=conn,
		table_name="threat_feed",
		key_column="url",
		key_field="url",
		extra_columns=["first_seen", "last_seen"],
	)
	vt_cache_collection = PostgresCollection(
		connection=conn,
		table_name="vt_url_cache",
		key_column="url",
		key_field="url",
		extra_columns=["fetched_at"],
	)

	# Backward-compatible alias used by older modules
	scan_collection = scans_collection
else:
	mongo_uri = (os.getenv("MONGO_URI") or "mongodb://localhost:27017/").strip()
	mongo_db_name = (os.getenv("MONGO_DB_NAME") or "spectrashield_db").strip()

	client = MongoClient(mongo_uri)
	db = client[mongo_db_name]

	scans_collection = db["scans"]

	def _drop_scan_ttl_indexes() -> None:
		# Keep scan history for lifetime: remove any legacy TTL index if present.
		for index_name, details in scans_collection.index_information().items():
			if "expireAfterSeconds" in details:
				scans_collection.drop_index(index_name)

	_drop_scan_ttl_indexes()

	scans_collection.create_index([("thread_id", ASCENDING)])
	scans_collection.create_index([("linkedin_thread_id", ASCENDING)], unique=True, sparse=True)

	# Backward-compatible alias used by older modules
	scan_collection = scans_collection

	threat_feed_collection = db["threat_feed"]
	threat_feed_collection.create_index([("url", ASCENDING)], unique=True)

	vt_cache_collection = db["vt_url_cache"]
	vt_cache_collection.create_index([("url", ASCENDING)], unique=True)