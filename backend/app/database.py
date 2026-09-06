from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any, Dict

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

from app.pg_collection import PostgresCollection, InMemoryCollection


# Explicitly load root .env and backend/.env as well as current working directory
_backend_env = Path(__file__).resolve().parent.parent / ".env"
_root_env = Path(__file__).resolve().parent.parent.parent / ".env"
if _root_env.is_file():
	load_dotenv(dotenv_path=_root_env)
if _backend_env.is_file():
	load_dotenv(dotenv_path=_backend_env, override=True)
load_dotenv()

logger = logging.getLogger("spectrashield.database")


def _postgres_url() -> str:
	return (
		os.getenv("DATABASE_URL")
		or os.getenv("SUPABASE_DB_URL")
		or os.getenv("POSTGRES_URL")
		or ""
	).strip()


def _db_backend() -> str:
	configured = (os.getenv("DB_BACKEND") or "").strip().lower()
	if configured in {"supabase", "postgres"}:
		return "supabase"
	return "supabase" if _postgres_url() else "in-memory"


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
		"""
		CREATE TABLE IF NOT EXISTS forensic_cases (
			id TEXT PRIMARY KEY,
			case_number TEXT UNIQUE,
			created_at TIMESTAMPTZ NULL,
			updated_at TIMESTAMPTZ NULL,
			payload JSONB NOT NULL DEFAULT '{}'::jsonb
		)
		""",
		"CREATE INDEX IF NOT EXISTS idx_cases_case_number ON forensic_cases(case_number)",
		"CREATE INDEX IF NOT EXISTS idx_cases_created_at ON forensic_cases(created_at)",
		"""
		CREATE TABLE IF NOT EXISTS forensic_analyses (
			id TEXT PRIMARY KEY,
			case_id TEXT UNIQUE,
			created_at TIMESTAMPTZ NULL,
			payload JSONB NOT NULL DEFAULT '{}'::jsonb
		)
		""",
		"CREATE INDEX IF NOT EXISTS idx_analyses_case_id ON forensic_analyses(case_id)",
		"""
		CREATE TABLE IF NOT EXISTS forensic_audit_ledger (
			id TEXT PRIMARY KEY,
			case_id TEXT,
			timestamp TIMESTAMPTZ NULL,
			payload JSONB NOT NULL DEFAULT '{}'::jsonb
		)
		""",
		"CREATE INDEX IF NOT EXISTS idx_audit_case_id ON forensic_audit_ledger(case_id)",
		"CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON forensic_audit_ledger(timestamp)",
		"""
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE,
			created_at TIMESTAMPTZ NULL,
			updated_at TIMESTAMPTZ NULL,
			payload JSONB NOT NULL DEFAULT '{}'::jsonb
		)
		""",
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
	]

	with conn.cursor() as cur:
		for stmt in statements:
			cur.execute(stmt)


# Initialize Database Connection
pg_url = _postgres_url()
is_connected = False
conn = None

if pg_url:
	try:
		conn = psycopg2.connect(pg_url, cursor_factory=RealDictCursor)
		conn.autocommit = True
		_setup_postgres_schema(conn)
		is_connected = True
		backend = "supabase"
		logger.info("Successfully connected to Supabase (PostgreSQL) and verified database schemas.")
	except Exception as exc:
		logger.warning(
			f"Failed to connect to Supabase PostgreSQL ({exc}). Operating in resilient in-memory mode."
		)
		is_connected = False
		backend = "in-memory"
else:
	backend = "in-memory"
	logger.info("No DATABASE_URL or SUPABASE_DB_URL configured. Operating in resilient in-memory mode.")


if is_connected and conn is not None:
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
	forensic_cases_collection = PostgresCollection(
		connection=conn,
		table_name="forensic_cases",
		key_column="id",
		key_field="id",
		extra_columns=["case_number", "created_at", "updated_at"],
	)
	forensic_analyses_collection = PostgresCollection(
		connection=conn,
		table_name="forensic_analyses",
		key_column="id",
		key_field="id",
		extra_columns=["case_id", "created_at"],
	)
	audit_ledger_collection = PostgresCollection(
		connection=conn,
		table_name="forensic_audit_ledger",
		key_column="id",
		key_field="id",
		extra_columns=["case_id", "timestamp"],
	)
	users_collection = PostgresCollection(
		connection=conn,
		table_name="users",
		key_column="id",
		key_field="id",
		extra_columns=["email", "created_at", "updated_at"],
	)
else:
	scans_collection = InMemoryCollection(name="scans", key_field="id")
	threat_feed_collection = InMemoryCollection(name="threat_feed", key_field="url")
	vt_cache_collection = InMemoryCollection(name="vt_url_cache", key_field="url")
	forensic_cases_collection = InMemoryCollection(name="forensic_cases", key_field="id")
	forensic_analyses_collection = InMemoryCollection(name="forensic_analyses", key_field="id")
	audit_ledger_collection = InMemoryCollection(name="forensic_audit_ledger", key_field="id")
	users_collection = InMemoryCollection(name="users", key_field="id")

# Backward-compatible alias used by older modules
scan_collection = scans_collection


def get_db_status() -> Dict[str, Any]:
	"""Returns real-time database connection diagnostics."""
	return {
		"backend": backend,
		"is_connected": is_connected,
		"provider": "Supabase (PostgreSQL)" if is_connected else "In-Memory Vault",
		"tables": [
			"scans",
			"threat_feed",
			"vt_url_cache",
			"forensic_cases",
			"forensic_analyses",
			"forensic_audit_ledger",
			"users",
		],
	}