-- SpectraShield baseline schema for Supabase PostgreSQL
-- Phase 1: collection-compatible storage while app logic is ported.

create table if not exists public.scans (
    id text primary key,
    thread_id text unique,
    linkedin_thread_id text unique,
    created_at timestamptz null,
    updated_at timestamptz null,
    payload jsonb not null default '{}'::jsonb
);

create index if not exists idx_scans_created_at on public.scans(created_at);
create index if not exists idx_scans_updated_at on public.scans(updated_at);

create table if not exists public.threat_feed (
    url text primary key,
    first_seen timestamptz null,
    last_seen timestamptz null,
    payload jsonb not null default '{}'::jsonb
);

create index if not exists idx_threat_feed_last_seen on public.threat_feed(last_seen);

create table if not exists public.vt_url_cache (
    url text primary key,
    fetched_at timestamptz null,
    payload jsonb not null default '{}'::jsonb
);

create index if not exists idx_vt_url_cache_fetched_at on public.vt_url_cache(fetched_at);

-- RLS baseline: enabled now as requested.
alter table public.scans enable row level security;
alter table public.threat_feed enable row level security;
alter table public.vt_url_cache enable row level security;

-- Service role bypasses RLS in Supabase; no anon policies are added yet.
-- Add anon/auth policies only when direct client access is introduced.
