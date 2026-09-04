-- SpectraShield 2.0 (Forensic Edition) — Supabase / PostgreSQL Schema v2
-- SIH 2026 Problem Statement ID: 26106

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Cases Table (Central Investigation Record)
CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_number VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    threat_category VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN')),
    status VARCHAR(20) NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'INVESTIGATING', 'ESCALATED', 'RESOLVED', 'ARCHIVED')),
    overall_risk_score NUMERIC(5, 2) NOT NULL,
    sha256_evidence_hash VARCHAR(64) NOT NULL,
    raw_email_path TEXT,
    assigned_analyst VARCHAR(100) DEFAULT 'SOC Analyst',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Email Analyses Table (Deep Dissection & Routing)
CREATE TABLE IF NOT EXISTS email_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    message_id TEXT,
    envelope_from TEXT,
    header_from TEXT,
    reply_to TEXT,
    subject TEXT,
    date_header TIMESTAMPTZ,
    authentication_results JSONB NOT NULL DEFAULT '{}'::jsonb,
    relay_hops JSONB NOT NULL DEFAULT '[]'::jsonb,
    originating_node JSONB NOT NULL DEFAULT '{}'::jsonb,
    nlp_intelligence JSONB NOT NULL DEFAULT '{}'::jsonb,
    iocs JSONB NOT NULL DEFAULT '{}'::jsonb,
    mitre_tactics TEXT[] DEFAULT ARRAY[]::TEXT[],
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Threat Campaigns Table (Attribution Clusters)
CREATE TABLE IF NOT EXISTS threat_campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_identifier VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    threat_actor_signature TEXT,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    associated_ips TEXT[] DEFAULT ARRAY[]::TEXT[],
    associated_domains TEXT[] DEFAULT ARRAY[]::TEXT[],
    minhash_cluster_id VARCHAR(64),
    attribution_confidence NUMERIC(5, 2) NOT NULL DEFAULT 75.0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Forensic Audit Logs Table (Tamper-Evident Chain of Custody)
CREATE TABLE IF NOT EXISTS forensic_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    actor VARCHAR(100) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_cases_case_number ON cases(case_number);
CREATE INDEX IF NOT EXISTS idx_cases_sha256 ON cases(sha256_evidence_hash);
CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_email_analyses_case_id ON email_analyses(case_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_identifier ON threat_campaigns(campaign_identifier);
CREATE INDEX IF NOT EXISTS idx_audit_logs_case_id ON forensic_audit_logs(case_id);
