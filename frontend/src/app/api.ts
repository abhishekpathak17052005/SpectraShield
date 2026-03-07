/**
 * Frontend API client for SpectraShield backend.
 * Base URL: VITE_API_URL or http://localhost:8000
 */

const getApiBase = (): string => {
  return (import.meta as unknown as { env?: { VITE_API_URL?: string } }).env?.VITE_API_URL ?? "http://localhost:8000";
};

export interface AnalyzeRequest {
  email_text: string;
  email_header?: string | null;
  url?: string | null;
  urls?: string[];
  sender_email?: string | null;
  private_mode?: boolean;
  thread_id?: string | null;
  opened_mail_body?: string | null;
  opened_mail_urls?: string[];
}

export interface IntelligenceProfile {
  ssl_status?: {
    issuer?: string | null;
    expiry_date?: string | null;
    is_valid?: boolean;
    validation_error?: string | null;
    subject_common_name?: string | null;
    subject_organization?: string | null;
    is_self_signed?: boolean;
  };
  location_data?: {
    country?: string | null;
    isp?: string | null;
    ip_address?: string | null;
  };
  threat_array?: string[];
  advanced_technical_details?: {
    page_title?: string | null;
    domain_age_days?: number | null;
    redirect_chain?: string[];
    redirect_hops?: number;
    dns_records?: {
      a?: string[];
      mx?: string[];
    };
    whois?: Record<string, unknown>;
    final_url?: string | null;
  };
}

export interface DomainAgeContext {
  bucket: string;
  label: string;
  color: string;
  message: string;
  risk_modifier_pct: number;
}

export interface SSLContext {
  bucket: string;
  label: string;
  badge: string;
  severity: string;
  color: string;
  symbol: string;
  message: string;
  risk_modifier_pct: number;
}

export interface AnalyzeResponse {
  final_risk: number;
  unified_severity_score?: number;
  timestamp?: string;
  verdict: string;
  confidence_level: string;
  threat_category?: string;
  reasoning_summary?: string;
  threat_array?: string[];
  intelligence_profile?: IntelligenceProfile;
  risk_breakdown?: {
    brand_match?: string;
    logic_flags?: string[];
    global_reputation?: { flagged?: number; total?: number };
    local_score?: number;
    external_score?: number;
    ssl_age_score?: number;
    domain_age_risk_modifier?: number;
  };
  breakdown: {
    manipulation_score: number;
    url_score: number;
    ai_generated_score: number;
    brand_impersonation_score: number;
    header_score: number;
  };
  psychological_index?: number;
  highlighted_phrases?: string[] | null;
  domain_age_days?: number | null;
  domain_age_context?: DomainAgeContext;
  ssl_context?: SSLContext;
  header_analysis?: unknown;
  threat_intel?: unknown;
  attack_simulation?: unknown;
}

export interface HistoryRecord {
  id: string;
  final_risk: number;
  verdict: string;
  confidence_level: string;
  threat_category?: string;
  timestamp: string;
}

export async function analyzeEmail(body: AnalyzeRequest): Promise<AnalyzeResponse> {
  const base = getApiBase();
  const res = await fetch(`${base}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Analyze failed: ${res.status} ${text}`);
  }
  return res.json();
}

export async function getHistory(): Promise<HistoryRecord[]> {
  const base = getApiBase();
  const res = await fetch(`${base}/history`);
  if (!res.ok) throw new Error(`History failed: ${res.status}`);
  return res.json();
}

export async function clearHistory(): Promise<{ message: string }> {
  const base = getApiBase();
  const res = await fetch(`${base}/history`, { method: "DELETE" });
  if (!res.ok) throw new Error(`Clear history failed: ${res.status}`);
  return res.json();
}

export async function deleteScan(scanId: string): Promise<{ message: string }> {
  const base = getApiBase();
  const res = await fetch(`${base}/history/${encodeURIComponent(scanId)}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`Delete scan failed: ${res.status}`);
  return res.json();
}
