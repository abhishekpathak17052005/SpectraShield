const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000").replace(/\/$/, "");

export function getApiBase(): string {
  return API_BASE;
}

// ─── Token Management ─────────────────────────────────────────────────────────
const TOKEN_KEY = "spectrashield_jwt_token";
const SIMULATED_ROLE_KEY = "spectrashield_simulated_role";

export function getAuthToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setAuthToken(token: string | null): void {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export function getStoredSimulatedRole(): string | null {
  return localStorage.getItem(SIMULATED_ROLE_KEY);
}

export function setStoredSimulatedRole(role: string | null): void {
  if (role) {
    localStorage.setItem(SIMULATED_ROLE_KEY, role);
  } else {
    localStorage.removeItem(SIMULATED_ROLE_KEY);
  }
}

// ─── Base API Request ─────────────────────────────────────────────────────────
export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getAuthToken();
  const authHeaders: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...authHeaders,
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    let detail = `Backend request failed (${response.status})`;
    try {
      const body = await response.json();
      detail = body.detail || body.message || detail;
    } catch {
      // Non-JSON response
    }
    throw new Error(detail);
  }

  return response.json() as Promise<T>;
}

// ─── Types & Schemas ──────────────────────────────────────────────────────────

export type AnalyzePayload = {
  email_text?: string;
  email_header?: string | null;
  url?: string | null;
  urls?: string[];
  sender_email?: string | null;
  private_mode?: boolean;
  platform?: string | null;
  thread_id?: string | null;
  link_pairs?: Array<{ text: string; href: string }>;
};

export type AnalyzeResponse = {
  final_risk: number;
  final_score?: number;
  verdict: string;
  confidence_level?: string;
  threat_category?: string;
  reasoning_summary?: string;
  breakdown?: {
    manipulation_score?: number;
    brand_impersonation_score?: number;
    header_score?: number;
    url_score?: number;
    attachment_score?: number;
    vip_score?: number;
    [key: string]: number | undefined;
  };
  highlighted_phrases?: string[];
  attack_simulation?: Array<{
    step: number;
    phase: string;
    tactic: string;
    description: string;
    indicators: string[];
  }>;
  case_id?: string;
  sha256_evidence_hash?: string;
  sha1?: string;
  md5?: string;
  created_at?: string;
  authentication?: {
    spf?: { status: string; sender_ip?: string; domain?: string };
    dkim?: {
      status: string;
      selector?: string;
      domain?: string;
      body_hash_valid?: boolean;
      signature_valid?: boolean;
      key_length?: number;
      diagnostic?: string;
    };
    dmarc?: { status: string; policy?: string; alignment?: string };
  };
  relay_path?: Array<{
    hop_number?: number;
    ip?: string;
    received_from?: string;
    by?: string;
    timestamp?: string;
    delay_seconds?: number;
    geo?: {
      city?: string;
      country?: string;
      country_code?: string;
      latitude?: number;
      longitude?: number;
      isp?: string;
      asn?: string;
      is_anonymized?: boolean;
      anonymization_type?: string;
    };
  }>;
  originating_node?: {
    ip?: string;
    country?: string;
    country_code?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    isp?: string;
    asn?: string;
    is_anonymized?: boolean;
    anonymization_type?: string;
  };
  attachments?: Array<{
    filename: string;
    sha256: string;
    file_type: string;
    size_bytes: number;
    entropy: number;
    fuzzy_simhash?: string;
    has_macros: boolean;
    is_malicious: boolean;
    quarantine_path?: string;
  }>;
  quishing?: {
    is_quishing_detected: boolean;
    qr_count: number;
    decoded_urls: string[];
    risk_score: number;
  };
  nlp_analysis?: {
    predicted_category: string;
    confidence: number;
    category_probabilities: Record<string, number>;
    model_name: string;
    inference_latency_ms: number;
  };
  vip_impersonation?: {
    is_vip_impersonation: boolean;
    matched_vip?: {
      name: string;
      title: string;
      authorized_domains: string[];
    } | null;
    divergence_score?: number;
  };
  cti_hits?: Array<{
    indicator: string;
    threat_category: string;
    confidence: number;
    sources: string[];
    is_malicious: boolean;
    is_vpn_or_tor: boolean;
  }>;
  campaign?: {
    id: string;
    name: string;
    attribution_confidence: number;
  };
  mitre_tactics?: string[];
  clean_text?: string;
  redacted_text?: string;
  [key: string]: unknown;
};

// ─── Real-time & History Endpoints ────────────────────────────────────────────

export function analyze(payload: AnalyzePayload): Promise<AnalyzeResponse> {
  return apiRequest<AnalyzeResponse>("/analyze", {
    method: "POST",
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(45000),
  });
}

export type HistoryRecord = Record<string, unknown> & {
  id?: string;
  final_risk?: number;
  verdict?: string;
  timestamp?: string;
  sender?: string;
  subject?: string;
};

export function getHistory(): Promise<HistoryRecord[]> {
  return apiRequest<HistoryRecord[]>("/history");
}

export function getHistoryCount(): Promise<{ count: number }> {
  return apiRequest<{ count: number }>("/history/count");
}

export function clearHistory(): Promise<{ deleted: number }> {
  return apiRequest<{ deleted: number }>("/history", { method: "DELETE" });
}

export function deleteHistoryItem(scanId: string): Promise<{ deleted: boolean }> {
  return apiRequest<{ deleted: boolean }>(`/history/${encodeURIComponent(scanId)}`, { method: "DELETE" });
}

export function getDashboardTopBrands(days: number): Promise<{ brands: { name: string; count: number }[] }> {
  return apiRequest<{ brands: { name: string; count: number }[] }>(`/dashboard/top-brands?days=${days}`);
}

export function getDashboardHeatmap(days: number): Promise<{ cells: { dayIndex: number; hour: number; value: number }[] }> {
  return apiRequest<{ cells: { dayIndex: number; hour: number; value: number }[] }>(`/dashboard/risk-heatmap?days=${days}`);
}

// ─── Forensics & File Upload Endpoints ─────────────────────────────────────────

export async function uploadForensics(file: File, redactPii: boolean = false): Promise<AnalyzeResponse> {
  const form = new FormData();
  form.append("file", file);
  form.append("redact_pii", String(redactPii));
  return apiRequest<AnalyzeResponse>("/api/forensics/upload-eml", {
    method: "POST",
    body: form,
    signal: AbortSignal.timeout(120000),
  });
}

export function analyzeForensics(payload: Record<string, unknown>): Promise<AnalyzeResponse> {
  return apiRequest<AnalyzeResponse>("/api/forensics/analyze-email", {
    method: "POST",
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(120000),
  });
}

// ─── Evidence Vault & Cases ───────────────────────────────────────────────────

export interface ForensicCaseRecord {
  id: string;
  case_id?: string;
  subject?: string;
  sender?: string;
  final_risk: number;
  verdict: string;
  status: "NEW" | "INVESTIGATING" | "REMEDIATED" | "CLOSED";
  created_at: string;
  assigned_analyst?: string;
  sha256_evidence_hash?: string;
  hashes?: { sha256: string; sha1: string; md5: string };
  threat_category?: string;
  campaign?: { id: string; name: string };
  originating_node?: {
    ip?: string;
    city?: string;
    country?: string;
    country_code?: string;
    latitude?: number;
    longitude?: number;
    is_anonymized?: boolean;
    anonymization_type?: string;
  };
  mitre_tactics?: string[];
  notes?: Array<{
    author: string;
    text: string;
    timestamp: string;
  }>;
  [key: string]: unknown;
}

export function getForensicCases(params?: {
  limit?: number;
  status?: string;
  severity?: string;
  search?: string;
}): Promise<{ total: number; cases: ForensicCaseRecord[] }> {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.status) q.set("status", params.status);
  if (params?.severity) q.set("severity", params.severity);
  if (params?.search) q.set("search", params.search);
  const queryStr = q.toString() ? `?${q.toString()}` : "";
  return apiRequest<{ total: number; cases: ForensicCaseRecord[] }>(`/api/forensics/cases${queryStr}`);
}

export function getCaseDetail(caseId: string): Promise<{
  case: ForensicCaseRecord;
  analysis: AnalyzeResponse & {
    why_flagged?: Array<{
      category: string;
      explanation: string;
      evidence: string;
      severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
      contribution?: number | null;
    }>;
    email_metadata?: {
      platform: string;
      subject: string;
      sender: { name: string; email: string };
      recipient: string;
      body: string;
      received: string;
      thread_id?: string | null;
      urls: Array<{ display_text: string; href: string }>;
    };
    risk_factors?: Record<string, {
      name: string;
      score: number | null;
      status: "ENRICHED" | "NOT ENRICHED";
      severity: string;
      explanation: string;
    }>;
    url_intelligence_list?: Array<{
      url: string;
      display_text: string;
      domain: string;
      lexical_risk: number;
      verdict: string;
      domain_age_days: number | null;
      status: string;
      reputation: string;
      evidence?: Array<{ label?: string; description?: string }>;
    }>;
  };
  audit_trail: Array<{
    index: number;
    action: string;
    actor_id: string;
    timestamp: string;
    prev_hash: string;
    entry_hash: string;
    details?: Record<string, unknown>;
  }>;
}> {
  return apiRequest(`/api/forensics/cases/${encodeURIComponent(caseId)}`);
}

export interface EmailExtractionPayload {
  platform?: string;
  subject?: string;
  sender?: {
    name?: string;
    email?: string;
  };
  recipient?: string;
  body?: string;
  urls?: Array<{
    display_text?: string;
    href?: string;
  }>;
  timestamp?: string;
  metadata?: Record<string, unknown>;
  raw_eml?: string;
  email_header?: string | null;
  email_text?: string;
  sender_email?: string | null;
  private_mode?: boolean;
}

export function analyzeForensicEmail(payload: EmailExtractionPayload): Promise<{
  case_id: string;
  case_number: string;
  sha256_evidence_hash: string;
  final_risk: number;
  verdict: string;
  threat_category: string;
  reasoning_summary: string;
  why_flagged?: Array<{
    category: string;
    explanation: string;
    evidence: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    contribution?: number | null;
  }>;
  email_metadata?: any;
  risk_factors?: any;
  url_intelligence_list?: any;
  [key: string]: any;
}> {
  return apiRequest("/api/forensics/analyze-email", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getCaseAuditTrail(caseId: string): Promise<{
  case_id: string;
  audit_trail: Array<{
    index: number;
    action: string;
    actor_id: string;
    timestamp: string;
    prev_hash: string;
    entry_hash: string;
    details?: Record<string, unknown>;
  }>;
  chain_valid: boolean;
  count: number;
}> {
  return apiRequest(`/api/forensics/cases/${encodeURIComponent(caseId)}/audit`);
}

export function updateCaseStatus(caseId: string, status: string, reason?: string): Promise<ForensicCaseRecord> {
  return apiRequest(`/api/forensics/cases/${encodeURIComponent(caseId)}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status, reason: reason || "SOC Analyst update" }),
  });
}

export function addCaseNote(caseId: string, text: string, author?: string): Promise<{ message: string; note: unknown }> {
  return apiRequest(`/api/forensics/cases/${encodeURIComponent(caseId)}/notes`, {
    method: "POST",
    body: JSON.stringify({ text, author: author || "SOC Forensic Analyst" }),
  });
}

export function assignCase(caseId: string, analyst: string): Promise<ForensicCaseRecord> {
  return apiRequest(`/api/forensics/cases/${encodeURIComponent(caseId)}/assign`, {
    method: "POST",
    body: JSON.stringify({ analyst }),
  });
}

export function getQuarantineDownloadUrl(caseId: string, sha256: string): string {
  return `${API_BASE}/api/forensics/cases/${encodeURIComponent(caseId)}/quarantine/${encodeURIComponent(sha256)}`;
}

// ─── Exports (PDF, STIX 2.1, CSV) ─────────────────────────────────────────────

export function getExportPdfUrl(caseId: string, redactPii: boolean = false): string {
  return `${API_BASE}/api/forensics/export/${encodeURIComponent(caseId)}/pdf?redact_pii=${redactPii}`;
}

export function getExportStixUrl(caseId: string): string {
  return `${API_BASE}/api/forensics/export/${encodeURIComponent(caseId)}/stix`;
}

export function getExportCsvUrl(caseId: string): string {
  return `${API_BASE}/api/forensics/export/${encodeURIComponent(caseId)}/csv`;
}

// ─── Cyber Threat Intelligence (CTI) & Graph ──────────────────────────────────

export interface CtiIndicatorHit {
  indicator: string;
  threat_category: string;
  confidence: number;
  confidence_score?: number;
  source?: string;
  sources: string[];
  is_malicious: boolean;
  is_vpn_or_tor: boolean;
  details?: Record<string, unknown>;
}

export async function lookupCti(indicator: string): Promise<{
  indicator: string;
  records: CtiIndicatorHit[];
  total_hits: number;
  malicious_hits: number;
  vpn_or_tor: boolean;
}> {
  const res = await apiRequest<any>(`/api/forensics/cti/lookup?indicator=${encodeURIComponent(indicator)}`);
  const rawRecords = Array.isArray(res?.records) ? res.records : [];
  const normalizedRecords: CtiIndicatorHit[] = rawRecords.map((r: any) => {
    const src = r.source || (Array.isArray(r.sources) ? r.sources.join(", ") : "CTI Feed");
    const srcList = Array.isArray(r.sources) ? r.sources : [src];
    const score = typeof r.confidence_score === "number"
      ? r.confidence_score
      : typeof r.confidence === "number"
      ? (r.confidence > 1 ? r.confidence : r.confidence * 100)
      : 0;

    return {
      indicator: r.indicator || res?.indicator || indicator,
      threat_category: r.threat_category || (r.is_malicious ? "THREAT_DETECTED" : "CLEAN"),
      confidence: score,
      confidence_score: score,
      source: src,
      sources: srcList,
      is_malicious: Boolean(r.is_malicious),
      is_vpn_or_tor: Boolean(r.vpn_detected || r.is_vpn_or_tor || res?.vpn_or_tor),
      details: r.details || {}
    };
  });

  return {
    indicator: res?.indicator || res?.query || indicator,
    records: normalizedRecords,
    total_hits: res?.feed_count ?? res?.total_hits ?? normalizedRecords.length,
    malicious_hits: res?.malicious_hits ?? normalizedRecords.filter(r => r.is_malicious).length,
    vpn_or_tor: Boolean(res?.vpn_or_tor || normalizedRecords.some(r => r.is_vpn_or_tor))
  };
}

export interface GraphData {
  nodes: Array<{
    id: string;
    type?: string;
    position?: { x: number; y: number };
    data: {
      label: string;
      kind?: "email" | "ip" | "domain" | "asn" | "threat-actor" | "case" | "victim";
      type?: string;
      detail?: string;
      [key: string]: unknown;
    };
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    label?: string;
    animated?: boolean;
    style?: Record<string, unknown>;
  }>;
}

export function getCampaignGraph(campaignId: string): Promise<GraphData> {
  return apiRequest(`/api/forensics/campaigns/${encodeURIComponent(campaignId)}/graph`);
}

export interface SyndicateCommunity {
  id: string;
  name: string;
  threat_category: string;
  node_count: number;
  density: number;
  members: string[];
}

export function getSyndicateCommunities(): Promise<{
  syndicates: SyndicateCommunity[];
  modularity_score: number;
  total_nodes: number;
  total_edges: number;
}> {
  return apiRequest("/api/forensics/campaigns/communities");
}

// ─── Protected VIP Executive Roster ───────────────────────────────────────────

export interface VipExecutive {
  id?: string;
  name: string;
  title: string;
  authorized_domains: string[];
  created_at?: string;
}

export function getVipRoster(): Promise<{ roster: VipExecutive[]; count: number }> {
  return apiRequest("/api/forensics/vip-roster");
}

export function addVipExecutive(vip: VipExecutive): Promise<{ message: string; executive: VipExecutive }> {
  return apiRequest("/api/forensics/vip-roster", {
    method: "POST",
    body: JSON.stringify(vip),
  });
}

// ─── Mailbox Sentinel ─────────────────────────────────────────────────────────

export function getMailboxStatus(): Promise<{
  is_active: boolean;
  poll_interval_seconds: number;
  last_poll: string | null;
  processed_count: number;
  flagged_count: number;
}> {
  return apiRequest("/api/forensics/mailbox/status");
}

export function triggerMailboxPoll(): Promise<{
  status: string;
  ingested_count: number;
  cases_created: string[];
}> {
  return apiRequest("/api/forensics/mailbox/poll", { method: "POST" });
}

// ─── Zero-Trust RBAC & 2FA TOTP ───────────────────────────────────────────────

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  role: "SUPER_ADMIN" | "FORENSIC_ANALYST" | "SOC_OPERATOR" | "AUDITOR";
  is_2fa_enabled: boolean;
  permissions?: string[];
}

export interface LoginResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  user: UserProfile;
}

export function login(email: string, password: string): Promise<LoginResponse> {
  return apiRequest<LoginResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  }).then((res) => {
    if (res.access_token) {
      setAuthToken(res.access_token);
    }
    return res;
  });
}

export function getMe(): Promise<UserProfile> {
  return apiRequest<UserProfile>("/api/auth/me");
}

export function simulateRole(role: string): Promise<{ access_token: string; role: string; user: UserProfile }> {
  return apiRequest("/api/auth/role-simulation", {
    method: "POST",
    body: JSON.stringify({ role }),
  }).then((res) => {
    if (res.access_token) {
      setAuthToken(res.access_token);
      setStoredSimulatedRole(role);
    }
    return res;
  });
}

export function setup2fa(): Promise<{ secret: string; otpauth_url: string; qr_svg?: string }> {
  return apiRequest("/api/auth/2fa/setup", { method: "POST" });
}

export function verify2fa(code: string): Promise<{ message: string; verified: boolean }> {
  return apiRequest("/api/auth/2fa/verify", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

export function disable2fa(code: string): Promise<{ message: string; disabled: boolean }> {
  return apiRequest("/api/auth/2fa/disable", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

export function getUsers(): Promise<{ users: UserProfile[] }> {
  return apiRequest("/api/auth/users");
}

export function logout(): Promise<{ message: string }> {
  setAuthToken(null);
  setStoredSimulatedRole(null);
  return apiRequest("/api/auth/logout", { method: "POST" }).catch(() => ({ message: "Logged out" }));
}

// ─── System & Threat Intelligence Integrations ──────────────────────────────
export interface IntegrationItem {
  name: string;
  service_id: string;
  configured: boolean;
  status: "operational" | "not_configured" | "fallback_vault" | string;
  key_masked?: string | null;
  cache_entries?: number;
  indicators_count?: number;
  feed_url?: string;
  sync_interval?: string;
  rate_limit?: string;
  version?: string;
  provider?: string;
  backend?: string;
  is_connected?: boolean;
  records_count?: number;
  description: string;
}

export interface SystemIntegrationsResponse {
  virustotal: IntegrationItem;
  openphish: IntegrationItem;
  google_safe_browsing: IntegrationItem;
  abuseipdb: IntegrationItem;
  database: IntegrationItem;
  detection_engine: {
    name: string;
    status: string;
    version: string;
    active_scanners: string[];
  };
}

export interface IntegrationTestResult {
  success: boolean;
  service: string;
  latency_ms: number;
  message: string;
  details?: Record<string, unknown>;
}

export interface OpenPhishSyncResult {
  success: boolean;
  message: string;
  total_indicators: number;
  details?: Record<string, unknown>;
}

export interface UpdateKeyResult {
  success: boolean;
  service: string;
  message: string;
  key_masked?: string;
}

export function getSystemIntegrations(): Promise<SystemIntegrationsResponse> {
  return apiRequest<SystemIntegrationsResponse>("/api/system/integrations");
}

export function testIntegration(service: string): Promise<IntegrationTestResult> {
  return apiRequest<IntegrationTestResult>("/api/system/integrations/test", {
    method: "POST",
    body: JSON.stringify({ service }),
  });
}

export function syncOpenPhishFeed(): Promise<OpenPhishSyncResult> {
  return apiRequest<OpenPhishSyncResult>("/api/system/integrations/sync-openphish", {
    method: "POST",
  });
}

export function updateIntegrationKey(service: string, apiKey: string): Promise<UpdateKeyResult> {
  return apiRequest<UpdateKeyResult>("/api/system/integrations/update-key", {
    method: "POST",
    body: JSON.stringify({ service, api_key: apiKey }),
  });
}

export default API_BASE;

