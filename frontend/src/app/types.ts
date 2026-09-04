/**
 * SpectraShield 2.0 Master Type Definitions
 * Covers Heritage 1.0 Telemetry, Deep Forensics, Relay Traceability, and Campaign Correlation
 */

// --- SpectraShield 1.0 Heritage Types ---

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
  sender?: string;
  subject?: string;
  risk_breakdown?: {
    brand_match?: string;
  };
}

export interface HistoryCountResponse {
  total_scans: number;
}

export interface TopBrandRecord {
  name: string;
  count: number;
  riskLevel?: 'high' | 'medium' | 'low';
}

export interface TopBrandsResponse {
  days: number;
  risk: "all" | "low" | "medium" | "high" | string;
  source: "internal" | "external" | "blended" | string;
  updated_at: string;
  total_brands: number;
  brands: TopBrandRecord[];
}

export interface HeatmapCell {
  dayIndex: number; // 0 = Sun, 6 = Sat
  hour: number;     // 0 - 23
  value: number;
}

export interface RiskHeatmapResponse {
  days: number;
  risk: "all" | "low" | "medium" | "high" | string;
  updated_at: string;
  max_count: number;
  cells: HeatmapCell[];
}

// --- SpectraShield 2.0 Forensic Types ---

export interface AuthMechanismResult {
  status: 'Pass' | 'Fail' | 'SoftFail' | 'Neutral' | 'None';
  domain?: string;
  sender_ip?: string;
  selector?: string;
  policy?: string;
  aligned?: boolean;
  alignment_type?: string;
  valid?: boolean;
  reason?: string;
}

export interface ForensicAuthentication {
  spf: AuthMechanismResult;
  dkim: AuthMechanismResult;
  dmarc: AuthMechanismResult;
}

export interface OriginGeoCoordinates {
  country?: string;
  country_code?: string;
  city?: string;
  lat?: number;
  lon?: number;
}

export interface OriginatingNode {
  ip: string;
  defanged_ip: string;
  country: string;
  country_code: string;
  city: string;
  latitude: number;
  longitude: number;
  asn: string;
  isp: string;
  is_anonymized: boolean;
  anonymization_type?: 'TOR' | 'VPN' | 'PROXY' | 'CLOUD' | 'NONE';
  risk_rating: number;
}

export interface RelayHop {
  hop: number;
  received_from: string;
  by: string;
  protocol?: string;
  ip: string;
  defanged_ip: string;
  is_private: boolean;
  is_origin: boolean;
  timestamp: string;
  delay_seconds: number;
  geo?: OriginGeoCoordinates | null;
  warning?: string;
}

export interface CampaignDetails {
  id: string;
  name: string;
  attribution_confidence: number;
  threat_actor: string;
  linked_incidents_count: number;
  first_seen?: string;
  last_seen?: string;
}

export interface NLPIntelligence {
  financial_intent: boolean;
  executive_impersonation: boolean;
  urgency_score: number;
  fear_score: number;
  authority_score: number;
  scarcity_score: number;
  homoglyph_detected: boolean;
  extracted_urgency_cues?: string[];
  extracted_impersonations?: string[];
}

export interface ForensicAnalyzeRequest {
  raw_eml?: string;
  email_text?: string;
  email_header?: string;
  sender_email?: string;
  subject?: string;
  private_mode?: boolean;
}

export interface AttachmentEvidence {
  filename: string;
  content_type: string;
  file_size_bytes: number;
  sha256: string;
  sha1: string;
  md5: string;
  fuzzy_hash?: string;
  entropy_score: number;
  is_executable_or_script: boolean;
  has_macros: boolean;
  has_embedded_scripts: boolean;
  risk_level: 'clean' | 'suspicious' | 'malicious' | string;
  risk_reasons: string[];
}

export interface CaseNote {
  id: string;
  text: string;
  author: string;
  timestamp: string;
}

export interface CaseRecord {
  id: string;
  case_number: string;
  title: string;
  threat_category: string;
  severity: string;
  status: string;
  overall_risk_score: number;
  sha256_evidence_hash: string;
  assigned_analyst: string;
  notes?: CaseNote[];
  created_at: string;
  updated_at: string;
}

export interface ForensicAnalyzeResponse {
  case_id: string;
  case_number: string;
  sha256_evidence_hash: string;
  sha1: string;
  md5: string;
  final_risk: number;
  verdict: string;
  threat_category: string;
  reasoning_summary: string;
  authentication: ForensicAuthentication;
  originating_node: OriginatingNode;
  relay_path: RelayHop[];
  campaign: CampaignDetails;
  nlp_intelligence: NLPIntelligence;
  attachments?: AttachmentEvidence[];
  breakdown: Record<string, number>;
  mitre_tactics: string[];
  attack_simulation?: unknown[];
  anomalies: string[];
  created_at: string;
}

// --- React Flow Threat Graph Types ---

export interface ThreatGraphNodeData {
  label: string;
  type: 'email' | 'ip' | 'domain' | 'asn' | 'campaign';
  subLabel?: string;
  riskScore?: number;
  meta?: Record<string, unknown>;
  icon?: string;
}

export interface ThreatGraphEdgeData {
  label?: string;
  type?: string;
  confidence?: number;
}
