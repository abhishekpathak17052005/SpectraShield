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
  quarantine_path?: string | null;
  is_quarantined?: boolean;
}

export interface QuishingEvidence {
  has_qr_code: boolean;
  qr_count: number;
  decoded_payloads: string[];
  defanged_payloads: string[];
  risk_level: 'clean' | 'suspicious' | 'malicious' | string;
  source_image_filename?: string | null;
  extracted_urls: string[];
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

export interface HomoglyphChar {
  index: number;
  raw_char: string;
  lookalike_char: string;
  unicode_hex: string;
  script: string;
  char_name?: string;
}

export interface HomoglyphAnalysis {
  has_homoglyphs: boolean;
  is_punycode: boolean;
  raw_domain: string;
  punycode_ascii?: string | null;
  normalized_ascii: string;
  target_brand?: string | null;
  target_domain?: string | null;
  substituted_characters: HomoglyphChar[];
  risk_score_modifier: number;
  verdict: string;
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
  homoglyph_analysis?: HomoglyphAnalysis;
  quishing_evidence?: QuishingEvidence;
  cti_reputation?: CtiReputationRecord[];
  dkim_verification?: DkimVerificationDetails;
  transformer_nlp?: TransformerNlpResult;
  ingestion_format?: string;
  sanitized_html?: string;
  script_cues?: string[];
  created_at: string;
}

// --- Phase 7: External Threat Feeds, Active DNS DKIM & Transformer Intelligence Types ---

export interface CtiReputationRecord {
  source: string;
  indicator: string;
  indicator_type: 'IP' | 'DOMAIN' | 'URL' | string;
  is_malicious: boolean;
  confidence_score: number;
  threat_category?: string | null;
  asn_isp?: string | null;
  country?: string | null;
  vpn_detected?: boolean;
  vpn_provider?: string | null;
  last_reported?: string | null;
  details?: Record<string, unknown>;
}

export interface DkimVerificationDetails {
  selector?: string | null;
  signing_domain?: string | null;
  key_length_bits: number;
  algorithm: string;
  body_hash_valid: boolean;
  signature_math_valid: boolean;
  dns_key_published: boolean;
  raw_public_key?: string | null;
  verification_status: 'PASS' | 'FAIL' | 'NONE' | string;
  reason?: string | null;
}

export interface TransformerNlpResult {
  top_intent: string;
  confidence: number;
  intent_probabilities: Record<string, number>;
  vip_impersonation: boolean;
  targeted_vip?: string | null;
  targeted_title?: string | null;
  vip_risk_level: string;
  explanation: string;
}

export interface ThreatCommunityCluster {
  community_id: number;
  syndicate_name: string;
  node_count: number;
  density: number;
  dominant_threat_actor: string;
  dominant_category: string;
  nodes: string[];
}

export interface LouvainCommunitiesResponse {
  modularity: number;
  syndicates_count: number;
  communities: ThreatCommunityCluster[];
}

export interface VipRosterEntry {
  name: string;
  title: string;
  authorized_domains: string[];
  authorized_emails: string[];
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

// --- Phase 6: Enterprise Identity & 4-Tier RBAC Types ---

export type EnterpriseRole = 'SUPER_ADMIN' | 'FORENSIC_ANALYST' | 'SOC_OPERATOR' | 'AUDITOR';

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  role: EnterpriseRole;
  totp_enabled: boolean;
  created_at?: string;
  updated_at?: string;
  last_login?: string | null;
  is_demo_fallback?: boolean;
}

export interface AuthSession {
  user: UserProfile;
  access_token: string;
  refresh_token: string;
  permissions: string[];
}

export interface Setup2FAResponse {
  secret: string;
  qr_code_base64: string;
  provisioning_uri: string;
  manual_entry_key: string;
  user_email: string;
  message: string;
}

export interface Verify2FAResponse {
  status: string;
  message: string;
  totp_enabled: boolean;
  access_token?: string;
  refresh_token?: string;
  user?: UserProfile;
  permissions?: string[];
}

export interface LoginResponse {
  status: string;
  requires_2fa: boolean;
  temp_token?: string;
  user_id?: string;
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  user?: UserProfile;
  permissions?: string[];
  message?: string;
}

