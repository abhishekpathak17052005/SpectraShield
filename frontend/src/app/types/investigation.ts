// ==============================================================================
// SPECTRASHIELD SECURITY INVESTIGATION — DATA TYPES & INTERFACES
// ==============================================================================

export type SeverityLevel = "SAFE" | "SUSPICIOUS" | "HIGH_RISK" | "NOT_ENRICHED";
export type AuthStatus = "PASS" | "FAIL" | "UNKNOWN" | "SOFTFAIL";

export interface InvestigationHeaderMeta {
  investigationId: string;
  sender: string;
  senderName?: string;
  subject: string;
  platform: string;
  receivedTime: string;
  status: "ACTIVE_TRIAGE" | "INVESTIGATING" | "REMEDIATED" | "CLOSED";
  assignedAnalyst?: string;
  isDemoData: boolean;
}

export interface RiskScoreData {
  score: number; // 0 - 100
  severity: SeverityLevel;
  confidence: number | null; // percentage e.g. 94.2 or null if not enriched
  primaryMessage: string;
  timeToAnalyzeMs: number;
  quarantinedAttachmentsCount: number;
  domainAgeDays: number | null;
}

export interface RiskFactor {
  id: string;
  name: string;
  score: number | null; // 0 - 100 or null if NOT ENRICHED
  severity: SeverityLevel | "NOT_ENRICHED";
  explanation: string;
  statusText?: string;
  evidence: Array<{
    label: string;
    value: string;
    codeSnippet?: string;
    flagged?: boolean;
  }>;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  confidence: number;
  evidence: string;
}

export interface ThreatAssessmentData {
  verdict: string;
  confidence: number | null;
  primaryAttack: string;
  threatCategory: string;
  detectedTechniques: MitreTechnique[];
  aiForensicExplanation: {
    summary: string;
    keyObservations: string[];
    riskEvaluation: string;
    recommendedAction: string;
  };
}

export interface MailRoutingHop {
  hopNumber: number;
  type: "SENDER" | "MAIL_SERVER" | "RELAY" | "GATEWAY" | "RECIPIENT";
  name: string;
  ip: string;
  defangedIp: string;
  hostname: string;
  location: string;
  isp: string;
  asn?: string;
  delaySeconds: number;
  isAnonymized?: boolean;
  anonymizationType?: string;
  timestamp: string;
  flagged?: boolean;
}

export interface HeaderForensicsData {
  spf: {
    status: AuthStatus;
    senderIp: string;
    domain: string;
    details: string;
  };
  dkim: {
    status: AuthStatus;
    selector: string;
    domain: string;
    keyLengthBits: number | null;
    bodyHashValid: boolean | null;
    signatureValid: boolean | null;
    details: string;
  };
  dmarc: {
    status: AuthStatus;
    policy: string;
    alignment: string;
    details: string;
  };
  senderIp: string;
  originatingServer: string;
  replyTo: string;
  returnPath: string;
  messageId: string;
  routingTimeline: MailRoutingHop[];
  anomalies: string[];
}

export interface RedirectHop {
  order: number;
  url: string;
  defangedUrl: string;
  statusCode: number;
  server?: string;
}

export interface UrlIntelligenceData {
  originalUrl: string;
  defangedUrl: string;
  domain: string;
  domainReputation: {
    score: number;
    verdict: string;
    ageDays: number | null;
    registrar: string;
    isBurnerOrNew: boolean;
  };
  typosquatting: {
    isImpersonating: boolean;
    targetBrand: string | null;
    levenshteinDistance: number | null;
    punycodeDetected: boolean;
    analysis: string;
  };
  redirectChain: RedirectHop[];
  reputationFeeds: {
    virusTotal: {
      status: "MALICIOUS" | "CLEAN" | "UNKNOWN" | "UNAVAILABLE";
      maliciousEngines: number;
      totalEngines: number;
      details: string;
    };
    openPhish: {
      status: "MATCHED" | "NO_MATCH" | "UNAVAILABLE";
      feedId?: string;
      details: string;
    };
    googleSafeBrowsing: {
      status: "MALICIOUS" | "SAFE" | "UNKNOWN" | "UNAVAILABLE";
      threatType?: string;
      details: string;
    };
    urlhaus: {
      status: "MALICIOUS" | "CLEAN" | "UNKNOWN" | "UNAVAILABLE";
      threatTag?: string;
      details: string;
    };
  };
}

export interface InfrastructureData {
  ip: string;
  defangedIp: string;
  country: string;
  countryCode: string;
  city: string;
  coordinates: { latitude: number; longitude: number };
  asn: string;
  isp: string;
  domainAge: string;
  sslCertificate: {
    valid: boolean;
    status: "VALID" | "INVALID" | "SELF_SIGNED" | "EXPIRED" | "UNKNOWN";
    issuer: string;
    subjectCN: string;
    daysUntilExpiry: number;
    hostMismatch: boolean;
  };
  hostingRiskScore: number;
  isTorExitNode: boolean;
  isCommercialVpn: boolean;
  vpnProvider?: string;
  abuseConfidenceScore: number;
}

export interface ThreatGraphNode {
  id: string;
  type: "email" | "sender" | "domain" | "url" | "ip" | "asn" | "hosting" | "threat_actor";
  label: string;
  sublabel: string;
  riskScore: number;
  severity: SeverityLevel;
  properties: Record<string, string | number | boolean>;
}

export interface ThreatGraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  animated?: boolean;
}

export interface ThreatGraphData {
  nodes: ThreatGraphNode[];
  edges: ThreatGraphEdge[];
  campaignName?: string;
  modularityScore?: number;
  hasCampaignGraph?: boolean;
}

export interface EvidenceVaultItem {
  id: string;
  type: "ORIGINAL_EMAIL" | "HEADERS" | "EXTRACTED_URLS" | "DNS_INTEL" | "WHOIS_INTEL" | "THREAT_INTEL" | "SCREENSHOT" | "FORENSIC_REPORT";
  title: string;
  timestamp: string;
  sha256: string;
  sizeBytes: number;
  integrityStatus: "VERIFIED_IMMUTABLE" | "PENDING_VERIFICATION" | "TAMPERED";
  downloadUrl?: string;
  previewSnippet?: string;
}

export interface InvestigationRecord {
  meta: InvestigationHeaderMeta;
  risk: RiskScoreData;
  riskFactors: RiskFactor[];
  threatAssessment: ThreatAssessmentData;
  headers: HeaderForensicsData;
  urlIntelligence: UrlIntelligenceData;
  infrastructure: InfrastructureData;
  threatGraph: ThreatGraphData;
  evidence: EvidenceVaultItem[];
  mode?: "LIVE" | "DEMO";
  hasCampaignGraph?: boolean;
  hasRedirectChain?: boolean;
}

export interface WhyFlaggedReason {
  category: string;
  explanation: string;
  evidence: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  contribution?: number | null;
}

export interface EmailMetadata {
  platform: string;
  subject: string;
  sender: {
    name: string;
    email: string;
  };
  recipient: string;
  body: string;
  received: string;
  thread_id?: string | null;
  urls: Array<{
    display_text: string;
    href: string;
  }>;
}

export interface EmailIntelligenceRecord {
  case_id: string;
  case_number: string;
  sha256: string;
  final_risk: number;
  verdict: string;
  threat_category: string;
  confidence: number | null;
  email_metadata: EmailMetadata;
  why_flagged: WhyFlaggedReason[];
  risk_factors: Record<string, {
    name: string;
    score: number | null;
    status: "ENRICHED" | "NOT ENRICHED";
    severity: SeverityLevel;
    explanation: string;
  }>;
  url_intelligence_list: Array<{
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
  authentication: {
    spf?: { status?: string; ip?: string; domain?: string; reason?: string };
    dkim?: { status?: string; selector?: string; domain?: string; reason?: string };
    dmarc?: { status?: string; policy?: string; alignment?: string; reason?: string };
  };
  originating_node?: {
    ip?: string;
    defanged_ip?: string;
    country?: string;
    asn?: string;
    isp?: string;
    is_anonymized?: boolean;
    anonymization_type?: string;
  };
  campaign_id?: string | null;
  created_at: string;
  mode: "LIVE" | "DEMO";
}
