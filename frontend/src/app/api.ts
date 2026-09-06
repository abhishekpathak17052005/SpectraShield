/**
 * SpectraShield 2.0 Unified API Client with Dynamic Offline Mock Fallbacks
 * Base URL: VITE_API_URL or http://localhost:8000
 */

import {
  AnalyzeRequest,
  AnalyzeResponse,
  HistoryRecord,
  HistoryCountResponse,
  TopBrandsResponse,
  RiskHeatmapResponse,
  ForensicAnalyzeRequest,
  ForensicAnalyzeResponse,
  CaseRecord,
  UserProfile,
  AuthSession,
  LoginResponse,
  Setup2FAResponse,
  Verify2FAResponse,
  EnterpriseRole,
  CtiReputationRecord,
  DkimVerificationDetails,
  TransformerNlpResult,
  ThreatCommunityCluster,
  LouvainCommunitiesResponse,
  VipRosterEntry,
} from './types';

export const getApiBase = (): string => {
  return (import.meta as unknown as { env?: { VITE_API_URL?: string } }).env?.VITE_API_URL ?? "http://localhost:8000";
};

// ==========================================
// HIGH-FIDELITY OFFLINE MOCK DATASETS
// ==========================================

export const MOCK_FORENSIC_ANALYSIS: ForensicAnalyzeResponse = {
  case_id: "8f3b2c1a-5e7d-4b9a-8c1e-9f3a2b1c0d5e",
  case_number: "CASE-2026-0891",
  sha256_evidence_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  md5: "d41d8cd98f00b204e9800998ecf8427e",
  final_risk: 94.5,
  verdict: "High Risk / Malicious",
  threat_category: "Business Email Compromise (BEC)",
  reasoning_summary: "Flagged as High Risk: Cryptographic DMARC alignment failed, origin IP traced to verified Tor exit node in Frankfurt, Germany, and executive financial diversion cues detected.",
  authentication: {
    spf: {
      status: "Fail",
      domain: "micro-soft-billing.top",
      sender_ip: "185.220.101.5",
      reason: "Sending IP not authorized in SPF DNS record"
    },
    dkim: {
      status: "Fail",
      selector: "default",
      domain: "micro-soft-billing.top",
      valid: false,
      reason: "Cryptographic body hash mismatch"
    },
    dmarc: {
      status: "Fail",
      domain: "micro-soft-billing.top",
      policy: "reject",
      aligned: false,
      alignment_type: "strict"
    }
  },
  originating_node: {
    ip: "185.220.101.5",
    defanged_ip: "185[.]220[.]101[.]5",
    country: "Germany",
    country_code: "DE",
    city: "Frankfurt",
    latitude: 50.1109,
    longitude: 8.6821,
    asn: "AS60729",
    isp: "Tor Exit Router Network",
    is_anonymized: true,
    anonymization_type: "TOR",
    risk_rating: 95.0
  },
  relay_path: [
    {
      hop: 1,
      received_from: "client-node.internal (10.0.0.15)",
      by: "mta1.local-lan.com",
      protocol: "ESMTP",
      ip: "10.0.0.15",
      defanged_ip: "10[.]0[.]0[.]15",
      is_private: true,
      is_origin: false,
      timestamp: "2026-09-04T10:14:00Z",
      delay_seconds: 0,
      geo: null
    },
    {
      hop: 2,
      received_from: "mta1.local-lan.com",
      by: "relay.attacker-infra.net",
      protocol: "ESMTPS",
      ip: "185.220.101.5",
      defanged_ip: "185[.]220[.]101[.]5",
      is_private: false,
      is_origin: true,
      timestamp: "2026-09-04T10:14:02Z",
      delay_seconds: 2,
      geo: {
        country: "Germany",
        country_code: "DE",
        city: "Frankfurt",
        lat: 50.1109,
        lon: 8.6821
      }
    },
    {
      hop: 3,
      received_from: "relay.attacker-infra.net",
      by: "mx.victim-corp.com",
      protocol: "ESMTPS",
      ip: "172.217.194.27",
      defanged_ip: "172[.]217[.]194[.]27",
      is_private: false,
      is_origin: false,
      timestamp: "2026-09-04T10:14:05Z",
      delay_seconds: 3,
      geo: {
        country: "United States",
        country_code: "US",
        city: "Mountain View",
        lat: 37.422,
        lon: -122.084
      }
    }
  ],
  campaign: {
    id: "CAMP-2026-042",
    name: "Targeted European Wire Diversion",
    attribution_confidence: 88.0,
    threat_actor: "FIN7 / Carbanak Emulation",
    linked_incidents_count: 8
  },
  nlp_intelligence: {
    financial_intent: true,
    executive_impersonation: true,
    urgency_score: 85.0,
    fear_score: 10.0,
    authority_score: 90.0,
    scarcity_score: 40.0,
    homoglyph_detected: true,
    extracted_urgency_cues: ["Immediate action required", "Wire payment within 24h"],
    extracted_impersonations: ["CEO / CFO Direct Directive"]
  },
  attachments: [
    {
      filename: "Acquisition_Wire_Instructions.docm",
      content_type: "application/vnd.ms-word.document.macroEnabled.12",
      file_size_bytes: 142850,
      sha256: "8e920d912440307bb28d6f5195eb03082390f7193ab46618e404be124e54cd89",
      sha1: "6f5195eb03082390f7193ab46618e404be124e54",
      md5: "2390f7193ab46618e404be124e54cd89",
      fuzzy_hash: "3072:8e920d912440307bb28d6f5195eb0308:3ab46618e404",
      entropy_score: 7.62,
      is_executable_or_script: false,
      has_macros: true,
      has_embedded_scripts: false,
      risk_level: "malicious",
      risk_reasons: [
        "VBA Macro project detected inside document archive",
        "High Shannon Entropy (7.62/8.0) indicating encrypted payload or obfuscated binary",
        "AutoOpen execution routine detected in Document structure"
      ]
    },
    {
      filename: "NDA_Agreement_Counterpart.pdf",
      content_type: "application/pdf",
      file_size_bytes: 48920,
      sha256: "b10a8db164e0754105b7a99be72e3fe5aa0a6bc84cb9ec87b99c148a071b7b7f",
      sha1: "05b7a99be72e3fe5aa0a6bc84cb9ec87b99c148a",
      md5: "72e3fe5aa0a6bc84cb9ec87b99c148a",
      fuzzy_hash: "1536:b10a8db164e0754105b7a99be72e3fe5:0a6bc84cb9ec",
      entropy_score: 5.84,
      is_executable_or_script: false,
      has_macros: false,
      has_embedded_scripts: false,
      risk_level: "clean",
      risk_reasons: []
    }
  ],
  breakdown: {
    header_score: 92.0,
    origin_score: 95.0,
    nlp_score: 88.0,
    url_score: 75.0,
    killchain_severity: 85.0
  },
  mitre_tactics: [
    "T1566.002 - Spearphishing Link",
    "T1598.003 - Spearphishing for Information",
    "T1090.003 - Multi-hop Proxy (Tor / VPN)"
  ],
  anomalies: [
    "RFC 1918 Bogon IP 10.0.0.15 discarded from physical geolocation resolution.",
    "Earliest Reliable Public Node (ERPN) isolated at Hop #2 (185.220.101.5).",
    "Sender envelope return-path mismatch with visible RFC 5322 From: address.",
    "Unicode Homoglyph Spoofing detected: micro-soft-billing.top mimics MICROSOFT"
  ],
  homoglyph_analysis: {
    has_homoglyphs: true,
    is_punycode: false,
    raw_domain: "micrоsoft-billing.top",
    punycode_ascii: null,
    normalized_ascii: "microsoft-billing.top",
    target_brand: "microsoft",
    target_domain: "microsoft.com",
    substituted_characters: [
      {
        index: 4,
        raw_char: "о",
        lookalike_char: "o",
        unicode_hex: "U+043E",
        script: "Cyrillic",
        char_name: "CYRILLIC SMALL LETTER O"
      }
    ],
    risk_score_modifier: 50.0,
    verdict: "Critical Homoglyph Spoofing (MICROSOFT)"
  },
  cti_reputation: [
    {
      source: "AbuseIPDB",
      indicator: "185.220.101.5",
      indicator_type: "IP",
      is_malicious: true,
      confidence_score: 98,
      threat_category: "Known Tor Exit Node / Scanner",
      asn_isp: "Zwiebelfreunde e.V.",
      country: "DE",
      vpn_detected: true,
      vpn_provider: "Tor Exit Node Network"
    },
    {
      source: "abuse.ch URLhaus",
      indicator: "hxxps://micro-soft-billing[.]top/auth/login",
      indicator_type: "URL",
      is_malicious: true,
      confidence_score: 95,
      threat_category: "Credential Harvester / Phish"
    },
    {
      source: "Google Safe Browsing",
      indicator: "micro-soft-billing.top",
      indicator_type: "DOMAIN",
      is_malicious: true,
      confidence_score: 90,
      threat_category: "SOCIAL_ENGINEERING"
    }
  ],
  dkim_verification: {
    selector: "default",
    signing_domain: "micro-soft-billing.top",
    key_length_bits: 2048,
    algorithm: "rsa-sha256",
    body_hash_valid: false,
    signature_math_valid: false,
    dns_key_published: true,
    raw_public_key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzqX...",
    verification_status: "FAIL",
    reason: "Cryptographic Body Hash Mismatch (Possible Message Tampering)"
  },
  transformer_nlp: {
    top_intent: "FINANCIAL_WIRE_FRAUD",
    confidence: 0.942,
    intent_probabilities: {
      "FINANCIAL_WIRE_FRAUD": 0.942,
      "EXECUTIVE_IMPERSONATION": 0.885,
      "CREDENTIAL_HARVESTING": 0.120,
      "INVOICE_SUPPLIER_FRAUD": 0.654,
      "EXTORTION_BLACKMAIL": 0.041,
      "CLEAN_BENIGN": 0.012
    },
    vip_impersonation: true,
    targeted_vip: "Satya Nadella",
    targeted_title: "Chief Executive Officer",
    vip_risk_level: "CRITICAL",
    explanation: "Deep transformer detected executive financial wire diversion cues paired with display name impersonation targeting CEO."
  },
  created_at: new Date().toISOString()
};

export const MOCK_TOP_BRANDS: TopBrandsResponse = {
  days: 7,
  risk: "all",
  source: "blended",
  updated_at: new Date().toISOString(),
  total_brands: 6,
  brands: [
    { name: "Microsoft 365", count: 142, riskLevel: 'high' },
    { name: "PayPal Payments", count: 98, riskLevel: 'high' },
    { name: "DHL Express", count: 64, riskLevel: 'medium' },
    { name: "Amazon Prime", count: 53, riskLevel: 'medium' },
    { name: "Google Workspace", count: 41, riskLevel: 'low' },
    { name: "Apple ID Support", count: 29, riskLevel: 'low' }
  ]
};

export const generateMockHeatmap = (): RiskHeatmapResponse => {
  const cells = [];
  let maxCount = 0;
  for (let day = 0; day < 7; day++) {
    for (let hour = 0; hour < 24; hour++) {
      // Simulate higher attack volume during business hours (09:00 - 17:00)
      const isPeakHour = hour >= 9 && hour <= 17;
      const base = isPeakHour ? Math.floor(Math.random() * 22) + 6 : Math.floor(Math.random() * 8);
      if (base > maxCount) maxCount = base;
      cells.push({ dayIndex: day, hour, value: base });
    }
  }
  return {
    days: 7,
    risk: "all",
    updated_at: new Date().toISOString(),
    max_count: maxCount,
    cells
  };
};

export const MOCK_HISTORY: HistoryRecord[] = [
  {
    id: "SCN-9021",
    final_risk: 94.5,
    verdict: "High Risk / Malicious",
    confidence_level: "High",
    threat_category: "Business Email Compromise (BEC)",
    timestamp: "10 mins ago",
    sender: "executive@micro-soft-billing.top",
    subject: "URGENT: Outstanding Vendor Invoice Confirmation",
    risk_breakdown: { brand_match: "Microsoft 365" }
  },
  {
    id: "SCN-9018",
    final_risk: 88.0,
    verdict: "High Risk / Malicious",
    confidence_level: "High",
    threat_category: "Credential Harvester",
    timestamp: "32 mins ago",
    sender: "service@paypaI-security-auth.cc",
    subject: "Account Suspended: Immediate Verification Required",
    risk_breakdown: { brand_match: "PayPal" }
  },
  {
    id: "SCN-9015",
    final_risk: 45.0,
    verdict: "Suspicious",
    confidence_level: "Medium",
    threat_category: "Brand Impersonation",
    timestamp: "1 hour ago",
    sender: "tracking@dhl-express-portal.org",
    subject: "Delivery on hold: Address amendment fee",
    risk_breakdown: { brand_match: "DHL Express" }
  },
  {
    id: "SCN-9011",
    final_risk: 12.0,
    verdict: "Clean / Verified",
    confidence_level: "High",
    threat_category: "Legitimate Transactional",
    timestamp: "2 hours ago",
    sender: "notifications@github.com",
    subject: "[GitHub] Security advisory alert for repository",
    risk_breakdown: { brand_match: "None" }
  },
  {
    id: "SCN-9008",
    final_risk: 91.0,
    verdict: "High Risk / Malicious",
    confidence_level: "High",
    threat_category: "QR Code Phishing (Quishing)",
    timestamp: "4 hours ago",
    sender: "admin@secure-mfa-update.xyz",
    subject: "2FA Policy Update: Scan QR Code to maintain access",
    risk_breakdown: { brand_match: "Microsoft 365" }
  }
];

export const MOCK_QUICK_ANALYZE: AnalyzeResponse = {
  final_risk: 86.0,
  unified_severity_score: 86.0,
  verdict: "High Risk / Phishing",
  confidence_level: "High",
  threat_category: "Credential Harvesting & Brand Spoofing",
  reasoning_summary: "Severe cognitive urgency cues detected, domain age is under 3 days old, and free certificate authority used for financial login simulation.",
  timestamp: new Date().toISOString(),
  threat_array: [
    "Cognitive Urgency Trigger (24-hour deadline)",
    "Domain Age < 7 Days (Burner Domain)",
    "TypoSquatting / Homoglyph Brand Impersonation",
    "Self-Signed / Let's Encrypt SSL on banking mimic"
  ],
  intelligence_profile: {
    ssl_status: {
      issuer: "Let's Encrypt Authority X3",
      expiry_date: "2026-11-20",
      is_valid: true,
      is_self_signed: false,
      subject_common_name: "secure-verify-account.tk",
      subject_organization: "Domain Validated"
    },
    location_data: {
      country: "Germany",
      city: "Frankfurt",
      isp: "DigitalOcean Cloud Infrastructure",
      ip_address: "185.220.101.5"
    },
    advanced_technical_details: {
      page_title: "Sign in to your Microsoft account",
      domain_age_days: 4,
      redirect_hops: 1,
      redirect_chain: ["https://secure-verify-account.tk/login/microsoft"],
      dns_records: {
        a: ["185.220.101.5"],
        mx: ["mail.secure-verify-account.tk"]
      }
    }
  },
  domain_age_days: 4,
  domain_age_context: {
    bucket: "newly_registered",
    label: "Freshly Registered Domain",
    color: "#ef4444",
    message: "Domain registered only 4 days ago. High likelihood of disposable phishing attack infrastructure.",
    risk_modifier_pct: 35
  },
  ssl_context: {
    bucket: "dv_free",
    label: "Standard DV (Free CA)",
    badge: "DV Validated",
    severity: "warning",
    color: "#f59e0b",
    symbol: "⚠️",
    message: "Free automated DV certificate on an entity claiming to represent a global financial platform.",
    risk_modifier_pct: 20
  },
  risk_breakdown: {
    brand_match: "Microsoft",
    logic_flags: ["Urgent Account Suspension Threat", "Unverified Subdomain Redirect"],
    local_score: 85,
    external_score: 90
  },
  breakdown: {
    manipulation_score: 92,
    url_score: 88,
    ai_generated_score: 74,
    brand_impersonation_score: 95,
    header_score: 82
  }
};

// ==========================================
// API CLIENT IMPLEMENTATIONS WITH FALLBACKS
// ==========================================

export async function analyzeEmail(body: AnalyzeRequest): Promise<AnalyzeResponse> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (res.ok) return await res.json();
  } catch {
    // Graceful offline fallback
  }
  return MOCK_QUICK_ANALYZE;
}

export async function getHistory(): Promise<HistoryRecord[]> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/history`);
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return MOCK_HISTORY;
}

export async function getHistoryCount(): Promise<HistoryCountResponse> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/history/count`);
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return { total_scans: 142 };
}

export async function getTopBrands(params: {
  days: number;
  risk: "all" | "low" | "medium" | "high";
  source?: "internal" | "external" | "blended";
  limit?: number;
}): Promise<TopBrandsResponse> {
  const base = getApiBase();
  try {
    const query = new URLSearchParams({
      days: String(params.days),
      risk: params.risk,
      source: params.source ?? "blended",
      limit: String(params.limit ?? 6),
    });
    const res = await fetch(`${base}/dashboard/top-brands?${query.toString()}`);
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return MOCK_TOP_BRANDS;
}

export async function getRiskHeatmap(params: {
  days: number;
  risk: "all" | "low" | "medium" | "high";
}): Promise<RiskHeatmapResponse> {
  const base = getApiBase();
  try {
    const query = new URLSearchParams({
      days: String(params.days),
      risk: params.risk,
    });
    const res = await fetch(`${base}/dashboard/risk-heatmap?${query.toString()}`);
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return generateMockHeatmap();
}

export async function clearHistory(): Promise<{ message: string }> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/history`, { method: "DELETE" });
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return { message: "History cleared successfully (Demo mode)" };
}

export async function deleteScan(scanId: string): Promise<{ message: string }> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/history/${encodeURIComponent(scanId)}`, { method: "DELETE" });
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return { message: `Scan ${scanId} removed (Demo mode)` };
}

export async function analyzeForensicEmail(payload: ForensicAnalyzeRequest): Promise<ForensicAnalyzeResponse> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/analyze-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return MOCK_FORENSIC_ANALYSIS;
}

export async function uploadEmlFile(file: File): Promise<ForensicAnalyzeResponse> {
  const base = getApiBase();
  try {
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch(`${base}/api/forensics/upload-eml`, {
      method: "POST",
      body: formData,
    });
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return MOCK_FORENSIC_ANALYSIS;
}

export function getQuarantineDownloadUrl(caseId: string, sha256: string): string {
  const base = getApiBase();
  return `${base}/api/forensics/cases/${encodeURIComponent(caseId)}/quarantine/${encodeURIComponent(sha256)}`;
}


export async function getCampaignGraph(campaignId: string): Promise<any> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/campaigns/${encodeURIComponent(campaignId)}/graph`);
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return null;
}

export async function checkBackendHealth(): Promise<boolean> {
  const base = getApiBase();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(`${base}/`, { signal: controller.signal });
    clearTimeout(timeout);
    return res.ok || res.status === 404;
  } catch {
    return false;
  }
}

export async function getCases(params?: { limit?: number; status?: string }): Promise<{ total: number; cases: CaseRecord[] }> {
  const base = getApiBase();
  try {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.status && params.status !== 'ALL') query.set('status', params.status);
    const res = await fetch(`${base}/api/forensics/cases?${query.toString()}`);
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return {
    total: 1,
    cases: [
      {
        id: "8f3b2c1a-5e7d-4b9a-8c1e-9f3a2b1c0d5e",
        case_number: "CASE-2026-0891",
        title: "URGENT: Acquisition Escrow Account Update",
        threat_category: "Business Email Compromise (BEC)",
        severity: "CRITICAL",
        status: "INVESTIGATING",
        overall_risk_score: 94.5,
        sha256_evidence_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        assigned_analyst: "Lead SOC Investigator",
        notes: [
          {
            id: "note-1",
            text: "Initial triage completed. Tor exit node confirmed at Hop #2. Executive impersonation cues match FIN7 syndicate MO.",
            author: "Automated Evidence Engine",
            timestamp: new Date().toISOString()
          }
        ],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }
    ]
  };
}

// ==========================================
// ENTERPRISE IDENTITY & AUTHENTICATION STATE
// ==========================================

let _authToken: string | null = null;

export function setAuthToken(token: string | null) {
  _authToken = token;
  if (typeof window !== "undefined") {
    if (token) {
      try { localStorage.setItem("spectrashield_jwt", token); } catch {}
    } else {
      try { localStorage.removeItem("spectrashield_jwt"); } catch {}
    }
  }
}

export function getAuthToken(): string | null {
  if (!_authToken && typeof window !== "undefined") {
    try { _authToken = localStorage.getItem("spectrashield_jwt"); } catch {}
  }
  return _authToken;
}

export function getAuthHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...extraHeaders
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

export async function updateCaseStatus(caseId: string, status: string, actor: string = "SOC Analyst", reason: string = ""): Promise<any> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/cases/${encodeURIComponent(caseId)}/status`, {
      method: "PATCH",
      headers: getAuthHeaders(),
      body: JSON.stringify({ status, actor, reason })
    });
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return { status: "success", case_id: caseId, new_status: status };
}

export async function addCaseNote(caseId: string, text: string, author: string = "SOC Analyst"): Promise<any> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/cases/${encodeURIComponent(caseId)}/notes`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ text, author })
    });
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return { status: "success", case_id: caseId };
}

export async function assignCase(caseId: string, analyst: string, actor: string = "Security Admin"): Promise<any> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/cases/${encodeURIComponent(caseId)}/assign`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ analyst, actor })
    });
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return { status: "success", case_id: caseId, assigned_analyst: analyst };
}

export async function pollMailbox(limit: number = 10): Promise<any> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/mailbox/poll?limit=${limit}`, {
      method: "POST"
    });
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return {
    status: "success",
    polled_messages_count: 2,
    triaged_cases: [
      { case_id: "8f3b2c1a-5e7d-4b9a-8c1e-9f3a2b1c0d5e", verdict: "High Risk / Malicious", risk_score: 94.5 }
    ]
  };
}

export async function getMailboxStatus(): Promise<any> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/mailbox/status`);
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return {
    configured: false,
    protocol: "IMAP/TLS (Simulation Mode)",
    host: "abuse.enterprise-soc.internal",
    poller_active: true,
    last_poll: new Date().toISOString()
  };
}

export function exportCaseCsvUrl(caseId: string, defang: boolean = true): string {
  return `${getApiBase()}/api/forensics/export/${encodeURIComponent(caseId)}/csv?defang=${defang}`;
}

// ==========================================
// PHASE 6: ENTERPRISE IDENTITY & AUTH METHODS
// ==========================================

export async function loginUser(email: string, password: string): Promise<LoginResponse> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "Authentication failed");
    }
    if (data.access_token) {
      setAuthToken(data.access_token);
    }
    return data;
  } catch (err: any) {
    if (err.message && err.message !== "Failed to fetch") {
      throw err;
    }
    // Offline simulation fallback
    const role: EnterpriseRole = email.includes("admin") ? "SUPER_ADMIN" : "FORENSIC_ANALYST";
    const mockUser: UserProfile = {
      id: "usr-demo-local",
      email,
      name: email.split("@")[0].toUpperCase(),
      role,
      totp_enabled: false,
      is_demo_fallback: true
    };
    return {
      status: "SUCCESS",
      requires_2fa: false,
      access_token: "mock-jwt-token",
      refresh_token: "mock-refresh-token",
      user: mockUser,
      permissions: ["cases:read", "cases:write", "analysis:execute"]
    };
  }
}

export async function setup2FA(): Promise<Setup2FAResponse> {
  const base = getApiBase();
  const res = await fetch(`${base}/api/auth/2fa/setup`, {
    method: "POST",
    headers: getAuthHeaders()
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Failed to setup 2FA");
  }
  return await res.json();
}

export async function verify2FA(code: string, secret?: string, tempToken?: string): Promise<Verify2FAResponse> {
  const base = getApiBase();
  const res = await fetch(`${base}/api/auth/2fa/verify`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify({ code, secret, temp_token: tempToken })
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || "2FA verification failed");
  }
  if (data.access_token) {
    setAuthToken(data.access_token);
  }
  return data;
}

export async function disable2FA(code: string): Promise<any> {
  const base = getApiBase();
  const res = await fetch(`${base}/api/auth/2fa/disable`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify({ code })
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Failed to disable 2FA");
  }
  return await res.json();
}

export async function fetchCurrentUser(): Promise<{ user: UserProfile; permissions: string[]; is_demo_fallback?: boolean }> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/auth/me`, {
      method: "GET",
      headers: getAuthHeaders()
    });
    if (res.ok) return await res.json();
  } catch {
    // Offline fallback
  }
  return {
    user: {
      id: "usr-fallback",
      email: "analyst@spectrashield.soc",
      name: "Lead Forensic Investigator",
      role: "FORENSIC_ANALYST",
      totp_enabled: false,
      is_demo_fallback: true
    },
    permissions: ["cases:read", "cases:write", "cases:assign", "cases:status", "analysis:execute", "sandbox:execute", "reports:generate", "audit:read"],
    is_demo_fallback: true
  };
}

export async function simulateRole(role: EnterpriseRole): Promise<any> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/auth/simulate-role`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to simulate role");
    if (data.access_token) {
      setAuthToken(data.access_token);
    }
    return data;
  } catch (err: any) {
    if (err.message && err.message !== "Failed to fetch") throw err;
    // Offline simulation
    const mockUser: UserProfile = {
      id: `usr-sim-${role.toLowerCase()}`,
      email: `${role.toLowerCase()}@spectrashield.soc`,
      name: `${role.replace("_", " ")}`,
      role,
      totp_enabled: false,
      is_demo_fallback: true
    };
    return {
      status: "SUCCESS",
      simulated_role: role,
      access_token: "mock-sim-token",
      refresh_token: "mock-sim-refresh",
      user: mockUser,
      permissions: ["cases:read", "analysis:execute"]
    };
  }
}

export async function fetchEnterpriseUsers(): Promise<UserProfile[]> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/auth/users`, {
      headers: getAuthHeaders()
    });
    if (res.ok) {
      const data = await res.json();
      return data.users || [];
    }
  } catch {}
  return [];
}

export async function logoutUser(): Promise<void> {
  const base = getApiBase();
  try {
    await fetch(`${base}/api/auth/logout`, {
      method: "POST",
      headers: getAuthHeaders()
    });
  } catch {}
  setAuthToken(null);
}

// ==========================================
// PHASE 7: CTI, DKIM & TRANSFORMER INTELLIGENCE APIS
// ==========================================

export async function lookupCti(query: string): Promise<CtiReputationRecord[]> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/cti/lookup?query=${encodeURIComponent(query)}`, {
      headers: getAuthHeaders()
    });
    if (res.ok) {
      const data = await res.json();
      return data.records || [];
    }
  } catch {}
  return [
    {
      source: "AbuseIPDB",
      indicator: query,
      indicator_type: query.includes("http") ? "URL" : (query.includes(".") && !query.match(/[a-z]/i) ? "IP" : "DOMAIN"),
      is_malicious: query.includes("185.220") || query.includes("suspicious"),
      confidence_score: query.includes("185.220") ? 98 : 15,
      threat_category: "Known Tor Exit Node / Scanner",
      asn_isp: "Zwiebelfreunde e.V.",
      country: "DE",
      vpn_detected: query.includes("185.220"),
      vpn_provider: "Tor Exit Node Network"
    }
  ];
}

export async function fetchCampaignCommunities(): Promise<LouvainCommunitiesResponse> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/campaigns/communities`, {
      headers: getAuthHeaders()
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {}
  return {
    modularity: 0.742,
    syndicates_count: 2,
    communities: [
      {
        community_id: 0,
        syndicate_name: "SYNDICATE-FIN7-M365",
        node_count: 5,
        density: 0.85,
        dominant_threat_actor: "FIN7 / Carbanak",
        dominant_category: "Business Email Compromise (BEC)",
        nodes: ["micro-soft-billing.top", "185.220.101.5", "CASE-2026-0891", "CAMPAIGN-01", "CEO Fraud"]
      },
      {
        community_id: 1,
        syndicate_name: "SYNDICATE-STORM-0829",
        node_count: 4,
        density: 0.72,
        dominant_threat_actor: "Storm-0829",
        dominant_category: "Credential Harvesting",
        nodes: ["login-secure-auth.xyz", "194.26.29.112", "CASE-2026-0892", "Office365 Phish"]
      }
    ]
  };
}

export async function fetchVipRoster(): Promise<VipRosterEntry[]> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/vip-roster`, {
      headers: getAuthHeaders()
    });
    if (res.ok) {
      const data = await res.json();
      return data.roster || [];
    }
  } catch {}
  return [
    { name: "Satya Nadella", title: "Chief Executive Officer", authorized_domains: ["microsoft.com"], authorized_emails: ["satya@microsoft.com"] },
    { name: "Amy Hood", title: "Chief Financial Officer", authorized_domains: ["microsoft.com"], authorized_emails: ["amy.hood@microsoft.com"] },
    { name: "Sundar Pichai", title: "Chief Executive Officer", authorized_domains: ["google.com", "alphabet.com"], authorized_emails: ["sundar@google.com"] },
    { name: "Tim Cook", title: "Chief Executive Officer", authorized_domains: ["apple.com"], authorized_emails: ["tcook@apple.com"] }
  ];
}

export async function addVipRosterEntry(entry: VipRosterEntry): Promise<VipRosterEntry> {
  const base = getApiBase();
  const res = await fetch(`${base}/api/forensics/vip-roster`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders()
    },
    body: JSON.stringify(entry)
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Failed to add VIP roster entry");
  }
  return await res.json();
}




