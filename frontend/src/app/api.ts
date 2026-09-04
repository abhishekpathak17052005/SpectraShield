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
    "Sender envelope return-path mismatch with visible RFC 5322 From: address."
  ],
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

export async function updateCaseStatus(caseId: string, status: string, actor: string = "SOC Analyst", reason: string = ""): Promise<any> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/cases/${encodeURIComponent(caseId)}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
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
      headers: { "Content-Type": "application/json" },
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
      headers: { "Content-Type": "application/json" },
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

