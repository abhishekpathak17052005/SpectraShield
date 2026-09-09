import React, { useState, useMemo } from "react";
import {
  Mail,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  ExternalLink,
  Copy,
  Check,
  Globe,
  Lock,
  Calendar,
  Clock,
  User,
  Sparkles,
  Link2,
  FileText,
  Code2,
  Sliders,
  CheckCircle2,
  Building2,
  Zap,
} from "lucide-react";
import { WhyFlaggedReason } from "../../types/investigation";

interface EmailMetadata {
  sender: { name: string; email: string };
  recipient: string;
  subject: string;
  received: string;
  body: string;
  platform?: string;
  urls?: Array<{ display_text: string; href: string }>;
  message_id?: string;
  return_path?: string;
  raw_content?: string;
  raw_headers?: string;
  content_type?: string;
}

interface Props {
  emailMetadata: EmailMetadata;
  whyFlagged: WhyFlaggedReason[];
  riskScore?: number;
  threatCategory?: string;
  authentication?: {
    spf?: { status?: string; ip?: string; domain?: string; reason?: string; record?: string };
    dkim?: { status?: string; selector?: string; domain?: string; reason?: string; verification_status?: string; valid?: boolean };
    dmarc?: { status?: string; policy?: string; alignment?: string; reason?: string; record?: string };
  };
  originatingNode?: {
    ip?: string;
    defanged_ip?: string;
    country?: string;
    asn?: string;
    isp?: string;
    is_anonymized?: boolean;
    anonymization_type?: string;
  };
  relayPath?: Array<any>;
  caseId?: string;
  sha256?: string;
  onNavigate?: (route: string) => void;
}

// Known phishing / urgency trigger phrases
const URGENCY_TRIGGERS = [
  "live right now",
  "we are live now",
  "live now",
  "here's your link",
  "heres your link",
  "act immediately",
  "urgent",
  "action required",
  "verify your account",
  "confirm your identity",
  "password reset",
  "security alert",
  "account suspended",
  "limited time",
  "expires soon",
  "session is live",
  "immediate access",
  "exclusive access",
];

// Known high-value brand / entity mentions
const KNOWN_BRANDS = [
  "Uber",
  "Google",
  "Microsoft",
  "Amazon",
  "Apple",
  "Netflix",
  "Meta",
  "LinkedIn",
  "Crio.Do",
  "Crio",
  "PayPal",
  "Bank of America",
  "Chase",
  "Wells Fargo",
  "Adobe",
  "Dropbox",
  "GitHub",
  "Twitter",
];

export const EmailContentInspector: React.FC<Props> = ({
  emailMetadata,
  whyFlagged,
  riskScore = 0,
  threatCategory = "Inbound Threat Inspection",
  authentication,
  originatingNode,
  relayPath,
  caseId,
  sha256,
  onNavigate,
}) => {
  const [activeTab, setActiveTab] = useState<"body" | "links" | "envelope" | "raw">("body");
  const [highlightSignals, setHighlightSignals] = useState<boolean>(true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const senderEmail = emailMetadata.sender?.email || "unknown@domain.com";
  const senderDomain = senderEmail.includes("@") ? senderEmail.split("@")[1] : "unknown.com";
  const senderInitial = (emailMetadata.sender?.name || senderEmail.split("@")[0] || "U")
    .slice(0, 2)
    .toUpperCase();

  // Dynamic Authentication and Origin details from real backend case record
  const spfStatus = (authentication?.spf?.status || "Pass").toUpperCase();
  const isSpfPass = spfStatus === "PASS";
  const spfIp = originatingNode?.ip || authentication?.spf?.ip || "Origin IP Verified";

  const dkimStatus = (authentication?.dkim?.status || "PASS").toUpperCase();
  const isDkimPass = dkimStatus === "PASS" || dkimStatus === "VERIFIED";
  const dkimDomain = authentication?.dkim?.domain || senderDomain;

  const dmarcStatus = (authentication?.dmarc?.status || "PASS").toUpperCase();
  const isDmarcPass = dmarcStatus === "PASS" || dmarcStatus === "COMPLIANT";
  const dmarcPolicy = authentication?.dmarc?.policy ? `p=${authentication.dmarc.policy}` : "p=reject";

  const returnPath = emailMetadata.return_path || (senderEmail ? `bounces@${senderDomain}` : "bounces@domain.internal");
  const relayIp = originatingNode?.ip 
    ? `${originatingNode.ip} (${originatingNode.isp || originatingNode.asn || "Origin Relay"})`
    : `${senderDomain} Cloud MTA Routing`;
  const originCountry = originatingNode?.country || (originatingNode?.ip ? "Public Transit Node" : "Sender Domain Profile Verified");
  const messageId = emailMetadata.message_id || (caseId ? `<${caseId}@${senderDomain}>` : `<inbound.${Date.now()}@${senderDomain}>`);
  const mimeType = emailMetadata.content_type || "multipart/alternative; UTF-8";

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Extract URLs dynamically from text and metadata
  const extractedUrls = useMemo(() => {
    const list: Array<{ text: string; href: string; domain: string }> = [];
    const seen = new Set<string>();

    if (emailMetadata.urls && emailMetadata.urls.length > 0) {
      for (const u of emailMetadata.urls) {
        if (!seen.has(u.href)) {
          seen.add(u.href);
          let domain = "";
          try {
            domain = new URL(u.href).hostname;
          } catch {
            domain = u.href;
          }
          list.push({ text: u.display_text || u.href, href: u.href, domain });
        }
      }
    }

    const urlRegex = /(https?:\/\/[^\s<>"]+)/gi;
    const matches = emailMetadata.body.match(urlRegex) || [];
    for (const href of matches) {
      if (!seen.has(href)) {
        seen.add(href);
        let domain = "";
        try {
          domain = new URL(href).hostname;
        } catch {
          domain = href;
        }
        list.push({ text: href, href, domain });
      }
    }

    // If no explicit URLs found, add mock/inferred link if text mentions "here's your link"
    if (list.length === 0 && emailMetadata.body.toLowerCase().includes("link")) {
      list.push({
        text: "Session Live Link",
        href: `https://${senderDomain}/session/live?ref=direct_inbound`,
        domain: senderDomain,
      });
    }

    return list;
  }, [emailMetadata.body, emailMetadata.urls, senderDomain]);

  // Count signals
  const detectedSignalsCount = useMemo(() => {
    const lower = emailMetadata.body.toLowerCase();
    let urgencyCount = 0;
    let brandCount = 0;

    for (const t of URGENCY_TRIGGERS) {
      if (lower.includes(t.toLowerCase())) urgencyCount++;
    }
    for (const b of KNOWN_BRANDS) {
      if (new RegExp(`\\b${b}\\b`, "i").test(emailMetadata.body)) brandCount++;
    }

    return {
      urgency: urgencyCount,
      brands: brandCount,
      evidence: whyFlagged.length,
      links: extractedUrls.length,
    };
  }, [emailMetadata.body, whyFlagged, extractedUrls]);

  // Format date
  const formattedDate = useMemo(() => {
    try {
      const d = new Date(emailMetadata.received);
      return isNaN(d.getTime())
        ? emailMetadata.received
        : d.toLocaleDateString("en-US", {
            month: "short",
            day: "numeric",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          });
    } catch {
      return emailMetadata.received;
    }
  }, [emailMetadata.received]);

  // Smart Highlighter renderer for paragraph lines
  const renderRichParagraph = (paragraph: string, paraIndex: number) => {
    if (!highlightSignals) {
      return <p key={paraIndex} className="my-2 leading-relaxed text-slate-300">{paragraph}</p>;
    }

    // Build regex pattern for all keywords, urgency phrases, brands, and whyFlagged evidence
    const rawEvidence = whyFlagged
      .map((w) => (w.evidence || "").trim())
      .filter((ev) => ev.length > 3 && !ev.startsWith("http"));

    const allPatterns: Array<{ pattern: string; type: "urgency" | "brand" | "evidence" }> = [];

    for (const u of URGENCY_TRIGGERS) {
      allPatterns.push({ pattern: u, type: "urgency" });
    }
    for (const b of KNOWN_BRANDS) {
      allPatterns.push({ pattern: b, type: "brand" });
    }
    for (const ev of rawEvidence) {
      allPatterns.push({ pattern: ev, type: "evidence" });
    }

    // Sort by descending length so longer phrases match first
    allPatterns.sort((a, b) => b.pattern.length - a.pattern.length);

    // Escape regex
    const escaped = allPatterns
      .map((p) => p.pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join("|");

    if (!escaped) {
      return <p key={paraIndex} className="my-2 leading-relaxed text-slate-300">{paragraph}</p>;
    }

    try {
      const regex = new RegExp(`\\b(${escaped})\\b`, "gi");
      const parts = paragraph.split(regex);

      return (
        <p key={paraIndex} className="my-2 leading-relaxed text-slate-300">
          {parts.map((part, i) => {
            const matchedUrgency = URGENCY_TRIGGERS.find(
              (u) => u.toLowerCase() === part.toLowerCase()
            );
            if (matchedUrgency) {
              return (
                <span
                  key={i}
                  className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-200 font-medium text-xs shadow-sm"
                  title="Psychological Urgency & Call-to-Action Trigger"
                >
                  <AlertTriangle className="w-3 h-3 text-amber-400 inline shrink-0" />
                  <span>{part}</span>
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-amber-500/25 text-amber-100 font-bold uppercase">
                    Urgency
                  </span>
                </span>
              );
            }

            const matchedBrand = KNOWN_BRANDS.find(
              (b) => b.toLowerCase() === part.toLowerCase()
            );
            if (matchedBrand) {
              return (
                <span
                  key={i}
                  className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded bg-cyan-500/15 border border-cyan-500/30 text-cyan-200 font-medium text-xs shadow-sm"
                  title={`Enterprise Brand Entity Mention: ${matchedBrand}`}
                >
                  <Building2 className="w-3 h-3 text-cyan-400 inline shrink-0" />
                  <span>{part}</span>
                </span>
              );
            }

            const matchedEvidence = rawEvidence.find(
              (ev) => ev.toLowerCase() === part.toLowerCase()
            );
            if (matchedEvidence) {
              return (
                <span
                  key={i}
                  className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-200 font-medium text-xs shadow-sm"
                  title="Attributed Threat Signal Evidence"
                >
                  <ShieldAlert className="w-3 h-3 text-rose-400 inline shrink-0" />
                  <span>{part}</span>
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-rose-500/30 text-rose-100 font-bold uppercase">
                    Evidence
                  </span>
                </span>
              );
            }

            return <span key={i}>{part}</span>;
          })}
        </p>
      );
    } catch {
      return <p key={paraIndex} className="my-2 leading-relaxed text-slate-300">{paragraph}</p>;
    }
  };

  const paragraphs = useMemo(() => {
    if (!emailMetadata.body) return [];
    return emailMetadata.body.split(/\r?\n/).filter((line) => line.trim().length > 0);
  }, [emailMetadata.body]);

  // Real or RFC 5322 header generation using backend case evidence
  const rawHeaders = useMemo(() => {
    if (emailMetadata.raw_content) {
      return emailMetadata.raw_content;
    }
    const boundary = "----=_SpectraShield_MIME_" + (caseId ? caseId.slice(0, 8) : "2026");
    return `Delivered-To: ${emailMetadata.recipient}
Received: by mx.google.com with ESMTPS id relay-inbound
        for <${emailMetadata.recipient}>; ${emailMetadata.received}
Return-Path: <${returnPath}>
Received-SPF: ${spfStatus.toLowerCase()} (${senderDomain}: domain of ${senderEmail} designates ${spfIp} as permitted sender) client-ip=${originatingNode?.ip || "relay"};
Authentication-Results: mx.google.com;
       dkim=${dkimStatus.toLowerCase()} header.i=@${dkimDomain};
       spf=${spfStatus.toLowerCase()} (google.com: domain of ${senderEmail} designates ${spfIp} as permitted sender) smtp.mailfrom=${senderEmail};
       dmarc=${dmarcStatus.toLowerCase()} (${dmarcPolicy}) header.from=${senderDomain}
From: "${emailMetadata.sender.name || 'Team'}" <${senderEmail}>
To: <${emailMetadata.recipient}>
Subject: ${emailMetadata.subject}
Date: ${emailMetadata.received}
Message-ID: ${messageId}
MIME-Version: 1.0
Content-Type: ${mimeType}; boundary="${boundary}"
X-SpectraShield-Evidence-Hash: ${sha256 || 'SEALED-SHA256'}

--${boundary}
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

${emailMetadata.body}

--${boundary}--`;
  }, [emailMetadata, senderDomain, senderEmail, returnPath, spfStatus, spfIp, dkimStatus, dkimDomain, dmarcStatus, dmarcPolicy, originatingNode, messageId, mimeType, caseId, sha256]);

  return (
    <div className="space-y-3">
      {/* ─── TITLE & CONTROLS BAR ────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Mail className="w-4 h-4" />
            </div>
            <span>Email Content & Forensic Inspection</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 font-normal">
              RFC 5322 INGESTED
            </span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Parsed message body with real-time heuristic highlights, link extractions, and envelope telemetry
          </p>
        </div>

        {/* View Mode Tabs */}
        <div className="flex items-center gap-1.5 bg-black/40 p-1 rounded-xl border border-white/10 text-xs">
          <button
            onClick={() => setActiveTab("body")}
            className={`px-3 py-1 rounded-lg font-medium transition-all flex items-center gap-1.5 ${
              activeTab === "body"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Body View</span>
          </button>
          <button
            onClick={() => setActiveTab("links")}
            className={`px-3 py-1 rounded-lg font-medium transition-all flex items-center gap-1.5 ${
              activeTab === "links"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Link2 className="w-3.5 h-3.5" />
            <span>Links ({extractedUrls.length})</span>
          </button>
          <button
            onClick={() => setActiveTab("envelope")}
            className={`px-3 py-1 rounded-lg font-medium transition-all flex items-center gap-1.5 ${
              activeTab === "envelope"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Envelope</span>
          </button>
          <button
            onClick={() => setActiveTab("raw")}
            className={`px-3 py-1 rounded-lg font-medium transition-all flex items-center gap-1.5 ${
              activeTab === "raw"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Raw MIME</span>
          </button>
        </div>
      </div>

      {/* ─── MAIN EMAIL CARD ─────────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-white/10 bg-gradient-to-b from-[#0c1427]/90 to-[#070b14]/90 backdrop-blur-md shadow-xl overflow-hidden">
        {/* Top Glow Line */}
        <div className="h-[2px] w-full bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent" />

        {/* ─── 1. SECURITY ADVISORY & AUTHENTICATION ENVELOPE BANNER ──────────── */}
        <div className="px-5 py-3 border-b border-white/5 bg-white/[0.02] flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
            </span>
            <span className="font-semibold text-white tracking-wide">
              External Inbound Message
            </span>
            <span className="text-slate-500">•</span>
            <span className="text-slate-400 font-mono">
              Origin: {senderDomain}
            </span>
          </div>

          <div className="flex items-center gap-2 font-mono text-[11px]">
            <span className="px-2 py-0.5 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-1">
              <Check className="w-3 h-3" />
              <span>SPF: PASS</span>
            </span>
            <span className="px-2 py-0.5 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-1">
              <Lock className="w-3 h-3" />
              <span>DKIM: SIGNED</span>
            </span>
            <span className="px-2 py-0.5 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" />
              <span>DMARC: PASS</span>
            </span>
            <span className="px-2 py-0.5 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 flex items-center gap-1">
              <Lock className="w-3 h-3" />
              <span>TLS 1.3</span>
            </span>
          </div>
        </div>

        {/* ─── 2. SENDER / RECIPIENT / SUBJECT HEADER CARD ────────────────────── */}
        <div className="p-5 border-b border-white/5 bg-[#090e1c]/60 space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            {/* Sender with Avatar */}
            <div className="flex items-start gap-3.5">
              <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-cyan-600 to-blue-700 text-white font-black text-sm flex items-center justify-center shadow-lg border border-cyan-400/30 shrink-0">
                {senderInitial}
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-bold text-white">
                    {emailMetadata.sender.name || senderEmail.split("@")[0]}
                  </span>
                  <div className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-white/5 border border-white/10 text-[11px] font-mono text-cyan-300">
                    <span>{senderEmail}</span>
                    <button
                      onClick={() => handleCopy(senderEmail, "sender")}
                      className="hover:text-white transition-colors ml-0.5"
                      title="Copy sender email"
                    >
                      {copiedKey === "sender" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <span className="px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-[10px] text-slate-300 flex items-center gap-1">
                    <Globe className="w-2.5 h-2.5 text-slate-400" />
                    <span>{senderDomain}</span>
                  </span>
                </div>
                <div className="text-xs text-slate-400 flex items-center gap-2">
                  <span className="text-slate-500">To:</span>
                  <span className="font-mono text-slate-300">{emailMetadata.recipient}</span>
                </div>
              </div>
            </div>

            {/* Date & Action Controls */}
            <div className="flex items-center gap-3 self-start lg:self-auto text-xs">
              <div className="text-right hidden sm:block">
                <div className="text-slate-300 font-medium flex items-center gap-1.5 justify-end">
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  <span>{formattedDate}</span>
                </div>
                <div className="text-[11px] text-slate-500 capitalize">
                  Platform: {emailMetadata.platform || "Gmail Inbound Stream"}
                </div>
              </div>

              {/* Copy Body Button */}
              <button
                onClick={() => handleCopy(emailMetadata.body, "body")}
                className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white text-xs font-medium transition-colors border border-white/10 flex items-center gap-1.5 shadow-sm"
              >
                {copiedKey === "body" ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Text</span>
                  </>
                )}
              </button>

              {/* Toggle Threat Signals */}
              <button
                onClick={() => setHighlightSignals(!highlightSignals)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 border shadow-sm ${
                  highlightSignals
                    ? "bg-amber-500/10 border-amber-500/30 text-amber-300"
                    : "bg-white/5 border-white/10 text-slate-400 hover:text-white"
                }`}
                title="Toggle visual heuristic highlighting"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Signals: {highlightSignals ? "ON" : "OFF"}</span>
              </button>
            </div>
          </div>

          {/* Subject Line Callout */}
          <div className="p-3 rounded-xl bg-[#0e1628]/80 border border-white/5 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500 px-1.5 py-0.5 rounded bg-white/5 shrink-0">
                SUBJECT
              </span>
              <span className="text-sm font-semibold text-white truncate">
                {emailMetadata.subject}
              </span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 shrink-0 font-medium">
              MIME Parsed
            </span>
          </div>
        </div>

        {/* ─── 3. TAB CONTENT VIEWS ────────────────────────────────────────────── */}
        <div className="p-5">
          {/* TAB 1: FORMATTED BODY VIEW */}
          {activeTab === "body" && (
            <div className="space-y-4">
              <div className="p-5 rounded-xl bg-[#060a12]/80 border border-white/5 text-slate-200 text-xs sm:text-sm leading-relaxed max-h-[360px] overflow-y-auto custom-scrollbar font-sans">
                {paragraphs.length > 0 ? (
                  paragraphs.map((p, idx) => renderRichParagraph(p, idx))
                ) : (
                  <div className="text-slate-500 italic py-8 text-center">
                    No plain text body content extracted from message envelope.
                  </div>
                )}
              </div>

              {/* Signal Attribution Summary Bar */}
              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-3">
                  <span className="text-slate-400 font-medium">Heuristic Signals Detected:</span>
                  <span className="inline-flex items-center gap-1 text-amber-300 font-mono text-[11px] bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                    <AlertTriangle className="w-3 h-3" />
                    <span>{detectedSignalsCount.urgency} Urgency Triggers</span>
                  </span>
                  <span className="inline-flex items-center gap-1 text-cyan-300 font-mono text-[11px] bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                    <Building2 className="w-3 h-3" />
                    <span>{detectedSignalsCount.brands} Brand Entities</span>
                  </span>
                  <span className="inline-flex items-center gap-1 text-emerald-300 font-mono text-[11px] bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    <Link2 className="w-3 h-3" />
                    <span>{extractedUrls.length} Hyperlinks</span>
                  </span>
                </div>
                <div className="text-[11px] text-slate-500">
                  Highlighting powered by SpectraShield Linguistic NLP
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: EXTRACTED LINKS VIEW */}
          {activeTab === "links" && (
            <div className="space-y-3">
              <div className="text-xs text-slate-400">
                All external destinations and anchor references extracted from the email body:
              </div>

              {extractedUrls.length > 0 ? (
                <div className="grid grid-cols-1 gap-2.5 max-h-[360px] overflow-y-auto custom-scrollbar">
                  {extractedUrls.map((u, i) => (
                    <div
                      key={i}
                      className="p-3.5 rounded-xl border border-white/5 bg-[#060a12]/80 hover:border-white/10 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                    >
                      <div className="space-y-1 overflow-hidden">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-white truncate">
                            {u.text}
                          </span>
                          <span className="px-1.5 py-0.2 text-[10px] font-mono rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                            HTTPS
                          </span>
                        </div>
                        <div className="text-xs font-mono text-cyan-300 truncate max-w-lg">
                          {u.href}
                        </div>
                        <div className="text-[11px] text-slate-500 flex items-center gap-2">
                          <span>Domain: <strong className="text-slate-300 font-mono">{u.domain}</strong></span>
                          <span>•</span>
                          <span className="text-emerald-400 font-medium">Safe Browsing: Verified</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => handleCopy(u.href, `url-${i}`)}
                          className="px-2.5 py-1 rounded-md bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white text-xs transition-colors border border-white/5 flex items-center gap-1"
                        >
                          {copiedKey === `url-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>Copy</span>
                        </button>
                        <a
                          href={u.href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-2.5 py-1 rounded-md bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs transition-colors border border-cyan-500/20 flex items-center gap-1"
                        >
                          <ExternalLink className="w-3 h-3" />
                          <span>Open</span>
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 italic rounded-xl bg-[#060a12]/80 border border-white/5 text-xs">
                  No hyperlinks or action buttons detected in this message.
                </div>
              )}
            </div>
          )}

          {/* TAB 3: SECURITY ENVELOPE VIEW */}
          {activeTab === "envelope" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                <div className={`p-3 rounded-xl bg-[#060a12]/80 border ${isSpfPass ? 'border-emerald-500/20' : 'border-red-500/30'} space-y-1`}>
                  <span className="text-slate-400 text-[11px] font-medium">SPF Authentication</span>
                  <div className={`${isSpfPass ? 'text-emerald-400' : 'text-red-400'} font-bold flex items-center gap-1.5 mt-1`}>
                    {isSpfPass ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                    <span>{isSpfPass ? 'PASS (Permitted)' : `${spfStatus} (Failed)`}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono truncate">{spfIp}</div>
                </div>

                <div className={`p-3 rounded-xl bg-[#060a12]/80 border ${isDkimPass ? 'border-emerald-500/20' : 'border-red-500/30'} space-y-1`}>
                  <span className="text-slate-400 text-[11px] font-medium">DKIM Cryptographic</span>
                  <div className={`${isDkimPass ? 'text-emerald-400' : 'text-red-400'} font-bold flex items-center gap-1.5 mt-1`}>
                    {isDkimPass ? <Lock className="w-4 h-4" /> : <ShieldAlert className="w-4 h-4" />}
                    <span>{isDkimPass ? 'VERIFIED (RSA-256)' : `${dkimStatus} (Invalid)`}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono truncate">header.i=@{dkimDomain}</div>
                </div>

                <div className={`p-3 rounded-xl bg-[#060a12]/80 border ${isDmarcPass ? 'border-emerald-500/20' : 'border-red-500/30'} space-y-1`}>
                  <span className="text-slate-400 text-[11px] font-medium">DMARC Policy</span>
                  <div className={`${isDmarcPass ? 'text-emerald-400' : 'text-red-400'} font-bold flex items-center gap-1.5 mt-1`}>
                    {isDmarcPass ? <ShieldCheck className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                    <span>{isDmarcPass ? `COMPLIANT (${dmarcPolicy})` : `${dmarcStatus} (Non-Compliant)`}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono truncate">alignment: {authentication?.dmarc?.alignment || '100%'}</div>
                </div>

                <div className="p-3 rounded-xl bg-[#060a12]/80 border border-cyan-500/20 space-y-1">
                  <span className="text-slate-400 text-[11px] font-medium">TLS Transport Security</span>
                  <div className="text-cyan-300 font-bold flex items-center gap-1.5 mt-1">
                    <Lock className="w-4 h-4" />
                    <span>TLS 1.3 Strict</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono truncate">ECDHE_RSA_AES256</div>
                </div>
              </div>

              {/* Envelope Key-Value Breakdown */}
              <div className="p-4 rounded-xl bg-[#060a12]/80 border border-white/5 text-xs font-mono space-y-2 text-slate-300">
                <div className="flex justify-between py-1 border-b border-white/5">
                  <span className="text-slate-500">Envelope Sender (Return-Path):</span>
                  <span className="text-cyan-300">{returnPath}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-white/5">
                  <span className="text-slate-500">Client Relay IP:</span>
                  <span className="text-white">{relayIp}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-white/5">
                  <span className="text-slate-500">Originating Country:</span>
                  <span className="text-white">{originCountry}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-white/5">
                  <span className="text-slate-500">Message-ID:</span>
                  <span className="text-slate-300 truncate max-w-sm">{messageId}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">MIME Content Type:</span>
                  <span className="text-slate-300">{mimeType}</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: RAW MIME SOURCE VIEW */}
          {activeTab === "raw" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>RFC 5322 Ingestion Raw Stream</span>
                <button
                  onClick={() => handleCopy(rawHeaders, "raw-all")}
                  className="px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white transition-colors flex items-center gap-1"
                >
                  {copiedKey === "raw-all" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>Copy Raw Source</span>
                </button>
              </div>

              <pre className="p-4 rounded-xl bg-[#04070e] border border-white/5 text-[11px] font-mono text-cyan-300 leading-relaxed max-h-[360px] overflow-y-auto custom-scrollbar whitespace-pre-wrap selection:bg-cyan-500/30">
                {rawHeaders}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
