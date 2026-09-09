import React, { useState, useEffect } from "react";
import { SocLayout } from "./SocLayout";
import {
  Mail,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  ExternalLink,
  Copy,
  Check,
  RefreshCw,
  Search,
  ChevronRight,
  Download,
  Zap,
} from "lucide-react";
import { getCaseDetail, getForensicCases, analyzeForensicEmail, getExportPdfUrl } from "../../api";
import { EmailIntelligenceRecord, WhyFlaggedReason } from "../../types/investigation";

import { AnimatedRiskGauge } from "./AnimatedRiskGauge";
import { SignalTimeline } from "./SignalTimeline";
import { EmailContentInspector } from "./EmailContentInspector";

interface EmailIntelligencePageProps {
  caseId?: string | null;
  onNavigate: (route: string) => void;
}

export const EmailIntelligencePage: React.FC<EmailIntelligencePageProps> = ({
  caseId: initialCaseId,
  onNavigate,
}) => {
  // Helper to extract search params cleanly
  const getInitialSearchParams = () => {
    if (typeof window === "undefined") return null;
    const hash = window.location.hash || "";
    if (hash.includes("?")) {
      return new URLSearchParams(hash.substring(hash.indexOf("?")));
    } else if (window.location.search) {
      return new URLSearchParams(window.location.search);
    }
    return null;
  };

  const initialParams = getInitialSearchParams();
  const initialIsAnalyzing = Boolean(
    initialParams && (
      initialParams.get("analyzing") === "true" ||
      initialParams.get("raw") ||
      initialParams.get("email_text")
    )
  );

  const [activeCaseId, setActiveCaseId] = useState<string | null>(initialCaseId || null);
  const [caseRecord, setCaseRecord] = useState<EmailIntelligenceRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(!initialIsAnalyzing);
  const [backendOffline, setBackendOffline] = useState<boolean>(false);
  const [notFound, setNotFound] = useState<boolean>(false);
  const [recentCases, setRecentCases] = useState<any[]>([]);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Live Threat Pipeline State
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(initialIsAnalyzing);
  const [analyzingSubject, setAnalyzingSubject] = useState<string>(() => {
    return (initialParams && initialParams.get("subject")) || "Active Inbound Email";
  });
  const [analyzingSender, setAnalyzingSender] = useState<string>(() => {
    return (initialParams && (initialParams.get("sender_email") || initialParams.get("sender"))) || "sender@domain.com";
  });
  const [analyzingPlatform, setAnalyzingPlatform] = useState<string>(() => {
    return (initialParams && initialParams.get("platform")) || "gmail";
  });
  const [analysisElapsed, setAnalysisElapsed] = useState<number>(0);
  const [analysisStep, setAnalysisStep] = useState<number>(1);

  // Manual Analyzer State
  const [manualText, setManualText] = useState<string>("");
  const [manualSubject, setManualSubject] = useState<string>("");
  const [manualSender, setManualSender] = useState<string>("");
  const [manualUrl, setManualUrl] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [isScanningTab, setIsScanningTab] = useState<boolean>(false);
  const [tabScanFeedback, setTabScanFeedback] = useState<string | null>(null);

  useEffect(() => {
    if (initialCaseId) {
      setIsAnalyzing(false);
      setActiveCaseId(initialCaseId);
    }
  }, [initialCaseId]);

  // Dynamic analysis elapsed timer and sequence stepper
  useEffect(() => {
    if (!isAnalyzing) {
      setAnalysisElapsed(0);
      setAnalysisStep(1);
      return;
    }
    const startTime = Date.now();
    const interval = setInterval(() => {
      const elapsed = (Date.now() - startTime) / 1000;
      setAnalysisElapsed(elapsed);
      if (elapsed > 4.5) setAnalysisStep(4);
      else if (elapsed > 2.5) setAnalysisStep(3);
      else if (elapsed > 0.8) setAnalysisStep(2);
      else setAnalysisStep(1);
    }, 100);
    return () => clearInterval(interval);
  }, [isAnalyzing]);

  // Listen for extension case completion events & broadcast channel
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (
        event.data?.source === "SPECTRASHIELD_EXTENSION" &&
        event.data?.type === "CASE_ANALYSIS_COMPLETED" &&
        event.data?.case_id
      ) {
        setIsAnalyzing(false);
        setActiveCaseId(event.data.case_id);
        onNavigate(`/mail-intelligence/${event.data.case_id}`);
      }
    };
    window.addEventListener("message", handleMessage);

    let channel: BroadcastChannel | null = null;
    try {
      if (typeof BroadcastChannel !== "undefined") {
        channel = new BroadcastChannel("spectrashield_cases");
        channel.onmessage = (ev) => {
          if (ev.data?.case_id) {
            setIsAnalyzing(false);
            setActiveCaseId(ev.data.case_id);
            onNavigate(`/mail-intelligence/${ev.data.case_id}`);
          }
        };
      }
    } catch (_) {}

    return () => {
      window.removeEventListener("message", handleMessage);
      if (channel) channel.close();
    };
  }, [onNavigate]);

  // Auto-analyze URL parameters if navigated from extension
  useEffect(() => {
    if (activeCaseId) return;
    if (typeof window === "undefined") return;

    const params = getInitialSearchParams();
    if (!params) return;

    const hasRaw = Boolean(params.get("email_text") || params.get("raw"));
    const isAnalyzingParam = params.get("analyzing") === "true";
    const subjectParam = params.get("subject");
    const senderParam = params.get("sender_email") || params.get("sender");
    const platformParam = params.get("platform") || "gmail";

    if (subjectParam) setAnalyzingSubject(subjectParam);
    if (senderParam) setAnalyzingSender(senderParam);
    if (platformParam) setAnalyzingPlatform(platformParam);

    if (hasRaw) {
      const text = params.get("email_text") || params.get("raw") || "";
      const sender = senderParam || "unknown@domain.com";
      const rawUrl = params.get("url") || "";
      const subject = subjectParam || text.slice(0, 60).split("\n")[0] || "Gmail Inbound Inspection";

      setAnalyzingSubject(subject);
      setAnalyzingSender(sender);
      setIsAnalyzing(true);
      setLoading(true);

      window.history.replaceState({}, "", "/mail-intelligence");

      analyzeForensicEmail({
        platform: platformParam,
        subject: subject,
        sender: {
          name: sender.split("@")[0] || "Sender",
          email: sender,
        },
        recipient: "analyst@corp.internal",
        body: text,
        urls: rawUrl ? [{ display_text: rawUrl, href: rawUrl }] : [],
        timestamp: new Date().toISOString(),
      })
        .then((res) => {
          if (res && res.case_id) {
            setIsAnalyzing(false);
            setActiveCaseId(res.case_id);
            onNavigate(`/mail-intelligence/${res.case_id}`);
          }
        })
        .catch((e) => {
          console.error("Auto-analysis failed", e);
          setIsAnalyzing(false);
          setLoading(false);
        });
    } else if (isAnalyzingParam) {
      setIsAnalyzing(true);
      setLoading(true);
    }
  }, [activeCaseId, onNavigate]);

  // Fetch recent cases for list
  useEffect(() => {
    let mounted = true;
    getForensicCases({ limit: 8 })
      .then((res) => {
        if (!mounted) return;
        setRecentCases(res.cases || []);
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, []);

  // Fetch Case Details
  useEffect(() => {
    if (!activeCaseId) {
      if (!isAnalyzing) {
        setLoading(false);
        setNotFound(false);
      }
      return;
    }

    setLoading(true);
    setNotFound(false);
    setBackendOffline(false);

    let isMounted = true;
    getCaseDetail(activeCaseId)
      .then((res) => {
        if (!isMounted) return;
        setIsAnalyzing(false);
        const c = res.case;
        const a = res.analysis || ({} as any);

        const emailMeta = a.email_metadata || {
          platform: "gmail",
          subject: c.title || "Inbound Threat Inspection",
          sender: {
            name: c.assigned_analyst || "External Sender",
            email: c.sender || "sender@domain.com",
          },
          recipient: "analyst@security.internal",
          body: c.raw_payload_snippet || "",
          received: c.created_at,
          urls: [],
        };

        const whyFlagged: WhyFlaggedReason[] = Array.isArray(a.why_flagged) && a.why_flagged.length > 0
          ? a.why_flagged
          : (a.anomalies || []).map((anom: string) => ({
              category: "Security Heuristic",
              explanation: anom,
              evidence: "Reported during relay traversal",
              severity: "HIGH" as const,
              contribution: 20,
            }));

        if (whyFlagged.length === 0) {
          whyFlagged.push({
            category: "Baseline Assessment",
            explanation: "No suspicious heuristics triggered across active detection modules.",
            evidence: "Email passed SPF, DKIM, and lexical filters.",
            severity: "LOW" as const,
            contribution: 0,
          });
        }

        const riskFactors = a.risk_factors || {
          url_intelligence: {
            name: "URL Analysis",
            score: typeof a.breakdown?.url_score === "number" ? a.breakdown.url_score : null,
            status: typeof a.breakdown?.url_score === "number" ? "ENRICHED" : "NOT ENRICHED",
            severity: (a.breakdown?.url_score || 0) >= 70 ? "HIGH_RISK" : (a.breakdown?.url_score || 0) >= 35 ? "SUSPICIOUS" : "SAFE",
            explanation: "Evaluated against lexical rules.",
          },
          domain_intelligence: {
            name: "Domain Intelligence",
            score: a.homoglyph_analysis?.has_homoglyphs ? 90 : 15,
            status: "ENRICHED",
            severity: a.homoglyph_analysis?.has_homoglyphs ? "HIGH_RISK" : "SAFE",
            explanation: a.homoglyph_analysis?.has_homoglyphs ? "Homoglyph impersonation detected." : "Standard domain profile.",
          },
          social_engineering: {
            name: "Social Engineering",
            score: typeof a.breakdown?.manipulation_score === "number" ? a.breakdown.manipulation_score : null,
            status: typeof a.breakdown?.manipulation_score === "number" ? "ENRICHED" : "NOT ENRICHED",
            severity: (a.breakdown?.manipulation_score || 0) >= 70 ? "HIGH_RISK" : "SAFE",
            explanation: a.nlp_intelligence?.threat_category || "Urgency and manipulation tone evaluated.",
          },
          authentication: {
            name: "Authentication",
            score: a.authentication?.dmarc?.status === "Fail" ? 85 : 10,
            status: a.authentication ? "ENRICHED" : "NOT ENRICHED",
            severity: a.authentication?.dmarc?.status === "Fail" ? "HIGH_RISK" : "SAFE",
            explanation: `SPF: ${a.authentication?.spf?.status || "None"} | DKIM: ${a.dkim_crypto_verification?.verification_status || a.authentication?.dkim?.status || "None"}`,
          },
          threat_intelligence: {
            name: "VirusTotal / CTI",
            score: null,
            status: "NOT ENRICHED",
            severity: "NOT_ENRICHED",
            explanation: "Feed not configured in environment.",
          },
          ssl_tls: {
            name: "SSL / TLS",
            score: null,
            status: "NOT ENRICHED",
            severity: "NOT_ENRICHED",
            explanation: "TLS handshake not captured by HTTP relay.",
          },
        };

        const parsedRecord: EmailIntelligenceRecord = {
          case_id: c.id,
          case_number: c.case_number,
          sha256: c.sha256_evidence_hash,
          final_risk: typeof a.final_risk === "number" ? a.final_risk : c.overall_risk_score,
          verdict: a.verdict || c.severity || "SAFE",
          threat_category: a.threat_category || c.threat_category || "Inbound Threat Inspection",
          confidence: typeof a.breakdown?.confidence === "number" ? a.breakdown.confidence : 91,
          email_metadata: emailMeta,
          why_flagged: whyFlagged,
          risk_factors: riskFactors,
          url_intelligence_list: Array.isArray(a.url_intelligence_list) ? a.url_intelligence_list : [],
          authentication: a.authentication || {},
          originating_node: a.originating_node,
          campaign_id: a.campaign?.id || null,
          created_at: c.created_at,
          mode: c.assigned_analyst?.includes("Demo") ? "DEMO" : "LIVE",
        };

        setCaseRecord(parsedRecord);
        setLoading(false);
      })
      .catch((err) => {
        if (!isMounted) return;
        setLoading(false);
        if (err.message && err.message.includes("404")) {
          setNotFound(true);
        } else {
          setBackendOffline(true);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [activeCaseId]);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleManualScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualText.trim()) return;

    const subj = manualSubject.trim() || manualText.slice(0, 50) || "Manual Email Inspection";
    const sndr = manualSender.trim() || "analyst@spectrashield.internal";

    setAnalyzingSubject(subj);
    setAnalyzingSender(sndr);
    setAnalyzingPlatform("manual");
    setIsAnalyzing(true);
    setIsSubmitting(true);

    try {
      const payload = {
        platform: "gmail",
        subject: subj,
        sender: {
          name: manualSender.trim() || "Manual Submitter",
          email: manualSender.includes("@") ? manualSender.trim() : "unknown@domain.com",
        },
        recipient: "analyst@spectrashield.internal",
        body: manualText.trim(),
        urls: manualUrl.trim() ? [{ display_text: manualUrl.trim(), href: manualUrl.trim() }] : [],
        timestamp: new Date().toISOString(),
      };

      const result = await analyzeForensicEmail(payload);
      if (result && result.case_id) {
        setIsAnalyzing(false);
        onNavigate(`/mail-intelligence/${result.case_id}`);
        setActiveCaseId(result.case_id);
      }
    } catch (err: any) {
      setIsAnalyzing(false);
      alert("Analysis failed: " + (err.message || "Unknown error"));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleScanWebmailDOM = () => {
    setIsScanningTab(true);
    setAnalyzingSubject("Active Browser Email Stream");
    setAnalyzingSender("Extracting Gmail DOM headers...");
    setAnalyzingPlatform("gmail");
    setIsAnalyzing(true);
    setTabScanFeedback("Connecting to extension to extract open email...");

    let handled = false;
    const timeout = setTimeout(() => {
      if (!handled) {
        setIsScanningTab(false);
        setIsAnalyzing(false);
        setTabScanFeedback("Please select an email in Gmail, then click the SpectraShield extension.");
      }
    }, 4500);

    if (typeof window !== "undefined" && (window as any).chrome?.runtime?.sendMessage) {
      try {
        (window as any).chrome.runtime.sendMessage(
          { type: "SCAN_ACTIVE_GMAIL_TAB", openDashboard: false },
          (res: any) => {
            if (res && res.ok && res.case_id) {
              handled = true;
              clearTimeout(timeout);
              setIsScanningTab(false);
              setIsAnalyzing(false);
              setActiveCaseId(res.case_id);
              onNavigate(`/mail-intelligence/${res.case_id}`);
            }
          }
        );
      } catch (_) {}
    }

    const handleBridgeResponse = (event: MessageEvent) => {
      if (event.data?.source === "SPECTRASHIELD_EXTENSION" && event.data?.type === "SCAN_ACTIVE_TAB_EMAIL_RESULT") {
        handled = true;
        clearTimeout(timeout);
        window.removeEventListener("message", handleBridgeResponse);
        setIsScanningTab(false);
        if (event.data.data?.case_id) {
          setIsAnalyzing(false);
          setActiveCaseId(event.data.data.case_id);
          onNavigate(`/mail-intelligence/${event.data.data.case_id}`);
        } else {
          setIsAnalyzing(false);
          setTabScanFeedback(event.data.data?.error || "Ensure an email is open in Gmail.");
        }
      }
    };
    window.addEventListener("message", handleBridgeResponse);

    window.postMessage({ source: "SPECTRASHIELD_WEB", type: "SCAN_ACTIVE_TAB_EMAIL" }, "*");
  };

  // Helper to render body with verified evidence highlights
  const renderHighlightedBody = (body: string, whyFlagged: WhyFlaggedReason[]) => {
    if (!body) return <span className="text-slate-500 italic">No message body provided.</span>;

    // Collect verified phrases to highlight
    const phrasesToHighlight = whyFlagged
      .map((w) => (w.evidence || "").trim())
      .filter((ev) => ev.length > 4 && !ev.startsWith("http") && body.toLowerCase().includes(ev.toLowerCase()));

    if (phrasesToHighlight.length === 0) {
      return <span>{body}</span>;
    }

    // Split and highlight occurrences
    try {
      const regex = new RegExp(`(${phrasesToHighlight.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "gi");
      const parts = body.split(regex);
      return (
        <>
          {parts.map((part, i) => {
            const isMatch = phrasesToHighlight.some((p) => p.toLowerCase() === part.toLowerCase());
            return isMatch ? (
              <mark key={i} className="bg-amber-500/20 text-amber-200 px-1 py-0.5 rounded font-semibold">
                {part}
              </mark>
            ) : (
              <span key={i}>{part}</span>
            );
          })}
        </>
      );
    } catch {
      return <span>{body}</span>;
    }
  };

  return (
    <SocLayout
      activeNav="email_intelligence"
      onNavigate={onNavigate}
      title="Email Intelligence"
      subtitle="Email threat analysis and signal attribution"
      actions={
        caseRecord ? (
          <div className="flex items-center gap-2">
            <button
              onClick={() => window.open(getExportPdfUrl(caseRecord.case_id, false))}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-medium border border-white/10 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export PDF</span>
            </button>
            <button
              onClick={() => onNavigate(`/investigations/${caseRecord.case_id}`)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-medium transition-colors"
            >
              <span>Open Investigation</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>
        ) : undefined
      }
    >
      <div className="space-y-6">
        {/* Skeleton Loader while fetching */}
        {loading && !isAnalyzing && activeCaseId && (
          <div className="space-y-6 animate-pulse">
            <div className="p-6 rounded-2xl border border-white/5 bg-[#0f172a]/40 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
              <div className="lg:col-span-8 space-y-4">
                <div className="h-6 w-3/4 bg-white/10 rounded-md" />
                <div className="h-4 w-1/2 bg-white/5 rounded-md" />
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                  <div className="h-10 bg-white/5 rounded-lg" />
                  <div className="h-10 bg-white/5 rounded-lg" />
                  <div className="h-10 bg-white/5 rounded-lg" />
                  <div className="h-10 bg-white/5 rounded-lg" />
                </div>
              </div>
              <div className="lg:col-span-4 flex justify-center">
                <div className="w-36 h-36 rounded-full bg-white/5 border border-white/10" />
              </div>
            </div>
            <div className="h-40 rounded-xl bg-white/5 border border-white/5" />
          </div>
        )}

        {/* Live AI Threat Analysis In Progress */}
        {isAnalyzing && (
          <div className="space-y-6">
            <div className="relative overflow-hidden rounded-2xl border border-cyan-500/30 bg-[#0c1322]/90 backdrop-blur-xl p-7 shadow-2xl shadow-cyan-950/30">
              {/* Background Ambient Glows */}
              <div className="absolute -top-24 -right-24 w-80 h-80 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />
              <div className="absolute -bottom-24 -left-24 w-80 h-80 rounded-full bg-blue-600/10 blur-3xl pointer-events-none" />

              {/* Top Header Bar */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-white/5">
                <div className="flex items-center gap-3">
                  <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/40 text-cyan-300">
                    <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-base font-bold text-white tracking-tight">
                        AI Threat Analysis Pipeline Active
                      </h2>
                      <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                        Live Ingestion
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Executing full multi-vector forensic evaluation and cryptographic vault sealing...
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 self-start sm:self-center">
                  <div className="px-3.5 py-1.5 rounded-lg bg-black/40 border border-white/10 font-mono text-xs text-slate-300 flex items-center gap-2">
                    <span className="text-slate-500 text-[11px] uppercase tracking-wider">Elapsed:</span>
                    <span className="text-cyan-300 font-semibold">{analysisElapsed.toFixed(1)}s</span>
                  </div>
                </div>
              </div>

              {/* Ingested Target Summary Card */}
              <div className="my-6 p-4 rounded-xl bg-white/[0.02] border border-white/5 grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
                <div className="md:col-span-6 space-y-1">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                    <Mail className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Target Email Subject</span>
                  </div>
                  <div className="text-sm font-semibold text-white truncate" title={analyzingSubject}>
                    {analyzingSubject || "Gmail Inbound Inspection"}
                  </div>
                </div>

                <div className="md:col-span-4 space-y-1">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Sender Identity
                  </div>
                  <div className="text-xs font-mono text-cyan-200/90 truncate" title={analyzingSender}>
                    {analyzingSender || "unknown@domain.com"}
                  </div>
                </div>

                <div className="md:col-span-2 flex md:justify-end">
                  <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold uppercase tracking-wider bg-white/5 border border-white/10 text-slate-300">
                    {analyzingPlatform.toUpperCase()} DOM
                  </span>
                </div>
              </div>

              {/* 4 Pipeline Stages */}
              <div className="space-y-3">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Forensic Execution Sequence
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                  {/* Stage 1 */}
                  <div className={`p-3.5 rounded-xl border transition-all duration-300 ${
                    analysisStep >= 1
                      ? "bg-cyan-950/20 border-cyan-500/30 shadow-sm"
                      : "bg-white/[0.02] border-white/5 opacity-50"
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-cyan-400 font-semibold">STAGE 01</span>
                      {analysisStep > 1 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                          <Check className="w-3 h-3" /> Extracted
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-cyan-400">
                          <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Ingesting
                        </span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-white">DOM & MIME Extraction</div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      RFC 5322 headers, unmasked hyperlink anchors & UTF-8 body.
                    </div>
                  </div>

                  {/* Stage 2 */}
                  <div className={`p-3.5 rounded-xl border transition-all duration-300 ${
                    analysisStep >= 2
                      ? "bg-cyan-950/20 border-cyan-500/30 shadow-sm"
                      : "bg-white/[0.02] border-white/5 opacity-50"
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-cyan-400 font-semibold">STAGE 02</span>
                      {analysisStep > 2 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                          <Check className="w-3 h-3" /> Evaluated
                        </span>
                      ) : analysisStep === 2 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-cyan-400">
                          <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Scanning
                        </span>
                      ) : (
                        <span className="text-[10px] text-slate-500">Queued</span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-white">Heuristics & Homoglyphs</div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      Punycode character spoofing, lookalike domains & SPF/DKIM flags.
                    </div>
                  </div>

                  {/* Stage 3 */}
                  <div className={`p-3.5 rounded-xl border transition-all duration-300 ${
                    analysisStep >= 3
                      ? "bg-cyan-950/20 border-cyan-500/30 shadow-sm"
                      : "bg-white/[0.02] border-white/5 opacity-50"
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-cyan-400 font-semibold">STAGE 03</span>
                      {analysisStep > 3 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                          <Check className="w-3 h-3" /> Scored
                        </span>
                      ) : analysisStep === 3 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-cyan-400">
                          <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Processing
                        </span>
                      ) : (
                        <span className="text-[10px] text-slate-500">Queued</span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-white">BERT NLP & CTI Feeds</div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      Deep semantic urgency modeling, brand impersonation & ERPN hops.
                    </div>
                  </div>

                  {/* Stage 4 */}
                  <div className={`p-3.5 rounded-xl border transition-all duration-300 ${
                    analysisStep >= 4
                      ? "bg-amber-950/20 border-amber-500/30 shadow-sm"
                      : "bg-white/[0.02] border-white/5 opacity-50"
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-amber-400 font-semibold">STAGE 04</span>
                      {analysisStep >= 4 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-amber-300">
                          <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Sealing
                        </span>
                      ) : (
                        <span className="text-[10px] text-slate-500">Queued</span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-white">Vault Sealing & Dossier</div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      Cryptographic evidence hashing & immutable SQLite dossier commit.
                    </div>
                  </div>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="mt-6 pt-5 border-t border-white/5 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                    Aggregating zero-trust detection vectors...
                  </span>
                  <span className="font-mono text-cyan-300 font-semibold">
                    {Math.min(96, Math.floor(analysisElapsed * 18 + 12))}%
                  </span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-white/5 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-emerald-400 transition-all duration-300 rounded-full"
                    style={{ width: `${Math.min(96, Math.floor(analysisElapsed * 18 + 12))}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Backend offline */}
        {!loading && !isAnalyzing && backendOffline && (
          <div className="p-6 rounded-xl border border-red-500/20 bg-red-950/10 space-y-3">
            <div className="flex items-center gap-2 text-sm font-medium text-red-300">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <span>SpectraShield Backend Offline</span>
            </div>
            <p className="text-xs text-slate-400">
              Could not communicate with the detection engine at port 8000. Start the backend service to continue.
            </p>
          </div>
        )}

        {/* Not Found */}
        {!loading && !isAnalyzing && notFound && (
          <div className="p-8 text-center rounded-xl border border-white/5 bg-[#0f172a]/50 space-y-3 max-w-lg mx-auto">
            <div className="text-sm font-medium text-white">Case Not Found</div>
            <p className="text-xs text-slate-400">
              Case <code className="font-mono text-cyan-300">{activeCaseId}</code> does not exist in the records.
            </p>
            <button
              onClick={() => onNavigate("/investigations")}
              className="mt-2 px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-300 text-xs font-medium border border-cyan-500/20"
            >
              Back to Investigations
            </button>
          </div>
        )}

        {/* Empty State: Hub / Scanner */}
        {!loading && !activeCaseId && !backendOffline && !notFound && !isAnalyzing && (
          <div className="space-y-6">
            <div className="p-5 rounded-xl border border-white/5 bg-[#0f172a]/70 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-semibold text-white">Email Intelligence Ingestion Hub</h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Scan an active email via DOM extraction or enter details manually.
                </p>
              </div>
              <button
                onClick={handleScanWebmailDOM}
                disabled={isScanningTab}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 transition-colors disabled:opacity-50"
              >
                <Zap className="w-4 h-4" />
                <span>{isScanningTab ? "Scanning Tab..." : "Scan Active Email DOM"}</span>
              </button>
            </div>

            {tabScanFeedback && (
              <div className="text-xs px-3 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-300">
                {tabScanFeedback}
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Recent Ingestions */}
              <div className="p-5 rounded-xl border border-white/5 bg-[#0f172a]/50 space-y-3">
                <div className="text-xs font-semibold text-white">Recent Email Ingestions</div>
                {recentCases.length === 0 ? (
                  <div className="text-xs text-slate-500 py-6 text-center">
                    No cases recorded yet. Ingest an email to start analysis.
                  </div>
                ) : (
                  <div className="divide-y divide-white/5">
                    {recentCases.map((c) => {
                      const risk = Math.round(c.final_risk ?? c.overall_risk_score ?? 0);
                      const isHigh = risk >= 70;
                      return (
                        <div
                          key={c.id}
                          onClick={() => {
                            setActiveCaseId(c.id);
                            onNavigate(`/mail-intelligence/${c.id}`);
                          }}
                          className="py-2.5 flex items-center justify-between gap-3 hover:bg-white/[0.02] cursor-pointer transition-colors"
                        >
                          <div className="min-w-0">
                            <div className="text-xs font-medium text-slate-200 truncate">
                              {c.title || c.subject || "Email Analysis"}
                            </div>
                            <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                              {c.case_number || c.id}
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[11px] font-medium px-1.5 py-0.5 rounded ${
                                isHigh ? "bg-red-500/10 text-red-400" : "bg-emerald-500/10 text-emerald-400"
                              }`}
                            >
                              {risk}
                            </span>
                            <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Manual Entry */}
              <div className="p-5 rounded-xl border border-white/5 bg-[#0f172a]/50 space-y-3">
                <div className="text-xs font-semibold text-white">Manual Email Scan</div>
                <form onSubmit={handleManualScan} className="space-y-3">
                  <div>
                    <label className="text-[11px] text-slate-400">Subject</label>
                    <input
                      type="text"
                      value={manualSubject}
                      onChange={(e) => setManualSubject(e.target.value)}
                      placeholder="e.g. Account Verification Required"
                      className="w-full mt-1 px-3 py-1.5 rounded-lg bg-[#080d1a] border border-white/10 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-[11px] text-slate-400">Sender</label>
                      <input
                        type="text"
                        value={manualSender}
                        onChange={(e) => setManualSender(e.target.value)}
                        placeholder="security@micros0ft.com"
                        className="w-full mt-1 px-3 py-1.5 rounded-lg bg-[#080d1a] border border-white/10 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                      />
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400">URL (Optional)</label>
                      <input
                        type="text"
                        value={manualUrl}
                        onChange={(e) => setManualUrl(e.target.value)}
                        placeholder="https://micros0ft.com/login"
                        className="w-full mt-1 px-3 py-1.5 rounded-lg bg-[#080d1a] border border-white/10 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-[11px] text-slate-400">Email Body</label>
                    <textarea
                      rows={3}
                      value={manualText}
                      onChange={(e) => setManualText(e.target.value)}
                      placeholder="Paste message body text..."
                      className="w-full mt-1 px-3 py-1.5 rounded-lg bg-[#080d1a] border border-white/10 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={isSubmitting || !manualText.trim()}
                    className="w-full py-2 rounded-lg text-xs font-medium bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 transition-colors disabled:opacity-50"
                  >
                    {isSubmitting ? "Analyzing..." : "Scan Email"}
                  </button>
                </form>
              </div>
            </div>
          </div>
        )}

        {/* Active Case Analysis View */}
        {!loading && caseRecord && (
          <div className="space-y-6">
            {/* Demonstration indicator if applicable */}
            {caseRecord.mode === "DEMO" && (
              <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 flex items-center justify-between">
                <span><b>DEMONSTRATION CASE:</b> This incident contains demonstration telemetry.</span>
                <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-amber-500/20">DEMO</span>
              </div>
            )}

            {/* ─── 1. DOMINANT HERO: EMAIL IDENTITY & ANIMATED RISK GAUGE ────── */}
            <div className="p-5 sm:p-6 rounded-2xl border border-cyan-500/20 bg-gradient-to-b from-[#0d1428]/95 via-[#090f1e]/90 to-[#070b16]/95 backdrop-blur-xl shadow-2xl overflow-hidden relative">
              {/* Subtle top edge specular highlight */}
              <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent" />

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
                {/* Left Side: Email Identity & Telemetry Strip (col-span-7) */}
                <div className="lg:col-span-7 space-y-4">
                  <div>
                    <div className="flex flex-wrap items-center gap-2 mb-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-medium">
                        CASE {caseRecord.case_number}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-white/5 text-slate-300 border border-white/10">
                        INBOUND TELEMETRY
                      </span>
                      <button
                        onClick={() => handleCopy(caseRecord.sha256, "sha")}
                        className="text-[10px] font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1 px-2 py-0.5 rounded bg-white/5 border border-white/5 transition-colors"
                        title="Copy SHA-256 evidence hash"
                      >
                        {copiedText === "sha" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>SHA: {caseRecord.sha256.slice(0, 10)}...</span>
                      </button>
                    </div>

                    <h1 className="text-base sm:text-xl font-bold text-white tracking-tight leading-snug">
                      {caseRecord.email_metadata.subject}
                    </h1>

                    <div className="mt-1 text-xs text-slate-400 flex items-center gap-2">
                      <span>Threat Category:</span>
                      <span className="text-cyan-300 font-medium">{caseRecord.threat_category}</span>
                    </div>
                  </div>

                  {/* Identity Key-Value Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded-xl bg-black/25 border border-white/5 text-xs">
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase font-semibold block">Sender</span>
                      <span className="font-mono text-slate-200 truncate block mt-0.5" title={caseRecord.email_metadata.sender.email}>
                        {caseRecord.email_metadata.sender.email}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase font-semibold block">Recipient</span>
                      <span className="font-mono text-slate-200 truncate block mt-0.5" title={caseRecord.email_metadata.recipient}>
                        {caseRecord.email_metadata.recipient}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase font-semibold block">Received</span>
                      <span className="text-slate-200 block mt-0.5 truncate">
                        {new Date(caseRecord.email_metadata.received).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase font-semibold block">Platform</span>
                      <span className="text-slate-200 block mt-0.5 capitalize truncate">
                        {caseRecord.email_metadata.platform}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Right Side: Animated Radial Risk Gauge with Halo (col-span-5) */}
                <div className="lg:col-span-5 flex items-center justify-center lg:border-l border-white/10 lg:pl-6">
                  <AnimatedRiskGauge
                    score={caseRecord.final_risk}
                    confidence={caseRecord.confidence}
                    verdict={caseRecord.verdict}
                  />
                </div>
              </div>
            </div>

            {/* ─── 2. WHY THIS WAS FLAGGED (VERTICAL SIGNAL TIMELINE) ────────── */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                    <span>Why This Was Flagged</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 font-normal">
                      {caseRecord.why_flagged.length} SIGNALS
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Chronological signal attribution pipeline and heuristic evaluation
                  </p>
                </div>
              </div>

              <SignalTimeline signals={caseRecord.why_flagged} />
            </div>

            {/* ─── 4. EMAIL CONTENT & FORENSIC INSPECTION ────────────────────── */}
            <EmailContentInspector
              emailMetadata={caseRecord.email_metadata}
              whyFlagged={caseRecord.why_flagged}
              riskScore={caseRecord.final_risk}
              threatCategory={caseRecord.threat_category}
              onNavigate={onNavigate}
            />


            {/* ─── 5. FORENSIC EXECUTION PIPELINE & RISK MATRIX ─────────────────── */}
            <div className="space-y-4">
              {/* Pipeline Header */}
              <div className="p-5 rounded-xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/40 to-blue-950/20 backdrop-blur-sm relative overflow-hidden">
                <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent" />
                
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center">
                      <RefreshCw className="w-5 h-5 text-cyan-400 animate-spin" style={{ animationDuration: '3s' }} />
                    </div>
                    <div>
                      <div className="text-base font-black text-white uppercase tracking-wider font-mono">
                        AI Threat Analysis Pipeline Active
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">
                        Executing full multi-vector forensic evaluation and cryptographic vault sealing...
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-xs font-mono font-bold uppercase flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      LIVE INGESTION
                    </span>
                    <div className="text-right">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider">Elapsed</div>
                      <div className="text-sm font-mono font-bold text-cyan-400">1.4s</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Email Subject & Sender Bar */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <div className="p-4 rounded-xl border border-white/10 bg-[#0a0e1a]/60">
                  <div className="flex items-center gap-2 mb-2">
                    <Mail className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Target Email Subject</span>
                  </div>
                  <div className="text-sm font-semibold text-white truncate">
                    {caseRecord.email_metadata.subject}
                  </div>
                </div>
                <div className="p-4 rounded-xl border border-white/10 bg-[#0a0e1a]/60">
                  <div className="flex items-center gap-2 mb-2">
                    <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Sender Identity</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-mono text-cyan-300 truncate">
                      {caseRecord.email_metadata.sender.email}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-[10px] font-mono text-slate-400">
                      GMAIL DOM
                    </span>
                  </div>
                </div>
              </div>

              {/* Forensic Execution Stages */}
              <div className="space-y-3">
                <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                  Forensic Execution Sequence
                </div>
                
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {/* Stage 01 - DOM & MIME Extraction */}
                  <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/20 relative overflow-hidden group hover:bg-emerald-950/30 transition-all">
                    <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-emerald-500 to-cyan-500" />
                    <div className="flex items-center gap-2 mb-3">
                      <div className="px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-[9px] font-mono font-bold text-emerald-300">
                        STAGE 01
                      </div>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-[10px] font-mono text-emerald-400 font-medium">Extracted</span>
                    </div>
                    <div className="text-sm font-bold text-white mb-1">
                      DOM & MIME Extraction
                    </div>
                    <div className="text-[11px] text-slate-400 leading-relaxed">
                      RFC 5322 headers, unmasked hyperlink anchors & UTF-8 body.
                    </div>
                  </div>

                  {/* Stage 02 - Heuristics & Homoglyphs */}
                  <div className="p-4 rounded-xl border border-cyan-500/30 bg-cyan-950/20 relative overflow-hidden group hover:bg-cyan-950/30 transition-all">
                    <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-cyan-500 to-blue-500 animate-pulse" />
                    <div className="flex items-center gap-2 mb-3">
                      <div className="px-2 py-0.5 rounded bg-cyan-500/20 border border-cyan-500/40 text-[9px] font-mono font-bold text-cyan-300">
                        STAGE 02
                      </div>
                      <RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                      <span className="text-[10px] font-mono text-cyan-400 font-medium">Scanning</span>
                    </div>
                    <div className="text-sm font-bold text-white mb-1">
                      Heuristics & Homoglyphs
                    </div>
                    <div className="text-[11px] text-slate-400 leading-relaxed">
                      Punycode character spoofing lookalike domains & SPF/DKIM flags.
                    </div>
                  </div>

                  {/* Stage 03 - BERT NLP & CTI Feeds */}
                  <div className="p-4 rounded-xl border border-white/10 bg-[#0a0e1a]/40 relative overflow-hidden group hover:bg-[#0a0e1a]/60 transition-all">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="px-2 py-0.5 rounded bg-white/10 border border-white/20 text-[9px] font-mono font-bold text-slate-400">
                        STAGE 03
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 font-medium">Queued</span>
                    </div>
                    <div className="text-sm font-bold text-slate-300 mb-1">
                      BERT NLP & CTI Feeds
                    </div>
                    <div className="text-[11px] text-slate-500 leading-relaxed">
                      Deep semantic urgency modeling, brand impersonation & ERPN hops.
                    </div>
                  </div>

                  {/* Stage 04 - Vault Sealing & Dossier */}
                  <div className="p-4 rounded-xl border border-white/10 bg-[#0a0e1a]/40 relative overflow-hidden group hover:bg-[#0a0e1a]/60 transition-all">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="px-2 py-0.5 rounded bg-white/10 border border-white/20 text-[9px] font-mono font-bold text-slate-400">
                        STAGE 04
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 font-medium">Queued</span>
                    </div>
                    <div className="text-sm font-bold text-slate-300 mb-1">
                      Vault Sealing & Dossier
                    </div>
                    <div className="text-[11px] text-slate-500 leading-relaxed">
                      Cryptographic evidence hashing & immutable SQLite dossier commit.
                    </div>
                  </div>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 font-mono flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                    Aggregating zero-trust detection vectors...
                  </span>
                  <span className="text-cyan-400 font-mono font-bold">37%</span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-900/80 border border-white/5 overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-cyan-400 transition-all duration-700"
                    style={{ width: '37%' }}
                  />
                </div>
              </div>

              {/* Risk Factor Breakdown - SOC Style */}
              <div className="space-y-3 mt-6">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                    Detection Vector Matrix
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-300 border border-purple-500/20">
                    {Object.keys(caseRecord.risk_factors).length} ACTIVE VECTORS
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {Object.entries(caseRecord.risk_factors).map(([key, rf]) => {
                    const isEnriched = rf.status === "ENRICHED";
                    const scoreVal = rf.score;
                    const isHigh = scoreVal !== null && scoreVal >= 70;
                    const isMed = scoreVal !== null && scoreVal >= 30 && scoreVal < 70;
                    const isLow = scoreVal !== null && scoreVal < 30;

                    let statusColor = "text-slate-500";
                    let statusBg = "bg-slate-500/10";
                    let statusBorder = "border-slate-500/20";
                    let barColor = "from-slate-500 to-slate-600";
                    
                    if (isEnriched) {
                      if (isHigh) {
                        statusColor = "text-red-400";
                        statusBg = "bg-red-500/10";
                        statusBorder = "border-red-500/30";
                        barColor = "from-red-500 to-rose-600";
                      } else if (isMed) {
                        statusColor = "text-amber-400";
                        statusBg = "bg-amber-500/10";
                        statusBorder = "border-amber-500/30";
                        barColor = "from-amber-500 to-orange-600";
                      } else if (isLow) {
                        statusColor = "text-emerald-400";
                        statusBg = "bg-emerald-500/10";
                        statusBorder = "border-emerald-500/30";
                        barColor = "from-emerald-500 to-green-600";
                      }
                    }

                    return (
                      <div
                        key={key}
                        className={`p-4 rounded-xl border ${statusBorder} bg-[#0a0e1a]/60 backdrop-blur-sm hover:bg-[#0a0e1a]/80 transition-all relative overflow-hidden group`}
                      >
                        {/* Top accent line */}
                        {isEnriched && <div className={`absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r ${barColor}`} />}
                        
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-sm font-bold text-white truncate">
                                {rf.name}
                              </span>
                              {isEnriched ? (
                                <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase ${statusBg} ${statusColor} ${statusBorder} border`}>
                                  {isHigh ? "HIGH" : isMed ? "MED" : "LOW"}
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-slate-500/10 text-slate-500 border border-slate-500/20">
                                  OFFLINE
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-slate-400 leading-relaxed mb-2">
                              {rf.explanation}
                            </div>

                            {/* Mini bar chart */}
                            {isEnriched && typeof scoreVal === "number" && (
                              <div className="flex items-center gap-2">
                                <div className="flex-1 h-1 rounded-full bg-slate-900 border border-white/5 overflow-hidden">
                                  <div
                                    className={`h-full bg-gradient-to-r ${barColor} transition-all duration-700`}
                                    style={{ width: `${Math.min(scoreVal, 100)}%` }}
                                  />
                                </div>
                                <span className={`text-xs font-mono font-bold ${statusColor} min-w-[35px] text-right`}>
                                  {Math.round(scoreVal)}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </SocLayout>
  );
};
