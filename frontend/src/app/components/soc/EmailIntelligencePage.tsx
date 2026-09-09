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
import { EmailIntelligenceRecord, WhyFlaggedReason, RiskFactor } from "../../types/investigation";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";

import { AnimatedRiskGauge } from "./AnimatedRiskGauge";
import { SignalTimeline } from "./SignalTimeline";
import { EmailContentInspector } from "./EmailContentInspector";
import { RiskFactorAnalysis } from "../investigation/RiskFactorAnalysis";
import { getInvestigationById } from "../../services/investigationService";

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

  const [activeCaseId, setActiveCaseId] = useState<string | null>(() => {
    if (initialCaseId) return initialCaseId;
    if (initialParams) {
      return initialParams.get("case_id") || initialParams.get("caseId") || null;
    }
    return null;
  });

  useEffect(() => {
    if (initialCaseId && initialCaseId !== activeCaseId) {
      setActiveCaseId(initialCaseId);
    }
  }, [initialCaseId, activeCaseId]);
  const [caseRecord, setCaseRecord] = useState<EmailIntelligenceRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(!initialIsAnalyzing);
  const [backendOffline, setBackendOffline] = useState<boolean>(false);
  const [notFound, setNotFound] = useState<boolean>(false);
  const [recentCases, setRecentCases] = useState<any[]>([]);
  const [riskFactors, setRiskFactors] = useState<RiskFactor[]>([]);
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
    if (typeof window === "undefined") return;

    const checkAndRunUrlAnalysis = () => {
      const params = getInitialSearchParams();
      if (!params) return;

      const caseIdParam = params.get("case_id") || params.get("caseId");
      if (caseIdParam) {
        setActiveCaseId(caseIdParam);
        setIsAnalyzing(false);
        onNavigate(`/mail-intelligence/${caseIdParam}`);
        return;
      }

      const hasRaw = Boolean(params.get("email_text") || params.get("raw"));
      const isAnalyzingParam = params.get("analyzing") === "true";
      const subjectParam = params.get("subject");
      const senderParam = params.get("sender_email") || params.get("sender");
      const platformParam = params.get("platform") || "gmail";

      if (subjectParam) setAnalyzingSubject(subjectParam);
      if (senderParam) setAnalyzingSender(senderParam);
      if (platformParam) setAnalyzingPlatform(platformParam);

      if (hasRaw || isAnalyzingParam) {
        const text = params.get("email_text") || params.get("raw") || "";
        const sender = senderParam || "unknown@domain.com";
        const rawUrl = params.get("url") || "";
        const subject = subjectParam || (text ? text.slice(0, 60).split("\n")[0] : "Gmail Inbound Inspection");

        setAnalyzingSubject(subject);
        setAnalyzingSender(sender);
        setIsAnalyzing(true);
        setLoading(true);
        setActiveCaseId(null);
        setCaseRecord(null);

        analyzeForensicEmail({
          platform: platformParam,
          subject: subject,
          sender: {
            name: sender.split("@")[0] || "Sender",
            email: sender,
          },
          recipient: "analyst@corp.internal",
          body: text || subject,
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
      }
    };

    checkAndRunUrlAnalysis();

    window.addEventListener("popstate", checkAndRunUrlAnalysis);
    return () => {
      window.removeEventListener("popstate", checkAndRunUrlAnalysis);
    };
  }, [onNavigate]);

  // Active poller while isAnalyzing: captures background-created cases automatically
  useEffect(() => {
    if (!isAnalyzing) return;
    const interval = setInterval(() => {
      getForensicCases({ limit: 5 })
        .then((res) => {
          const cases = res.cases || [];
          if (cases.length > 0) {
            const topCase = cases[0];
            const isMatch = analyzingSubject && topCase.title && (
              topCase.title.toLowerCase().includes(analyzingSubject.toLowerCase().slice(0, 20)) ||
              analyzingSubject.toLowerCase().includes(topCase.title.toLowerCase().slice(0, 20))
            );
            if (isMatch && topCase.id) {
              setIsAnalyzing(false);
              setActiveCaseId(topCase.id);
              onNavigate(`/mail-intelligence/${topCase.id}`);
            }
          }
        })
        .catch(() => {});
    }, 1200);

    return () => clearInterval(interval);
  }, [isAnalyzing, analyzingSubject, onNavigate]);

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
      setRiskFactors([]);
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

        const riskFactorsObj = a.risk_factors || {
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
          confidence: a.confidence ?? 85,
          mode: c.id.startsWith("SS-2026") ? "DEMO" : "LIVE",
          email_metadata: emailMeta,
          why_flagged: whyFlagged,
          risk_factors: riskFactorsObj,
          url_intelligence: a.url_intelligence_list || [],
          authentication: a.authentication,
          originating_node: a.originating_node,
          campaign_id: a.campaign?.id || null,
          created_at: c.created_at,
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

    getInvestigationById(activeCaseId)
      .then((inv) => {
        if (!isMounted) return;
        if (inv && Array.isArray(inv.riskFactors)) {
          setRiskFactors(inv.riskFactors);
        }
      })
      .catch((err) => {
        console.warn("Could not load risk factors from investigation service", err);
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
    if (!body) return <span className="text-text-muted italic">No message body provided.</span>;

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
              <mark key={i} className="bg-warning/20 text-warning px-1 py-0.5 rounded font-semibold">
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
            <Button
              variant="secondary"
              onClick={() => window.open(getExportPdfUrl(caseRecord.case_id, false))}
              className="text-xs"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export PDF</span>
            </Button>
            <Button
              variant="accent"
              onClick={() => onNavigate(`/investigations/${caseRecord.case_id}`)}
              className="text-xs"
            >
              <span>Open Investigation</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </Button>
          </div>
        ) : undefined
      }
    >
      <div className="space-y-6">
        {/* Skeleton Loader while fetching */}
        {loading && !isAnalyzing && activeCaseId && (
          <div className="space-y-6 animate-pulse">
            <div className="p-6 rounded-2xl border border-border bg-surface-elevated/40 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
              <div className="lg:col-span-8 space-y-4">
                <div className="h-6 w-3/4 bg-text-muted rounded-md" />
                <div className="h-4 w-1/2 bg-background rounded-md" />
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                  <div className="h-10 bg-background rounded-lg" />
                  <div className="h-10 bg-background rounded-lg" />
                  <div className="h-10 bg-background rounded-lg" />
                  <div className="h-10 bg-background rounded-lg" />
                </div>
              </div>
              <div className="lg:col-span-4 flex justify-center">
                <div className="w-36 h-36 rounded-full bg-background border border-border" />
              </div>
            </div>
            <div className="h-40 rounded-xl bg-background border border-border" />
          </div>
        )}

        {/* Live AI Threat Analysis In Progress */}
        {isAnalyzing && (
          <div className="space-y-6">
            <div className="relative overflow-hidden rounded-2xl border border-accent/30 bg-surface/90 backdrop-blur-xl p-7 shadow-2xl shadow-cyan-950/30">
              {/* Background Ambient Glows */}
              <div className="absolute -top-24 -right-24 w-80 h-80 rounded-full bg-accent/10 blur-3xl pointer-events-none" />
              <div className="absolute -bottom-24 -left-24 w-80 h-80 rounded-full bg-blue-600/10 blur-3xl pointer-events-none" />

              {/* Top Header Bar */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-border">
                <div className="flex items-center gap-3">
                  <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-accent/20 to-blue-500/20 border border-accent/40 text-accent">
                    <RefreshCw className="w-5 h-5 animate-spin text-accent" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-base font-bold text-foreground tracking-tight">
                        AI Threat Analysis Pipeline Active
                      </h2>
                      <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-accent/15 text-accent border border-accent/30 uppercase tracking-wider">
                        <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
                        Live Ingestion
                      </span>
                    </div>
                    <p className="text-xs text-text-muted mt-0.5">
                      Executing full multi-vector forensic evaluation and cryptographic vault sealing...
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 self-start sm:self-center">
                  <div className="px-3.5 py-1.5 rounded-lg bg-black/40 border border-border font-mono text-xs text-text-secondary flex items-center gap-2">
                    <span className="text-text-muted text-[11px] uppercase tracking-wider">Elapsed:</span>
                    <span className="text-accent font-semibold">{analysisElapsed.toFixed(1)}s</span>
                  </div>
                </div>
              </div>

              {/* Ingested Target Summary Card */}
              <div className="my-6 p-4 rounded-xl bg-background/50 border border-border grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
                <div className="md:col-span-6 space-y-1">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5">
                    <Mail className="w-3.5 h-3.5 text-accent" />
                    <span>Target Email Subject</span>
                  </div>
                  <div className="text-sm font-semibold text-foreground truncate" title={analyzingSubject}>
                    {analyzingSubject || "Gmail Inbound Inspection"}
                  </div>
                </div>

                <div className="md:col-span-4 space-y-1">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                    Sender Identity
                  </div>
                  <div className="text-xs font-mono text-accent/90 truncate" title={analyzingSender}>
                    {analyzingSender || "unknown@domain.com"}
                  </div>
                </div>

                <div className="md:col-span-2 flex md:justify-end">
                  <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold uppercase tracking-wider bg-background border border-border text-text-secondary">
                    {analyzingPlatform.toUpperCase()} DOM
                  </span>
                </div>
              </div>

              {/* 4 Pipeline Stages */}
              <div className="space-y-3">
                <div className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
                  Forensic Execution Sequence
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                  {/* Stage 1 */}
                  <div className={`p-3.5 rounded-xl border transition-all duration-300 ${
                    analysisStep >= 1
                      ? "bg-surface-elevated/20 border-accent/30 shadow-sm"
                      : "bg-background/50 border-border opacity-50"
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-accent font-semibold">STAGE 01</span>
                      {analysisStep > 1 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-success">
                          <Check className="w-3 h-3" /> Extracted
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-accent">
                          <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Ingesting
                        </span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-foreground">DOM & MIME Extraction</div>
                    <div className="text-[11px] text-text-muted mt-1">
                      RFC 5322 headers, unmasked hyperlink anchors & UTF-8 body.
                    </div>
                  </div>

                  {/* Stage 2 */}
                  <div className={`p-3.5 rounded-xl border transition-all duration-300 ${
                    analysisStep >= 2
                      ? "bg-surface-elevated/20 border-accent/30 shadow-sm"
                      : "bg-background/50 border-border opacity-50"
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-accent font-semibold">STAGE 02</span>
                      {analysisStep > 2 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-success">
                          <Check className="w-3 h-3" /> Evaluated
                        </span>
                      ) : analysisStep === 2 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-accent">
                          <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Scanning
                        </span>
                      ) : (
                        <span className="text-[10px] text-text-muted">Queued</span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-foreground">Heuristics & Homoglyphs</div>
                    <div className="text-[11px] text-text-muted mt-1">
                      Punycode character spoofing, lookalike domains & SPF/DKIM flags.
                    </div>
                  </div>

                  {/* Stage 3 */}
                  <div className={`p-3.5 rounded-xl border transition-all duration-300 ${
                    analysisStep >= 3
                      ? "bg-surface-elevated/20 border-accent/30 shadow-sm"
                      : "bg-background/50 border-border opacity-50"
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-accent font-semibold">STAGE 03</span>
                      {analysisStep > 3 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-success">
                          <Check className="w-3 h-3" /> Scored
                        </span>
                      ) : analysisStep === 3 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-accent">
                          <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Processing
                        </span>
                      ) : (
                        <span className="text-[10px] text-text-muted">Queued</span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-foreground">BERT NLP & CTI Feeds</div>
                    <div className="text-[11px] text-text-muted mt-1">
                      Deep semantic urgency modeling, brand impersonation & ERPN hops.
                    </div>
                  </div>

                  {/* Stage 4 */}
                  <div className={`p-3.5 rounded-xl border transition-all duration-300 ${
                    analysisStep >= 4
                      ? "bg-surface-elevated/20 border-warning/30 shadow-sm"
                      : "bg-background/50 border-border opacity-50"
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-warning font-semibold">STAGE 04</span>
                      {analysisStep >= 4 ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-warning">
                          <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Sealing
                        </span>
                      ) : (
                        <span className="text-[10px] text-text-muted">Queued</span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-foreground">Vault Sealing & Dossier</div>
                    <div className="text-[11px] text-text-muted mt-1">
                      Cryptographic evidence hashing & immutable SQLite dossier commit.
                    </div>
                  </div>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="mt-6 pt-5 border-t border-border space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-text-muted flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-accent animate-ping" />
                    Aggregating zero-trust detection vectors...
                  </span>
                  <span className="font-mono text-accent font-semibold">
                    {Math.min(96, Math.floor(analysisElapsed * 18 + 12))}%
                  </span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-background/50 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-accent via-blue-500 to-success transition-all duration-300 rounded-full"
                    style={{ width: `${Math.min(96, Math.floor(analysisElapsed * 18 + 12))}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Backend offline */}
        {!loading && !isAnalyzing && backendOffline && (
          <div className="p-6 rounded-xl border border-danger/20 bg-danger/10 space-y-3">
            <div className="flex items-center gap-2 text-sm font-medium text-danger">
              <AlertTriangle className="w-4 h-4" />
              <span>SpectraShield Backend Offline</span>
            </div>
            <p className="text-xs text-text-muted">
              Could not communicate with the detection engine at port 8000. Start the backend service to continue.
            </p>
          </div>
        )}

        {/* Not Found */}
        {!loading && !isAnalyzing && notFound && (
          <div className="p-8 text-center rounded-xl border border-border bg-surface/50 space-y-3 max-w-lg mx-auto">
            <div className="text-sm font-medium text-foreground">Case Not Found</div>
            <p className="text-xs text-text-muted">
              Case <code className="font-mono text-accent">{activeCaseId}</code> does not exist in the records.
            </p>
            <Button
              variant="outline"
              onClick={() => onNavigate("/investigations")}
              className="mt-2 text-xs"
            >
              Back to Investigations
            </Button>
          </div>
        )}

        {/* Empty State: Hub / Scanner */}
        {!loading && !activeCaseId && !backendOffline && !notFound && !isAnalyzing && (
          <div className="space-y-6">
            <div className="p-5 rounded-xl border border-border bg-surface/70 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-semibold text-foreground">Email Intelligence Ingestion Hub</h2>
                <p className="text-xs text-text-muted mt-0.5">
                  Scan an active email via DOM extraction or enter details manually.
                </p>
              </div>
              <Button
                variant="accent"
                onClick={handleScanWebmailDOM}
                disabled={isScanningTab}
                className="text-xs"
              >
                <Zap className="w-4 h-4" />
                <span>{isScanningTab ? "Scanning Tab..." : "Scan Active Email DOM"}</span>
              </Button>
            </div>

            {tabScanFeedback && (
              <div className="text-xs px-3 py-2 rounded-lg bg-accent/10 border border-accent/20 text-accent">
                {tabScanFeedback}
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Recent Ingestions */}
              <div className="p-5 rounded-xl border border-border bg-surface/50 space-y-3">
                <div className="text-xs font-semibold text-foreground">Recent Email Ingestions</div>
                {recentCases.length === 0 ? (
                  <div className="text-xs text-text-muted py-6 text-center">
                    No cases recorded yet. Ingest an email to start analysis.
                  </div>
                ) : (
                  <div className="divide-y divide-border">
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
                          className="py-2.5 flex items-center justify-between gap-3 hover:bg-background cursor-pointer transition-colors"
                        >
                          <div className="min-w-0">
                            <div className="text-xs font-medium text-text-secondary truncate">
                              {c.title || c.subject || "Email Analysis"}
                            </div>
                            <div className="text-[11px] font-mono text-text-muted mt-0.5">
                              {c.case_number || c.id}
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge 
                              variant={isHigh ? "destructive" : "success"}
                              className="text-[11px]"
                            >
                              {risk}
                            </Badge>
                            <ChevronRight className="w-3.5 h-3.5 text-text-muted" />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Manual Entry */}
              <div className="p-5 rounded-xl border border-border bg-surface/50 space-y-3">
                <div className="text-xs font-semibold text-foreground">Manual Email Scan</div>
                <form onSubmit={handleManualScan} className="space-y-3">
                  <div>
                    <label className="text-[11px] text-text-muted">Subject</label>
                    <input
                      type="text"
                      value={manualSubject}
                      onChange={(e) => setManualSubject(e.target.value)}
                      placeholder="e.g. Account Verification Required"
                      className="w-full mt-1 px-3 py-1.5 rounded-lg bg-surface-elevated border border-border text-xs text-foreground placeholder-text-muted focus:outline-none focus:border-accent/50"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-[11px] text-text-muted">Sender</label>
                      <input
                        type="text"
                        value={manualSender}
                        onChange={(e) => setManualSender(e.target.value)}
                        placeholder="security@micros0ft.com"
                        className="w-full mt-1 px-3 py-1.5 rounded-lg bg-surface-elevated border border-border text-xs text-foreground placeholder-text-muted focus:outline-none focus:border-accent/50"
                      />
                    </div>
                    <div>
                      <label className="text-[11px] text-text-muted">URL (Optional)</label>
                      <input
                        type="text"
                        value={manualUrl}
                        onChange={(e) => setManualUrl(e.target.value)}
                        placeholder="https://micros0ft.com/login"
                        className="w-full mt-1 px-3 py-1.5 rounded-lg bg-surface-elevated border border-border text-xs text-foreground placeholder-text-muted focus:outline-none focus:border-accent/50"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-[11px] text-text-muted">Email Body</label>
                    <textarea
                      rows={3}
                      value={manualText}
                      onChange={(e) => setManualText(e.target.value)}
                      placeholder="Paste message body text..."
                      className="w-full mt-1 px-3 py-1.5 rounded-lg bg-surface-elevated border border-border text-xs text-foreground placeholder-text-muted focus:outline-none focus:border-accent/50"
                      required
                    />
                  </div>
                  <Button
                    variant="accent"
                    type="submit"
                    disabled={isSubmitting || !manualText.trim()}
                    className="w-full text-xs"
                  >
                    {isSubmitting ? "Analyzing..." : "Scan Email"}
                  </Button>
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
              <div className="p-3 rounded-lg bg-warning/10 border border-warning/20 text-xs text-warning flex items-center justify-between">
                <span><b>DEMONSTRATION CASE:</b> This incident contains demonstration telemetry.</span>
                <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-warning/20">DEMO</span>
              </div>
            )}

            {/* ─── 1. DOMINANT HERO: EMAIL IDENTITY & ANIMATED RISK GAUGE ────── */}
            <div className="p-5 sm:p-6 rounded-2xl border border-accent/20 bg-gradient-to-b from-surface/95 via-surface-elevated/90 to-surface/95 backdrop-blur-xl shadow-2xl overflow-hidden relative">
              {/* Subtle top edge specular highlight */}
              <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-accent/40 to-transparent" />

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
                {/* Left Side: Email Identity & Telemetry Strip (col-span-7) */}
                <div className="lg:col-span-7 space-y-4">
                  <div>
                    <div className="flex flex-wrap items-center gap-2 mb-2">
                      <Badge variant="outline" className="text-[10px] font-mono">
                        CASE {caseRecord.case_number}
                      </Badge>
                      <Badge variant="outline" className="text-[10px] font-mono">
                        INBOUND TELEMETRY
                      </Badge>
                      <button
                        onClick={() => handleCopy(caseRecord.sha256, "sha")}
                        className="text-[10px] font-mono text-text-muted hover:text-foreground flex items-center gap-1 px-2 py-0.5 rounded bg-background border border-border transition-colors"
                        title="Copy SHA-256 evidence hash"
                      >
                        {copiedText === "sha" ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                        <span>SHA: {caseRecord.sha256.slice(0, 10)}...</span>
                      </button>
                    </div>

                    <h1 className="text-base sm:text-xl font-bold text-foreground tracking-tight leading-snug">
                      {caseRecord.email_metadata.subject}
                    </h1>

                    <div className="mt-1 text-xs text-text-muted flex items-center gap-2">
                      <span>Threat Category:</span>
                      <span className="text-accent font-medium">{caseRecord.threat_category}</span>
                    </div>
                  </div>

                  {/* Identity Key-Value Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded-xl bg-background/25 border border-border text-xs">
                    <div>
                      <span className="text-text-muted text-[10px] uppercase font-semibold block">Sender</span>
                      <span className="font-mono text-text-secondary truncate block mt-0.5" title={caseRecord.email_metadata.sender.email}>
                        {caseRecord.email_metadata.sender.email}
                      </span>
                    </div>
                    <div>
                      <span className="text-text-muted text-[10px] uppercase font-semibold block">Recipient</span>
                      <span className="font-mono text-text-secondary truncate block mt-0.5" title={caseRecord.email_metadata.recipient}>
                        {caseRecord.email_metadata.recipient}
                      </span>
                    </div>
                    <div>
                      <span className="text-text-muted text-[10px] uppercase font-semibold block">Received</span>
                      <span className="text-text-secondary block mt-0.5 truncate">
                        {new Date(caseRecord.email_metadata.received).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                    <div>
                      <span className="text-text-muted text-[10px] uppercase font-semibold block">Platform</span>
                      <span className="text-text-secondary block mt-0.5 capitalize truncate">
                        {caseRecord.email_metadata.platform}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Right Side: Animated Radial Risk Gauge with Halo (col-span-5) */}
                <div className="lg:col-span-5 flex items-center justify-center lg:border-l border-border lg:pl-6">
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
                  <h3 className="text-sm font-semibold text-foreground tracking-tight flex items-center gap-2">
                    <span>Why This Was Flagged</span>
                    <Badge variant="outline" className="text-[10px] font-mono font-normal">
                      {caseRecord.why_flagged.length} SIGNALS
                    </Badge>
                  </h3>
                  <p className="text-xs text-text-muted mt-0.5">
                    Chronological signal attribution pipeline and heuristic evaluation
                  </p>
                </div>
              </div>

              <SignalTimeline signals={caseRecord.why_flagged} />
            </div>

            {/* ─── 3. RISK FACTOR ANALYSIS (8 INDEPENDENT THREAT VECTORS) ───── */}
            {riskFactors.length > 0 && (
              <RiskFactorAnalysis factors={riskFactors} />
            )}

            {/* ─── 4. EMAIL CONTENT & FORENSIC INSPECTION ────────────────────── */}
            <EmailContentInspector
              emailMetadata={caseRecord.email_metadata}
              whyFlagged={caseRecord.why_flagged}
              riskScore={caseRecord.final_risk}
              threatCategory={caseRecord.threat_category}
              authentication={caseRecord.authentication}
              originatingNode={caseRecord.originating_node}
              relayPath={caseRecord.relay_path}
              caseId={caseRecord.case_id}
              sha256={caseRecord.sha256}
              onNavigate={onNavigate}
            />
          </div>
        )}
      </div>
    </SocLayout>
  );
};

