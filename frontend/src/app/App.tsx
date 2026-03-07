import React, { useState, useEffect } from "react";
import { ShieldCheck, Monitor, Link2, BarChart3, Sun, Moon, Laptop } from "lucide-react";
import { motion } from "motion/react";
import { useTheme } from "next-themes";
import { ThemeProvider } from "./components/ThemeProvider";
import RiskMeter from "./components/RiskMeter";
import RiskBreakdown from "./components/RiskBreakdown";
import WhyFlagged from "./components/WhyFlagged";
import GmailInboxRiskIndicators from "./components/GmailInboxRiskIndicators";
import ActionButtons from "./components/ActionButtons";
import PhishingWarningBanner from "./components/PhishingWarningBanner";
import GmailDemo from "./components/GmailDemo";
import LinkPreview from "./components/LinkPreview";
import LinkPreviewDemo from "./components/LinkPreviewDemo";
import Dashboard from "./components/Dashboard";
import StyleGuide from "./components/StyleGuide";
import { analyzeEmail, type AnalyzeResponse } from "./api";

const DEFAULT_EMAIL_TEXT = "URGENT: Verify your account now. Click here to avoid suspension. Your Microsoft account has been locked. Confirm your identity within 24 hours.";
const DEFAULT_URL = "https://secure-verify-account.tk/login/microsoft";
const DEFAULT_SENDER = "security-noreply@accountverify.tk";

const AppContent = () => {
  const { theme, setTheme } = useTheme();
  const [emailText, setEmailText] = useState(DEFAULT_EMAIL_TEXT);
  const [emailHeader, setEmailHeader] = useState("");
  const [url, setUrl] = useState(DEFAULT_URL);
  const [senderEmail, setSenderEmail] = useState(DEFAULT_SENDER);
  const [privateMode, setPrivateMode] = useState(true);
   // If true, page was opened via Gmail badge deep link (show focused view only)
  const [fromBadge, setFromBadge] = useState(false);
  const [riskScore, setRiskScore] = useState(0);
  const [loading, setLoading] = useState(true);
  const [showBanner, setShowBanner] = useState(false);
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [viewMode, setViewMode] = useState<"popup" | "gmail" | "linkpreview" | "linkdemo" | "dashboard" | "styleguide">("popup");
  const [themeMounted, setThemeMounted] = useState(false);

  useEffect(() => {
    document.title = "SpectraShield AI";
  }, []);

  useEffect(() => {
    setThemeMounted(true);
  }, []);

  const cycleTheme = () => {
    const current = theme || "system";
    if (current === "system") {
      setTheme("light");
      return;
    }
    if (current === "light") {
      setTheme("dark");
      return;
    }
    setTheme("system");
  };

  const themeIcon = (() => {
    const current = themeMounted ? (theme || "system") : "system";
    if (current === "light") return <Sun className="w-4 h-4" />;
    if (current === "dark") return <Moon className="w-4 h-4" />;
    return <Laptop className="w-4 h-4" />;
  })();

  const themeLabel = (() => {
    const current = themeMounted ? (theme || "system") : "system";
    if (current === "light") return "Theme: Light (click to switch to Dark)";
    if (current === "dark") return "Theme: Dark (click to switch to System)";
    return "Theme: System (click to switch to Light)";
  })();

  const extractFirstUrl = (text: string): string | null => {
    const match = text.match(/https?:\/\/[^\s]+/i);
    return match ? match[0] : null;
  };

  const getDeepLinkParams = (): URLSearchParams => {
    const searchParams = new URLSearchParams(window.location.search || "");
    if (["email_text", "email_header", "url", "sender_email"].some((key) => !!searchParams.get(key))) {
      return searchParams;
    }

    const hash = window.location.hash || "";
    if (!hash) return searchParams;

    const queryStart = hash.indexOf("?");
    if (queryStart >= 0) {
      return new URLSearchParams(hash.slice(queryStart + 1));
    }

    const cleaned = hash.startsWith("#") ? hash.slice(1) : hash;
    return new URLSearchParams(cleaned);
  };

  const runAnalysis = (payload: { email_text: string; email_header?: string; url?: string; sender_email?: string; private_mode: boolean }) => {
    setLoading(true);
    analyzeEmail({
      email_text: payload.email_text,
      email_header: payload.email_header || undefined,
      url: payload.url?.trim() || undefined,
      sender_email: payload.sender_email?.trim() || undefined,
      private_mode: payload.private_mode,
    })
      .then((data) => {
        setRiskScore(Math.round(data.final_risk));
        setAnalysis(data);
        setShowBanner(data.final_risk >= 70);
      })
      .catch(() => {
        setRiskScore(0);
        setAnalysis(null);
        setShowBanner(false);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const params = getDeepLinkParams();
    const qEmailText = params.get("email_text");
    const qHeader = params.get("email_header");
    const qUrl = params.get("url");
    const qSender = params.get("sender_email");

    const hasDeepLinkParams = !!(qEmailText || qHeader || qUrl || qSender);
    setFromBadge(hasDeepLinkParams);

    if (hasDeepLinkParams) {
      const initialEmail = qEmailText || DEFAULT_EMAIL_TEXT;
      const initialHeader = qHeader || "";
      const detectedUrl = qUrl || extractFirstUrl(initialEmail) || "";
      const initialSender = qSender || "";

      setEmailText(initialEmail);
      setEmailHeader(initialHeader);
      setUrl(detectedUrl);
      setSenderEmail(initialSender || DEFAULT_SENDER);

      runAnalysis({
        email_text: initialEmail,
        email_header: initialHeader,
        url: detectedUrl || undefined,
        sender_email: initialSender,
        private_mode: true,
      });
    } else {
      runAnalysis({
        email_text: DEFAULT_EMAIL_TEXT,
        url: DEFAULT_URL,
        sender_email: DEFAULT_SENDER,
        private_mode: true,
      });
    }
  }, []);

  const getRiskLabel = (score: number) => {
    if (score < 30) return { text: "Safe", color: "text-safe", bg: "bg-safe/10", border: "border-safe/20" };
    if (score < 70) return { text: "Suspicious", color: "text-warning", bg: "bg-warning/10", border: "border-warning/20" };
    return { text: "High Risk", color: "text-destructive", bg: "bg-destructive/10", border: "border-destructive/20" };
  };

  const riskStatus = getRiskLabel(riskScore);

  // Helper for view toggles to keep code DRY
  const ViewToggle = () => (
    <div className="fixed top-4 right-4 z-50 flex gap-2">
      <button
        onClick={() => setViewMode("popup")}
        className="flex items-center gap-2 px-3 py-2 bg-card text-card-foreground rounded-full shadow-lg border border-border hover:bg-accent transition-all text-sm"
        title="Popup View"
      >
        <Monitor className="w-4 h-4" />
      </button>
      <button
        onClick={() => setViewMode("linkpreview")}
        className="flex items-center gap-2 px-3 py-2 bg-card text-card-foreground rounded-full shadow-lg border border-border hover:bg-accent transition-all text-sm"
        title="Link Preview"
      >
        <Link2 className="w-4 h-4" />
      </button>
      <button
        onClick={() => setViewMode("dashboard")}
        className="flex items-center gap-2 px-3 py-2 bg-card text-card-foreground rounded-full shadow-lg border border-border hover:bg-accent transition-all text-sm"
        title="Dashboard"
      >
        <BarChart3 className="w-4 h-4" />
      </button>
    </div>
  );

  // Dashboard View
  if (viewMode === "dashboard") {
    return (
      <div className="bg-background min-h-screen text-foreground">
        <ViewToggle />
        <Dashboard />
      </div>
    );
  }

  // Link Preview Demo View
  if (viewMode === "linkdemo") {
    return (
      <div className="bg-background min-h-screen text-foreground">
        <ViewToggle />
        <LinkPreviewDemo />
      </div>
    );
  }

  // Link Preview View
  if (viewMode === "linkpreview") {
    return (
      <div className="relative w-full min-h-screen bg-background text-foreground flex items-center justify-center p-8">
        <ViewToggle />
        <LinkPreview
          url={url}
          riskScore={analysis?.breakdown?.url_score ?? analysis?.unified_severity_score ?? analysis?.final_risk ?? riskScore}
          domainAgeDays={analysis?.domain_age_days ?? null}
          domainAgeContext={analysis?.domain_age_context}
          sslContext={analysis?.ssl_context}
          intelligenceProfile={analysis?.intelligence_profile}
          riskBreakdown={analysis?.risk_breakdown}
          threatArray={analysis?.threat_array}
          scannedAt={analysis?.timestamp}
        />
      </div>
    );
  }

  // Gmail Demo View
  if (viewMode === "gmail") {
    return (
      <div className="relative w-full h-screen bg-background text-foreground">
        <ViewToggle />
        <GmailDemo />
      </div>
    );
  }

  // Style Guide View
  if (viewMode === "styleguide") {
    return (
      <div className="relative w-full h-screen bg-background text-foreground overflow-auto">
        <ViewToggle />
        <StyleGuide />
      </div>
    );
  }

  // Extension Popup View
  return (
    <div className="w-full min-h-screen bg-background text-foreground flex items-center justify-center p-8 transition-colors duration-300">
      <ViewToggle />

      <div className="w-[400px] min-h-[600px] bg-card text-card-foreground font-sans overflow-hidden relative shadow-2xl border border-border flex flex-col rounded-xl transition-colors duration-300">
      
        {/* Floating Warning Banner Overlay */}
        <div className="absolute top-0 left-0 right-0 z-50 pointer-events-none p-2">
          <div className="pointer-events-auto">
            <PhishingWarningBanner 
              isVisible={showBanner} 
              onDismiss={() => setShowBanner(false)}
              riskScore={riskScore} 
            />
          </div>
        </div>

        {/* Background Elements - Themed */}
        <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none z-0">
          <div className="absolute inset-0 bg-[linear-gradient(rgba(15,23,42,0.1)_1px,transparent_1px),linear-gradient(90deg,rgba(15,23,42,0.1)_1px,transparent_1px)] bg-[size:20px_20px] [mask-image:radial-gradient(ellipse_at_center,black_70%,transparent_100%)] opacity-20 dark:opacity-20 opacity-5"></div>
          <div className="absolute -top-20 -right-20 w-64 h-64 bg-primary/5 rounded-full blur-3xl"></div>
          <div className="absolute top-40 -left-20 w-48 h-48 bg-safe/5 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 right-0 w-80 h-80 bg-destructive/5 rounded-full blur-3xl"></div>
        </div>

        {/* Header */}
        <header className="relative z-10 flex items-center justify-between px-6 py-4 border-b border-border backdrop-blur-md bg-background/80">
          <div className="flex items-center gap-2">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/20 blur-sm rounded-full"></div>
              <ShieldCheck className="w-6 h-6 text-primary relative z-10" />
            </div>
            <span className="font-bold text-lg tracking-tight text-foreground">
              SpectraShield AI
            </span>
          </div>
          <button
            type="button"
            onClick={cycleTheme}
            title={themeLabel}
            aria-label={themeLabel}
            className="p-2 hover:bg-accent rounded-full transition-colors text-muted-foreground hover:text-foreground"
          >
            {themeIcon}
          </button>
        </header>

        {/* Main Content */}
        <main className="relative z-10 flex-1 flex flex-col p-6 gap-4 overflow-y-auto custom-scrollbar">
          {/* Scan form: only when not opened via Gmail badge */}
          {!fromBadge && (
            <section className="space-y-2">
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block">Email text</label>
              <textarea
                value={emailText}
                onChange={(e) => setEmailText(e.target.value)}
                placeholder="Paste or type email content..."
                className="w-full min-h-[60px] px-3 py-2 text-sm bg-background/80 border border-border rounded-lg resize-y focus:outline-none focus:ring-2 focus:ring-primary/50 text-foreground placeholder:text-muted-foreground"
                rows={2}
              />
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block">Header (optional)</label>
              <input
                type="text"
                value={emailHeader}
                onChange={(e) => setEmailHeader(e.target.value)}
                placeholder="From: ... Received: ..."
                className="w-full px-3 py-2 text-sm bg-background/80 border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 text-foreground placeholder:text-muted-foreground"
              />
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block">Link (optional)</label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://..."
                className="w-full px-3 py-2 text-sm bg-background/80 border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 text-foreground placeholder:text-muted-foreground"
              />
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block">Sender (optional)</label>
              <input
                type="text"
                value={senderEmail}
                onChange={(e) => setSenderEmail(e.target.value)}
                placeholder="sender@example.com"
                className="w-full px-3 py-2 text-sm bg-background/80 border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 text-foreground placeholder:text-muted-foreground"
              />
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={privateMode}
                  onChange={(e) => setPrivateMode(e.target.checked)}
                  className="rounded border-border"
                />
                <span className="text-xs text-muted-foreground">Private mode (do not store scan)</span>
              </label>
              <button
                type="button"
                onClick={() =>
                  runAnalysis({
                    email_text: emailText,
                    email_header: emailHeader.trim() || undefined,
                    url: url.trim() || undefined,
                    sender_email: senderEmail.trim() || undefined,
                    private_mode: privateMode,
                  })
                }
                disabled={loading}
                className="w-full py-2.5 px-4 bg-primary text-primary-foreground font-semibold text-sm rounded-lg hover:opacity-90 disabled:opacity-60 transition-opacity"
              >
                {loading ? "Analyzing…" : "Submit scan"}
              </button>
            </section>
          )}

          {/* Risk Meter Section */}
          <section className="flex flex-col items-center justify-center py-2">
            <RiskMeter score={riskScore} loading={loading} />
            
            <motion.div 
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className={`mt-4 px-4 py-1.5 rounded-full border ${riskStatus.border} ${riskStatus.bg} backdrop-blur-sm`}
            >
              <span className={`text-sm font-semibold tracking-wide uppercase ${riskStatus.color}`}>
                {loading ? "Analyzing..." : riskStatus.text}
              </span>
            </motion.div>
            {analysis && !loading && (
              <>
                <p className="text-xs text-muted-foreground mt-1">Confidence: {analysis.confidence_level}</p>
                {analysis.threat_category && (
                  <p className="text-xs font-medium text-foreground/90 mt-0.5">Threat: {analysis.threat_category}</p>
                )}
              </>
            )}
            {fromBadge && url.trim().length > 0 && (
              <button
                type="button"
                onClick={() => setViewMode("linkpreview")}
                className="mt-4 inline-flex items-center justify-center px-4 py-2 text-xs font-semibold rounded-lg bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20 transition-colors"
              >
                Scan Link
              </button>
            )}
          </section>

          {/* Breakdown Panel */}
          <RiskBreakdown loading={loading} breakdown={analysis?.breakdown} />

          {/* Gmail Inbox Simulation: hide for deep-link view from Gmail */}
          {!fromBadge && <GmailInboxRiskIndicators />}

          {/* Why Flagged Section - explainable reasoning */}
          <WhyFlagged
            loading={loading}
            verdict={analysis?.verdict}
            highlightedPhrases={analysis?.highlighted_phrases ?? undefined}
            reasoningSummary={analysis?.reasoning_summary ?? undefined}
          />

        </main>

        {/* Footer / Actions */}
        <footer className="relative z-10 p-6 pt-2 bg-gradient-to-t from-background to-transparent">
          <ActionButtons />
        </footer>
      </div>
    </div>
  );
};

const App = () => {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <AppContent />
    </ThemeProvider>
  );
};

export default App;