import React, { useState, useEffect, lazy, Suspense, Component } from "react";
import {
  ShieldCheck, Settings, Monitor, Mail, Link2, Zap, BarChart3,
  Palette, Globe, Layers, Shield, GitBranch, Map, UserCheck, KeyRound,
  Radio, Crosshair,
} from "lucide-react";
import { motion } from "motion/react";
import { ThemeProvider } from "./components/ThemeProvider";
import { ThemeToggle } from "./components/ThemeToggle";
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
import { CtiLookupModal } from "./components/CtiLookupModal";
import { VipRosterModal } from "./components/VipRosterModal";
import { AuthRbacModal } from "./components/AuthRbacModal";
import { getMe, type UserProfile } from "./api";

// Lazy-load new pages so a single module failure doesn't crash the whole app
const LandingPage = lazy(() => import("./components/LandingPage"));
const AnalyzePage = lazy(() => import("./components/AnalyzePage"));
const ForensicsPage = lazy(() => import("./components/ForensicsPage"));
const CasesPage = lazy(() => import("./components/CasesPage"));
const ThreatGraph = lazy(() => import("./components/ThreatGraph"));
const GeoMap = lazy(() => import("./components/GeoMap"));
const InvestigationPage = lazy(() => import("./components/investigation/InvestigationPage").then(m => ({ default: m.InvestigationPage })));

// SOC Unified Pages
const OverviewPage = lazy(() => import("./components/soc/OverviewPage").then(m => ({ default: m.OverviewPage })));
const InvestigationsListPage = lazy(() => import("./components/soc/InvestigationsListPage").then(m => ({ default: m.InvestigationsListPage })));
const EmailIntelligencePage = lazy(() => import("./components/soc/EmailIntelligencePage").then(m => ({ default: m.EmailIntelligencePage })));
const ThreatIntelligencePage = lazy(() => import("./components/soc/ThreatIntelligencePage").then(m => ({ default: m.ThreatIntelligencePage })));
const ForensicIntelligencePage = lazy(() => import("./components/soc/ForensicIntelligencePage").then(m => ({ default: m.ForensicIntelligencePage })));
const EvidenceVaultPage = lazy(() => import("./components/soc/EvidenceVaultPage").then(m => ({ default: m.EvidenceVaultPage })));
const ReportsPage = lazy(() => import("./components/soc/ReportsPage").then(m => ({ default: m.ReportsPage })));
const SettingsPage = lazy(() => import("./components/soc/SettingsPage").then(m => ({ default: m.SettingsPage })));

// Loading spinner shown while lazy module downloads
const PageLoader = ({ name }: { name: string }) => (
  <div className="w-full min-h-screen flex items-center justify-center"
    style={{ background: "linear-gradient(135deg, #05070d 0%, #0b0f1a 100%)" }}>
    <div className="flex flex-col items-center gap-4">
      <div className="w-10 h-10 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin"
        style={{ borderColor: "rgba(0,229,255,0.15)", borderTopColor: "#00e5ff" }} />
      <div className="text-xs text-slate-500 uppercase tracking-widest">Loading {name}...</div>
    </div>
  </div>
);

// Error boundary — catches both lazy-load failures and runtime render errors
class ViewErrorBoundary extends Component<
  { children: React.ReactNode; name: string },
  { error: string | null }
> {
  state = { error: null };
  static getDerivedStateFromError(e: Error) { return { error: e.message }; }
  componentDidCatch(e: Error, info: React.ErrorInfo) {
    console.error(`[ViewErrorBoundary ${this.props.name}]:`, e, info);
  }
  componentDidUpdate(prevProps: { name: string }) {
    if (prevProps.name !== this.props.name && this.state.error) {
      this.setState({ error: null });
    }
  }
  render() {
    if (this.state.error) {
      return (
        <div className="w-full min-h-screen flex items-center justify-center p-8"
          style={{ background: "linear-gradient(135deg, #05070d, #0b0f1a)" }}>
          <div className="max-w-lg w-full rounded-2xl border border-red-500/30 p-8 text-center"
            style={{ background: "rgba(239,68,68,0.06)", backdropFilter: "blur(20px)" }}>
            <div className="text-red-400 text-lg font-bold mb-3">⚠ Could not load {this.props.name}</div>
            <div className="text-slate-400 text-xs font-mono break-all leading-relaxed">{this.state.error}</div>
            <button
              onClick={() => this.setState({ error: null })}
              className="mt-4 px-4 py-1.5 rounded-lg border border-red-500/40 text-red-300 text-xs font-semibold hover:bg-red-500/20 transition-all"
            >
              Retry View
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// Combines Suspense + ErrorBoundary in one wrapper
const SafeView: React.FC<{ name: string; children: React.ReactNode }> = ({ name, children }) => (
  <ViewErrorBoundary key={name} name={name}>
    <Suspense fallback={<PageLoader name={name} />}>
      {children}
    </Suspense>
  </ViewErrorBoundary>
);

type ViewMode =
  | "popup" | "gmail" | "linkpreview" | "linkdemo" | "dashboard" | "styleguide"
  | "landing" | "analyze" | "forensics" | "cases" | "threatgraph" | "geomap"
  | "investigation";

export type SocRouteState =
  | { route: "overview" }
  | { route: "investigations" }
  | { route: "investigation"; caseId: string }
  | { route: "email_intelligence"; caseId?: string }
  | { route: "threat_intelligence" }
  | { route: "forensics" }
  | { route: "evidence" }
  | { route: "reports" }
  | { route: "settings" };

export const resolveSocRoute = (pathInput: string): SocRouteState => {
  let pathname = pathInput || "";
  let search = "";
  try {
    if (pathname.includes("?")) {
      const parts = pathname.split("?");
      pathname = parts[0];
      search = "?" + parts.slice(1).join("?");
    } else if (typeof window !== "undefined") {
      search = window.location.search || "";
    }
  } catch (_) {}

  // 1. Check for specific Case IDs in pathname first (e.g. /mail-intelligence/CASE-123)
  const emailCaseMatch = pathname.match(/^\/(?:email|mail)-(?:intelligence|investigation)\/([^/?#]+)/i);
  if (emailCaseMatch) {
    return { route: "email_intelligence", caseId: decodeURIComponent(emailCaseMatch[1]) };
  }

  const investigationCaseMatch = pathname.match(/^\/(?:investigation|investigations)\/([^/?#]+)/i);
  if (investigationCaseMatch) {
    return { route: "investigation", caseId: decodeURIComponent(investigationCaseMatch[1]) };
  }

  // 2. Check query params for case_id or caseId
  const queryParams = new URLSearchParams(search);
  const explicitCaseId = queryParams.get("case_id") || queryParams.get("caseId");

  const clean = pathname.toLowerCase().replace(/\/$/, "");

  if (
    clean === "/email-intelligence" ||
    clean === "/mail-intelligence" ||
    clean === "/email-investigation" ||
    clean === "/mail-investigation"
  ) {
    if (explicitCaseId) {
      return { route: "email_intelligence", caseId: explicitCaseId };
    }
    // Check if this is from extension with analyzing params
    if (search.includes("analyzing=true") || search.includes("raw=") || search.includes("email_text=") || search.includes("subject=")) {
      return { route: "email_intelligence" };
    }
    return { route: "email_intelligence" };
  }

  if (typeof window !== "undefined") {
    const hash = window.location.hash || "";
    if (hash.includes("spectra") || search.includes("email_text") || search.includes("raw=") || search.includes("analyzing")) {
      if (explicitCaseId) {
        return { route: "email_intelligence", caseId: explicitCaseId };
      }
      return { route: "email_intelligence" };
    }
  }

  if (clean === "" || clean === "/overview") {
    return { route: "overview" };
  }
  if (clean === "/investigations") {
    return { route: "investigations" };
  }
  if (clean === "/threat-intelligence") {
    return { route: "threat_intelligence" };
  }
  if (clean === "/forensic-intelligence") {
    return { route: "forensics" };
  }
  if (clean === "/evidence") {
    return { route: "evidence" };
  }
  if (clean === "/reports") {
    return { route: "reports" };
  }
  if (clean === "/settings") {
    return { route: "settings" };
  }

  return { route: "overview" };
};

const AppContent = () => {
  const [riskScore, setRiskScore] = useState(0);
  const [loading, setLoading] = useState(true);
  const [showBanner, setShowBanner] = useState(false);

  // SOC Route & Legacy View State
  const [socRoute, setSocRoute] = useState<SocRouteState>(() => {
    if (typeof window !== "undefined") {
      // Include full URL path + search for proper route resolution
      const fullPath = window.location.pathname + window.location.search;
      return resolveSocRoute(fullPath);
    }
    return resolveSocRoute("/");
  });
  const [legacyView, setLegacyView] = useState<ViewMode | null>(() => {
    if (typeof window !== "undefined") {
      const q = new URLSearchParams(window.location.search).get("mode");
      if (q && ["popup", "gmail", "linkpreview", "linkdemo", "dashboard", "styleguide", "landing", "analyze"].includes(q)) {
        return q as ViewMode;
      }
    }
    return null;
  });

  // Modal Dialogs for Extra Backend Features
  const [isCtiOpen, setIsCtiOpen] = useState(false);
  const [isVipOpen, setIsVipOpen] = useState(false);
  const [isRbacOpen, setIsRbacOpen] = useState(false);
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null);

  // Synchronize browser history across all SOC routes
  useEffect(() => {
    const handlePopState = () => {
      setLegacyView(null);
      const fullPath = window.location.pathname + window.location.search;
      setSocRoute(resolveSocRoute(fullPath));
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigateTo = (path: string) => {
    setLegacyView(null);
    window.history.pushState({}, "", path);
    setSocRoute(resolveSocRoute(path));
  };

  const handleLegacyViewChange = (mode: ViewMode) => {
    setLegacyView(mode);
  };

  // Load user profile / role on mount
  useEffect(() => {
    getMe().then(setCurrentUser).catch(() => {});
  }, []);

  // Simulate analysis loading
  useEffect(() => {
    const timer = setTimeout(() => {
      setRiskScore(78);
      setLoading(false);
      setShowBanner(true);
    }, 1500);
    return () => clearTimeout(timer);
  }, []);

  const getRiskLabel = (score: number) => {
    if (score < 30) return { text: "Safe", color: "text-safe", bg: "bg-safe/10", border: "border-safe/20" };
    if (score < 70) return { text: "Suspicious", color: "text-warning", bg: "bg-warning/10", border: "border-warning/20" };
    return { text: "High Risk", color: "text-destructive", bg: "bg-destructive/10", border: "border-destructive/20" };
  };

  const riskStatus = getRiskLabel(riskScore);



  // ─── LEGACY & EXTENSION DEMO VIEWS (WHEN EXPLICITLY REQUESTED) ───────────────
  if (legacyView === "gmail") {
    return (
      <div className="relative w-full h-screen bg-background text-foreground">
        <GmailDemo onOpenInvestigation={(id) => navigateTo(`/investigations/${id || "SS-2026-0912-00421"}`)} />
      </div>
    );
  }

  if (legacyView === "linkpreview" || legacyView === "linkdemo") {
    return (
      <div className="relative w-full min-h-screen bg-background text-foreground flex items-center justify-center p-8">
        <LinkPreview />
      </div>
    );
  }

  if (legacyView === "landing") {
    return (
      <div className="relative w-full min-h-screen">
        <SafeView name="Landing Page">
          <LandingPage onLaunchConsole={() => handleLegacyViewChange("analyze")} />
        </SafeView>
      </div>
    );
  }

  if (legacyView === "analyze") {
    return (
      <div className="relative w-full min-h-screen">
        <SafeView name="Threat Analyzer">
          <AnalyzePage onOpenForensics={() => navigateTo("/forensic-intelligence")} />
        </SafeView>
      </div>
    );
  }

  if (legacyView === "dashboard") {
    return (
      <div className="bg-background min-h-screen text-foreground">
        <Dashboard />
      </div>
    );
  }

  if (legacyView === "styleguide") {
    return (
      <div className="relative w-full h-screen bg-background text-foreground overflow-auto">
        <StyleGuide />
      </div>
    );
  }

  // ─── CORE SOC ARCHITECTURE: 7 FUNCTIONAL WORKSPACES ──────────────────────────
  if (!legacyView) {
    if (socRoute.route === "overview") {
      return (
        <div className="relative w-full min-h-screen">
          <SafeView name="SOC Overview">
            <OverviewPage onNavigate={navigateTo} />
          </SafeView>
        </div>
      );
    }

    if (socRoute.route === "investigations") {
      return (
        <div className="relative w-full min-h-screen">
          <SafeView name="Incident Investigations">
            <InvestigationsListPage onNavigate={navigateTo} />
          </SafeView>
        </div>
      );
    }

    if (socRoute.route === "investigation") {
      return (
        <div className="relative w-full min-h-screen">
          <SafeView name="Security Investigation">
            <InvestigationPage
              initialId={socRoute.caseId}
              onNavigate={navigateTo}
              onBackToDashboard={() => navigateTo("/overview")}
              onNavigateToCase={(cId) => navigateTo(`/investigations/${cId}`)}
            />
          </SafeView>
        </div>
      );
    }

    if (socRoute.route === "email_intelligence") {
      return (
        <div className="relative w-full min-h-screen">
          <SafeView name="Email Intelligence">
            <EmailIntelligencePage
              caseId={socRoute.caseId}
              onNavigate={navigateTo}
            />
          </SafeView>
        </div>
      );
    }

    if (socRoute.route === "threat_intelligence") {
      return (
        <div className="relative w-full min-h-screen">
          <SafeView name="Threat Intelligence">
            <ThreatIntelligencePage onNavigate={navigateTo} />
          </SafeView>
        </div>
      );
    }

    if (socRoute.route === "forensics") {
      return (
        <div className="relative w-full min-h-screen">
          <SafeView name="Forensic Intelligence">
            <ForensicIntelligencePage onNavigate={navigateTo} />
          </SafeView>
        </div>
      );
    }

    if (socRoute.route === "evidence") {
      return (
        <div className="relative w-full min-h-screen">
          <SafeView name="Evidence Vault">
            <EvidenceVaultPage onNavigate={navigateTo} />
          </SafeView>
        </div>
      );
    }

    if (socRoute.route === "reports") {
      return (
        <div className="relative w-full min-h-screen">
          <SafeView name="Forensic Reports">
            <ReportsPage onNavigate={navigateTo} />
          </SafeView>
        </div>
      );
    }

    if (socRoute.route === "settings") {
      return (
        <div className="relative w-full min-h-screen">
          <SafeView name="System Settings">
            <SettingsPage onNavigate={navigateTo} />
          </SafeView>
        </div>
      );
    }
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
              riskScore={82} 
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
            onClick={() => setIsRbacOpen(true)}
            className="p-2 hover:bg-accent rounded-full transition-colors text-muted-foreground hover:text-foreground"
            title="RBAC Settings"
          >
            <Settings className="w-4 h-4" />
          </button>
        </header>

        {/* Main Content */}
        <main className="relative z-10 flex-1 flex flex-col p-6 gap-6 overflow-y-auto custom-scrollbar">
          
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
          </section>

          {/* Breakdown Panel */}
          <RiskBreakdown loading={loading} />

          {/* Gmail Inbox Simulation */}
          <GmailInboxRiskIndicators />

          {/* Why Flagged Section */}
          <WhyFlagged loading={loading} />

        </main>

        {/* Footer / Actions */}
        <footer className="relative z-10 p-6 pt-2 bg-gradient-to-t from-background to-transparent">
          <ActionButtons
            currentEmailSnippet="High risk phishing email targeting corporate credentials"
            onOpenDashboard={() => navigateToInvestigation("SS-2026-0912-00421")}
          />
        </footer>
      </div>

      {/* Global Modals for Extra Features */}
      <CtiLookupModal isOpen={isCtiOpen} onClose={() => setIsCtiOpen(false)} />
      <VipRosterModal isOpen={isVipOpen} onClose={() => setIsVipOpen(false)} />
      <AuthRbacModal isOpen={isRbacOpen} onClose={() => setIsRbacOpen(false)} onUserChanged={setCurrentUser} />
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