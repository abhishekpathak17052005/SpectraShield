import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  ShieldAlert,
  Sliders,
  Crosshair,
  Server,
  Link2,
  GitBranch,
  FileText,
  Search,
  RefreshCw,
  Layers,
  ArrowLeft,
  ChevronDown,
  Info,
  Globe,
  Radio,
  Clock,
  Download,
  AlertOctagon,
  WifiOff,
  HelpCircle,
} from "lucide-react";
import { InvestigationRecord } from "../../types/investigation";
import { getInvestigationById } from "../../services/investigationService";
import { getExportPdfUrl, updateCaseStatus } from "../../api";
import { Sidebar, NavItemKey } from "./Sidebar";
import { TopHeader } from "./TopHeader";
import { InvestigationHeader } from "./InvestigationHeader";
import { RiskFactorAnalysis } from "./RiskFactorAnalysis";
import { ThreatAssessment } from "./ThreatAssessment";
import { AttackTechniques } from "./AttackTechniques";
import { UserActionsBar } from "./UserActionsBar";
import { OverviewTab } from "./tabs/OverviewTab";
import { HeaderForensicsTab } from "./tabs/HeaderForensicsTab";
import { UrlIntelligenceTab } from "./tabs/UrlIntelligenceTab";
import { InfrastructureTab } from "./tabs/InfrastructureTab";
import { ThreatGraphTab } from "./tabs/ThreatGraphTab";
import { EvidenceVaultTab } from "./tabs/EvidenceVaultTab";

type TabKey = "overview" | "headers" | "infrastructure" | "urls" | "graph" | "evidence";
type ErrorType = "NOT_FOUND" | "BACKEND_UNAVAILABLE" | "UNAUTHORIZED" | null;

interface Props {
  initialId?: string;
  investigationId?: string;
  onBackToDashboard?: () => void;
  onNavigateToCase?: (id: string) => void;
  onNavigate?: (route: string) => void;
}

export const InvestigationPage: React.FC<Props> = ({
  initialId,
  investigationId,
  onBackToDashboard,
  onNavigateToCase,
  onNavigate,
}) => {
  const currentIdProp = initialId || investigationId || "SS-2026-0912-00421";
  const [activeId, setActiveId] = useState<string>(currentIdProp);
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [activeNav, setActiveNav] = useState<NavItemKey>("investigations");
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [loading, setLoading] = useState<boolean>(true);
  const [investigationData, setInvestigationData] = useState<InvestigationRecord | null>(null);
  const [errorType, setErrorType] = useState<ErrorType>(null);
  const [errorMessage, setErrorMessage] = useState<string>("");

  useEffect(() => {
    if (initialId || investigationId) {
      setActiveId(initialId || investigationId || "SS-2026-0912-00421");
    }
  }, [initialId, investigationId]);

  const loadInvestigation = (id: string) => {
    setLoading(true);
    setErrorType(null);
    setErrorMessage("");
    setInvestigationData(null);

    getInvestigationById(id)
      .then((data) => {
        setInvestigationData(data);
        setLoading(false);
      })
      .catch((err: any) => {
        console.error("Investigation load error:", err);
        const code = err?.code || "";
        const msg = String(err?.message || "Unknown error");
        if (code === "NOT_FOUND" || msg.toLowerCase().includes("not found")) {
          setErrorType("NOT_FOUND");
          setErrorMessage(msg);
        } else if (code === "BACKEND_UNAVAILABLE" || msg.toLowerCase().includes("unavailable") || msg.toLowerCase().includes("fetch")) {
          setErrorType("BACKEND_UNAVAILABLE");
          setErrorMessage(msg);
        } else {
          setErrorType("BACKEND_UNAVAILABLE");
          setErrorMessage(msg);
        }
        setLoading(false);
      });
  };

  useEffect(() => {
    loadInvestigation(activeId);
  }, [activeId]);

  const handleSelectCase = (id: string) => {
    setActiveId(id);
    onNavigateToCase?.(id);
    if (typeof window !== "undefined") {
      window.history.pushState({ investigationId: id }, "", `/investigations/${encodeURIComponent(id)}`);
    }
  };

  const handleReportThreat = async () => {
    try {
      await updateCaseStatus(activeId, "INVESTIGATING", "Analyst reported threat via SOC console");
    } catch {
      // offline / demo fallback
    }
  };

  const handleMarkSafeAction = async () => {
    try {
      await updateCaseStatus(activeId, "CLOSED", "Analyst marked case as safe");
    } catch {
      // offline / demo fallback
    }
  };

  const tabs: Array<{ key: TabKey; label: string; icon: React.FC<{ className?: string }> }> = [
    { key: "overview", label: "Overview", icon: Layers },
    { key: "headers", label: "Email Headers", icon: Server },
    { key: "infrastructure", label: "Infrastructure", icon: Globe },
    { key: "urls", label: "URL Intelligence", icon: Link2 },
    { key: "graph", label: "Threat Graph", icon: GitBranch },
    { key: "evidence", label: "Evidence Vault", icon: FileText },
  ];

  // ─── Error: Backend Unavailable ────────────────────────────────────────────
  const renderBackendOffline = () => (
    <div className="w-full min-h-[60vh] flex flex-col items-center justify-center p-10 rounded-2xl border border-orange-500/30 bg-orange-500/5 text-center gap-5">
      <div className="w-16 h-16 rounded-2xl bg-orange-500/10 border border-orange-500/30 flex items-center justify-center">
        <WifiOff className="w-8 h-8 text-orange-400" />
      </div>
      <div>
        <div className="text-sm font-bold text-white font-mono tracking-wide mb-1">
          SpectraShield Analysis Backend Unavailable
        </div>
        <p className="text-xs text-slate-400 max-w-md leading-relaxed">
          The SpectraShield FastAPI backend is not responding on port 8000. Verify the server is
          running and accessible before loading live intelligence.
        </p>
        {errorMessage && (
          <p className="text-[11px] text-orange-400/70 font-mono mt-2 max-w-md break-words">
            {errorMessage}
          </p>
        )}
      </div>
      <div className="flex items-center gap-3">
        <button
          onClick={() => loadInvestigation(activeId)}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-orange-300 bg-orange-500/15 border border-orange-500/30 hover:bg-orange-500/25 transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Retry Connection
        </button>
        <button
          onClick={() => handleSelectCase("SS-2026-0912-00421")}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/25 hover:bg-amber-500/20 transition-all"
        >
          <Info className="w-3.5 h-3.5" />
          Load Demo Investigation
        </button>
      </div>
      <div className="text-[10px] text-slate-600 font-mono">
        STATUS: BACKEND_OFFLINE · No fallback to demo data
      </div>
    </div>
  );

  // ─── Error: Not Found ───────────────────────────────────────────────────────
  const renderNotFound = () => (
    <div className="w-full min-h-[60vh] flex flex-col items-center justify-center p-10 rounded-2xl border border-red-500/30 bg-red-500/5 text-center gap-5">
      <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center">
        <HelpCircle className="w-8 h-8 text-red-400" />
      </div>
      <div>
        <div className="text-sm font-bold text-white font-mono tracking-wide mb-1">
          Investigation Not Found
        </div>
        <p className="text-[11px] font-mono text-red-400/80 mb-2">{activeId}</p>
        <p className="text-xs text-slate-400 max-w-md leading-relaxed">
          No investigation record matching this ID was found in the SpectraShield vault. The case
          may have been archived, or the ID may be incorrect.
        </p>
      </div>
      <div className="flex items-center gap-3">
        <button
          onClick={() => handleSelectCase("SS-2026-0912-00421")}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/25 hover:bg-amber-500/20 transition-all"
        >
          <Info className="w-3.5 h-3.5" />
          Load Demo Investigation
        </button>
        {onBackToDashboard && (
          <button
            onClick={onBackToDashboard}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-slate-300 bg-white/5 border border-white/10 hover:bg-white/10 transition-all"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Cases
          </button>
        )}
      </div>
      <div className="text-[10px] text-slate-600 font-mono">
        STATUS: NOT_FOUND · No demo substitution applied
      </div>
    </div>
  );

  return (
    <div
      className="w-full min-h-screen flex text-foreground font-sans transition-colors duration-300 antialiased overflow-x-hidden"
      style={{
        background: "linear-gradient(135deg, #05070d 0%, #080d1a 50%, #050812 100%)",
      }}
    >
      {/* ─── LEFT COLLAPSIBLE SIDEBAR ────────────────────────────────────────── */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        activeItem={activeNav}
        onSelectItem={(item) => {
          setActiveNav(item);
          const navMap: Record<NavItemKey, string> = {
            overview: "/overview",
            investigations: "/investigations",
            mail_intelligence: "/mail-intelligence",
            email_intelligence: "/mail-intelligence",
            threat_intelligence: "/threat-intelligence",
            forensics: "/forensic-intelligence",
            evidence: "/evidence",
            reports: "/reports",
            settings: "/settings",
          };
          const target = navMap[item];
          if (target && onNavigate) {
            onNavigate(target);
          } else if (item === "overview" && onBackToDashboard) {
            onBackToDashboard();
          }
        }}
      />

      {/* ─── MAIN WORKSPACE COLUMN ───────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen">
        {/* Top Header */}
        <TopHeader
          investigationId={activeId}
          onSelectCaseId={handleSelectCase}
          onBackToDashboard={onBackToDashboard}
        />

        {/* Scrollable Main Content */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-[1600px] w-full mx-auto space-y-8">
          {loading ? (
            <div className="w-full min-h-[60vh] flex flex-col items-center justify-center gap-4">
              <div
                className="w-12 h-12 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin"
                style={{ borderColor: "rgba(0, 229, 255, 0.15)", borderTopColor: "#00E5FF" }}
              />
              <div className="text-xs font-mono text-slate-400 uppercase tracking-widest animate-pulse">
                Loading Investigation {activeId}…
              </div>
            </div>
          ) : errorType === "BACKEND_UNAVAILABLE" ? (
            renderBackendOffline()
          ) : errorType === "NOT_FOUND" ? (
            renderNotFound()
          ) : investigationData ? (
            <div className="space-y-8">
              {/* 1. PRIMARY INVESTIGATION HERO */}
              <InvestigationHeader
                meta={investigationData.meta}
                risk={investigationData.risk}
                onMarkSafe={handleMarkSafeAction}
                onReportThreat={handleReportThreat}
                onExportReport={() => window.open(getExportPdfUrl(activeId, false))}
              />

              {/* 2. THREAT FACTOR BREAKDOWN */}
              <RiskFactorAnalysis factors={investigationData.riskFactors} />

              {/* 3. EMAIL THREAT SUMMARY & AI EXPLANATION */}
              <ThreatAssessment assessment={investigationData.threatAssessment} />

              {/* 4. ATTACK TECHNIQUES (MITRE ATT&CK Matrix) */}
              <AttackTechniques techniques={investigationData.threatAssessment.detectedTechniques} />

              {/* 5. FORENSIC INTELLIGENCE WORKSPACE TABS */}
              <div
                className="p-6 rounded-2xl border border-cyan-500/20 shadow-2xl space-y-6"
                style={{
                  background: "linear-gradient(135deg, rgba(10, 16, 32, 0.95) 0%, rgba(6, 10, 22, 0.98) 100%)",
                  backdropFilter: "blur(20px)",
                }}
              >
                {/* Forensic Intelligence Workspace Header */}
                <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-white/5">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                      <Layers className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div>
                      <h2 className="text-sm md:text-base font-extrabold text-white tracking-widest uppercase font-mono">
                        FORENSIC INTELLIGENCE WORKSPACE
                      </h2>
                      <p className="text-xs text-slate-400 font-sans">
                        Deep forensic telemetry, protocol authentication, and adversary infrastructure attribution
                      </p>
                    </div>
                  </div>

                  {/* Tabs Navigation */}
                  <div className="flex items-center gap-1.5 p-1 rounded-xl bg-black/40 border border-white/10 overflow-x-auto max-w-full">
                    {tabs.map((tab) => {
                      const Icon = tab.icon;
                      const isActive = activeTab === tab.key;
                      return (
                        <button
                          key={tab.key}
                          onClick={() => setActiveTab(tab.key)}
                          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all whitespace-nowrap ${
                            isActive
                              ? "bg-cyan-500/20 text-cyan-200 border border-cyan-500/40 shadow-sm"
                              : "text-slate-400 hover:text-slate-200 hover:bg-white/5 border border-transparent"
                          }`}
                        >
                          <Icon className={`w-3.5 h-3.5 ${isActive ? "text-cyan-400" : "text-slate-500"}`} />
                          <span>{tab.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Tab Content Panels */}
                <div>
                  {activeTab === "overview" && (
                    <OverviewTab
                      data={investigationData}
                    />
                  )}

                  {activeTab === "headers" && (
                    <HeaderForensicsTab headers={investigationData.headers} />
                  )}

                  {activeTab === "infrastructure" && (
                    <InfrastructureTab infrastructure={investigationData.infrastructure} />
                  )}

                  {activeTab === "urls" && (
                    <UrlIntelligenceTab urlData={investigationData.urlIntelligence} />
                  )}

                  {activeTab === "graph" && (
                    <ThreatGraphTab graphData={investigationData.threatGraph} />
                  )}

                  {activeTab === "evidence" && (
                    <EvidenceVaultTab
                      evidenceList={investigationData.evidence}
                      investigationId={activeId}
                    />
                  )}
                </div>
              </div>

              {/* 6. USER ACTIONS BAR */}
              <UserActionsBar
                investigationId={activeId}
                mode={investigationData.mode}
                onReportPhishing={handleReportThreat}
                onMarkSafe={handleMarkSafeAction}
                onExportReport={() => window.open(getExportPdfUrl(activeId, false))}
                onInvestigateFurther={() => setActiveTab("graph")}
              />
            </div>
          ) : (
            renderBackendOffline()
          )}
        </main>
      </div>
    </div>
  );
};

export default InvestigationPage;
