import React, { useState, useEffect } from "react";
import { motion } from "motion/react";
import { Sidebar, NavItemKey } from "../investigation/Sidebar";
import {
  ShieldCheck,
  Search,
  Bell,
  ChevronRight,
  Activity,
  Terminal,
  Layers,
  Check,
  Copy,
  Clock,
  Sparkles,
  ExternalLink,
} from "lucide-react";
import { getApiBase } from "../../api";

interface SocLayoutProps {
  activeNav: NavItemKey;
  onNavigate: (route: string) => void;
  title: string;
  subtitle?: string;
  badge?: string;
  breadcrumbs?: Array<{ label: string; route?: string }>;
  actions?: React.ReactNode;
  children: React.ReactNode;
}

export const SocLayout: React.FC<SocLayoutProps> = ({
  activeNav,
  onNavigate,
  title,
  subtitle,
  badge,
  breadcrumbs,
  actions,
  children,
}) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    return localStorage.getItem("spectrashield_sidebar_collapsed") === "true";
  });
  const [backendHealth, setBackendHealth] = useState<{
    status: "healthy" | "offline" | "checking";
    version?: string;
  }>({ status: "checking" });
  const [showNotifications, setShowNotifications] = useState<boolean>(false);

  useEffect(() => {
    localStorage.setItem("spectrashield_sidebar_collapsed", String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  // Ping backend health
  useEffect(() => {
    let mounted = true;
    fetch(`${getApiBase()}/health`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!mounted) return;
        if (data && data.status === "healthy") {
          setBackendHealth({ status: "healthy", version: data.version || "2.0.0" });
        } else {
          setBackendHealth({ status: "offline" });
        }
      })
      .catch(() => {
        if (mounted) setBackendHealth({ status: "offline" });
      });
    return () => {
      mounted = false;
    };
  }, []);

  const navKeyToRoute: Record<NavItemKey, string> = {
    overview: "/overview",
    investigations: "/investigations",
    email_intelligence: "/mail-intelligence",
    mail_intelligence: "/mail-intelligence",
    threat_intelligence: "/threat-intelligence",
    forensics: "/forensic-intelligence",
    evidence: "/evidence",
    reports: "/reports",
    settings: "/settings",
  };

  const handleSelectNav = (key: NavItemKey) => {
    const route = navKeyToRoute[key];
    if (route) {
      onNavigate(route);
    }
  };

  return (
    <div
      className="w-full min-h-screen flex text-foreground font-sans transition-colors duration-300 antialiased overflow-x-hidden bg-depth-ambient relative"
      style={{
        background: "radial-gradient(ellipse 80% 50% at 50% -20%, rgba(6, 182, 212, 0.06), transparent 70%), linear-gradient(135deg, #05070d 0%, #080d1a 50%, #050812 100%)",
      }}
    >
      {/* Subtle background ambient mesh grid overlay */}
      <div 
        className="pointer-events-none absolute inset-0 z-0 opacity-25"
        style={{
          backgroundImage: "linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
          maskImage: "radial-gradient(ellipse 60% 50% at 50% 0%, black 70%, transparent 100%)",
          WebkitMaskImage: "radial-gradient(ellipse 60% 50% at 50% 0%, black 70%, transparent 100%)"
        }}
      />

      {/* ─── LEFT COLLAPSIBLE SIDEBAR ────────────────────────────────────────── */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        activeItem={activeNav}
        onSelectItem={handleSelectNav}
      />

      {/* ─── MAIN WORKSPACE COLUMN ───────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen relative z-10">
        {/* Top Header */}
        <header
          className="h-16 px-6 border-b border-cyan-500/15 flex items-center justify-between gap-4 sticky top-0 z-20 backdrop-blur-xl"
          style={{
            background: "rgba(7, 11, 20, 0.85)",
          }}
        >
          {/* Breadcrumbs & Title */}
          <div className="flex items-center gap-3 min-w-0">
            <nav className="flex items-center gap-2 text-xs font-medium text-slate-400 truncate">
              <span
                className="hover:text-slate-200 transition-colors cursor-pointer"
                onClick={() => onNavigate("/overview")}
              >
                SpectraShield
              </span>
              <ChevronRight className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
              {breadcrumbs ? (
                breadcrumbs.map((b, idx) => (
                  <React.Fragment key={idx}>
                    {idx > 0 && <ChevronRight className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />}
                    {b.route ? (
                      <span
                        className="hover:text-slate-200 transition-colors cursor-pointer truncate"
                        onClick={() => onNavigate(b.route!)}
                      >
                        {b.label}
                      </span>
                    ) : (
                      <span className="text-slate-200 font-medium truncate">{b.label}</span>
                    )}
                  </React.Fragment>
                ))
              ) : (
                <span className="text-slate-200 font-medium truncate">{title}</span>
              )}
            </nav>
          </div>

          {/* Right Controls */}
          <div className="flex items-center gap-3">
            {/* Compact Global Engine Status Area */}
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900/60 border border-white/5 shadow-inner">
              <span
                className={`w-2 h-2 rounded-full ${
                  backendHealth.status === "healthy"
                    ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]"
                    : backendHealth.status === "offline"
                    ? "bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.6)]"
                    : "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.6)]"
                }`}
              />
              <span className="text-xs text-slate-300 font-medium">
                {backendHealth.status === "healthy"
                  ? "Engine Online"
                  : backendHealth.status === "offline"
                  ? "Engine Offline"
                  : "Connecting..."}
              </span>
            </div>

            {/* Notifications Button */}
            <div className="relative">
              <button
                onClick={() => setShowNotifications(!showNotifications)}
                className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-white/5 border border-transparent transition-all relative"
                title="Notifications"
              >
                <Bell className="w-4 h-4" />
                <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(6,182,212,0.8)]" />
              </button>

              {showNotifications && (
                <div
                  className="absolute right-0 top-full mt-2 w-80 rounded-xl border border-cyan-500/20 p-4 shadow-2xl z-50 space-y-3 backdrop-blur-xl"
                  style={{ background: "rgba(13, 19, 34, 0.95)" }}
                >
                  <div className="flex items-center justify-between pb-2 border-b border-white/5">
                    <span className="text-xs font-semibold text-white">
                      Notifications
                    </span>
                    <span className="text-[10px] text-slate-400">All Systems Normal</span>
                  </div>
                  <div className="space-y-2 max-h-64 overflow-y-auto text-xs">
                    <div className="p-2.5 rounded-lg bg-white/5 border border-white/5 space-y-0.5">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-slate-200">Evidence Vault</span>
                        <span className="text-[10px] text-slate-400">Active</span>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        Evidence digests synchronized with local database.
                      </p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-white/5 border border-white/5 space-y-0.5">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-slate-200">Detection Engine</span>
                        <span className="text-[10px] text-emerald-400">Online</span>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        Analysis pipeline ready for incoming email payloads.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Analyst Avatar */}
            <div className="flex items-center gap-2 pl-2 border-l border-white/10">
              <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-cyan-600 to-indigo-700 border border-white/20 flex items-center justify-center font-medium text-xs text-white shadow-md">
                AM
              </div>
              <div className="hidden lg:block leading-tight">
                <div className="text-xs font-medium text-slate-200">Alex Mercer</div>
                <div className="text-[10px] text-cyan-300/70 font-mono">SOC Analyst</div>
              </div>
            </div>
          </div>
        </header>

        {/* Workspace Title Strip */}
        {(subtitle || actions) && (
          <div className="px-6 py-4 border-b border-white/5 flex flex-wrap items-center justify-between gap-4 bg-slate-900/20 backdrop-blur-sm">
            <div>
              <h1 className="text-lg md:text-xl font-semibold text-white tracking-tight flex items-center gap-2.5">
                <span>{title}</span>
                {badge && (
                  <span className="text-xs font-medium px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                    {badge}
                  </span>
                )}
              </h1>
              {subtitle && <p className="text-xs text-slate-400 mt-1">{subtitle}</p>}
            </div>
            {actions && <div className="flex items-center gap-2.5">{actions}</div>}
          </div>
        )}

        {/* Scrollable Main Content with gentle transition */}
        <motion.main 
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, ease: "easeOut" }}
          className="flex-1 p-4 sm:p-6 lg:p-8 max-w-[1600px] w-full mx-auto space-y-6"
        >
          {children}
        </motion.main>
      </div>
    </div>
  );
};
