import React, { useState } from "react";
import {
  Search,
  Bell,
  Check,
  Copy,
  Terminal,
  Activity,
  ChevronRight,
  Shield,
  Filter,
} from "lucide-react";

interface TopHeaderProps {
  investigationId: string;
  onSelectCaseId?: (caseId: string) => void;
  onBackToDashboard?: () => void;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  investigationId,
  onSelectCaseId,
  onBackToDashboard,
}) => {
  const [copied, setCopied] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [showNotifications, setShowNotifications] = useState(false);

  const handleCopy = () => {
    navigator.clipboard?.writeText(investigationId);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const sampleNotifications = [
    { id: 1, title: "Threat Cluster Correlated", time: "2m ago", desc: "Similar credential harvesting detected in European tenant" },
    { id: 2, title: "Perimeter Rule Updated", time: "8m ago", desc: "IP 185.220.101.5 quarantined across firewall egress" },
    { id: 3, title: "MTA Relay Verified", time: "14m ago", desc: "Sender domain paypa1-support.com added to blocklist" },
  ];

  return (
    <header
      className="h-16 px-6 border-b border-cyan-500/15 flex items-center justify-between gap-4 sticky top-0 z-20 backdrop-blur-xl"
      style={{
        background: "rgba(7, 11, 20, 0.85)",
      }}
    >
      {/* Left: Context */}
      <div className="flex items-center gap-3 min-w-0">
        {/* Investigation ID Pill */}
        <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-xs">
          <span className="text-[10px] uppercase tracking-wider text-cyan-400/70 font-mono font-bold">
            ID
          </span>
          <span className="font-mono font-bold text-cyan-200">{investigationId}</span>
          <button
            onClick={handleCopy}
            className="text-cyan-400 hover:text-white transition-colors ml-0.5"
            title="Copy Investigation ID"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          </button>
        </div>

        {/* Context Label */}
        <span className="text-xs text-slate-400 hidden lg:inline font-mono">
          Gmail • Email Analysis
        </span>
      </div>

      {/* Middle/Right: Live System Engine & Search & Actions */}
      <div className="flex items-center gap-3.5">
        {/* Live System Indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/25">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
          </span>
          <span className="text-xs font-bold text-emerald-300 tracking-wide font-mono">
            Analysis Engine Online
          </span>
        </div>

        {/* Global Search Bar */}
        <div className="relative hidden sm:block w-48 md:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search IOCs, IPs, domains..."
            className="w-full bg-slate-900/80 border border-cyan-500/20 rounded-xl pl-8 pr-8 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition-all font-sans"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] font-mono text-slate-500 bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
            ⌘K
          </kbd>
        </div>

        {/* Preset Investigation Selector */}
        {onSelectCaseId && (
          <select
            value={investigationId}
            onChange={(e) => onSelectCaseId(e.target.value)}
            className="bg-slate-900 border border-cyan-500/30 text-xs font-mono font-semibold text-cyan-300 rounded-xl px-2.5 py-1.5 outline-none focus:border-cyan-400 hidden xl:block cursor-pointer"
            title="Switch Case"
          >
            {!["SS-2026-0912-00421", "INV-2026-9041", "INV-2026-8812", "INV-2026-7734"].includes(investigationId) && (
              <option value={investigationId}>Case: {investigationId} (Live Vault)</option>
            )}
            <option value="SS-2026-0912-00421">Case: SS-2026-0912-00421 (PayPal Phish)</option>
            <option value="INV-2026-9041">Case: INV-2026-9041 (M365 Phish)</option>
            <option value="INV-2026-8812">Case: INV-2026-8812 (DHL Malware)</option>
            <option value="INV-2026-7734">Case: INV-2026-7734 (Internal Memo)</option>
          </select>
        )}

        {/* Notifications */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-xl text-slate-400 hover:text-cyan-300 hover:bg-cyan-500/10 border border-transparent hover:border-cyan-500/20 transition-all"
            title="Notifications"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-cyan-400 ring-2 ring-[#070b14]" />
          </button>

          {showNotifications && (
            <div
              className="absolute right-0 top-full mt-2 w-80 rounded-2xl border border-cyan-500/25 p-4 shadow-2xl z-50 space-y-3"
              style={{ background: "rgba(10, 16, 32, 0.98)", backdropFilter: "blur(24px)" }}
            >
              <div className="flex items-center justify-between pb-2 border-b border-white/5">
                <span className="text-xs font-bold text-white uppercase tracking-wider">Live SOC Alerts</span>
                <span className="text-[10px] text-cyan-400 font-mono font-bold">3 UNREAD</span>
              </div>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {sampleNotifications.map((n) => (
                  <div key={n.id} className="p-2.5 rounded-xl bg-white/3 border border-white/5 hover:border-cyan-500/30 transition-all">
                    <div className="flex items-center justify-between text-xs mb-0.5">
                      <span className="font-semibold text-slate-200">{n.title}</span>
                      <span className="text-[10px] text-slate-500 font-mono">{n.time}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">{n.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User Avatar */}
        <div className="flex items-center gap-2 pl-1 border-l border-white/10">
          <div className="relative w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center font-bold text-xs text-white border border-cyan-400/40 shadow-sm">
            AM
            <span className="absolute bottom-0 right-0 w-2 h-2 rounded-full bg-emerald-400 ring-1 ring-slate-950" />
          </div>
        </div>
      </div>
    </header>
  );
};
