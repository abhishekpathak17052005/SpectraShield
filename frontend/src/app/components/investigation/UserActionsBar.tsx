import React, { useState } from "react";
import {
  Flag,
  ShieldCheck,
  GitBranch,
  Download,
  Check,
  AlertOctagon,
  Database,
} from "lucide-react";

interface UserActionsBarProps {
  investigationId: string;
  mode?: "LIVE" | "DEMO";
  onReportPhishing?: () => void;
  onMarkSafe?: () => void;
  onInvestigateFurther?: () => void;
  onExportReport?: () => void;
}

export const UserActionsBar: React.FC<UserActionsBarProps> = ({
  investigationId,
  mode,
  onReportPhishing,
  onMarkSafe,
  onInvestigateFurther,
  onExportReport,
}) => {
  const [reported, setReported] = useState(false);
  const [markedSafe, setMarkedSafe] = useState(false);

  const handleReport = () => {
    setReported(true);
    setTimeout(() => setReported(false), 2500);
    onReportPhishing?.();
  };

  const handleSafe = () => {
    setMarkedSafe(true);
    setTimeout(() => setMarkedSafe(false), 2500);
    onMarkSafe?.();
  };

  const isDemo = mode === "DEMO";

  return (
    <div
      className="p-4 rounded-2xl border border-cyan-500/20 shadow-2xl flex flex-wrap items-center justify-between gap-4"
      style={{
        background: "linear-gradient(135deg, rgba(10, 16, 32, 0.95) 0%, rgba(6, 10, 22, 0.98) 100%)",
        backdropFilter: "blur(20px)",
      }}
    >
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
          <AlertOctagon className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <div className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider">
            Analyst Actions
            {isDemo && (
              <span className="ml-2 px-2 py-0.5 rounded-full text-[9px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/25">
                DEMO MODE
              </span>
            )}
          </div>
          <div className="text-[11px] text-slate-400 font-sans">
            {isDemo
              ? "Demo mode — actions are simulated and not persisted"
              : "Apply triage verdict or export forensic artifacts to vault"}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        {/* Log Threat in Vault */}
        <button
          onClick={handleReport}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 border border-red-500/40 shadow-lg shadow-red-500/25 transition-all"
        >
          {reported ? <Check className="w-4 h-4" /> : <Flag className="w-4 h-4" />}
          <span>{reported ? "Threat Logged!" : "Log Threat in Vault"}</span>
        </button>

        {/* Mark as Closed / Safe */}
        <button
          onClick={handleSafe}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 transition-all shadow-sm"
        >
          {markedSafe ? <Check className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
          <span>{markedSafe ? "Closed — Marked Safe" : "Mark as Closed / Safe"}</span>
        </button>

        {/* Inspect Threat Graph */}
        <button
          onClick={onInvestigateFurther}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold text-cyan-200 bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 transition-all shadow-sm shadow-cyan-500/10"
        >
          <GitBranch className="w-4 h-4 text-cyan-400" />
          <span>Inspect Threat Graph</span>
        </button>

        {/* Export PDF Dossier */}
        <button
          onClick={onExportReport}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold text-slate-300 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-cyan-500/40 transition-all"
        >
          <Download className="w-4 h-4 text-slate-400" />
          <span>Export PDF Dossier</span>
        </button>
      </div>
    </div>
  );
};
