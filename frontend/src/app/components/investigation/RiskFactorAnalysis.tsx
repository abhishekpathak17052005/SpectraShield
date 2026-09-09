import React, { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  ChevronDown,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Sliders,
  Layers,
  Info,
  CheckCircle2,
  ExternalLink,
} from "lucide-react";
import { RiskFactor, SeverityLevel } from "../../types/investigation";

interface Props {
  factors: RiskFactor[];
}

export const RiskFactorAnalysis: React.FC<Props> = ({ factors }) => {
  const [expandedFactor, setExpandedFactor] = useState<string | null>(factors[0]?.id || null);

  const toggleFactor = (id: string) => {
    setExpandedFactor((prev) => (prev === id ? null : id));
  };

  const getSeverityStyle = (score: number | null, level: SeverityLevel) => {
    if (score === null || level === "NOT_ENRICHED") {
      return {
        badge: "bg-slate-700/40 text-slate-500 border-slate-600/30 font-medium",
        label: "NOT ENRICHED",
        glow: "transparent",
        color: "#64748B",
        fillColor: "from-slate-700 to-slate-600",
        isUnenriched: true,
      };
    }
    if (score >= 90) {
      return {
        badge: "bg-red-500/15 text-red-400 border-red-500/40 font-bold",
        label: "CRITICAL",
        glow: "rgba(239, 68, 68, 0.4)",
        color: "#EF4444",
        fillColor: "from-red-600 via-rose-500 to-red-400",
        isUnenriched: false,
      };
    }
    if (score >= 70) {
      return {
        badge: "bg-rose-500/15 text-rose-300 border-rose-500/30 font-semibold",
        label: "HIGH",
        glow: "rgba(244, 63, 94, 0.3)",
        color: "#F43F5E",
        fillColor: "from-rose-600 via-amber-500 to-rose-400",
        isUnenriched: false,
      };
    }
    if (score >= 30) {
      return {
        badge: "bg-amber-500/15 text-amber-300 border-amber-500/30 font-medium",
        label: "SUSPICIOUS",
        glow: "rgba(245, 158, 11, 0.25)",
        color: "#F59E0B",
        fillColor: "from-amber-600 to-yellow-400",
        isUnenriched: false,
      };
    }
    return {
      badge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-medium",
      label: "SAFE",
      glow: "rgba(16, 185, 129, 0.25)",
      color: "#10B981",
      fillColor: "from-emerald-600 to-teal-400",
      isUnenriched: false,
    };
  };

  return (
    <div
      className="p-6 rounded-2xl border border-cyan-500/20 relative overflow-hidden shadow-2xl"
      style={{
        background: "linear-gradient(135deg, rgba(10, 16, 32, 0.95) 0%, rgba(6, 10, 22, 0.98) 100%)",
        backdropFilter: "blur(20px)",
      }}
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 pb-4 border-b border-white/5">
        <div>
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm md:text-base font-extrabold text-white tracking-widest uppercase font-mono">
              Risk Factor Analysis
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5 font-sans">
            Granular evaluation across 8 independent threat vectors
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 flex-wrap">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500" /> CRITICAL (90+)
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-rose-400" /> HIGH (70–89)
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400" /> SUSPICIOUS (30–69)
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400" /> SAFE (0–29)
          </span>
        </div>
      </div>

      {/* Grid of 8 Risk Factors */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {factors.map((factor) => {
          const isExpanded = expandedFactor === factor.id;
          const sev = getSeverityStyle(factor.score, factor.severity);

          // 12-segment analytical meter
          const totalSegments = 12;
          const activeSegments = sev.isUnenriched ? 0 : Math.round(((factor.score ?? 0) / 100) * totalSegments);

          return (
            <div
              key={factor.id}
              className={`rounded-xl border transition-all duration-200 overflow-hidden ${
                isExpanded
                  ? "border-cyan-500/40 bg-slate-900/90 shadow-xl shadow-black/50"
                  : "border-white/5 bg-white/2 hover:border-cyan-500/20 hover:bg-white/4"
              }`}
            >
              {/* Factor Header / Interactive Card */}
              <button
                onClick={() => toggleFactor(factor.id)}
                className="w-full p-4 flex items-start justify-between gap-3 text-left transition-colors"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-sm font-bold text-slate-200 truncate font-sans">
                      {factor.name}
                    </span>
                    <div className="flex items-center gap-2">
                      {sev.isUnenriched ? (
                        <span className="text-xs font-mono text-slate-500 italic">—</span>
                      ) : (
                        <span className="text-xs font-mono font-black text-white">
                          {factor.score}
                          <span className="text-[10px] text-slate-500 font-normal">/100</span>
                        </span>
                      )}
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono border ${sev.badge}`}
                      >
                        {sev.label}
                      </span>
                    </div>
                  </div>

                  {/* Elegant Segmented Analytical Telemetry Bar */}
                  <div className="flex items-center gap-1 my-2">
                    {Array.from({ length: totalSegments }).map((_, segIdx) => {
                      const isActive = segIdx < activeSegments;
                      return (
                        <div
                          key={segIdx}
                          className="h-2 flex-1 rounded-sm transition-all duration-500"
                          style={{
                            background: isActive
                              ? sev.color
                              : "rgba(255, 255, 255, 0.08)",
                            boxShadow: isActive ? `0 0 6px ${sev.glow}` : "none",
                            opacity: isActive ? 0.95 : 0.4,
                          }}
                        />
                      );
                    })}
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-1 mt-1 font-sans">
                    {factor.explanation}
                  </p>
                </div>

                <div className="p-1 rounded-lg hover:bg-white/5 text-slate-400 mt-0.5">
                  <ChevronDown
                    className={`w-4 h-4 transition-transform duration-200 ${
                      isExpanded ? "rotate-180 text-cyan-400" : ""
                    }`}
                  />
                </div>
              </button>

              {/* Expandable Forensic Evidence Details */}
              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.2 }}
                    className="border-t border-white/5 px-4 pb-4 pt-3 bg-black/25 space-y-3"
                  >
                    <div className="text-[11px] text-slate-300 font-sans leading-relaxed">
                      {factor.explanation}
                    </div>

                    <div className="space-y-1.5 pt-1">
                      <div className="text-[10px] uppercase font-mono tracking-wider text-slate-500 font-semibold">
                        Forensic Evidence Items:
                      </div>
                      {factor.evidence.map((ev, i) => (
                        <div
                          key={i}
                          className={`p-2 rounded-lg border text-xs flex items-start justify-between gap-3 ${
                            ev.flagged
                              ? "border-red-500/25 bg-red-500/5 text-red-200"
                              : "border-white/5 bg-white/2 text-slate-300"
                          }`}
                        >
                          <span className="font-semibold text-slate-400 flex-shrink-0">
                            {ev.label}:
                          </span>
                          <span className="font-mono text-right truncate flex-1 text-slate-200">
                            {ev.value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </div>
  );
};
