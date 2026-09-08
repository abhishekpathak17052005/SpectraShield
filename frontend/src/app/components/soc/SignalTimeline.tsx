import React, { useState } from "react";
import { motion } from "motion/react";
import { Copy, Check, ShieldAlert, AlertTriangle, ShieldCheck, Zap } from "lucide-react";
import { WhyFlaggedReason } from "../../types/investigation";

interface SignalTimelineProps {
  signals: WhyFlaggedReason[];
}

export const SignalTimeline: React.FC<SignalTimelineProps> = ({ signals }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleCopy = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  if (!signals || signals.length === 0) {
    return (
      <div className="p-6 rounded-xl border border-white/5 bg-[#0f172a]/50 text-xs text-slate-400 text-center">
        No anomalous signals detected in this message.
      </div>
    );
  }

  return (
    <div className="relative pl-6 sm:pl-8 space-y-4">
      {/* Vertical Connecting Tracer Line */}
      <div className="absolute left-[11px] sm:left-[15px] top-4 bottom-4 w-[2px] bg-gradient-to-b from-cyan-500/50 via-blue-500/30 to-slate-700/20" />

      {signals.map((item, idx) => {
        const isHigh = item.severity === "HIGH" || item.severity === "CRITICAL";
        const isMed = item.severity === "MEDIUM" || item.severity === "SUSPICIOUS";

        const dotColor = isHigh ? "bg-red-400" : isMed ? "bg-amber-400" : "bg-emerald-400";
        const dotRing = isHigh
          ? "border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.5)]"
          : isMed
          ? "border-amber-500/50 shadow-[0_0_10px_rgba(245,158,11,0.5)]"
          : "border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.5)]";

        return (
          <motion.div
            key={idx}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3, delay: idx * 0.08 }}
            className="relative group"
          >
            {/* Timeline Node Dot on the Tracer Line */}
            <div
              className={`absolute -left-[23px] sm:-left-[27px] top-4 w-3.5 h-3.5 rounded-full bg-[#0b101d] border-2 ${dotRing} flex items-center justify-center`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
            </div>

            {/* Signal Card Content */}
            <div className="p-4 rounded-xl border border-white/5 bg-gradient-to-br from-[#0e1628]/80 to-[#0b1120]/90 backdrop-blur-md shadow-md hover:border-white/15 transition-all space-y-2.5">
              {/* Header: Signal ID, Category, Contribution */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-white/5 text-slate-300 border border-white/10">
                    SIG-{String(idx + 1).padStart(2, "0")}
                  </span>
                  <span
                    className={`text-[10px] font-semibold px-2 py-0.5 rounded border uppercase flex items-center gap-1 ${
                      isHigh
                        ? "bg-red-500/15 text-red-300 border-red-500/30"
                        : isMed
                        ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
                        : "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                    }`}
                  >
                    {isHigh ? (
                      <ShieldAlert className="w-3 h-3" />
                    ) : isMed ? (
                      <AlertTriangle className="w-3 h-3" />
                    ) : (
                      <ShieldCheck className="w-3 h-3" />
                    )}
                    <span>{item.severity}</span>
                  </span>
                  <span className="text-xs font-semibold text-slate-200">
                    {item.category}
                  </span>
                </div>

                {typeof item.contribution === "number" && item.contribution > 0 && (
                  <span className="text-xs font-mono font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20 flex items-center gap-1">
                    <Zap className="w-3 h-3" />
                    <span>+{item.contribution}% Risk</span>
                  </span>
                )}
              </div>

              {/* Explanation Text */}
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {item.explanation}
              </p>

              {/* Evidence Box */}
              {item.evidence && (
                <div className="pt-2 border-t border-white/5 text-[11px] font-mono text-slate-400 bg-black/20 p-2.5 rounded-lg border border-white/5 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <span className="text-slate-500 block text-[10px] uppercase tracking-wider font-semibold">
                      Extracted Evidence Snippet:
                    </span>
                    <span className="text-slate-200 break-all select-all font-mono mt-0.5 block">
                      {item.evidence}
                    </span>
                  </div>
                  <button
                    onClick={() => handleCopy(item.evidence!, idx)}
                    className="p-1 rounded text-slate-400 hover:text-cyan-300 hover:bg-white/5 transition-colors flex-shrink-0"
                    title="Copy evidence snippet"
                  >
                    {copiedIndex === idx ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              )}
            </div>
          </motion.div>
        );
      })}
    </div>
  );
};
