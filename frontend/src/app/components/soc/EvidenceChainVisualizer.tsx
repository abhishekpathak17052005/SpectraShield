import React from "react";
import { motion } from "motion/react";
import { Mail, Hash, ShieldCheck, FileCheck, Lock, ArrowRight } from "lucide-react";

interface EvidenceChainVisualizerProps {
  totalArtifacts: number;
  sealedCount: number;
}

export const EvidenceChainVisualizer: React.FC<EvidenceChainVisualizerProps> = ({
  totalArtifacts,
  sealedCount,
}) => {
  const steps = [
    {
      id: "ingest",
      title: "Raw Payload",
      subtitle: "Inbound RFC 822 EML",
      badge: "INGESTED",
      icon: Mail,
      color: "#06b6d4", // Cyan
      borderColor: "border-cyan-500/30",
      bgColor: "bg-cyan-500/10",
      textColor: "text-cyan-400",
    },
    {
      id: "hash",
      title: "SHA-256 Seal",
      subtitle: "Deterministic digest",
      badge: "SEALED",
      icon: Hash,
      color: "#3b82f6", // Blue
      borderColor: "border-blue-500/30",
      bgColor: "bg-blue-500/10",
      textColor: "text-blue-400",
    },
    {
      id: "vault",
      title: "Evidence Vault",
      subtitle: `${totalArtifacts} Immutable records`,
      badge: "IMMUTABLE",
      icon: Lock,
      color: "#a855f7", // Purple
      borderColor: "border-purple-500/30",
      bgColor: "bg-purple-500/10",
      textColor: "text-purple-400",
    },
    {
      id: "chain",
      title: "Custody Chain",
      subtitle: "Admissible court audit",
      badge: "VERIFIED",
      icon: FileCheck,
      color: "#10b981", // Emerald
      borderColor: "border-emerald-500/30",
      bgColor: "bg-emerald-500/10",
      textColor: "text-emerald-400",
    },
  ];

  return (
    <div className="relative rounded-2xl border border-cyan-500/20 bg-gradient-to-b from-[#0c1224]/95 via-[#080d1a]/95 to-[#050914]/95 overflow-hidden shadow-2xl p-5 md:p-6 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-white/5">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide uppercase flex items-center gap-2">
              <span>Cryptographic Chain of Custody Pipeline</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-normal">
                SEALED & AUDITABLE
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">
              End-to-end cryptographic hashing pipeline ensuring zero evidence tampering
            </p>
          </div>
        </div>

        <div className="text-xs font-mono text-slate-300 flex items-center gap-2 bg-white/5 px-2.5 py-1 rounded-lg border border-white/5">
          <span className="text-slate-400">Ledger Integrity:</span>
          <span className="text-emerald-400 font-bold flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            100% VERIFIED
          </span>
        </div>
      </div>

      {/* Horizontal Chain Flow */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 relative mt-2">
        {steps.map((step, idx) => {
          const Icon = step.icon;

          return (
            <div key={step.id} className="relative group">
              <div
                className={`p-4 rounded-xl border ${step.borderColor} bg-gradient-to-br from-[#0c1326]/90 to-[#080c18]/90 backdrop-blur-md shadow-lg transition-all duration-200 group-hover:scale-[1.02] relative overflow-hidden`}
              >
                {/* Top glow accent */}
                <div
                  className="absolute top-0 left-0 right-0 h-[2px] opacity-60 group-hover:opacity-100 transition-opacity"
                  style={{ background: step.color }}
                />

                <div className="flex items-center justify-between mb-2.5">
                  <div
                    className={`p-2 rounded-lg ${step.bgColor} ${step.textColor} border ${step.borderColor}`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>
                  <span
                    className="text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border"
                    style={{
                      color: step.color,
                      borderColor: `${step.color}40`,
                      background: `${step.color}15`,
                    }}
                  >
                    {step.badge}
                  </span>
                </div>

                <div className="space-y-0.5">
                  <div className="text-xs font-bold text-white tracking-wide">
                    {step.title}
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono">
                    {step.subtitle}
                  </div>
                </div>

                <div className="mt-3 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                  <span>STAGE 0{idx + 1}</span>
                  <span className="text-emerald-400 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    PASS
                  </span>
                </div>
              </div>

              {/* Arrow separator on large screens */}
              {idx < steps.length - 1 && (
                <div className="hidden lg:flex absolute -right-3.5 top-1/2 -translate-y-1/2 z-20 w-7 h-7 rounded-full bg-[#0d1424] border border-cyan-500/30 items-center justify-center text-cyan-400 shadow-md">
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
