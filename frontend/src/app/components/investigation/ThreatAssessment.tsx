import React, { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Brain,
  Crosshair,
  AlertOctagon,
  CheckCircle2,
  ChevronDown,
  ShieldAlert,
  Layers,
  Sparkles,
  Info,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";
import { ThreatAssessmentData } from "../../types/investigation";

interface Props {
  assessment: ThreatAssessmentData;
}

export const ThreatAssessment: React.FC<Props> = ({ assessment }) => {
  const [whyFlaggedExpanded, setWhyFlaggedExpanded] = useState(true);

  // Derive tags from real backend MITRE techniques, fallback to none
  const detectedTechniqueTags: string[] =
    assessment.detectedTechniques && assessment.detectedTechniques.length > 0
      ? assessment.detectedTechniques.map((t) => t.name || t.id).filter(Boolean)
      : [];

  return (
    <div className="space-y-6">
      {/* ─── THREAT ASSESSMENT SECTION ───────────────────────────────────────── */}
      <div
        className="p-6 rounded-2xl border border-cyan-500/20 relative overflow-hidden shadow-2xl"
        style={{
          background: "linear-gradient(135deg, rgba(10, 16, 32, 0.95) 0%, rgba(6, 10, 22, 0.98) 100%)",
          backdropFilter: "blur(20px)",
        }}
      >
        <div className="flex items-center gap-2.5 mb-5 pb-3 border-b border-white/5">
          <Crosshair className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm md:text-base font-extrabold text-white tracking-widest uppercase font-mono">
            Threat Assessment
          </h2>
        </div>

        {/* 4 Core SOC Metrics */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {/* Verdict */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-red-500/30 flex flex-col justify-between shadow-sm">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1 font-semibold">
              Verdict
            </span>
            <div className="text-sm font-black text-red-400 flex items-center gap-2 font-mono">
              <AlertOctagon className="w-4 h-4 text-red-400 flex-shrink-0" />
              <span>{assessment.verdict || "UNRESOLVED"}</span>
            </div>
          </div>

          {/* Confidence */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-cyan-500/30 flex flex-col justify-between shadow-sm">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1 font-semibold">
              Confidence
            </span>
            <div className="text-sm font-bold text-cyan-300 font-mono flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0" />
              <span>{assessment.confidence != null ? `${assessment.confidence}% Certainty` : "N/A"}</span>
            </div>
          </div>

          {/* Primary Attack */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-white/10 flex flex-col justify-between shadow-sm">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1 font-semibold">
              Primary Attack
            </span>
            <div className="text-sm font-bold text-slate-100 truncate">
              {assessment.primaryAttack || "Not Classified"}
            </div>
          </div>

          {/* Threat Category */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-purple-500/30 flex flex-col justify-between shadow-sm">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1 font-semibold">
              Threat Category
            </span>
            <div className="text-sm font-bold text-purple-300 truncate">
              {assessment.threatCategory || "Unspecified"}
            </div>
          </div>
        </div>

        {/* Detected Techniques Tags */}
        <div className="mb-6 space-y-2">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            Detected Threat Vectors &amp; Behavioral Signatures:
          </div>
          <div className="flex flex-wrap gap-2">
            {detectedTechniqueTags.length > 0 ? (
              detectedTechniqueTags.map((tag, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1 rounded-lg text-xs font-mono font-semibold bg-cyan-500/10 text-cyan-300 border border-cyan-500/25 flex items-center gap-1.5 shadow-sm"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  {tag}
                </span>
              ))
            ) : (
              <span className="text-xs font-mono text-slate-500 italic">
                No automated behavioral signatures flagged by analysis engine
              </span>
            )}
          </div>
        </div>

        {/* AI-Generated Explanation Section */}
        <div className="p-4 rounded-xl border border-cyan-500/30 bg-cyan-950/20 relative overflow-hidden">
          <div className="flex items-center gap-2 mb-2">
            <Brain className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-mono font-bold text-cyan-300 tracking-wide uppercase">
              AI Forensic Reasoning &amp; Context Interpretation
            </span>
            <span className="text-[10px] text-cyan-500/80 font-mono">(Evidence Synthesis)</span>
          </div>
          <p className="text-xs text-slate-200 leading-relaxed font-sans italic border-l-2 border-cyan-400/60 pl-3 py-1">
            "{assessment.aiForensicExplanation?.summary || "Automated threat evaluation completed based on forensic heuristics and multi-engine telemetry."}"
          </p>
        </div>
      </div>

      {/* ─── EXPANDABLE AI SECTION: WHY SPECTRASHIELD FLAGGED THIS EMAIL ───── */}
      <div
        className="rounded-2xl border border-cyan-500/20 overflow-hidden shadow-2xl"
        style={{
          background: "linear-gradient(135deg, rgba(10, 16, 32, 0.95) 0%, rgba(6, 10, 22, 0.98) 100%)",
          backdropFilter: "blur(20px)",
        }}
      >
        <button
          onClick={() => setWhyFlaggedExpanded(!whyFlaggedExpanded)}
          className="w-full p-5 flex items-center justify-between text-left hover:bg-white/2 transition-colors border-b border-white/5"
        >
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-500/20 to-indigo-600/30 border border-cyan-400/40 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <div className="text-sm font-bold text-white font-mono tracking-tight uppercase">
                Why SpectraShield Flagged This Email
              </div>
              <div className="text-xs text-slate-400 font-sans">
                Automated heuristic &amp; machine-learning rationale breakdown
              </div>
            </div>
          </div>

          <ChevronDown
            className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${
              whyFlaggedExpanded ? "rotate-180 text-cyan-400" : ""
            }`}
          />
        </button>

        <AnimatePresence>
          {whyFlaggedExpanded && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.2 }}
              className="p-6 space-y-4 font-sans text-xs"
            >
              {/* Primary Reason */}
              <div className="p-3.5 rounded-xl bg-white/2 border border-white/5 space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase font-bold tracking-wider">
                  Primary Reason
                </span>
                <p className="text-slate-200 leading-relaxed font-medium">
                  {assessment.aiForensicExplanation?.summary || "Automated threat evaluation completed based on forensic heuristics and multi-engine telemetry."}
                </p>
              </div>

              {/* Supporting Evidence */}
              <div className="p-3.5 rounded-xl bg-white/2 border border-white/5 space-y-2">
                <span className="text-[10px] font-mono text-slate-400 uppercase font-bold tracking-wider">
                  Supporting Evidentiary Findings
                </span>
                <ul className="space-y-1.5 text-slate-300">
                  {assessment.aiForensicExplanation?.keyObservations && assessment.aiForensicExplanation.keyObservations.length > 0 ? (
                    assessment.aiForensicExplanation.keyObservations.map((obs, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-red-400 font-bold">•</span>
                        <span>{obs}</span>
                      </li>
                    ))
                  ) : (
                    <li className="flex items-start gap-2 text-slate-500 italic">
                      <span>No specific evidentiary findings logged for this investigation.</span>
                    </li>
                  )}
                </ul>
              </div>

              {/* Recommended Action */}
              <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 space-y-1">
                <span className="text-[10px] font-mono text-red-400 uppercase font-bold tracking-wider flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Recommended Analyst Action
                </span>
                <p className="text-red-200 font-bold text-xs leading-relaxed">
                  "{assessment.aiForensicExplanation?.recommendedAction || "Do not click links or provide credentials. Report the message to your security team."}"
                </p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};
