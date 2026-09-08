import React from "react";
import { Layers, ShieldAlert, CheckCircle2, ExternalLink } from "lucide-react";
import { MitreTechnique } from "../../types/investigation";

interface Props {
  techniques: MitreTechnique[];
}

export const AttackTechniques: React.FC<Props> = ({ techniques }) => {
  return (
    <div
      className="p-6 rounded-2xl border border-cyan-500/20 relative overflow-hidden shadow-2xl"
      style={{
        background: "linear-gradient(135deg, rgba(10, 16, 32, 0.95) 0%, rgba(6, 10, 22, 0.98) 100%)",
        backdropFilter: "blur(20px)",
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-4 mb-5 pb-3 border-b border-white/5">
        <div className="flex items-center gap-2.5">
          <Layers className="w-4 h-4 text-purple-400" />
          <h2 className="text-sm md:text-base font-extrabold text-white tracking-widest uppercase font-mono">
            ATTACK TECHNIQUES
          </h2>
          <span className="text-xs text-purple-300/70 font-mono hidden sm:inline">
            (MITRE ATT&amp;CK Matrix)
          </span>
        </div>

        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
          v14 ENTERPRISE FRAMEWORK
        </span>
      </div>

      {techniques && techniques.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {techniques.map((tech) => (
            <div
              key={tech.id}
              className="p-4 rounded-xl border border-white/5 bg-white/2 hover:border-purple-500/40 hover:bg-white/4 transition-all flex flex-col justify-between gap-3 group shadow-sm"
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-purple-500/15 text-purple-300 border border-purple-500/30">
                    {tech.id}
                  </span>
                  <span className="text-xs font-mono font-bold text-cyan-300 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3 text-cyan-400" />
                    {tech.confidence}%
                  </span>
                </div>

                <div className="text-sm font-bold text-slate-100 mb-1 group-hover:text-purple-200 transition-colors">
                  {tech.name}
                </div>
                <div className="text-[10px] font-mono uppercase text-slate-400 font-semibold mb-2">
                  Tactic: {tech.tactic}
                </div>

                <p className="text-xs text-slate-300 leading-relaxed font-sans border-l border-purple-500/40 pl-2.5 py-0.5">
                  {tech.evidence}
                </p>
              </div>

              <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                <span>Technique Verified</span>
                <span className="text-purple-400 flex items-center gap-1">
                  Sub-technique match
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-8 gap-2 text-center">
          <p className="text-xs font-mono text-slate-500">
            No MITRE ATT&amp;CK techniques mapped for this investigation
          </p>
          <span className="text-[10px] font-mono text-slate-700 px-3 py-1 rounded-full border border-slate-700/40 bg-slate-900/60">
            STATUS: NOT ENRICHED
          </span>
        </div>
      )}
    </div>
  );
};
