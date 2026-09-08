import React, { useState } from "react";
import { motion } from "motion/react";
import { Globe, Server, Hash, ArrowRight, ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink, Network } from "lucide-react";

interface IocItem {
  id: string;
  type: "DOMAIN" | "IP" | "HASH";
  indicator: string;
  defangedIndicator: string;
  riskRating: number;
  threatSeverity: "HIGH" | "MEDIUM" | "SAFE";
  source: string;
  associatedCaseId: string;
  associatedCaseNumber: string;
  firstSeen: string;
}

interface IocExplorationFieldProps {
  iocs: IocItem[];
  onNavigate: (route: string) => void;
}

export const IocExplorationField: React.FC<IocExplorationFieldProps> = ({ iocs, onNavigate }) => {
  const [selectedIocId, setSelectedIocId] = useState<string | null>(() => {
    return iocs.length > 0 ? iocs[0].id : null;
  });

  const selectedIoc = iocs.find((i) => i.id === selectedIocId) || iocs[0] || null;

  if (!selectedIoc) return null;

  const isHigh = selectedIoc.threatSeverity === "HIGH" || selectedIoc.riskRating >= 70;
  const isMed = selectedIoc.threatSeverity === "MEDIUM" || (selectedIoc.riskRating >= 30 && selectedIoc.riskRating < 70);

  const getIcon = (type: IocItem["type"]) => {
    switch (type) {
      case "DOMAIN":
        return Globe;
      case "IP":
        return Server;
      case "HASH":
        return Hash;
    }
  };

  const SelectedIcon = getIcon(selectedIoc.type);

  return (
    <div className="rounded-2xl border border-cyan-500/20 bg-gradient-to-b from-[#0c1224]/95 via-[#080d1a]/95 to-[#050914]/95 overflow-hidden shadow-2xl p-5 md:p-6 space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-white/5">
        <div>
          <h3 className="text-sm font-semibold text-white tracking-wide uppercase flex items-center gap-2">
            <span>IOC Relationship & Correlation Explorer</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-normal">
              PIVOT GRAPH
            </span>
          </h3>
          <p className="text-[11px] text-slate-400">
            Interactive correlation graph: select an observable to trace its propagation chain
          </p>
        </div>

        {/* Observable Quick Picker */}
        <div className="flex items-center gap-1.5 overflow-x-auto max-w-full pb-1">
          {iocs.slice(0, 5).map((ioc) => (
            <button
              key={ioc.id}
              onClick={() => setSelectedIocId(ioc.id)}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all flex items-center gap-1.5 whitespace-nowrap ${
                selectedIoc.id === ioc.id
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                  : "bg-white/5 text-slate-400 hover:text-slate-200 border border-white/5"
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${ioc.riskRating >= 70 ? "bg-red-400" : ioc.riskRating >= 30 ? "bg-amber-400" : "bg-emerald-400"}`} />
              <span>{ioc.defangedIndicator.slice(0, 16)}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Correlation Pipeline Graphic */}
      <div className="p-4 rounded-xl bg-[#060a14]/60 border border-white/5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
          {/* Node 1: Indicator Origin */}
          <div className="p-3.5 rounded-xl border border-white/10 bg-[#0c1426] space-y-1.5 relative overflow-hidden">
            <div className="text-[10px] font-mono text-purple-400 uppercase font-semibold flex items-center justify-between">
              <span>Source Observable</span>
              <span className="px-1.5 py-0.2 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
                {selectedIoc.type}
              </span>
            </div>
            <div className="text-xs font-bold text-white font-mono truncate">
              {selectedIoc.defangedIndicator}
            </div>
            <div className="text-[10px] text-slate-400">
              Source: {selectedIoc.source}
            </div>
          </div>

          {/* Tracer Link 1 */}
          <div className="hidden md:flex flex-col items-center justify-center text-center">
            <div className="text-[10px] font-mono text-cyan-400 mb-1 flex items-center gap-1">
              <span>ATTRIBUTED_TO</span>
              <ArrowRight className="w-3 h-3 animate-pulse" />
            </div>
            <div className="w-full h-[2px] bg-gradient-to-r from-purple-500/40 via-cyan-400 to-blue-500/40" />
          </div>

          {/* Node 2: Associated Case */}
          <div className="p-3.5 rounded-xl border border-cyan-500/30 bg-[#0a152a] space-y-1.5 relative overflow-hidden">
            <div className="text-[10px] font-mono text-cyan-400 uppercase font-semibold flex items-center justify-between">
              <span>Forensic Case</span>
              <span className={`px-1.5 py-0.2 rounded font-bold ${
                isHigh ? "bg-red-500/20 text-red-300" : isMed ? "bg-amber-500/20 text-amber-300" : "bg-emerald-500/20 text-emerald-300"
              }`}>
                RISK {selectedIoc.riskRating}
              </span>
            </div>
            <div className="text-xs font-bold text-white font-mono truncate">
              {selectedIoc.associatedCaseNumber}
            </div>
            <button
              onClick={() => onNavigate(`/investigations/${selectedIoc.associatedCaseId}`)}
              className="text-[11px] text-cyan-300 hover:text-cyan-200 flex items-center gap-1 font-medium pt-0.5"
            >
              <span>Inspect Investigation</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
