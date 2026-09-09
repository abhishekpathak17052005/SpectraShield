import React, { useState } from "react";
import {
  Link2,
  ExternalLink,
  ShieldAlert,
  ArrowRight,
  Globe,
  Radio,
  FileCheck,
  AlertTriangle,
  CheckCircle2,
  Copy,
  ChevronDown,
  HelpCircle,
  XCircle,
} from "lucide-react";
import { UrlIntelligenceData } from "../../../types/investigation";

interface Props {
  urlData: UrlIntelligenceData;
}

function getReputationColor(verdict: string): string {
  const v = verdict?.toUpperCase() || "";
  if (v.includes("HIGH") || v.includes("MALICIOUS")) return "text-red-400";
  if (v.includes("SUSPICIOUS")) return "text-amber-400";
  if (v.includes("NOT ENRICHED") || v.includes("UNAVAILABLE")) return "text-slate-500";
  return "text-emerald-400";
}

function getReputationBorder(verdict: string): string {
  const v = verdict?.toUpperCase() || "";
  if (v.includes("HIGH") || v.includes("MALICIOUS")) return "border-red-500/30";
  if (v.includes("SUSPICIOUS")) return "border-amber-500/30";
  if (v.includes("NOT ENRICHED") || v.includes("UNAVAILABLE")) return "border-slate-700/30";
  return "border-emerald-500/30";
}

export const UrlIntelligenceTab: React.FC<Props> = ({ urlData }) => {
  const [selectedNodeIdx, setSelectedNodeIdx] = useState<number | null>(null);

  const vtData = urlData?.reputationFeeds?.virusTotal;
  const opData = urlData?.reputationFeeds?.openPhish;

  // Summary metrics derived from real data
  const domainVerdict = urlData?.domainReputation?.verdict || "NOT ENRICHED";
  const typosquattingStatus = urlData?.typosquatting?.isImpersonating ? "DETECTED" : "NOT DETECTED";
  const redirectChainCount = Array.isArray(urlData?.redirectChain) ? urlData.redirectChain.length : 0;
  const vtStatus = vtData?.status || "UNAVAILABLE";
  const opStatus = opData?.status || "UNAVAILABLE";

  return (
    <div className="space-y-6">
      {/* ─── 6 KEY PARAMETERS SUMMARY GRID ────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Domain Reputation */}
        <div className={`p-3.5 rounded-xl bg-slate-900/80 border flex flex-col justify-between ${getReputationBorder(domainVerdict)}`}>
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">
            Domain Reputation
          </span>
          <span className={`text-xs font-mono font-black mt-1 ${getReputationColor(domainVerdict)}`}>
            {domainVerdict}
          </span>
        </div>

        {/* Typosquatting */}
        <div className={`p-3.5 rounded-xl bg-slate-900/80 border flex flex-col justify-between ${urlData?.typosquatting?.isImpersonating ? "border-red-500/30" : "border-slate-700/30"}`}>
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">
            Typosquatting
          </span>
          <span className={`text-xs font-mono font-black mt-1 ${urlData?.typosquatting?.isImpersonating ? "text-red-400" : "text-slate-500"}`}>
            {typosquattingStatus}
          </span>
        </div>

        {/* Redirect Chain */}
        <div className={`p-3.5 rounded-xl bg-slate-900/80 border flex flex-col justify-between ${redirectChainCount > 0 ? "border-amber-500/30" : "border-slate-700/30"}`}>
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">
            Redirect Chain
          </span>
          <span className={`text-xs font-mono font-black mt-1 ${redirectChainCount > 0 ? "text-amber-300" : "text-slate-500"}`}>
            {redirectChainCount > 0 ? `${redirectChainCount} hops` : "N/A"}
          </span>
        </div>

        {/* VirusTotal */}
        <div className={`p-3.5 rounded-xl bg-slate-900/80 border flex flex-col justify-between ${vtStatus === "MALICIOUS" ? "border-red-500/30" : vtStatus === "UNAVAILABLE" ? "border-slate-700/30" : "border-emerald-500/30"}`}>
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">
            VirusTotal
          </span>
          <span className={`text-xs font-mono font-black mt-1 ${vtStatus === "MALICIOUS" ? "text-red-400" : vtStatus === "UNAVAILABLE" ? "text-slate-500" : "text-emerald-400"}`}>
            {vtStatus === "MALICIOUS" && vtData?.maliciousEngines != null
              ? `${vtData.maliciousEngines} / ${vtData.totalEngines} detected`
              : vtStatus === "CLEAN"
              ? "CLEAN"
              : "NOT ENRICHED"}
          </span>
        </div>

        {/* OpenPhish */}
        <div className={`p-3.5 rounded-xl bg-slate-900/80 border flex flex-col justify-between ${opStatus === "MATCHED" ? "border-red-500/30" : "border-slate-700/30"}`}>
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">
            OpenPhish
          </span>
          <span className={`text-xs font-mono font-black mt-1 ${opStatus === "MATCHED" ? "text-red-400" : "text-slate-500"}`}>
            {opStatus === "MATCHED" ? "MATCH FOUND" : opStatus === "NO_MATCH" ? "NO MATCH" : "NOT ENRICHED"}
          </span>
        </div>

        {/* Google Safe Browse */}
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-700/30 flex flex-col justify-between">
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">
            Safe Browse
          </span>
          <span className="text-xs font-mono font-black mt-1 text-slate-500">
            NOT ENRICHED
          </span>
        </div>
      </div>

      {/* ─── ORIGINAL & DEFANGED URL DISPLAY ────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl border border-white/10 bg-slate-900/80">
          <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1 font-semibold">
            Original URL
          </div>
          <div className="text-xs font-mono text-slate-300 break-all bg-black/40 p-2.5 rounded-lg border border-white/5">
            {urlData?.originalUrl || "UNAVAILABLE"}
          </div>
        </div>

        <div className="p-4 rounded-xl border border-cyan-500/30 bg-slate-900/80">
          <div className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider mb-1 font-semibold">
            Defanged URL
          </div>
          <div className="text-xs font-mono text-cyan-200 font-bold break-all bg-black/40 p-2.5 rounded-lg border border-cyan-500/30">
            {urlData?.defangedUrl || "UNAVAILABLE"}
          </div>
        </div>
      </div>

      {/* ─── REDIRECT CHAIN VISUALIZATION ──────────────────────────────────── */}
      <div className="p-5 rounded-xl border border-cyan-500/20 bg-slate-900/80">
        <div className="flex items-center justify-between mb-4">
          <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-2">
            <Link2 className="w-3.5 h-3.5 text-cyan-400" />
            Redirect Chain Visualization
          </div>
          {redirectChainCount > 0 && (
            <span className="text-[10px] font-mono text-cyan-400">{redirectChainCount} hop{redirectChainCount > 1 ? "s" : ""} traversed</span>
          )}
        </div>

        {redirectChainCount > 0 ? (
          <>
            {/* Chain Nodes from real data */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {urlData.redirectChain.map((node: any, idx: number) => {
                const isSelected = selectedNodeIdx === idx;
                return (
                  <div
                    key={idx}
                    onClick={() => setSelectedNodeIdx(isSelected ? null : idx)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all flex flex-col justify-between gap-2.5 relative ${
                      isSelected
                        ? "border-cyan-400 bg-cyan-950/40 shadow-lg shadow-cyan-500/10 ring-1 ring-cyan-400/40"
                        : "border-white/10 bg-white/2 hover:border-cyan-500/30 hover:bg-white/4"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono font-bold text-slate-400">STAGE {idx + 1}</span>
                      <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                        {node.status || node.type || "HOP"}
                      </span>
                    </div>

                    <div>
                      <div className="text-sm font-bold text-white font-sans">{node.name || `Hop ${idx + 1}`}</div>
                      <div className="text-xs font-mono text-cyan-300/80 truncate mt-0.5">{node.url || node.domain || "—"}</div>
                    </div>

                    <div className="text-[10px] text-slate-500 font-mono flex items-center justify-between pt-1 border-t border-white/5">
                      <span>{node.type || "redirect"}</span>
                      <span className="text-cyan-400">click to view</span>
                    </div>
                  </div>
                );
              })}
            </div>

            {selectedNodeIdx !== null && urlData.redirectChain[selectedNodeIdx] && (
              <div className="mt-4 p-3.5 rounded-xl bg-black/40 border border-cyan-500/20 text-xs font-mono">
                <div className="flex items-center justify-between pb-1.5 border-b border-white/5 mb-2">
                  <span className="font-bold text-cyan-300">
                    Stage {selectedNodeIdx + 1}: {urlData.redirectChain[selectedNodeIdx].name || "Redirect"}
                  </span>
                  <span className="text-slate-500 text-[11px]">{urlData.redirectChain[selectedNodeIdx].url || "—"}</span>
                </div>
                <p className="text-slate-300 font-sans text-xs leading-relaxed">
                  {urlData.redirectChain[selectedNodeIdx].details || "No additional details available for this hop."}
                </p>
              </div>
            )}
          </>
        ) : (
          <div className="flex flex-col items-center justify-center py-10 gap-3 text-center">
            <HelpCircle className="w-8 h-8 text-slate-600" />
            <div className="text-xs font-mono text-slate-500">
              Redirect chain not available for this investigation
            </div>
            <span className="text-[10px] font-mono text-slate-700 px-3 py-1 rounded-full border border-slate-700/40 bg-slate-900/60">
              STATUS: NOT ENRICHED
            </span>
          </div>
        )}
      </div>

      {/* ─── DOMAIN REPUTATION & TYPOSQUATTING RADAR ───────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Domain Profile */}
        <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 flex flex-col justify-between">
          <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-3 flex items-center gap-2">
            <Globe className="w-3.5 h-3.5 text-purple-400" />
            Domain Reputation &amp; WHOIS Radar
          </div>
          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex justify-between py-1 border-b border-white/5">
              <span className="text-slate-500">Domain Name:</span>
              <span className="text-slate-200 font-bold">{urlData?.domain || "NOT ENRICHED"}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-white/5">
              <span className="text-slate-500">Domain Age:</span>
              <span className={`font-bold ${urlData?.domainReputation?.ageDays != null && urlData.domainReputation.ageDays < 30 ? "text-amber-400" : "text-slate-400"}`}>
                {urlData?.domainReputation?.ageDays != null ? `${urlData.domainReputation.ageDays} days` : "NOT ENRICHED"}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-white/5">
              <span className="text-slate-500">Domain Reputation:</span>
              <span className={`font-bold ${getReputationColor(domainVerdict)}`}>{domainVerdict}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-500">Registrar:</span>
              <span className="text-slate-300">{urlData?.domainReputation?.registrar || "NOT ENRICHED"}</span>
            </div>
          </div>
        </div>

        {/* Typosquatting / Impersonation */}
        <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 flex flex-col justify-between">
          <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-3 flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            Brand Typosquatting &amp; Punycode Analysis
          </div>
          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex justify-between py-1 border-b border-white/5">
              <span className="text-slate-500">Targeted Brand:</span>
              <span className={urlData?.typosquatting?.targetBrand ? "text-cyan-300 font-bold" : "text-slate-500"}>
                {urlData?.typosquatting?.targetBrand || "None detected"}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-white/5">
              <span className="text-slate-500">Typosquatting Status:</span>
              <span className={urlData?.typosquatting?.isImpersonating ? "text-red-400 font-bold" : "text-emerald-400"}>
                {typosquattingStatus}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-white/5">
              <span className="text-slate-500">Analysis:</span>
              <span className="text-slate-300 text-right max-w-[180px] truncate">
                {urlData?.typosquatting?.analysis || "NOT ENRICHED"}
              </span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-500">Punycode:</span>
              <span className={urlData?.typosquatting?.punycodeDetected ? "text-amber-300 font-bold" : "text-slate-500"}>
                {urlData?.typosquatting?.punycodeDetected ? "DETECTED" : "NOT DETECTED"}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
