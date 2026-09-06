import React, { useState } from "react";
import { 
  Globe2, 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  Radio, 
  Database, 
  Server, 
  Activity, 
  ExternalLink,
  Shield,
  Loader2
} from "lucide-react";
import { LiquidGlassCard } from "../liquid/LiquidGlassCard";
import { LiquidGlassBadge } from "../liquid/LiquidGlassBadge";
import { CtiReputationRecord } from "../../types";
import { lookupCti } from "../../api";

interface CtiReputationMatrixProps {
  initialRecords?: CtiReputationRecord[];
  originIp?: string;
  senderDomain?: string;
}

export const CtiReputationMatrix: React.FC<CtiReputationMatrixProps> = ({
  initialRecords = [],
  originIp,
  senderDomain
}) => {
  const [records, setRecords] = useState<CtiReputationRecord[]>(initialRecords);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isSearching, setIsSearching] = useState<boolean>(false);
  const [activeFilter, setActiveFilter] = useState<"ALL" | "MALICIOUS" | "VPN">("ALL");

  const handleManualLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    setIsSearching(true);
    try {
      const results = await lookupCti(searchQuery.trim());
      if (results && results.length > 0) {
        setRecords(prev => [...results, ...prev.filter(r => r.indicator !== searchQuery.trim())]);
      }
    } catch (err) {
      console.error("CTI Lookup error:", err);
    } finally {
      setIsSearching(false);
    }
  };

  const filteredRecords = records.filter(rec => {
    if (activeFilter === "MALICIOUS") return rec.is_malicious;
    if (activeFilter === "VPN") return rec.vpn_detected;
    return true;
  });

  const getSourceIcon = (source: string) => {
    const s = source.toLowerCase();
    if (s.includes("google") || s.includes("safe")) return <Globe2 className="w-3.5 h-3.5 text-cyan-400" />;
    if (s.includes("urlhaus") || s.includes("abuse.ch")) return <Database className="w-3.5 h-3.5 text-amber-400" />;
    if (s.includes("abuseipdb")) return <Activity className="w-3.5 h-3.5 text-rose-400" />;
    return <Server className="w-3.5 h-3.5 text-purple-400" />;
  };

  return (
    <LiquidGlassCard glowColor="cyan" className="p-5 space-y-4">
      {/* Header with Live CTI Status & Search Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold tracking-wide text-white font-mono">
                EXTERNAL CTI THREAT INTELLIGENCE MATRIX
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                INT-03 / GEO-02-EXT
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Multi-feed triangulation: Google Safe Browsing v4, abuse.ch URLhaus, AbuseIPDB & Commercial VPN/Tor Subnet Matcher
            </p>
          </div>
        </div>

        {/* Quick manual query bar */}
        <form onSubmit={handleManualLookup} className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Query IP, Domain or URL..."
              className="pl-8 pr-3 py-1.5 bg-slate-950/60 border border-white/10 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40 transition-all w-60"
            />
          </div>
          <button
            type="submit"
            disabled={isSearching || !searchQuery.trim()}
            className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 transition-all flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_10px_rgba(6,182,212,0.2)]"
          >
            {isSearching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : "Lookup"}
          </button>
        </form>
      </div>

      {/* Filter Tabs & Counter */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveFilter("ALL")}
            className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all ${
              activeFilter === "ALL"
                ? "bg-white/15 text-white border border-white/30"
                : "text-slate-400 hover:text-white bg-transparent"
            }`}
          >
            All Indicators ({records.length})
          </button>
          <button
            onClick={() => setActiveFilter("MALICIOUS")}
            className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all ${
              activeFilter === "MALICIOUS"
                ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                : "text-slate-400 hover:text-rose-300 bg-transparent"
            }`}
          >
            Malicious Hits ({records.filter(r => r.is_malicious).length})
          </button>
          <button
            onClick={() => setActiveFilter("VPN")}
            className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all ${
              activeFilter === "VPN"
                ? "bg-purple-500/20 text-purple-300 border border-purple-500/40"
                : "text-slate-400 hover:text-purple-300 bg-transparent"
            }`}
          >
            VPN / Tor Anonymized ({records.filter(r => r.vpn_detected).length})
          </button>
        </div>

        <div className="text-[11px] font-mono text-slate-400">
          Evaluated Indicators: <span className="text-cyan-400 font-bold">{records.length}</span>
        </div>
      </div>

      {/* Record Cards Grid */}
      {filteredRecords.length === 0 ? (
        <div className="p-8 text-center rounded-xl bg-slate-950/40 border border-dashed border-white/10 text-slate-400 text-xs font-mono space-y-2">
          <Shield className="w-8 h-8 mx-auto text-slate-600 mb-2" />
          <p>No threat indicators matched the selected filter.</p>
          <p className="text-[11px] text-slate-500">
            Use the lookup bar above to test arbitrary indicators against Safe Browsing, URLhaus, and AbuseIPDB.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {filteredRecords.map((rec, idx) => {
            const isBad = rec.is_malicious;
            const borderTint = isBad 
              ? "border-rose-500/40 bg-rose-950/15 shadow-[0_0_15px_rgba(244,63,94,0.15)]" 
              : "border-white/10 bg-slate-950/40";

            return (
              <div
                key={`${rec.indicator}-${idx}`}
                className={`p-3.5 rounded-xl border ${borderTint} backdrop-blur-md transition-all hover:scale-[1.01] space-y-2.5`}
              >
                {/* Header row */}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div className="p-1 rounded-md bg-white/5 border border-white/10">
                      {getSourceIcon(rec.source)}
                    </div>
                    <span className="text-xs font-bold font-mono text-white">
                      {rec.source}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-slate-400 border border-white/10">
                      {rec.indicator_type}
                    </span>
                  </div>

                  <div>
                    {isBad ? (
                      <LiquidGlassBadge
                        variant="critical"
                        label={`MALICIOUS (${rec.confidence_score}%)`}
                        icon={ShieldAlert}
                        size="sm"
                      />
                    ) : (
                      <LiquidGlassBadge
                        variant="safe"
                        label="CLEAN"
                        icon={ShieldCheck}
                        size="sm"
                      />
                    )}
                  </div>
                </div>

                {/* Indicator text (defanged style) */}
                <div className="bg-black/40 border border-white/5 px-2.5 py-1.5 rounded-lg text-xs font-mono text-cyan-300 break-all select-all flex items-center justify-between">
                  <span>{rec.indicator}</span>
                </div>

                {/* Badges & Details */}
                <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
                  {rec.threat_category && (
                    <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      {rec.threat_category}
                    </span>
                  )}
                  {rec.vpn_detected && (
                    <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 flex items-center gap-1">
                      <Shield className="w-3 h-3 text-purple-400" />
                      {rec.vpn_provider || "Commercial VPN / Tor"}
                    </span>
                  )}
                  {rec.country && (
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-white/10">
                      Country: {rec.country}
                    </span>
                  )}
                  {rec.asn_isp && (
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-white/10 truncate max-w-[200px]" title={rec.asn_isp}>
                      {rec.asn_isp}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </LiquidGlassCard>
  );
};
