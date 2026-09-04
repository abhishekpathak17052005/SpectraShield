import React from "react";
import { Clock, Server, ArrowDown, AlertTriangle, ShieldAlert, CheckCircle2 } from "lucide-react";
import { RelayHopGeo } from "./HopMapVisualizer";
import { DefangedText } from "../common/DefangedText";
import { LiquidGlassCard } from "../liquid/LiquidGlassCard";
import { LiquidGlassBadge } from "../liquid/LiquidGlassBadge";

interface RelayHopTimelineProps {
  hops: RelayHopGeo[];
  anomalies?: string[];
}

export const RelayHopTimeline: React.FC<RelayHopTimelineProps> = ({ hops, anomalies = [] }) => {
  if (!hops || hops.length === 0) {
    return (
      <div className="p-8 text-center text-slate-400 font-mono text-xs border border-dashed border-white/10 rounded-3xl bg-slate-900/40 backdrop-blur-xl">
        No Received: header hops detected in message. Direct submission or unparsed raw RFC 5322 payload.
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Detected Header Anomalies Box */}
      {anomalies.length > 0 && (
        <div className="p-4 bg-amber-950/25 border border-amber-500/30 rounded-2xl backdrop-blur-xl text-xs font-mono text-amber-300 space-y-2 shadow-lg">
          <div className="flex items-center gap-2 font-bold text-amber-400 text-sm">
            <AlertTriangle className="h-4 w-4 text-amber-400 animate-bounce" />
            <span>CRITICAL RELAY & HEADER ANOMALIES DETECTED ({anomalies.length}):</span>
          </div>
          <ul className="space-y-1 pl-6 list-disc text-slate-300">
            {anomalies.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Chronological Vertical Circuit Pipeline */}
      <div className="relative pl-8 border-l-2 border-cyan-500/30 dark:border-cyan-500/20 space-y-6">
        {hops.map((hop, idx) => {
          const isOrigin = hop.is_origin;
          const isTor = hop.geo?.is_anonymized;

          return (
            <div key={hop.hop} className="relative group">
              {/* Timeline Marker Node */}
              <div
                className={`absolute -left-[45px] top-3 h-8 w-8 rounded-2xl flex items-center justify-center text-xs font-mono font-bold text-white border-2 shadow-xl transition-transform duration-300 group-hover:scale-110 ${
                  isOrigin
                    ? "bg-red-600 border-red-300 shadow-red-950/60 ring-4 ring-red-500/20 animate-pulse"
                    : isTor
                    ? "bg-amber-600 border-amber-300 shadow-amber-950/60"
                    : "bg-cyan-600 border-cyan-300 shadow-cyan-950/60"
                }`}
              >
                {hop.hop}
              </div>

              {/* Hop Card with Liquid Glass */}
              <LiquidGlassCard
                glowColor={isOrigin ? 'crimson' : isTor ? 'amber' : 'cyan'}
                className={`p-4 md:p-5 ${
                  isOrigin
                    ? "border-red-500/40 bg-red-950/20"
                    : "border-white/10 bg-slate-900/60"
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-bold text-white tracking-tight">
                      HOP #{hop.hop}: {hop.received_from}
                    </span>
                    {isOrigin && (
                      <LiquidGlassBadge
                        variant="critical"
                        label="EARLIEST RELIABLE PUBLIC NODE (ERPN)"
                        icon={ShieldAlert}
                        size="sm"
                      />
                    )}
                    {hop.is_private && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800/80 border border-white/10 text-slate-400">
                        RFC 1918 / BOGON
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                    <Clock className="h-3.5 w-3.5 text-cyan-400" />
                    <span className="text-cyan-300 font-semibold">+{hop.delay_seconds}s transit latency</span>
                    {hop.timestamp && (
                      <span className="text-[11px] text-slate-500">
                        ({new Date(hop.timestamp).toLocaleTimeString()})
                      </span>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono text-slate-300">
                  <div className="space-y-1.5">
                    <div className="text-slate-400 flex items-center gap-1.5">
                      <Server className="h-3.5 w-3.5 text-cyan-400" />
                      <span>Transferred By:</span>
                      <span className="text-slate-200 font-medium">{hop.by}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400">IP Address:</span>
                      {hop.ip ? (
                        <DefangedText value={hop.defanged_ip || hop.ip} />
                      ) : (
                        <span className="text-slate-500 italic">No IP in header</span>
                      )}
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    {hop.geo ? (
                      <>
                        <div>
                          <span className="text-slate-400">Location:</span>{" "}
                          <span className="text-slate-200">
                            {hop.geo.city || "Unknown City"}, {hop.geo.country || "Unknown Country"}
                          </span>
                        </div>
                        <div className="truncate">
                          <span className="text-slate-400">ISP / ASN:</span>{" "}
                          <span className="text-slate-200">
                            {hop.geo.asn || "N/A"} ({hop.geo.isp || "N/A"})
                          </span>
                        </div>
                      </>
                    ) : (
                      <div className="text-slate-500 italic">
                        Internal LAN or private subnet (Non-routable)
                      </div>
                    )}
                  </div>
                </div>

                {isTor && (
                  <div className="mt-3 p-2.5 rounded-xl bg-amber-950/40 border border-amber-500/40 text-xs font-mono text-amber-300 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 animate-pulse" />
                    <span>
                      Identified as a public <b>TOR EXIT ROUTER</b> or anonymization proxy relay.
                    </span>
                  </div>
                )}
              </LiquidGlassCard>

              {idx < hops.length - 1 && (
                <div className="flex justify-center my-2 text-cyan-500/40">
                  <ArrowDown className="h-4 w-4 animate-bounce" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
