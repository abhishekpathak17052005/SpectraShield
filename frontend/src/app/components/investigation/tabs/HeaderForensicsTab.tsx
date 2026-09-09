import React, { useState } from "react";
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  Server,
  ArrowDown,
  Clock,
  MapPin,
  Globe,
  Lock,
  Hash,
  AlertOctagon,
} from "lucide-react";
import { HeaderForensicsData, AuthStatus, MailRoutingHop } from "../../../types/investigation";

interface Props {
  headers: HeaderForensicsData;
}

export const HeaderForensicsTab: React.FC<Props> = ({ headers }) => {
  const [expandedHop, setExpandedHop] = useState<number | null>(null);

  const toggleHop = (hopNum: number) => {
    setExpandedHop((prev) => (prev === hopNum ? null : hopNum));
  };
  const renderAuthPill = (label: string, status: AuthStatus, subtitle: string, details: string) => {
    const cfg = {
      PASS: { icon: CheckCircle2, color: "text-emerald-400", border: "border-emerald-500/30", bg: "bg-emerald-500/10" },
      FAIL: { icon: XCircle, color: "text-red-400", border: "border-red-500/30", bg: "bg-red-500/10" },
      SOFTFAIL: { icon: AlertTriangle, color: "text-amber-400", border: "border-amber-500/30", bg: "bg-amber-500/10" },
      UNKNOWN: { icon: HelpCircle, color: "text-slate-400", border: "border-slate-500/30", bg: "bg-slate-500/10" },
    }[status] || { icon: HelpCircle, color: "text-slate-400", border: "border-slate-500/30", bg: "bg-slate-500/10" };

    return (
      <div className={`p-4 rounded-xl border ${cfg.border} ${cfg.bg} flex flex-col justify-between`}>
        <div className="flex items-center justify-between gap-2 mb-2">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">{label}</span>
          <div className="flex items-center gap-1">
            <cfg.icon className={`w-4 h-4 ${cfg.color}`} />
            <span className={`text-xs font-mono font-bold ${cfg.color}`}>{status}</span>
          </div>
        </div>
        <div className="text-xs font-mono text-slate-200 truncate mb-1">{subtitle}</div>
        <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">{details}</p>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Protocol Authentication Matrix */}
      <div>
        <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-3 flex items-center gap-2">
          <Lock className="w-3.5 h-3.5 text-cyan-400" />
          Cryptographic Email Protocol Verification
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {renderAuthPill("SPF Protocol", headers.spf.status, `IP: ${headers.spf.senderIp}`, headers.spf.details)}
          {renderAuthPill(
            "Standalone DKIM Math",
            headers.dkim.status,
            `s=${headers.dkim.selector} · ${headers.dkim.keyLengthBits ? `${headers.dkim.keyLengthBits}-bit RSA` : "Key Unknown"}`,
            headers.dkim.details
          )}
          {renderAuthPill("DMARC Alignment", headers.dmarc.status, `Policy: ${headers.dmarc.policy}`, headers.dmarc.details)}
        </div>
      </div>

      {/* Envelope Identity Details */}
      <div className="p-5 rounded-xl border border-white/5 bg-white/2">
        <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-4 flex items-center gap-2">
          <Server className="w-3.5 h-3.5 text-purple-400" />
          Envelope &amp; Transmission Identifiers
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div>
            <div className="text-slate-500 mb-1">Sender IP (ERPN):</div>
            <div className="text-red-300 font-bold break-all">{headers.senderIp}</div>
          </div>
          <div>
            <div className="text-slate-500 mb-1">Originating Server:</div>
            <div className="text-slate-200 truncate">{headers.originatingServer}</div>
          </div>
          <div>
            <div className="text-slate-500 mb-1">Reply-To Header:</div>
            <div className="text-amber-300 truncate">{headers.replyTo}</div>
          </div>
          <div>
            <div className="text-slate-500 mb-1">Return-Path Envelope:</div>
            <div className="text-red-300 truncate">{headers.returnPath}</div>
          </div>
        </div>
        <div className="mt-4 pt-3 border-t border-white/5 text-xs font-mono">
          <span className="text-slate-500">RFC 822 Message-ID: </span>
          <span className="text-slate-300 break-all">{headers.messageId}</span>
        </div>
      </div>

      {/* Visual Mail-Routing Timeline */}
      <div className="p-5 rounded-xl border border-white/5 bg-white/2">
        <div className="flex items-center justify-between mb-4">
          <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-2">
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            Visual Mail-Routing Flight Path (Hop-by-Hop Timeline)
          </div>
          <span className="text-[10px] font-mono text-slate-500">Reverse Traversal Analysis</span>
        </div>

        <div className="space-y-3">
          {headers.routingTimeline.map((hop, idx) => (
            <div key={hop.hopNumber} className="relative flex items-start gap-4">
              {/* Vertical Hop Line indicator */}
              <div className="flex flex-col items-center">
                <div
                  className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-mono font-bold border ${
                    hop.flagged
                      ? "border-red-500/50 bg-red-500/20 text-red-300"
                      : "border-cyan-500/30 bg-cyan-500/10 text-cyan-300"
                  }`}
                >
                  {hop.hopNumber}
                </div>
                {idx < headers.routingTimeline.length - 1 && (
                  <div className="w-[1px] h-8 bg-gradient-to-b from-cyan-500/40 to-white/10 my-1" />
                )}
              </div>

              {/* Hop Content Card (Expandable) */}
              <div
                onClick={() => toggleHop(hop.hopNumber)}
                className={`flex-1 p-3.5 rounded-xl border cursor-pointer transition-all ${
                  hop.flagged ? "border-red-500/30 bg-red-500/5 hover:bg-red-500/10" : "border-white/5 bg-white/2 hover:border-cyan-500/30 hover:bg-white/4"
                } ${expandedHop === hop.hopNumber ? "border-cyan-500/50 bg-slate-900/90 shadow-lg" : ""}`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono font-bold text-white">{hop.name}</span>
                      <span className="text-xs font-mono text-cyan-400 font-semibold">({hop.defangedIp})</span>
                      {hop.isAnonymized && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-300 border border-purple-500/30">
                          {hop.anonymizationType || "ANONYMIZED"}
                        </span>
                      )}
                      <span className="text-[10px] text-slate-500 font-mono">
                        {expandedHop === hop.hopNumber ? "▲ click to collapse" : "▼ click to inspect"}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 flex items-center gap-3 mt-1 font-mono flex-wrap">
                      <span className="flex items-center gap-1">
                        <MapPin className="w-3 h-3 text-slate-500" />
                        {hop.location}
                      </span>
                      <span>·</span>
                      <span>{hop.isp}</span>
                      {hop.asn && <span>({hop.asn})</span>}
                    </div>
                  </div>

                  <div className="text-right text-xs font-mono flex sm:flex-col items-center sm:items-end justify-between sm:justify-center gap-1 text-slate-400">
                    <span className="text-slate-300">{hop.timestamp}</span>
                    <span className="text-[11px] text-cyan-400 font-semibold">Transit: +{hop.delaySeconds}s</span>
                  </div>
                </div>

                {/* Expanded Hop Technical Details */}
                {expandedHop === hop.hopNumber && (
                  <div className="mt-3 pt-3 border-t border-white/5 grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs font-mono">
                    <div className="p-2 rounded-lg bg-black/40 border border-white/5">
                      <span className="text-slate-500 text-[10px] block">HELO/EHLO Hostname:</span>
                      <span className="text-cyan-300 font-semibold truncate block">{hop.hostname}</span>
                    </div>
                    <div className="p-2 rounded-lg bg-black/40 border border-white/5">
                      <span className="text-slate-500 text-[10px] block">Public IPv4:</span>
                      <span className="text-slate-200 font-semibold truncate block">{hop.ip}</span>
                    </div>
                    <div className="p-2 rounded-lg bg-black/40 border border-white/5">
                      <span className="text-slate-500 text-[10px] block">Verification Status:</span>
                      <span className={hop.flagged ? "text-red-400 font-bold block" : "text-emerald-400 font-bold block"}>
                        {hop.flagged ? "FLAGGED ANOMALY" : "VERIFIED HOP"}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Header Anomalies List */}
      {headers.anomalies.length > 0 && (
        <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/5">
          <div className="text-xs font-mono uppercase tracking-wider text-red-400 font-bold mb-2 flex items-center gap-1.5">
            <AlertOctagon className="w-4 h-4 text-red-400" />
            Detected Header Anomalies ({headers.anomalies.length})
          </div>
          <div className="space-y-1.5">
            {headers.anomalies.map((anom, i) => (
              <div key={i} className="text-xs font-mono text-red-200 flex items-start gap-2">
                <span className="text-red-400 font-bold">!</span>
                <span>{anom}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
