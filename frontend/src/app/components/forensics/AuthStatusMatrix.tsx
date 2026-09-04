import React from "react";
import { ShieldCheck, ShieldAlert, Key, Lock, CheckCircle2, XCircle } from "lucide-react";
import { LiquidGlassCard } from "../liquid/LiquidGlassCard";
import { LiquidGlassBadge } from "../liquid/LiquidGlassBadge";

interface AuthStatusMatrixProps {
  authentication?: {
    spf?: {
      status?: string;
      domain?: string;
      sender_ip?: string;
      reason?: string;
      record?: string;
    };
    dkim?: {
      status?: string;
      selector?: string;
      domain?: string;
      valid?: boolean;
      reason?: string;
    };
    dmarc?: {
      status?: string;
      domain?: string;
      policy?: string;
      aligned?: boolean;
      reason?: string;
    };
  };
}

export const AuthStatusMatrix: React.FC<AuthStatusMatrixProps> = ({ authentication }) => {
  const spf = authentication?.spf || {};
  const dkim = authentication?.dkim || {};
  const dmarc = authentication?.dmarc || {};

  const getStatusBadge = (status?: string) => {
    const s = (status || "none").toLowerCase();
    if (s === "pass") {
      return <LiquidGlassBadge variant="safe" label="PASS" icon={CheckCircle2} size="sm" />;
    }
    if (s === "softfail" || s === "neutral") {
      return <LiquidGlassBadge variant="warning" label={s.toUpperCase()} icon={ShieldAlert} size="sm" />;
    }
    return <LiquidGlassBadge variant="critical" label="FAIL" icon={XCircle} size="sm" />;
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {/* SPF Card */}
      <LiquidGlassCard
        glowColor={spf.status?.toLowerCase() === 'pass' ? 'emerald' : 'crimson'}
        className="p-5 space-y-3"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-white tracking-wide">
            <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400">
              <Lock className="h-4 w-4" />
            </div>
            <span>SPF AUTHENTICATION</span>
          </div>
          {getStatusBadge(spf.status)}
        </div>
        <div className="text-xs font-mono space-y-1.5 text-slate-300">
          <div>
            <span className="text-slate-400">Target Domain:</span>{" "}
            <span className="text-cyan-300 font-semibold">{spf.domain || "N/A"}</span>
          </div>
          {spf.sender_ip && (
            <div>
              <span className="text-slate-400">Evaluated IP:</span>{" "}
              <span className="text-slate-200">{spf.sender_ip}</span>
            </div>
          )}
          <div className="text-slate-400 text-[11px] pt-1 leading-relaxed border-t border-white/5">
            {spf.reason || "Sender Policy Framework RFC 7208 record validation."}
          </div>
        </div>
      </LiquidGlassCard>

      {/* DKIM Card */}
      <LiquidGlassCard
        glowColor={dkim.status?.toLowerCase() === 'pass' ? 'emerald' : 'purple'}
        className="p-5 space-y-3"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-white tracking-wide">
            <div className="p-1.5 rounded-lg bg-purple-500/20 text-purple-400">
              <Key className="h-4 w-4" />
            </div>
            <span>DKIM SIGNATURE</span>
          </div>
          {getStatusBadge(dkim.status)}
        </div>
        <div className="text-xs font-mono space-y-1.5 text-slate-300">
          <div>
            <span className="text-slate-400">Key Selector:</span>{" "}
            <span className="text-slate-200 font-semibold">{dkim.selector || "default"}</span>
          </div>
          <div>
            <span className="text-slate-400">Signing Domain:</span>{" "}
            <span className="text-purple-300 font-semibold">{dkim.domain || "N/A"}</span>
          </div>
          <div className="text-slate-400 text-[11px] pt-1 leading-relaxed border-t border-white/5">
            {dkim.reason || "Cryptographic public-key body hash signature check."}
          </div>
        </div>
      </LiquidGlassCard>

      {/* DMARC Card */}
      <LiquidGlassCard
        glowColor={dmarc.status?.toLowerCase() === 'pass' ? 'emerald' : 'crimson'}
        className="p-5 space-y-3"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-white tracking-wide">
            <div className="p-1.5 rounded-lg bg-red-500/20 text-red-400">
              <ShieldCheck className="h-4 w-4" />
            </div>
            <span>DMARC ALIGNMENT</span>
          </div>
          {getStatusBadge(dmarc.status)}
        </div>
        <div className="text-xs font-mono space-y-1.5 text-slate-300">
          <div>
            <span className="text-slate-400">Enforced Policy:</span>{" "}
            <span className="font-bold text-amber-400 uppercase tracking-wider">
              {dmarc.policy || "none"}
            </span>
          </div>
          <div>
            <span className="text-slate-400">Alignment:</span>{" "}
            <span className={dmarc.aligned ? "text-emerald-400 font-bold" : "text-red-400 font-bold"}>
              {dmarc.aligned ? "ALIGNED (Strict Pass)" : "MISALIGNED (Policy Breach)"}
            </span>
          </div>
          <div className="text-slate-400 text-[11px] pt-1 leading-relaxed border-t border-white/5">
            {dmarc.reason || "DMARC RFC 7489 alignment and reporting verification."}
          </div>
        </div>
      </LiquidGlassCard>
    </div>
  );
};
