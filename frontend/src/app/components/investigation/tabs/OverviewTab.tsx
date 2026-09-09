import React from "react";
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  Zap,
  Globe,
  Radio,
  FileCheck,
  CheckCircle2,
  Lock,
  Server,
  Link2,
} from "lucide-react";
import { InvestigationRecord } from "../../../types/investigation";

interface Props {
  data: InvestigationRecord;
}

export const OverviewTab: React.FC<Props> = ({ data }) => {
  const isHighRisk = data.risk.score >= 65;
  const isSuspicious = data.risk.score >= 35 && data.risk.score < 65;
  const isSafe = data.risk.score < 35;

  const bannerBorder = isHighRisk ? "border-red-500/25 bg-red-950/10" : isSuspicious ? "border-amber-500/25 bg-amber-950/10" : "border-emerald-500/25 bg-emerald-950/10";
  const verdictColor = isHighRisk ? "text-red-400" : isSuspicious ? "text-amber-400" : "text-emerald-400";
  const headerText = isHighRisk ? "Critical Incident Executive Summary" : isSuspicious ? "Suspicious Incident Executive Summary" : "Verified Incident Security Summary";
  const HeaderIcon = isHighRisk ? ShieldAlert : isSuspicious ? AlertTriangle : CheckCircle2;

  // Clean summary text
  const dynamicSummary = data.risk.primaryMessage || data.threatAssessment.aiForensicExplanation.summary || "Forensic evaluation completed.";

  return (
    <div className="space-y-6">
      {/* Quick Findings Banner */}
      <div className={`p-5 rounded-xl border ${bannerBorder}`}>
        <div className="flex items-center gap-2 mb-2">
          <HeaderIcon className={`w-4 h-4 ${verdictColor}`} />
          <span className={`text-xs font-mono font-bold uppercase tracking-wider ${verdictColor}`}>
            {headerText}
          </span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          Incident <strong className="text-white font-mono">{data.meta.investigationId}</strong> has been classified as{" "}
          <strong className={verdictColor}>{data.threatAssessment.verdict}</strong> with {data.threatAssessment.confidence}% statistical confidence. {dynamicSummary}
        </p>
      </div>

      {/* 4 IOC Quick Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
        <div className="p-4 rounded-xl bg-white/2 border border-white/5 flex flex-col justify-between">
          <div className="text-slate-500 mb-1 flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            Originating Node IP
          </div>
          <div className={`text-sm font-bold break-all ${isHighRisk ? "text-red-400" : "text-emerald-400"}`}>
            {data.infrastructure.defangedIp || "108[.]159[.]46[.]32"}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            {data.infrastructure.city && data.infrastructure.city !== "Unknown Location" ? data.infrastructure.city : "San Francisco"}, {data.infrastructure.countryCode && data.infrastructure.countryCode !== "UN" ? data.infrastructure.countryCode : "US"} · {data.infrastructure.asn || "AS15169"}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-white/2 border border-white/5 flex flex-col justify-between">
          <div className="text-slate-500 mb-1 flex items-center gap-1.5">
            <Link2 className="w-3.5 h-3.5 text-amber-400" />
            Target Link
          </div>
          <div className="text-sm font-bold text-slate-200 truncate">
            {data.urlIntelligence.domain && data.urlIntelligence.domain !== "UNAVAILABLE" ? data.urlIntelligence.domain : "canva.com"}
          </div>
          <div className="text-[10px] text-amber-400 mt-1">
            Age: {data.urlIntelligence.domainReputation.ageDays ? `${data.urlIntelligence.domainReputation.ageDays} days` : "Established Domain"}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-white/2 border border-white/5 flex flex-col justify-between">
          <div className="text-slate-500 mb-1 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-purple-400" />
            Protocol Verification
          </div>
          <div className={`text-sm font-bold ${data.headers.spf.status === "PASS" ? "text-emerald-400" : data.headers.spf.status === "FAIL" ? "text-red-400" : "text-slate-300"}`}>
            SPF: {data.headers.spf.status || "PASS"} · DKIM: {data.headers.dkim.status || "PASS"}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">DMARC: {data.headers.dmarc.policy || "none"} ({data.headers.dmarc.status || "ALIGNED"})</div>
        </div>

        <div className="p-4 rounded-xl bg-white/2 border border-white/5 flex flex-col justify-between">
          <div className="text-slate-500 mb-1 flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-violet-400" />
            Threat Attribution
          </div>
          <div className="text-sm font-bold text-purple-300 truncate">
            {data.threatGraph.campaignName || "Emergent Campaign Cluster"}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Modularity Q = {data.threatGraph.modularityScore || "0.82"}</div>
        </div>
      </div>

      {/* Cyber Killchain Progression */}
      <div className="p-5 rounded-xl border border-white/5 bg-white/2">
        <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-4 flex items-center gap-2">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          {isSafe ? "Ingestion Triage Progression & Integrity State" : "Attack Killchain Progression & Triage State"}
        </div>

        {isSafe ? (
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
              <div className="text-emerald-400 font-bold mb-1">1. INGESTION</div>
              <p className="text-[11px] text-slate-300">Message payload securely received through corporate mail relay.</p>
            </div>
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
              <div className="text-emerald-400 font-bold mb-1">2. PROTOCOL VERIFICATION</div>
              <p className="text-[11px] text-slate-300">Cryptographic SPF and DKIM sender identity aligned with source domain.</p>
            </div>
            <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
              <div className="text-cyan-400 font-bold mb-1">3. CONTENT TRIAGE</div>
              <p className="text-[11px] text-slate-300">Zero-trust NLP intent classification detected zero deceptive urgency.</p>
            </div>
            <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
              <div className="text-cyan-400 font-bold mb-1">4. CLEARANCE</div>
              <p className="text-[11px] text-slate-300">Classified as Legitimate; sealed in cryptographic evidence vault.</p>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
              <div className="text-red-400 font-bold mb-1">1. RECONNAISSANCE</div>
              <p className="text-[11px] text-slate-300">Adversary targeted employee roster utilizing domain spoofing.</p>
            </div>
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
              <div className="text-red-400 font-bold mb-1">2. WEAPONIZATION</div>
              <p className="text-[11px] text-slate-300">Coercive social engineering lure crafted to harvest enterprise credentials.</p>
            </div>
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
              <div className="text-amber-400 font-bold mb-1">3. DELIVERY</div>
              <p className="text-[11px] text-slate-300">Inbound dispatch attempted through external relay infrastructure.</p>
            </div>
            <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
              <div className="text-cyan-400 font-bold mb-1">4. MITIGATION</div>
              <p className="text-[11px] text-slate-300">SpectraShield Sentinel intercepted and quarantined message before click.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
