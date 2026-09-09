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
  return (
    <div className="space-y-6">
      {/* Quick Findings Banner */}
      <div className="p-5 rounded-xl border border-red-500/25 bg-red-950/10">
        <div className="flex items-center gap-2 mb-2">
          <ShieldAlert className="w-4 h-4 text-red-400" />
          <span className="text-xs font-mono font-bold text-red-300 uppercase tracking-wider">
            Critical Incident Executive Summary
          </span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          Incident <strong className="text-white font-mono">{data.meta.investigationId}</strong> has been classified as{" "}
          <strong className="text-red-400">{data.threatAssessment.verdict}</strong> with {data.threatAssessment.confidence}% statistical confidence. Originating public hop was isolated to a known Tor Exit Node ({data.infrastructure.defangedIp}) on bulletproof ASN {data.infrastructure.asn}. The payload targets Microsoft 365 credentials through a 302 redirect chain pointing to newly registered domain {data.urlIntelligence.defangedUrl}.
        </p>
      </div>

      {/* 4 IOC Quick Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
        <div className="p-4 rounded-xl bg-white/2 border border-white/5 flex flex-col justify-between">
          <div className="text-slate-500 mb-1 flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            Originating Node IP
          </div>
          <div className="text-sm font-bold text-red-400 break-all">{data.infrastructure.defangedIp}</div>
          <div className="text-[10px] text-slate-500 mt-1">{data.infrastructure.city}, {data.infrastructure.countryCode}</div>
        </div>

        <div className="p-4 rounded-xl bg-white/2 border border-white/5 flex flex-col justify-between">
          <div className="text-slate-500 mb-1 flex items-center gap-1.5">
            <Link2 className="w-3.5 h-3.5 text-red-400" />
            Target Link
          </div>
          <div className="text-sm font-bold text-slate-200 truncate">{data.urlIntelligence.domain}</div>
          <div className="text-[10px] text-amber-400 mt-1">Age: {data.urlIntelligence.domainReputation.ageDays} days</div>
        </div>

        <div className="p-4 rounded-xl bg-white/2 border border-white/5 flex flex-col justify-between">
          <div className="text-slate-500 mb-1 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-purple-400" />
            Protocol Verification
          </div>
          <div className="text-sm font-bold text-red-400">
            SPF: {data.headers.spf.status} · DKIM: {data.headers.dkim.status}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">DMARC: {data.headers.dmarc.policy}</div>
        </div>

        <div className="p-4 rounded-xl bg-white/2 border border-white/5 flex flex-col justify-between">
          <div className="text-slate-500 mb-1 flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-violet-400" />
            Threat Attribution
          </div>
          <div className="text-sm font-bold text-purple-300 truncate">{data.threatGraph.campaignName}</div>
          <div className="text-[10px] text-slate-500 mt-1">Modularity Q = {data.threatGraph.modularityScore}</div>
        </div>
      </div>

      {/* Cyber Killchain Progression */}
      <div className="p-5 rounded-xl border border-white/5 bg-white/2">
        <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-4 flex items-center gap-2">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          Attack Killchain Progression &amp; Triage State
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
            <div className="text-red-400 font-bold mb-1">1. RECONNAISSANCE</div>
            <p className="text-[11px] text-slate-300">Executive roster scraping and domain registration 14 days prior to dispatch.</p>
          </div>
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
            <div className="text-red-400 font-bold mb-1">2. WEAPONIZATION</div>
            <p className="text-[11px] text-slate-300">Deceptive M365 authentication landing page deployed with 302 redirector.</p>
          </div>
          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
            <div className="text-amber-400 font-bold mb-1">3. DELIVERY</div>
            <p className="text-[11px] text-slate-300">Inbound dispatch via Tor Exit Node bypassing initial gateway heuristics.</p>
          </div>
          <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
            <div className="text-cyan-400 font-bold mb-1">4. MITIGATION</div>
            <p className="text-[11px] text-slate-300">SpectraShield Sentinel intercepted and quarantined message before click.</p>
          </div>
        </div>
      </div>
    </div>
  );
};
