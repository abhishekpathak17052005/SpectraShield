import React from "react";
import {
  Server,
  MapPin,
  Globe,
  Lock,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Radio,
  Wifi,
  Activity,
  Calendar,
  Layers,
} from "lucide-react";
import { InfrastructureData } from "../../../types/investigation";

interface Props {
  infrastructure: InfrastructureData;
}

function isUnenriched(value: string | null | undefined): boolean {
  if (!value) return true;
  const v = value.toUpperCase();
  return v === "NOT ENRICHED" || v === "UNAVAILABLE" || v === "UNKNOWN" || v === "N/A";
}

export const InfrastructureTab: React.FC<Props> = ({ infrastructure }) => {
  const ip = infrastructure?.ip || "NOT ENRICHED";
  const country = infrastructure?.country || "NOT ENRICHED";
  const city = infrastructure?.city || "NOT ENRICHED";
  const asn = infrastructure?.asn || "NOT ENRICHED";
  const isp = infrastructure?.isp || "NOT ENRICHED";
  const domainAge = infrastructure?.domainAge || "NOT ENRICHED";
  const isTor = infrastructure?.isTorExitNode ?? false;
  const isVpn = infrastructure?.isCommercialVpn ?? false;
  const hostingRisk = infrastructure?.hostingRiskScore ?? 0;

  // SSL from sslCertificate object
  const ssl = infrastructure?.sslCertificate;
  const sslStatus = ssl?.status || "UNKNOWN";
  const sslIssuer = ssl?.issuer || "NOT ENRICHED";
  const sslValid = ssl?.valid ?? false;

  const intelCards = [
    {
      title: "IP Address",
      value: infrastructure?.ip || "NOT ENRICHED",
      sublabel: `Defanged: ${infrastructure?.defangedIp || "NOT ENRICHED"}`,
      status: isTor ? "TOR EXIT NODE" : isUnenriched(ip) ? "NOT ENRICHED" : "ORIGINATING IP",
      statusColor: isTor
        ? "text-red-400 bg-red-500/10 border-red-500/30"
        : isUnenriched(ip)
        ? "text-slate-500 bg-slate-700/20 border-slate-600/20"
        : "text-amber-400 bg-amber-500/10 border-amber-500/30",
      icon: Server,
    },
    {
      title: "Country",
      value: country,
      sublabel: `Code: ${infrastructure?.countryCode || "—"} · ${city}`,
      status: isUnenriched(country) ? "NOT ENRICHED" : "GEO ATTRIBUTED",
      statusColor: isUnenriched(country)
        ? "text-slate-500 bg-slate-700/20 border-slate-600/20"
        : "text-amber-400 bg-amber-500/10 border-amber-500/30",
      icon: MapPin,
    },
    {
      title: "ASN",
      value: asn,
      sublabel: "Routing Autonomous System",
      status: isUnenriched(asn) ? "NOT ENRICHED" : "ASN MAPPED",
      statusColor: isUnenriched(asn)
        ? "text-slate-500 bg-slate-700/20 border-slate-600/20"
        : "text-cyan-400 bg-cyan-500/10 border-cyan-500/30",
      icon: Globe,
    },
    {
      title: "ISP",
      value: isp,
      sublabel: "Hosting & VPS Infrastructure",
      status: isUnenriched(isp) ? "NOT ENRICHED" : "ISP IDENTIFIED",
      statusColor: isUnenriched(isp)
        ? "text-slate-500 bg-slate-700/20 border-slate-600/20"
        : "text-amber-400 bg-amber-500/10 border-amber-500/30",
      icon: Wifi,
    },
    {
      title: "Domain Age",
      value: domainAge,
      sublabel: "Domain Registration Lifespan",
      status: isUnenriched(domainAge)
        ? "NOT ENRICHED"
        : parseInt(domainAge) < 30
        ? "NEWLY REGISTERED"
        : parseInt(domainAge) < 90
        ? "RECENT REGISTRATION"
        : "ESTABLISHED DOMAIN",
      statusColor: isUnenriched(domainAge)
        ? "text-slate-500 bg-slate-700/20 border-slate-600/20"
        : parseInt(domainAge) < 30
        ? "text-red-400 bg-red-500/10 border-red-500/30"
        : parseInt(domainAge) < 90
        ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
        : "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
      icon: Calendar,
    },
    {
      title: "SSL Status",
      value: sslValid ? "Valid" : isUnenriched(sslStatus) ? "NOT ENRICHED" : sslStatus,
      sublabel: `Issuer: ${sslIssuer}`,
      status: isUnenriched(sslStatus) ? "NOT ENRICHED" : sslValid ? "VALID TLS" : "INVALID TLS",
      statusColor:
        isUnenriched(sslStatus)
          ? "text-slate-500 bg-slate-700/20 border-slate-600/20"
          : sslValid
          ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
          : "text-red-400 bg-red-500/10 border-red-500/30",
      icon: Lock,
    },
    {
      title: "Tor Exit Node",
      value: isTor ? "YES — TOR EXIT" : "NOT DETECTED",
      sublabel: `VPN: ${isVpn ? infrastructure?.vpnProvider || "Yes" : "Not detected"}`,
      status: isTor ? "ANONYMIZATION ACTIVE" : "NO ANONYMIZATION",
      statusColor: isTor
        ? "text-red-400 bg-red-500/10 border-red-500/30"
        : "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
      icon: ShieldAlert,
    },
    {
      title: "Hosting Risk",
      value: hostingRisk > 0 ? `${hostingRisk}/100` : "NOT ENRICHED",
      sublabel: "Infrastructure Risk Score",
      status: hostingRisk >= 70 ? "ELEVATED RISK" : hostingRisk > 0 ? "MODERATE RISK" : "NOT ENRICHED",
      statusColor:
        hostingRisk >= 70
          ? "text-red-400 bg-red-500/10 border-red-500/30"
          : hostingRisk > 0
          ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
          : "text-slate-500 bg-slate-700/20 border-slate-600/20",
      icon: ShieldCheck,
    },
    {
      title: "Abuse Score",
      value: typeof infrastructure?.abuseConfidenceScore === "number"
        ? `${infrastructure.abuseConfidenceScore}%`
        : "NOT ENRICHED",
      sublabel: "Global Abuse Confidence",
      status:
        typeof infrastructure?.abuseConfidenceScore !== "number"
          ? "NOT ENRICHED"
          : infrastructure.abuseConfidenceScore >= 50
          ? "HIGH ABUSE CONFIDENCE"
          : infrastructure.abuseConfidenceScore > 0
          ? "LOW ABUSE CONFIDENCE"
          : "CLEAN / BENIGN IP",
      statusColor:
        typeof infrastructure?.abuseConfidenceScore !== "number"
          ? "text-slate-500 bg-slate-700/20 border-slate-600/20"
          : infrastructure.abuseConfidenceScore >= 50
          ? "text-red-400 bg-red-500/15 border-red-500/40 font-bold"
          : infrastructure.abuseConfidenceScore > 0
          ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
          : "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
      icon: Radio,
    },
  ];

  return (
    <div className="space-y-6">
      {/* ─── SECTION TITLE ──────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between pb-2 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-cyan-400" />
          <h2 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
            Infrastructure Attribution Intelligence Cards
          </h2>
        </div>
        <span className="text-[10px] font-mono text-cyan-400">9 Attributes Evaluated</span>
      </div>

      {/* ─── 9 INTELLIGENCE CARDS GRID ──────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {intelCards.map((card, idx) => {
          const Icon = card.icon;
          return (
            <div
              key={idx}
              className="p-4 rounded-xl border border-cyan-500/20 bg-slate-900/80 shadow-md flex flex-col justify-between gap-3 hover:border-cyan-500/40 transition-all group"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
                    <Icon className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[11px] font-mono text-slate-400 uppercase font-semibold">
                    {card.title}
                  </span>
                </div>
                <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${card.statusColor}`}>
                  {card.status}
                </span>
              </div>

              <div>
                <div className="text-base font-black text-white font-mono tracking-tight">
                  {card.value}
                </div>
                <div className="text-xs font-mono text-slate-400 mt-0.5 truncate">
                  {card.sublabel}
                </div>
              </div>

              <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-500">
                <span>Autonomous Triangulation</span>
                <span className={isUnenriched(card.value) ? "text-slate-600" : "text-cyan-400"}>
                  {isUnenriched(card.value) ? "Unavailable" : "Verified"}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* ─── GEOLOCATION & NETWORK ARCHITECTURE SUMMARY ─────────────────────── */}
      <div className="p-5 rounded-2xl border border-white/10 bg-slate-900/80 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
        <div className="p-3.5 rounded-xl bg-black/40 border border-white/5 space-y-1">
          <span className="text-[10px] uppercase text-slate-500 font-bold">Network Location</span>
          <div className="text-sm font-bold text-slate-200">
            {[city, country].filter((v) => !isUnenriched(v)).join(", ") || "NOT ENRICHED"}
          </div>
          <div className="text-slate-400 text-[11px]">
            {infrastructure?.coordinates?.latitude && infrastructure?.coordinates?.longitude
              ? `${infrastructure.coordinates.latitude}° N, ${infrastructure.coordinates.longitude}° E`
              : "Coordinates not available"}
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-black/40 border border-white/5 space-y-1">
          <span className="text-[10px] uppercase text-slate-500 font-bold">Transport Layer Security</span>
          <div className={`text-sm font-bold ${sslValid ? "text-emerald-400" : isUnenriched(sslStatus) ? "text-slate-400" : "text-amber-400"}`}>
            {sslValid ? `Valid (${sslIssuer})` : isUnenriched(sslStatus) ? "NOT ENRICHED" : `${sslStatus} (${sslIssuer})`}
          </div>
          {ssl?.daysUntilExpiry != null && ssl.daysUntilExpiry > 0 ? (
            <div className="text-slate-400 text-[11px]">{ssl.daysUntilExpiry} days remaining</div>
          ) : ssl?.subjectCN && !isUnenriched(ssl.subjectCN) ? (
            <div className="text-slate-400 text-[11px]">Subject: {ssl.subjectCN}</div>
          ) : null}
        </div>

        <div className="p-3.5 rounded-xl bg-black/40 border border-white/5 space-y-1">
          <span className="text-[10px] uppercase text-slate-500 font-bold">Abuse &amp; Hosting Classification</span>
          <div className={`text-sm font-bold ${hostingRisk >= 70 ? "text-red-400" : hostingRisk > 0 ? "text-amber-400" : "text-slate-400"}`}>
            {hostingRisk > 0 ? `Risk Score: ${hostingRisk}/100` : "NOT ENRICHED"}
          </div>
          {isTor && (
            <div className="text-red-400 text-[11px]">TOR exit node detected</div>
          )}
          {isVpn && (
            <div className="text-amber-400 text-[11px]">VPN / Commercial anonymizer: {infrastructure?.vpnProvider || "Unknown provider"}</div>
          )}
          {!isTor && !isVpn && hostingRisk === 0 && (
            <div className="text-slate-500 text-[11px]">No anonymization detected</div>
          )}
        </div>
      </div>
    </div>
  );
};
