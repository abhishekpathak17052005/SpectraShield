import React, { useEffect, useState, useMemo } from "react";
import { SocLayout } from "./SocLayout";
import {
  RefreshCw,
  ChevronRight,
  Server,
  Globe,
  Network,
} from "lucide-react";
import { getForensicCases, ForensicCaseRecord } from "../../api";
import { defangText } from "../../services/investigationService";
import { InfrastructureGraph } from "./InfrastructureGraph";
import { Button, Badge } from "../ui";

interface Props {
  onNavigate: (route: string) => void;
}

export const ForensicIntelligencePage: React.FC<Props> = ({ onNavigate }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [cases, setCases] = useState<ForensicCaseRecord[]>([]);

  const fetchCases = async () => {
    setLoading(true);
    try {
      const res = await getForensicCases({ limit: 100 });
      setCases(res?.cases || []);
    } catch (err) {
      console.error("Failed to load cases:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  // Compute Originating IPs
  const originIps = useMemo(() => {
    const map = new Map<string, { ip: string; count: number; cases: string[]; isp?: string; country?: string; isTor?: boolean }>();
    cases.forEach((c) => {
      const ip = c.originating_node?.ip;
      if (ip) {
        const entry = map.get(ip) || {
          ip,
          count: 0,
          cases: [],
          isp: c.originating_node?.isp,
          country: c.originating_node?.country,
          isTor: c.originating_node?.is_anonymized,
        };
        entry.count++;
        entry.cases.push(c.case_number || c.id);
        map.set(ip, entry);
      }
    });
    return Array.from(map.values()).sort((a, b) => b.count - a.count);
  }, [cases]);

  // Compute Sender Domains
  const senderDomains = useMemo(() => {
    const map = new Map<string, { domain: string; count: number; cases: string[]; highRiskCount: number }>();
    cases.forEach((c) => {
      let domain = "";
      if (c.sender && c.sender.includes("@")) {
        domain = c.sender.split("@")[1]?.replace(/[>]/g, "").trim().toLowerCase();
      }
      if (domain) {
        const entry = map.get(domain) || { domain, count: 0, cases: [], highRiskCount: 0 };
        entry.count++;
        entry.cases.push(c.case_number || c.id);
        const risk = c.final_risk ?? c.overall_risk_score ?? 0;
        if (risk >= 70) entry.highRiskCount++;
        map.set(domain, entry);
      }
    });
    return Array.from(map.values()).sort((a, b) => b.count - a.count);
  }, [cases]);

  // Compute ASNs
  const asns = useMemo(() => {
    const map = new Map<string, { asn: string; isp: string; count: number }>();
    cases.forEach((c) => {
      const asn = c.originating_node?.asn;
      const isp = c.originating_node?.isp || "Unknown Provider";
      if (asn) {
        const entry = map.get(asn) || { asn, isp, count: 0 };
        entry.count++;
        map.set(asn, entry);
      }
    });
    return Array.from(map.values()).sort((a, b) => b.count - a.count);
  }, [cases]);

  return (
    <SocLayout
      activeNav="forensics"
      onNavigate={onNavigate}
      title="Forensic Intelligence"
      subtitle="Infrastructure, sender domains, and campaign correlation"
      actions={
        <Button
          onClick={fetchCases}
          disabled={loading}
          variant="ghost"
          size="sm"
          className="flex items-center gap-1.5"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-accent" : ""}`} />
          <span>Refresh</span>
        </Button>
      }
    >
      {/* ─── 1. TOP METRICS (MAX 3 USEFUL METRICS) ─────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl border border-border bg-surface-elevated">
          <div className="text-xs text-text-muted font-medium">Originating IPs</div>
          <div className="text-2xl font-semibold text-foreground mt-1">
            {originIps.length}
          </div>
          <div className="text-[11px] text-text-muted mt-0.5">
            Ingress nodes from header hops
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border bg-surface-elevated">
          <div className="text-xs text-text-muted font-medium">Sender Domains</div>
          <div className="text-2xl font-semibold text-foreground mt-1">
            {senderDomains.length}
          </div>
          <div className="text-[11px] text-text-muted mt-0.5">
            Envelope From identities
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border bg-surface-elevated">
          <div className="text-xs text-text-muted font-medium">Autonomous Systems</div>
          <div className="text-2xl font-semibold text-foreground mt-1">
            {asns.length}
          </div>
          <div className="text-[11px] text-text-muted mt-0.5">
            ASN routing carriers
          </div>
        </div>
      </div>

      {/* ─── 2. RELATIONSHIP GRAPH (VISUAL CENTERPIECE) ──────────────────────── */}
      {loading ? (
        <div className="rounded-xl border border-border bg-surface-elevated p-12 text-center text-xs text-text-muted flex flex-col items-center justify-center gap-3">
          <RefreshCw className="w-5 h-5 animate-spin text-accent" />
          <span>Synthesizing topological infrastructure relationships...</span>
        </div>
      ) : (
        <InfrastructureGraph cases={cases} onNavigate={onNavigate} />
      )}

      {/* ─── 3. INFRASTRUCTURE TABLES ────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Originating IPs */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-foreground tracking-tight">
            Originating IPs
          </h3>
          <div className="rounded-xl border border-border bg-surface-elevated/50 overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-border text-text-muted font-medium">
                  <th className="py-2.5 px-3">IP Address</th>
                  <th className="py-2.5 px-3">Location / ISP</th>
                  <th className="py-2.5 px-3 text-right">Cases</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {originIps.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="py-6 text-center text-text-muted">
                      No IPs captured.
                    </td>
                  </tr>
                ) : (
                  originIps.slice(0, 6).map((item, idx) => (
                    <tr key={idx} className="hover:bg-surface-hover">
                      <td className="py-2.5 px-3 font-mono text-foreground">
                        {defangText(item.ip)}
                      </td>
                      <td className="py-2.5 px-3 text-text-muted text-[11px] truncate max-w-xs">
                        {item.country ? `${item.country} · ` : ""}{item.isp || "Direct"}
                      </td>
                      <td className="py-2.5 px-3 text-right text-foreground font-mono">
                        {item.count}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Sender Domains */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-foreground tracking-tight">
            Sender Domains
          </h3>
          <div className="rounded-xl border border-border bg-surface-elevated/50 overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-border text-text-muted font-medium">
                  <th className="py-2.5 px-3">Domain</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Cases</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {senderDomains.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="py-6 text-center text-text-muted">
                      No domains recorded.
                    </td>
                  </tr>
                ) : (
                  senderDomains.slice(0, 6).map((item, idx) => (
                    <tr key={idx} className="hover:bg-surface-hover">
                      <td className="py-2.5 px-3 font-mono text-foreground">
                        {defangText(item.domain)}
                      </td>
                      <td className="py-2.5 px-3">
                        <Badge
                          variant={item.highRiskCount > 0 ? "destructive" : "success"}
                          size="xs"
                        >
                          {item.highRiskCount > 0 ? "Suspicious" : "Clean"}
                        </Badge>
                      </td>
                      <td className="py-2.5 px-3 text-right text-foreground font-mono">
                        {item.count}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </SocLayout>
  );
};
