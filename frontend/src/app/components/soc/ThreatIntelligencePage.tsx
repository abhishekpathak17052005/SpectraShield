import React, { useEffect, useState, useMemo } from "react";
import { SocLayout } from "./SocLayout";
import {
  Search,
  RefreshCw,
  ChevronRight,
  Radio,
} from "lucide-react";
import { getForensicCases, lookupCti, ForensicCaseRecord, CtiIndicatorHit } from "../../api";
import { defangText } from "../../services/investigationService";
import { IocExplorationField } from "./IocExplorationField";
import { Button, Badge } from "../ui";

interface Props {
  onNavigate: (route: string) => void;
}

type IocType = "ALL" | "DOMAIN" | "IP" | "HASH";

interface AggregatedIoc {
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
  status: string;
}

export const ThreatIntelligencePage: React.FC<Props> = ({ onNavigate }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [cases, setCases] = useState<ForensicCaseRecord[]>([]);
  const [iocTypeFilter, setIocTypeFilter] = useState<IocType>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Live CTI Lookup Tool State
  const [lookupQuery, setLookupQuery] = useState<string>("");
  const [lookupLoading, setLookupLoading] = useState<boolean>(false);
  const [lookupResult, setLookupResult] = useState<{
    indicator: string;
    records: CtiIndicatorHit[];
    total_hits: number;
    malicious_hits: number;
    vpn_or_tor: boolean;
  } | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);

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

  // Extract IOCs strictly from active backend cases (Zero fabricated data)
  const allIocs = useMemo(() => {
    const list: AggregatedIoc[] = [];
    const seen = new Set<string>();

    cases.forEach((c) => {
      const caseId = c.id;
      const caseNum = c.case_number || c.id;
      const timestamp = c.created_at || new Date().toISOString();
      const caseRisk = Math.round(c.final_risk ?? c.overall_risk_score ?? 0);

      // 1. Originating IP
      const originIp = c.originating_node?.ip;
      if (originIp && !seen.has(`ip:${originIp}`)) {
        seen.add(`ip:${originIp}`);
        list.push({
          id: `ioc-ip-${list.length + 1}`,
          type: "IP",
          indicator: originIp,
          defangedIndicator: defangText(originIp),
          riskRating: Math.round(c.originating_node?.risk_rating ?? caseRisk),
          threatSeverity: caseRisk >= 70 ? "HIGH" : caseRisk >= 30 ? "MEDIUM" : "SAFE",
          source: c.originating_node?.isp || "Origin Header",
          associatedCaseId: caseId,
          associatedCaseNumber: caseNum,
          firstSeen: timestamp,
          status: caseRisk >= 70 ? "FLAGGED" : "OBSERVED",
        });
      }

      // 2. Sender Domain
      let senderDomain = "";
      if (c.sender && c.sender.includes("@")) {
        senderDomain = c.sender.split("@")[1]?.replace(/[>]/g, "").trim();
      }
      if (senderDomain && !seen.has(`domain:${senderDomain}`)) {
        seen.add(`domain:${senderDomain}`);
        list.push({
          id: `ioc-dom-${list.length + 1}`,
          type: "DOMAIN",
          indicator: senderDomain,
          defangedIndicator: defangText(senderDomain),
          riskRating: caseRisk,
          threatSeverity: caseRisk >= 70 ? "HIGH" : caseRisk >= 30 ? "MEDIUM" : "SAFE",
          source: "Sender Domain",
          associatedCaseId: caseId,
          associatedCaseNumber: caseNum,
          firstSeen: timestamp,
          status: caseRisk >= 70 ? "FLAGGED" : "OBSERVED",
        });
      }

      // 3. Evidence SHA-256 Hash
      const sha256 = c.sha256_evidence_hash;
      if (sha256 && !seen.has(`hash:${sha256}`)) {
        seen.add(`hash:${sha256}`);
        list.push({
          id: `ioc-hash-${list.length + 1}`,
          type: "HASH",
          indicator: sha256,
          defangedIndicator: `${sha256.slice(0, 16)}...`,
          riskRating: caseRisk,
          threatSeverity: caseRisk >= 70 ? "HIGH" : caseRisk >= 30 ? "MEDIUM" : "SAFE",
          source: "Evidence Vault SHA-256",
          associatedCaseId: caseId,
          associatedCaseNumber: caseNum,
          firstSeen: timestamp,
          status: "SEALED",
        });
      }
    });

    return list;
  }, [cases]);

  // Filter IOCs
  const filteredIocs = useMemo(() => {
    return allIocs.filter((ioc) => {
      if (iocTypeFilter !== "ALL" && ioc.type !== iocTypeFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchInd = ioc.indicator.toLowerCase().includes(q);
        const matchCase = ioc.associatedCaseNumber.toLowerCase().includes(q);
        const matchSrc = ioc.source.toLowerCase().includes(q);
        if (!matchInd && !matchCase && !matchSrc) return false;
      }
      return true;
    });
  }, [allIocs, iocTypeFilter, searchQuery]);

  // Handle live CTI lookup
  const handlePerformLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = lookupQuery.trim();
    if (!q) return;

    setLookupLoading(true);
    setLookupError(null);
    setLookupResult(null);

    try {
      const res = await lookupCti(q);
      setLookupResult(res);
    } catch (err: any) {
      setLookupError(err?.message || "Threat feed query failed.");
    } finally {
      setLookupLoading(false);
    }
  };

  const domainCount = allIocs.filter((i) => i.type === "DOMAIN").length;
  const ipCount = allIocs.filter((i) => i.type === "IP").length;
  const hashCount = allIocs.filter((i) => i.type === "HASH").length;

  return (
    <SocLayout
      activeNav="threat_intelligence"
      onNavigate={onNavigate}
      title="Threat Intelligence"
      subtitle="Indicators of compromise, reputation lookup, and feed correlations"
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
      {/* ─── 1. IOC LOOKUP SEARCH ───────────────────────────────────────────── */}
      <div className="p-4 rounded-xl border border-border bg-surface-elevated space-y-3">
        <div className="text-xs font-medium text-text-secondary">
          Search: IP / Domain / URL / Hash
        </div>
        <form onSubmit={handlePerformLookup} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              placeholder="Enter IP, domain, URL, or hash..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-input border border-input-border text-xs text-foreground placeholder-input-placeholder focus:outline-none focus:border-input-border-focus"
            />
          </div>
          <Button
            type="submit"
            disabled={lookupLoading || !lookupQuery.trim()}
            variant="accent"
            size="sm"
          >
            {lookupLoading ? "Looking up..." : "Lookup"}
          </Button>
        </form>

        {lookupError && (
          <div className="text-xs text-danger font-mono pt-1">
            {lookupError}
          </div>
        )}

        {lookupResult && (
          <div className="pt-3 border-t border-border text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-accent font-medium">
                {defangText(lookupResult.indicator)}
              </span>
              <Badge
                variant={lookupResult.malicious_hits > 0 ? "danger" : "success"}
                size="xs"
              >
                {lookupResult.malicious_hits > 0 ? "Threat Match" : "Clean"}
              </Badge>
            </div>
            {lookupResult.records.length > 0 ? (
              <div className="space-y-1">
                {lookupResult.records.map((r, i) => (
                  <div key={i} className="flex justify-between text-text-muted text-[11px]">
                    <span>{r.source}</span>
                    <span className={r.is_malicious ? "text-danger font-medium" : "text-success"}>
                      {r.is_malicious ? "Malicious" : "Clean"}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-text-muted">
                External feeds not configured.
              </div>
            )}
          </div>
        )}
      </div>

      {/* ─── 2. IOC EXPLORATION & CORRELATION FIELD ────────────────────────── */}
      {allIocs.length > 0 && (
        <IocExplorationField iocs={allIocs} onNavigate={onNavigate} />
      )}

      {/* ─── 3. ELEVATED METRIC SUMMARY STRIP ───────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl border border-accent/30 bg-surface-elevated">
          <div className="text-[11px] text-text-muted font-medium">Total Observables</div>
          <div className="text-xl font-bold font-mono text-accent mt-1">{allIocs.length}</div>
        </div>
        <div className="p-3.5 rounded-xl border border-border bg-surface-elevated">
          <div className="text-[11px] text-text-muted font-medium">Sender Domains</div>
          <div className="text-xl font-bold font-mono text-foreground mt-1">{domainCount}</div>
        </div>
        <div className="p-3.5 rounded-xl border border-border bg-surface-elevated">
          <div className="text-[11px] text-text-muted font-medium">Originating IPs</div>
          <div className="text-xl font-bold font-mono text-foreground mt-1">{ipCount}</div>
        </div>
        <div className="p-3.5 rounded-xl border border-success/30 bg-surface-elevated">
          <div className="text-[11px] text-text-muted font-medium">Evidence Hashes</div>
          <div className="text-xl font-bold font-mono text-success mt-1">{hashCount}</div>
        </div>
      </div>

      {/* ─── 3. CLEAN IOC TABLE ─────────────────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-1 bg-surface p-1 rounded-lg border border-border text-xs">
            {(["ALL", "IP", "DOMAIN", "HASH"] as const).map((t) => (
              <Button
                key={t}
                onClick={() => setIocTypeFilter(t)}
                variant={iocTypeFilter === t ? "accent" : "ghost"}
                size="sm"
              >
                {t === "ALL" ? "All Types" : t}
              </Button>
            ))}
          </div>

          <div className="relative w-full sm:w-60">
            <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter observables..."
              className="w-full pl-8 pr-3 py-1 rounded-lg bg-input border border-input-border text-xs text-foreground placeholder-input-placeholder focus:outline-none focus:border-input-border-focus"
            />
          </div>
        </div>

        <div className="rounded-xl border border-border bg-surface-elevated/50 overflow-hidden">
          {loading ? (
            <div className="py-12 text-center text-xs text-text-muted flex items-center justify-center gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-accent" />
              <span>Loading threat indicators...</span>
            </div>
          ) : filteredIocs.length === 0 ? (
            <div className="py-12 text-center text-xs text-text-muted">
              No indicators found matching the criteria.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-text-muted font-medium">
                    <th className="py-2.5 px-4">Type</th>
                    <th className="py-2.5 px-4">Indicator</th>
                    <th className="py-2.5 px-4">Risk</th>
                    <th className="py-2.5 px-4">Source</th>
                    <th className="py-2.5 px-4">Case</th>
                    <th className="py-2.5 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredIocs.map((ioc) => {
                    const isHigh = ioc.riskRating >= 70;
                    const isMed = ioc.riskRating >= 30 && ioc.riskRating < 70;

                    return (
                      <tr key={ioc.id} className="hover:bg-surface-hover transition-colors">
                        <td className="py-2.5 px-4">
                          <Badge variant="outline" size="xs">
                            {ioc.type}
                          </Badge>
                        </td>
                        <td className="py-2.5 px-4 font-mono text-foreground max-w-xs truncate font-medium">
                          {ioc.defangedIndicator}
                        </td>
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <span
                            className={`text-[11px] font-medium ${
                              isHigh ? "text-danger" : isMed ? "text-warning" : "text-success"
                            }`}
                          >
                            {ioc.riskRating}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-text-muted text-[11px] truncate max-w-xs">
                          {ioc.source}
                        </td>
                        <td className="py-2.5 px-4 font-mono">
                          <Button
                            onClick={() => onNavigate(`/investigations/${ioc.associatedCaseId}`)}
                            variant="link"
                            size="sm"
                          >
                            {ioc.associatedCaseNumber}
                          </Button>
                        </td>
                        <td className="py-2.5 px-4 text-right">
                          <Button
                            onClick={() => onNavigate(`/investigations/${ioc.associatedCaseId}`)}
                            variant="link"
                            size="sm"
                          >
                            Open
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </SocLayout>
  );
};
