import React, { useEffect, useState } from "react";
import { SocLayout } from "./SocLayout";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  ArrowUpRight,
  ChevronRight,
  FolderOpen,
} from "lucide-react";
import { getForensicCases, getApiBase, ForensicCaseRecord } from "../../api";
import { ThreatActivityField } from "./ThreatActivityField";
import { Card, CardContent, Table, TableHeader, TableBody, TableRow, TableHead, TableCell, Badge, Button } from "../ui";

interface Props {
  onNavigate: (route: string) => void;
}

export const OverviewPage: React.FC<Props> = ({ onNavigate }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [cases, setCases] = useState<ForensicCaseRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [engineOnline, setEngineOnline] = useState<boolean>(false);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [casesRes, healthRes] = await Promise.all([
        getForensicCases({ limit: 50 }).catch((err) => {
          console.warn("Failed to fetch cases:", err);
          return { total: 0, cases: [] };
        }),
        fetch(`${getApiBase()}/health`)
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
      ]);

      setCases(casesRes?.cases || []);
      setEngineOnline(healthRes?.status === "healthy");
    } catch (err: any) {
      setError(err?.message || "Failed to communicate with SpectraShield engine.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Compute metrics strictly from actual cases (Zero fabricated data)
  const highRiskCases = cases.filter((c) => {
    const risk = c.final_risk ?? c.overall_risk_score ?? 0;
    const sev = (c.severity || "").toUpperCase();
    return risk >= 70 || sev === "HIGH" || sev === "CRITICAL";
  });

  const suspiciousCases = cases.filter((c) => {
    const risk = c.final_risk ?? c.overall_risk_score ?? 0;
    const sev = (c.severity || "").toUpperCase();
    return (risk >= 30 && risk < 70) || sev === "MEDIUM" || sev === "SUSPICIOUS";
  });

  const safeCases = cases.filter((c) => {
    const risk = c.final_risk ?? c.overall_risk_score ?? 0;
    const sev = (c.severity || "").toUpperCase();
    return risk < 30 && sev !== "HIGH" && sev !== "CRITICAL" && sev !== "SUSPICIOUS";
  });

  const openCases = cases.filter((c) => (c.status || "").toUpperCase() !== "CLOSED");
  const totalCases = cases.length;

  // Attention required: prioritized high + suspicious cases sorted by risk descending
  const attentionRequired = [...highRiskCases, ...suspiciousCases]
    .filter((v, idx, arr) => arr.findIndex((t) => t.id === v.id) === idx)
    .sort((a, b) => {
      const riskA = a.final_risk ?? a.overall_risk_score ?? 0;
      const riskB = b.final_risk ?? b.overall_risk_score ?? 0;
      return riskB - riskA;
    });

  // Recent investigations sorted by creation date
  const recentCases = [...cases].sort((a, b) => {
    const dateA = new Date(a.created_at || 0).getTime();
    const dateB = new Date(b.created_at || 0).getTime();
    return dateB - dateA;
  });

  const formatRelativeTime = (dateStr?: string) => {
    if (!dateStr) return "Recently";
    try {
      const diffSec = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
      if (diffSec < 60) return "Just now";
      if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
      if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
      return `${Math.floor(diffSec / 86400)}d ago`;
    } catch {
      return "Recently";
    }
  };

  return (
    <SocLayout
      activeNav="overview"
      onNavigate={onNavigate}
      title="SOC Overview"
      subtitle="Autonomous Threat Telemetry & Incident Command"
      actions={
        <div className="flex items-center gap-2">
          <Button 
            variant="ghost"
            size="sm"
            onClick={fetchData}
            disabled={loading}
            className="gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </Button>
          <Button 
            variant="accent"
            size="sm"
            onClick={() => onNavigate("/investigations")}
            className="gap-1.5"
          >
            <span>All Investigations</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Button>
        </div>
      }
    >
      {/* ─── DOMINANT 2.5D THREAT ACTIVITY SECURITY FIELD ─────────────────────── */}
      <ThreatActivityField
        engineOnline={engineOnline}
        highRiskCount={highRiskCases.length}
        suspiciousCount={suspiciousCases.length}
        safeCount={safeCases.length}
        totalCount={totalCases}
        openCasesCount={openCases.length}
        onNavigate={onNavigate}
      />

      {/* ─── SECONDARY 4 METRICS STRIP ───────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* High Risk */}
        <Card elevated interactive>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between text-xs font-medium text-text-secondary">
              <span>High Risk Cases</span>
              <ShieldAlert className="w-4 h-4 text-danger" />
            </div>
            <div className="mt-2 text-2xl font-bold font-mono text-danger">
              {highRiskCases.length}
            </div>
            <div className="text-[11px] text-text-muted mt-1">
              Cases requiring immediate action
            </div>
          </CardContent>
        </Card>

        {/* Suspicious */}
        <Card elevated interactive>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between text-xs font-medium text-text-secondary">
              <span>Suspicious Cases</span>
              <AlertTriangle className="w-4 h-4 text-warning" />
            </div>
            <div className="mt-2 text-2xl font-bold font-mono text-warning">
              {suspiciousCases.length}
            </div>
            <div className="text-[11px] text-text-muted mt-1">
              Anomalies under automated review
            </div>
          </CardContent>
        </Card>

        {/* Open Cases */}
        <Card elevated interactive>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between text-xs font-medium text-text-secondary">
              <span>Open In Vault</span>
              <FolderOpen className="w-4 h-4 text-accent" />
            </div>
            <div className="mt-2 text-2xl font-bold font-mono text-accent">
              {openCases.length}
            </div>
            <div className="text-[11px] text-text-muted mt-1">
              {totalCases} total records in vault
            </div>
          </CardContent>
        </Card>

        {/* Engine Status */}
        <Card elevated interactive>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between text-xs font-medium text-text-secondary">
              <span>Detection Engine</span>
              <ShieldCheck className={`w-4 h-4 ${engineOnline ? "text-success" : "text-danger"}`} />
            </div>
            <div className="mt-2 text-2xl font-semibold text-foreground flex items-center gap-2">
              <span
                className={`w-2.5 h-2.5 rounded-full ${
                  engineOnline ? "bg-success shadow-[0_0_8px_rgba(22,163,74,0.8)]" : "bg-danger shadow-[0_0_8px_rgba(220,38,38,0.8)]"
                }`}
              />
              <span className="font-mono text-xl">{engineOnline ? "Online" : "Offline"}</span>
            </div>
            <div className="text-[11px] text-text-muted mt-1">
              FastAPI analysis pipeline (Port 8000)
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ─── ATTENTION REQUIRED SECTION ─────────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground tracking-tight">
            Attention Required
          </h2>
          <span className="text-xs text-text-muted">
            {attentionRequired.length} prioritized {attentionRequired.length === 1 ? "item" : "items"}
          </span>
        </div>

        <Card>
          {loading ? (
            <div className="p-8 text-center text-xs text-text-muted flex items-center justify-center gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-accent" />
              <span>Checking incident queue...</span>
            </div>
          ) : attentionRequired.length === 0 ? (
            <div className="p-8 text-center text-xs text-text-muted">
              No high risk or suspicious incidents requiring immediate triage.
            </div>
          ) : (
            <div className="divide-y divide-border overflow-hidden">
              {attentionRequired.slice(0, 5).map((c) => {
                const risk = Math.round(c.final_risk ?? c.overall_risk_score ?? 0);
                const isHigh = risk >= 70 || (c.severity || "").toUpperCase() === "HIGH" || (c.severity || "").toUpperCase() === "CRITICAL";

                return (
                  <div
                    key={c.id}
                    onClick={() => onNavigate(`/investigations/${c.id}`)}
                    className="p-3.5 flex items-center justify-between gap-4 hover:bg-surface-hover cursor-pointer transition-colors"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <Badge variant={isHigh ? "destructive" : "warning"} className="flex-shrink-0">
                        {isHigh ? "High" : "Suspicious"}
                      </Badge>
                      <div className="min-w-0">
                        <div className="text-xs font-medium text-foreground truncate">
                          {c.title || c.subject || "Security Threat Investigation"}
                        </div>
                        <div className="text-[11px] text-text-muted flex items-center gap-2 mt-0.5">
                          <span className="font-mono text-text-secondary">{c.case_number || c.id}</span>
                          <span>·</span>
                          <span className="font-medium text-text-secondary">Risk {risk}</span>
                          <span>·</span>
                          <span>{formatRelativeTime(c.created_at)}</span>
                        </div>
                      </div>
                    </div>

                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        onNavigate(`/investigations/${c.id}`);
                      }}
                      className="gap-1 flex-shrink-0"
                    >
                      <span>Open</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>

      {/* ─── RECENT INVESTIGATIONS SECTION ───────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground tracking-tight">
            Recent Investigations
          </h2>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onNavigate("/investigations")}
            className="gap-1"
          >
            <span>View All</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </Button>
        </div>

        <Card>
          {loading ? (
            <div className="p-8 text-center text-xs text-text-muted flex items-center justify-center gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-accent" />
              <span>Loading investigations...</span>
            </div>
          ) : recentCases.length === 0 ? (
            <div className="p-8 text-center text-xs text-text-muted">
              No investigations recorded yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <tr className="border-b border-border text-text-secondary font-medium">
                    <TableHead>Case</TableHead>
                    <TableHead>Subject</TableHead>
                    <TableHead>Sender</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Received</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {recentCases.slice(0, 6).map((c) => {
                    const risk = Math.round(c.final_risk ?? c.overall_risk_score ?? 0);
                    const isHigh = risk >= 70;
                    const isMed = risk >= 30 && risk < 70;

                    return (
                      <TableRow
                        key={c.id}
                        onClick={() => onNavigate(`/investigations/${c.id}`)}
                        className="cursor-pointer hover:bg-surface-hover"
                      >
                        <TableCell className="font-mono text-text-secondary whitespace-nowrap">
                          {c.case_number || c.id.slice(0, 16)}
                        </TableCell>
                        <TableCell className="text-foreground font-medium max-w-xs truncate">
                          {c.title || c.subject || "Email Analysis"}
                        </TableCell>
                        <TableCell className="font-mono text-text-muted max-w-[180px] truncate">
                          {c.sender || "—"}
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          <Badge 
                            variant={isHigh ? "destructive" : isMed ? "warning" : "default"}
                            className="text-xs"
                          >
                            {risk}
                          </Badge>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          <span
                            className={`text-xs font-medium uppercase ${
                              isHigh
                                ? "text-danger"
                                : isMed
                                ? "text-warning"
                                : "text-success"
                            }`}
                          >
                            {c.verdict || (isHigh ? "PHISHING" : isMed ? "SUSPICIOUS" : "SAFE")}
                          </span>
                        </TableCell>
                        <TableCell className="text-text-muted whitespace-nowrap">
                          {c.status || "Investigating"}
                        </TableCell>
                        <TableCell className="text-text-muted whitespace-nowrap">
                          {c.created_at ? new Date(c.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : "—"}
                        </TableCell>
                        <TableCell className="text-right whitespace-nowrap">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              onNavigate(`/investigations/${c.id}`);
                            }}
                          >
                            Open
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </Card>
      </div>
    </SocLayout>
  );
};
