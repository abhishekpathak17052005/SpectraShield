import React, { useEffect, useState } from "react";
import { SocLayout } from "./SocLayout";
import {
  Search,
  RefreshCw,
  ChevronRight,
  Download,
} from "lucide-react";
import { getForensicCases, getExportPdfUrl, ForensicCaseRecord } from "../../api";
import { Button } from "../ui/Button";
import { Badge } from "../ui/Badge";
import { Input } from "../ui/Input";
import { Select } from "../ui/Select";
import { Card } from "../ui/Card";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "../ui/Table";

interface Props {
  onNavigate: (route: string) => void;
}

type SeverityFilter = "all" | "high" | "suspicious" | "safe";
type StatusFilter = "all" | "NEW" | "INVESTIGATING" | "CLOSED";
type DateSort = "desc" | "asc";

export const InvestigationsListPage: React.FC<Props> = ({ onNavigate }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [cases, setCases] = useState<ForensicCaseRecord[]>([]);
  const [search, setSearch] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [dateSort, setDateSort] = useState<DateSort>("desc");

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

  // Filter cases strictly
  const filteredCases = cases
    .filter((c) => {
      const risk = c.final_risk ?? c.overall_risk_score ?? 0;
      const sev = (c.severity || "").toLowerCase();
      const verdict = (c.verdict || "").toLowerCase();

      // Severity / verdict filter
      if (severityFilter === "high") {
        if (risk < 70 && !sev.includes("high") && !verdict.includes("phishing") && !verdict.includes("malicious")) {
          return false;
        }
      } else if (severityFilter === "suspicious") {
        if ((risk < 30 || risk >= 70) && !sev.includes("med") && !verdict.includes("suspicious")) {
          return false;
        }
      } else if (severityFilter === "safe") {
        if (risk >= 30 && !sev.includes("safe") && !verdict.includes("safe")) {
          return false;
        }
      }

      // Status filter
      if (statusFilter !== "all") {
        const cStatus = (c.status || "").toUpperCase();
        if (statusFilter === "NEW" && cStatus !== "NEW" && cStatus !== "OPEN") return false;
        if (statusFilter === "INVESTIGATING" && cStatus !== "INVESTIGATING") return false;
        if (statusFilter === "CLOSED" && cStatus !== "CLOSED") return false;
      }

      // Text search
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchId = (c.case_number || c.id || "").toLowerCase().includes(q);
        const matchTitle = (c.title || c.subject || "").toLowerCase().includes(q);
        const matchSender = (c.sender || "").toLowerCase().includes(q);
        if (!matchId && !matchTitle && !matchSender) return false;
      }

      return true;
    })
    .sort((a, b) => {
      const timeA = new Date(a.created_at || 0).getTime();
      const timeB = new Date(b.created_at || 0).getTime();
      return dateSort === "desc" ? timeB - timeA : timeA - timeB;
    });

  return (
    <SocLayout
      activeNav="investigations"
      onNavigate={onNavigate}
      title="Investigations"
      subtitle="Security incident work queue and forensic records"
      actions={
        <Button 
          variant="ghost"
          size="sm"
          onClick={fetchCases}
          disabled={loading}
          className="gap-1.5"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </Button>
      }
    >
      {/* ─── FILTER & SEARCH BAR ────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
        {/* Search */}
        <div className="flex-1 max-w-md">
          <Input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by case ID, subject, or sender..."
            icon={<Search className="w-4 h-4" />}
          />
        </div>

        {/* Severity Tabs */}
        <div className="flex items-center gap-1 bg-surface p-1 rounded-lg border border-border text-xs">
          {(
            [
              { id: "all", label: "All" },
              { id: "high", label: "High Risk" },
              { id: "suspicious", label: "Suspicious" },
              { id: "safe", label: "Safe" },
            ] as const
          ).map((t) => (
            <button
              key={t.id}
              onClick={() => setSeverityFilter(t.id)}
              className={`px-2.5 py-1 rounded-md transition-colors font-medium ${
                severityFilter === t.id
                  ? "bg-accent/15 text-accent"
                  : "text-text-secondary hover:text-foreground"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Status Dropdown & Date Sort */}
        <div className="flex items-center gap-2">
          <Select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
            className="text-xs"
          >
            <option value="all">All Statuses</option>
            <option value="NEW">New / Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CLOSED">Closed</option>
          </Select>

          <Select
            value={dateSort}
            onChange={(e) => setDateSort(e.target.value as DateSort)}
            className="text-xs"
          >
            <option value="desc">Newest First</option>
            <option value="asc">Oldest First</option>
          </Select>
        </div>
      </div>

      {/* ─── WORK QUEUE TABLE ───────────────────────────────────────────────── */}
      <Card>
        {loading ? (
          <div className="py-16 text-center text-xs text-text-muted flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-accent" />
            <span>Loading work queue...</span>
          </div>
        ) : filteredCases.length === 0 ? (
          <div className="py-16 text-center text-xs text-text-muted space-y-2">
            <div>No investigations found matching your filter criteria.</div>
            {(search || severityFilter !== "all" || statusFilter !== "all") && (
              <button
                onClick={() => {
                  setSearch("");
                  setSeverityFilter("all");
                  setStatusFilter("all");
                }}
                className="text-accent hover:underline text-xs font-medium"
              >
                Reset filters
              </button>
            )}
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
                {filteredCases.map((c) => {
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
                        {c.case_number || c.id}
                      </TableCell>
                      <TableCell className="text-foreground font-medium max-w-sm truncate">
                        {c.title || c.subject || "Inbound Threat Inspection"}
                      </TableCell>
                      <TableCell className="font-mono text-text-muted max-w-xs truncate">
                        {c.sender || "—"}
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        <Badge variant={isHigh ? "destructive" : isMed ? "warning" : "default"} className="text-xs">
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
                        {c.created_at
                          ? new Date(c.created_at).toLocaleTimeString([], {
                              hour: "2-digit",
                              minute: "2-digit",
                            })
                          : "—"}
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              window.open(getExportPdfUrl(c.id, false));
                            }}
                            title="Export PDF"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              onNavigate(`/investigations/${c.id}`);
                            }}
                            className="gap-0.5"
                          >
                            <span>Open</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </Card>
    </SocLayout>
  );
};
