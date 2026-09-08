import React, { useEffect, useState } from "react";
import { SocLayout } from "./SocLayout";
import {
  RefreshCw,
  Search,
  Download,
} from "lucide-react";
import {
  getForensicCases,
  getExportPdfUrl,
  getExportStixUrl,
  getExportCsvUrl,
  ForensicCaseRecord,
} from "../../api";
import { Button, Badge } from "../ui";

interface Props {
  onNavigate: (route: string) => void;
}

export const ReportsPage: React.FC<Props> = ({ onNavigate }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [cases, setCases] = useState<ForensicCaseRecord[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>("");

  const fetchCases = async () => {
    setLoading(true);
    try {
      const res = await getForensicCases({ limit: 100 });
      setCases(res?.cases || []);
    } catch (err) {
      console.error("Failed to load cases for reports:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const filteredCases = cases.filter((c) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      (c.case_number || c.id).toLowerCase().includes(q) ||
      (c.title || c.subject || "").toLowerCase().includes(q)
    );
  });

  return (
    <SocLayout
      activeNav="reports"
      onNavigate={onNavigate}
      title="Reports"
      subtitle="Case export dossiers in PDF, STIX, and CSV formats"
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
      {/* ─── SEARCH BAR ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search reports..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-input border border-input-border text-xs text-foreground placeholder-input-placeholder focus:outline-none focus:border-input-border-focus"
          />
        </div>

        <span className="text-xs text-text-muted">
          {filteredCases.length} reports available
        </span>
      </div>

      {/* ─── REPORTS TABLE ──────────────────────────────────────────────────── */}
      <div className="rounded-xl border border-border bg-surface-elevated/50 overflow-hidden">
        {loading ? (
          <div className="py-16 text-center text-xs text-text-muted flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-accent" />
            <span>Loading reports catalog...</span>
          </div>
        ) : filteredCases.length === 0 ? (
          <div className="py-16 text-center text-xs text-text-muted">
            No report dossiers available.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-border text-text-muted font-medium">
                  <th className="py-3 px-4">Case</th>
                  <th className="py-3 px-4">Investigation</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4">Generated</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredCases.map((c) => {
                  const risk = Math.round(c.final_risk ?? c.overall_risk_score ?? 0);
                  const isHigh = risk >= 70;
                  const isMed = risk >= 30 && risk < 70;

                  return (
                    <tr key={c.id} className="hover:bg-surface-hover transition-colors">
                      <td className="py-3 px-4 font-mono text-foreground whitespace-nowrap">
                        <Button
                          onClick={() => onNavigate(`/investigations/${c.id}`)}
                          variant="link"
                          size="sm"
                        >
                          {c.case_number || c.id}
                        </Button>
                      </td>
                      <td className="py-3 px-4 text-foreground font-medium max-w-sm truncate">
                        {c.title || c.subject || "Email Security Investigation"}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <Badge
                          variant={
                            isHigh
                              ? "destructive"
                              : isMed
                              ? "warning"
                              : "success"
                          }
                          size="xs"
                        >
                          {risk}
                        </Badge>
                      </td>
                      <td className="py-3 px-4 text-text-muted whitespace-nowrap">
                        {c.created_at ? new Date(c.created_at).toLocaleDateString() : "Active"}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-2">
                          <Button
                            asChild
                            variant="secondary"
                            size="sm"
                            className="text-xs"
                          >
                            <a
                              href={getExportPdfUrl(c.id, false)}
                              target="_blank"
                              rel="noreferrer"
                            >
                              PDF
                            </a>
                          </Button>
                          <Button
                            asChild
                            variant="secondary"
                            size="sm"
                            className="text-xs"
                          >
                            <a
                              href={getExportStixUrl(c.id)}
                              target="_blank"
                              rel="noreferrer"
                            >
                              STIX
                            </a>
                          </Button>
                          <Button
                            asChild
                            variant="secondary"
                            size="sm"
                            className="text-xs"
                          >
                            <a
                              href={getExportCsvUrl(c.id)}
                              target="_blank"
                              rel="noreferrer"
                            >
                              CSV
                            </a>
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </SocLayout>
  );
};
