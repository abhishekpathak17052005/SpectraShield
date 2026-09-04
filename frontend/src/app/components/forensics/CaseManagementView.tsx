import React, { useState, useEffect } from "react";
import {
  FolderKanban,
  ShieldAlert,
  UserCheck,
  MessageSquare,
  Send,
  Clock,
  CheckCircle2,
  AlertOctagon,
  RefreshCw,
  Search,
  ChevronDown,
  ChevronUp
} from "lucide-react";

export interface CaseRecord {
  id: string;
  case_number: string;
  title: string;
  threat_category: string;
  severity: string;
  status: string;
  overall_risk_score: number;
  sha256_evidence_hash: string;
  assigned_analyst: string;
  notes?: Array<{ id: string; text: string; author: string; timestamp: string }>;
  created_at: string;
  updated_at: string;
}

const DEFAULT_CASES: CaseRecord[] = [
  {
    id: "8f3b2c1a-5e7d-4b9a-8c1e-9f3a2b1c0d5e",
    case_number: "CASE-2026-0891",
    title: "URGENT: Acquisition Escrow Account Update",
    threat_category: "Business Email Compromise (BEC)",
    severity: "CRITICAL",
    status: "INVESTIGATING",
    overall_risk_score: 94.5,
    sha256_evidence_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    assigned_analyst: "Lead SOC Investigator",
    notes: [
      {
        id: "note-1",
        text: "Initial triage completed. Tor exit node confirmed at Hop #2. Executive impersonation cues match FIN7 syndicate MO.",
        author: "Automated Evidence Engine",
        timestamp: new Date().toISOString()
      }
    ],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  },
  {
    id: "7c2b1a0e-4d6c-3b8a-7b0d-8e2a1b0c9f4d",
    case_number: "CASE-2026-0889",
    title: "Overdue Invoice Notice - Macro Attachment",
    threat_category: "Malware Delivery / Trojan",
    severity: "HIGH",
    status: "NEW",
    overall_risk_score: 87.0,
    sha256_evidence_hash: "8e920d912440307bb28d6f5195eb03082390f7193ab46618e404be124e54cd89",
    assigned_analyst: "Unassigned",
    notes: [],
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString()
  }
];

interface CaseManagementViewProps {
  apiBaseUrl?: string;
  onSelectCase?: (caseId: string) => void;
}

export const CaseManagementView: React.FC<CaseManagementViewProps> = ({
  apiBaseUrl = "http://localhost:8000",
  onSelectCase
}) => {
  const [cases, setCases] = useState<CaseRecord[]>(DEFAULT_CASES);
  const [loading, setLoading] = useState(false);
  const [polling, setPolling] = useState(false);
  const [filterStatus, setFilterStatus] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedCaseId, setExpandedCaseId] = useState<string | null>("8f3b2c1a-5e7d-4b9a-8c1e-9f3a2b1c0d5e");
  const [newNoteText, setNewNoteText] = useState<{ [caseId: string]: string }>({});
  const [analystName] = useState("Investigating Analyst");

  const fetchCases = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/forensics/cases?limit=100`);
      if (res.ok) {
        const data = await res.json();
        if (data.cases && data.cases.length > 0) {
          setCases(data.cases);
        } else {
          setCases(DEFAULT_CASES);
        }
      } else {
        setCases(DEFAULT_CASES);
      }
    } catch {
      setCases(DEFAULT_CASES);
    } finally {
      setLoading(false);
    }
  };

  const handlePollMailbox = async () => {
    setPolling(true);
    try {
      await fetch(`${apiBaseUrl}/api/forensics/mailbox/poll?limit=5`, { method: "POST" });
      await fetchCases();
    } catch {
      // Offline fallback
    } finally {
      setPolling(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleStatusChange = async (caseId: string, newStatus: string) => {
    try {
      const res = await fetch(`${apiBaseUrl}/api/forensics/cases/${caseId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus, actor: analystName, reason: "SOC Analyst Triage" })
      });
      if (res.ok) {
        fetchCases();
      }
    } catch (e) {
      console.error("Failed to update status:", e);
    }
  };

  const handleAddNote = async (caseId: string) => {
    const text = newNoteText[caseId]?.trim();
    if (!text) return;

    try {
      const res = await fetch(`${apiBaseUrl}/api/forensics/cases/${caseId}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, author: analystName })
      });
      if (res.ok) {
        setNewNoteText((prev) => ({ ...prev, [caseId]: "" }));
        fetchCases();
      }
    } catch (e) {
      console.error("Failed to add note:", e);
    }
  };

  const getStatusBadge = (status: string) => {
    const s = status.toUpperCase();
    if (s === "NEW") {
      return "bg-cyan-500/20 text-cyan-300 border-cyan-500/40";
    }
    if (s === "INVESTIGATING") {
      return "bg-purple-500/20 text-purple-300 border-purple-500/40";
    }
    if (s === "ESCALATED") {
      return "bg-red-500/20 text-red-400 border-red-500/40 animate-pulse";
    }
    if (s.startsWith("CLOSED")) {
      return "bg-emerald-500/20 text-emerald-400 border-emerald-500/40";
    }
    return "bg-slate-800 text-slate-300 border-slate-700";
  };

  const filteredCases = cases.filter((c) => {
    const matchesStatus = filterStatus === "ALL" || c.status.toUpperCase() === filterStatus;
    const matchesSearch =
      searchQuery === "" ||
      c.case_number.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.threat_category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesStatus && matchesSearch;
  });

  return (
    <div className="space-y-4">
      {/* Controls & Search Bar */}
      <div className="p-4 rounded-xl liquid-glass-panel border border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <FolderKanban className="h-4 w-4 text-cyan-400" />
          <span className="font-mono text-xs font-bold text-slate-100">
            INCIDENT CASE WORKSPACE & TRIAGE BOARD ({cases.length})
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Filter cases by ref or title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-1 font-mono text-xs">
            {["ALL", "NEW", "INVESTIGATING", "ESCALATED", "CLOSED_RESOLVED"].map((status) => (
              <button
                key={status}
                onClick={() => setFilterStatus(status)}
                className={`px-2.5 py-1 rounded-lg transition-all ${
                  filterStatus === status
                    ? "bg-cyan-600 text-white font-bold"
                    : "bg-slate-900 text-slate-400 hover:text-white"
                }`}
              >
                {status.replace("CLOSED_RESOLVED", "CLOSED")}
              </button>
            ))}
          </div>

          <button
            onClick={handlePollMailbox}
            disabled={polling || loading}
            className="px-2.5 py-1 rounded-lg bg-purple-600/30 border border-purple-500/50 hover:bg-purple-600/50 text-purple-300 font-mono text-xs flex items-center gap-1.5 transition-all"
            title="Poll Autonomous Abuse Mailbox (IMAP/TLS)"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${polling ? "animate-spin" : ""}`} />
            <span>{polling ? "Polling..." : "Poll Abuse Inbox"}</span>
          </button>

          <button
            onClick={fetchCases}
            disabled={loading}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
            title="Refresh Cases"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Case List */}
      {filteredCases.length === 0 ? (
        <div className="p-8 text-center font-mono text-xs text-slate-400 liquid-glass-panel rounded-xl border border-slate-800">
          No forensic cases match the current filter.
        </div>
      ) : (
        <div className="space-y-3">
          {filteredCases.map((c) => {
            const isExpanded = expandedCaseId === c.id;
            const notes = c.notes || [];

            return (
              <div
                key={c.id}
                className="p-4 rounded-xl liquid-glass-panel border border-slate-800 space-y-3 transition-all"
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className="font-bold text-cyan-400">{c.case_number}</span>
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getStatusBadge(
                          c.status
                        )}`}
                      >
                        {c.status}
                      </span>
                      <span className="text-slate-400">
                        Assigned: <span className="text-slate-200">{c.assigned_analyst}</span>
                      </span>
                    </div>
                    <div className="font-bold text-sm text-slate-100">{c.title}</div>
                    <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
                      <span>Category: <b className="text-amber-300">{c.threat_category}</b></span>
                      <span>•</span>
                      <span>Risk: <b className="text-red-400">{c.overall_risk_score}%</b></span>
                      <span>•</span>
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {new Date(c.created_at).toLocaleDateString()} {new Date(c.created_at).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>

                  {/* Actions & Status Dropdown */}
                  <div className="flex items-center gap-2">
                    <select
                      value={c.status}
                      onChange={(e) => handleStatusChange(c.id, e.target.value)}
                      className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none"
                    >
                      <option value="NEW">Status: NEW</option>
                      <option value="TRIAGED">Status: TRIAGED</option>
                      <option value="INVESTIGATING">Status: INVESTIGATING</option>
                      <option value="ESCALATED">Status: ESCALATED</option>
                      <option value="CLOSED_RESOLVED">Status: CLOSED (RESOLVED)</option>
                      <option value="CLOSED_FALSE_POSITIVE">Status: CLOSED (FP)</option>
                    </select>

                    {onSelectCase && (
                      <button
                        onClick={() => onSelectCase(c.id)}
                        className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-cyan-600 hover:bg-cyan-500 text-white transition-all shadow"
                      >
                        Inspect Dossier ↗
                      </button>
                    )}

                    <button
                      onClick={() => setExpandedCaseId(isExpanded ? null : c.id)}
                      className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                      title="Toggle Notes"
                    >
                      {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded Notes and Audit Ledger section */}
                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-3 font-mono text-xs">
                    <div className="flex items-center gap-1.5 text-slate-300 font-bold">
                      <MessageSquare className="h-3.5 w-3.5 text-purple-400" />
                      Investigation Notes & Evidentiary Log ({notes.length}):
                    </div>

                    {notes.length === 0 ? (
                      <div className="text-slate-500 text-[11px] italic">
                        No analyst notes recorded for this case yet.
                      </div>
                    ) : (
                      <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                        {notes.map((n) => (
                          <div
                            key={n.id}
                            className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1"
                          >
                            <div className="flex items-center justify-between text-[10px] text-slate-400">
                              <span className="font-bold text-cyan-300">{n.author}</span>
                              <span>{new Date(n.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <div className="text-slate-200 text-xs">{n.text}</div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Add note input */}
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        placeholder="Add timestamped forensic note..."
                        value={newNoteText[c.id] || ""}
                        onChange={(e) =>
                          setNewNoteText((prev) => ({ ...prev, [c.id]: e.target.value }))
                        }
                        onKeyDown={(e) => {
                          if (e.key === "Enter") handleAddNote(c.id);
                        }}
                        className="flex-1 p-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                      />
                      <button
                        onClick={() => handleAddNote(c.id)}
                        className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white"
                        title="Add Note"
                      >
                        <Send className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
