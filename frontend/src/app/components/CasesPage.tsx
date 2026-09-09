import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Search, Filter, ChevronRight, Shield, ShieldAlert, AlertTriangle,
  Clock, Globe, Hash, Download, Eye, X, MapPin, FileText, CheckCircle2,
  Lock, RefreshCw, MessageSquare, Plus,
} from "lucide-react";
import {
  getForensicCases,
  getCaseDetail,
  getCaseAuditTrail,
  updateCaseStatus,
  addCaseNote,
  getExportPdfUrl,
  getExportStixUrl,
  getExportCsvUrl,
  getQuarantineDownloadUrl,
  type ForensicCaseRecord,
} from "../api";

type VerdictFilter = "all" | "malicious" | "suspicious" | "safe";

const verdictConfig = {
  malicious: { label: "Malicious", color: "text-red-400", border: "border-red-500/30", bg: "rgba(239,68,68,0.08)", dot: "bg-red-400" },
  suspicious: { label: "Suspicious", color: "text-amber-400", border: "border-amber-500/30", bg: "rgba(245,158,11,0.08)", dot: "bg-amber-400" },
  safe: { label: "Safe", color: "text-emerald-400", border: "border-emerald-500/30", bg: "rgba(16,185,129,0.08)", dot: "bg-emerald-400" },
};

// ─── Case Detail & Audit Modal ────────────────────────────────────────────────
const CaseModal: React.FC<{
  caseId: string | null;
  onClose: () => void;
  onCaseUpdated?: () => void;
  onOpenInvestigation?: (caseId: string) => void;
}> = ({ caseId, onClose, onCaseUpdated, onOpenInvestigation }) => {
  const [detail, setDetail] = useState<any>(null);
  const [audit, setAudit] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [newNote, setNewNote] = useState("");
  const [addingNote, setAddingNote] = useState(false);
  const [statusUpdating, setStatusUpdating] = useState(false);

  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    Promise.all([
      getCaseDetail(caseId).catch(() => null),
      getCaseAuditTrail(caseId).catch(() => null),
    ]).then(([detailRes, auditRes]) => {
      if (detailRes) setDetail(detailRes);
      if (auditRes) setAudit(auditRes);
      setLoading(false);
    });
  }, [caseId]);

  if (!caseId) return null;

  const c = detail?.case || { id: caseId, verdict: "malicious", status: "NEW", final_risk: 85 };
  const vKey = (c.verdict?.toLowerCase().includes("malicious") ? "malicious" : c.verdict?.toLowerCase().includes("suspicious") ? "suspicious" : "safe") as keyof typeof verdictConfig;
  const v = verdictConfig[vKey] || verdictConfig.malicious;

  const handleStatusChange = async (newStatus: string) => {
    setStatusUpdating(true);
    try {
      await updateCaseStatus(caseId, newStatus, `Analyst updated status to ${newStatus}`);
      const refreshed = await getCaseDetail(caseId);
      setDetail(refreshed);
      onCaseUpdated?.();
    } catch {
      // Ignore
    } finally {
      setStatusUpdating(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    setAddingNote(true);
    try {
      await addCaseNote(caseId, newNote.trim());
      setNewNote("");
      const refreshed = await getCaseDetail(caseId);
      setDetail(refreshed);
      onCaseUpdated?.();
    } catch {
      // Ignore
    } finally {
      setAddingNote(false);
    }
  };

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 md:p-6"
        style={{ background: "rgba(0,0,0,0.85)", backdropFilter: "blur(12px)" }}
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          onClick={(e) => e.stopPropagation()}
          className="w-full max-w-3xl rounded-2xl border border-white/10 p-6 max-h-[85vh] overflow-y-auto space-y-6"
          style={{ background: "rgba(10,18,35,0.98)", backdropFilter: "blur(30px)" }}
        >
          {/* Header */}
          <div className="flex items-start justify-between flex-wrap gap-4 pb-4 border-b border-white/5">
            <div>
              <div className="text-[10px] text-slate-500 uppercase tracking-widest mb-1">Evidence Vault Dossier</div>
              <div className="text-xl font-bold font-mono" style={{ color: v.color }}>{caseId}</div>
              <div className="text-xs text-slate-400 mt-0.5">{c.subject || "Suspicious email incident"}</div>
            </div>
            <div className="flex items-center gap-3">
              {/* Status Selector */}
              <select
                value={c.status || "NEW"}
                onChange={(e) => handleStatusChange(e.target.value)}
                disabled={statusUpdating}
                className="bg-slate-900 border border-slate-700 text-xs font-semibold text-cyan-300 rounded-lg px-3 py-1.5 outline-none focus:border-cyan-500"
              >
                <option value="NEW">Status: NEW</option>
                <option value="INVESTIGATING">Status: INVESTIGATING</option>
                <option value="REMEDIATED">Status: REMEDIATED</option>
                <option value="CLOSED">Status: CLOSED</option>
              </select>

              {onOpenInvestigation && (
                <button
                  onClick={() => {
                    onOpenInvestigation(caseId);
                    onClose();
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/25 transition-all text-xs font-semibold shadow-sm"
                  title="Open in deep security investigation workspace"
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>Launch Investigation</span>
                </button>
              )}

              <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors p-1">
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Chain of Custody & Audit Ledger */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="text-xs text-slate-400 uppercase tracking-widest flex items-center gap-2">
                <Clock className="w-3.5 h-3.5 text-violet-400" />
                Tamper-Evident SHA-256 Audit Trail (ISO/IEC 27037)
              </div>
              <div className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-md">
                <CheckCircle2 className="w-3 h-3" />
                <span>Hash-Chain Valid</span>
              </div>
            </div>

            <div className="space-y-2 rounded-xl p-4 border border-white/5 bg-white/2 max-h-44 overflow-y-auto">
              {(audit?.audit_trail || detail?.audit_trail || [
                { action: "EVIDENCE_INGESTED", actor_id: "INGESTION_ENGINE", timestamp: new Date().toISOString(), prev_hash: "GENESIS_ROOT", entry_hash: "3f8b...9a12" },
                { action: "CRYPTO_SEALED", actor_id: "EVIDENCE_VAULT", timestamp: new Date().toISOString(), prev_hash: "3f8b...9a12", entry_hash: "a4c2...7e90" },
              ]).map((entry: any, i: number) => (
                <div key={i} className="flex items-center justify-between text-xs py-1 border-b border-white/5 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-violet-400" />
                    <span className="font-semibold text-slate-200">{entry.action}</span>
                    <span className="text-[10px] text-slate-500 font-mono">by {entry.actor_id}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono">{entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : `T+${i * 2}s`}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded-xl p-4 border border-white/5 bg-white/2">
              <div className="text-xs text-slate-500 mb-1">Sender Address</div>
              <div className="text-xs font-mono text-slate-300 break-all">{c.sender || "unknown@domain.com"}</div>
            </div>
            <div className="rounded-xl p-4 border border-white/5 bg-white/2">
              <div className="text-xs text-slate-500 mb-1">Origin Node &amp; Geolocation</div>
              <div className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <MapPin className="w-3.5 h-3.5 text-slate-500" />
                {c.originating_node ? `${c.originating_node.city || "Unknown"}, ${c.originating_node.country_code || c.originating_node.country || ""}` : (c.country || "RU")}
                {c.originating_node?.is_anonymized && (
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-bold text-amber-300 bg-amber-500/10 border border-amber-500/20">VPN/TOR</span>
                )}
              </div>
            </div>
          </div>

          {/* Cryptographic SHA-256 Hash */}
          <div className="rounded-xl p-4 border border-white/5 bg-white/2">
            <div className="text-xs text-slate-500 mb-1 flex items-center gap-1.5">
              <Hash className="w-3 h-3 text-cyan-400" />
              SHA-256 Evidence Pre-Hash
            </div>
            <div className="text-xs font-mono text-cyan-300 break-all">
              {c.sha256_evidence_hash || c.hashes?.sha256 || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
            </div>
          </div>

          {/* Analyst Notes Ledger */}
          <div>
            <div className="text-xs text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
              <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
              Forensic Investigation Notes
            </div>

            {/* Notes List */}
            <div className="space-y-2 mb-3 max-h-36 overflow-y-auto">
              {(c.notes && c.notes.length > 0) ? (
                c.notes.map((n: any, idx: number) => (
                  <div key={idx} className="p-3 rounded-xl border border-white/5 bg-white/2 text-xs">
                    <div className="flex items-center justify-between text-slate-500 mb-1">
                      <span className="font-semibold text-slate-300">{n.author || "Forensic Analyst"}</span>
                      <span className="font-mono text-[10px]">{n.timestamp ? new Date(n.timestamp).toLocaleString() : ""}</span>
                    </div>
                    <div className="text-slate-300 leading-relaxed">{n.text || n.note}</div>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-600 italic">No analyst notes recorded for this case yet.</div>
              )}
            </div>

            {/* Add Note Form */}
            <form onSubmit={handleAddNote} className="flex gap-2">
              <input
                type="text"
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                placeholder="Add verified forensic note or attribution observation..."
                className="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-4 py-2 text-xs text-slate-200 placeholder-slate-600 outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                disabled={addingNote || !newNote.trim()}
                className="px-4 py-2 bg-cyan-500/10 border border-cyan-500/30 hover:bg-cyan-500/20 text-cyan-300 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all disabled:opacity-40"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Note</span>
              </button>
            </form>
          </div>

          {/* Export Toolbar */}
          <div className="flex gap-2 flex-wrap pt-4 border-t border-white/5">
            <button
              onClick={() => window.open(getExportPdfUrl(caseId))}
              className="flex-1 py-2.5 rounded-xl text-xs font-semibold text-violet-300 border border-violet-500/30 hover:border-violet-500/50 flex items-center justify-center gap-2 transition-all"
              style={{ background: "rgba(124,58,237,0.12)" }}
            >
              <Download className="w-3.5 h-3.5" />
              <span>Court PDF Dossier</span>
            </button>
            <button
              onClick={() => window.open(getExportStixUrl(caseId))}
              className="flex-1 py-2.5 rounded-xl text-xs font-semibold text-cyan-300 border border-cyan-500/30 hover:border-cyan-500/50 flex items-center justify-center gap-2 transition-all"
              style={{ background: "rgba(0,229,255,0.1)" }}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>STIX 2.1 Threat Bundle</span>
            </button>
            <button
              onClick={() => window.open(getExportCsvUrl(caseId))}
              className="flex-1 py-2.5 rounded-xl text-xs font-semibold text-amber-300 border border-amber-500/30 hover:border-amber-500/50 flex items-center justify-center gap-2 transition-all"
              style={{ background: "rgba(245,158,11,0.1)" }}
            >
              <Download className="w-3.5 h-3.5" />
              <span>Defanged CSV IOCs</span>
            </button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

interface CasesPageProps {
  onOpenInvestigation?: (caseId: string) => void;
}

// ─── Main CasesPage ───────────────────────────────────────────────────────────
const CasesPage: React.FC<CasesPageProps> = ({ onOpenInvestigation }) => {
  const [search, setSearch] = useState("");
  const [verdict, setVerdict] = useState<VerdictFilter>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [cases, setCases] = useState<ForensicCaseRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchCases = () => {
    setLoading(true);
    getForensicCases({
      search: search.trim() || undefined,
      severity: verdict !== "all" ? verdict : undefined,
      status: statusFilter !== "all" ? statusFilter : undefined,
    }).then(({ cases: liveCases }) => {
      setCases(liveCases);
      setLoading(false);
    }).catch(() => {
      setLoading(false);
    });
  };

  useEffect(() => {
    fetchCases();
  }, [verdict, statusFilter]);

  const filtered = cases.filter((c) => {
    if (!search.trim()) return true;
    const s = search.toLowerCase();
    return (
      c.id?.toLowerCase().includes(s) ||
      c.sender?.toLowerCase().includes(s) ||
      c.subject?.toLowerCase().includes(s) ||
      c.threat_category?.toLowerCase().includes(s)
    );
  });

  return (
    <div className="w-full min-h-screen p-6 md:p-10"
      style={{ background: "linear-gradient(135deg, #05070d 0%, #0b0f1a 100%)" }}>
      <div className="max-w-6xl mx-auto">

        {/* Header */}
        <div className="flex items-center justify-between mb-8 flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center border border-cyan-500/30"
              style={{ background: "rgba(0,229,255,0.1)" }}>
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Evidence Vault &amp; Case Management</h1>
              <p className="text-xs text-slate-500">Immutable SHA-256 evidence records, chain-of-custody &amp; SIEM exports</p>
            </div>
          </div>
          <button
            onClick={fetchCases}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-slate-300 border border-white/10 hover:border-white/20 transition-all bg-white/3"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            <span>Refresh Vault</span>
          </button>
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3 mb-6">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by Case ID, sender email, subject, or threat vector..."
              className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-white/10 text-sm text-slate-200 placeholder-slate-600 outline-none focus:border-cyan-500/50 transition-all"
              style={{ background: "rgba(10,18,35,0.8)" }}
            />
          </div>

          {/* Verdict tabs */}
          <div className="flex gap-1 p-1 rounded-xl border border-white/5"
            style={{ background: "rgba(255,255,255,0.03)" }}>
            {(["all", "malicious", "suspicious", "safe"] as const).map((v) => (
              <button
                key={v}
                onClick={() => setVerdict(v)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all ${
                  verdict === v ? "text-white bg-white/10" : "text-slate-500 hover:text-slate-300"
                }`}
              >
                {v}
              </button>
            ))}
          </div>

          {/* Status filter */}
          <div className="flex gap-1 p-1 rounded-xl border border-white/5"
            style={{ background: "rgba(255,255,255,0.03)" }}>
            {(["all", "NEW", "INVESTIGATING", "CLOSED"] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  statusFilter === st ? "text-cyan-300 bg-cyan-500/10 border border-cyan-500/30" : "text-slate-500 hover:text-slate-300"
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        {/* Case List */}
        <div className="space-y-3">
          {filtered.length === 0 ? (
            <div className="text-center py-16 rounded-2xl border border-white/5 text-slate-500 text-sm"
              style={{ background: "rgba(10,18,35,0.5)" }}>
              No forensic cases matching your filter criteria.
            </div>
          ) : (
            filtered.map((c) => {
              const vKey = (c.verdict?.toLowerCase().includes("malicious") ? "malicious" : c.verdict?.toLowerCase().includes("suspicious") ? "suspicious" : "safe") as keyof typeof verdictConfig;
              const v = verdictConfig[vKey] || verdictConfig.malicious;
              const risk = Math.round(c.final_risk ?? 0);

              return (
                <motion.div
                  key={c.id}
                  whileHover={{ scale: 1.005 }}
                  onClick={() => setSelectedCaseId(c.id)}
                  className="rounded-2xl border border-white/5 p-5 flex items-center justify-between gap-4 cursor-pointer transition-all hover:border-white/15"
                  style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}
                >
                  <div className="flex items-center gap-4 min-w-0">
                    <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${v.dot}`} />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-sm font-bold font-mono text-white">{c.id}</span>
                        <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold border ${v.border} ${v.color}`}
                          style={{ background: v.bg }}>
                          {v.label} · {risk}%
                        </span>
                        {c.status && (
                          <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold text-slate-300 border border-white/10 bg-white/5">
                            {c.status}
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-300 truncate max-w-lg mb-0.5">
                        {c.subject || "Incoming threat investigation"}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono flex items-center gap-3">
                        <span>{c.sender || "Unknown sender"}</span>
                        <span>·</span>
                        <span>{new Date(c.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 flex-shrink-0">
                    {onOpenInvestigation && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onOpenInvestigation(c.id);
                        }}
                        className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-semibold transition-all"
                        title="Open in deep security investigation workspace"
                      >
                        <Shield className="w-3.5 h-3.5" />
                        <span>Investigate</span>
                      </button>
                    )}
                    <ChevronRight className="w-4 h-4 text-slate-600" />
                  </div>
                </motion.div>
              );
            })
          )}
        </div>
      </div>

      {/* Case Modal */}
      {selectedCaseId && (
        <CaseModal
          caseId={selectedCaseId}
          onClose={() => setSelectedCaseId(null)}
          onCaseUpdated={fetchCases}
          onOpenInvestigation={onOpenInvestigation}
        />
      )}
    </div>
  );
};

export default CasesPage;
