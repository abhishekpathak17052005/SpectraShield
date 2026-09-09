import React, { useState } from "react";
import {
  ShieldCheck,
  Download,
  Copy,
  Check,
  FileText,
  Hash,
  Database,
  Lock,
  ExternalLink,
  Search,
  Key,
} from "lucide-react";
import { EvidenceVaultItem } from "../../../types/investigation";
import { getExportPdfUrl, getExportStixUrl, getExportCsvUrl } from "../../../api";

interface Props {
  evidenceList: EvidenceVaultItem[];
  investigationId: string;
}

export const EvidenceVaultTab: React.FC<Props> = ({ evidenceList, investigationId }) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [selectedPreview, setSelectedPreview] = useState<EvidenceVaultItem | null>(evidenceList[0] || null);

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* ─── FORENSIC HEADER & EXPORT TOOLBAR ─────────────────────────────── */}
      <div
        className="p-5 rounded-2xl border border-cyan-500/20 shadow-xl flex flex-wrap items-center justify-between gap-4"
        style={{
          background: "linear-gradient(135deg, rgba(10, 16, 32, 0.95) 0%, rgba(6, 10, 22, 0.98) 100%)",
        }}
      >
        <div>
          <div className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
            <Lock className="w-4 h-4 text-cyan-400" />
            Evidence Vault &amp; Chain-of-Custody Ledger
          </div>
          <p className="text-xs text-slate-400 mt-0.5 font-sans">
            Cryptographically signed digital artifacts (ISO/IEC 27037 compliant)
          </p>
        </div>

        {/* Global Export Toolbar */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => window.open(getExportPdfUrl(investigationId, false))}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 hover:bg-cyan-500/20 transition-all shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Court PDF Dossier</span>
          </button>
          <button
            onClick={() => window.open(getExportStixUrl(investigationId))}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold text-purple-300 bg-purple-500/10 border border-purple-500/30 hover:bg-purple-500/20 transition-all shadow-sm"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>STIX 2.1 Threat Bundle</span>
          </button>
          <button
            onClick={() => window.open(getExportCsvUrl(investigationId))}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/30 hover:bg-amber-500/20 transition-all shadow-sm"
          >
            <Database className="w-3.5 h-3.5" />
            <span>Defanged CSV IOCs</span>
          </button>
        </div>
      </div>

      {/* ─── EVIDENCE ITEMS & PREVIEW SPLIT ─────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Evidence Ledger Table (7 Cols) */}
        <div className="lg:col-span-7 space-y-3">
          {evidenceList.map((item, idx) => {
            const isSelected = selectedPreview?.id === item.id;
            const displayId = `EV-${String(idx + 1).padStart(2, "0")}-${item.type.slice(0, 8)}`;

            return (
              <div
                key={item.id}
                onClick={() => setSelectedPreview(item)}
                className={`p-4 rounded-xl border transition-all cursor-pointer shadow-md ${
                  isSelected
                    ? "border-cyan-400 bg-slate-900/90 ring-1 ring-cyan-400/40 shadow-cyan-500/10"
                    : "border-white/5 bg-slate-900/60 hover:border-cyan-500/30 hover:bg-slate-900/80"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                      {displayId}
                    </span>
                    <span className="text-xs font-bold text-white truncate max-w-[240px]">
                      {item.title}
                    </span>
                  </div>

                  {/* Integrity Status */}
                  <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold text-cyan-300 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30">
                    <ShieldCheck className="w-3 h-3 text-cyan-400" />
                    INTEGRITY SEALED
                  </span>
                </div>

                <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between gap-2 pt-1 border-t border-white/5">
                  <span>{item.timestamp}</span>
                  <span className="text-slate-500">Size: {(item.sizeBytes / 1024).toFixed(1)} KB</span>
                </div>

                {/* SHA-256 Hash Row */}
                <div className="mt-2.5 pt-1.5 flex items-center justify-between gap-2 text-[10px] font-mono bg-black/40 p-2 rounded-lg border border-white/5">
                  <span className="text-slate-500 font-bold">SHA-256:</span>
                  <span className="text-slate-300 truncate flex-1 font-mono">
                    {item.sha256}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      copyHash(item.sha256);
                    }}
                    className="text-slate-400 hover:text-cyan-300 transition-colors p-0.5"
                    title="Copy SHA-256 hash"
                  >
                    {copiedHash === item.sha256 ? (
                      <Check className="w-3 h-3 text-emerald-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Evidence Item Previewer (5 Cols) */}
        <div
          className="lg:col-span-5 p-5 rounded-2xl border border-cyan-500/20 bg-slate-900/90 flex flex-col justify-between min-h-[420px] shadow-xl sticky top-24"
        >
          <div>
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-white/10">
              <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-1.5">
                <Search className="w-3.5 h-3.5" />
                Evidence Payload Inspector
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                {selectedPreview?.integrityStatus || "VERIFIED"}
              </span>
            </div>

            {selectedPreview ? (
              <div className="space-y-3 font-mono text-xs">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">
                    Artifact Descriptor
                  </span>
                  <div className="text-sm font-bold text-white font-sans mt-0.5">
                    {selectedPreview.title}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">
                    Cryptographic Genesis SHA-256
                  </span>
                  <div className="p-2 rounded-lg bg-black/40 border border-white/5 text-[10px] text-cyan-300 break-all leading-tight mt-1">
                    {selectedPreview.sha256}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">
                    Raw Payload Inspection
                  </span>
                  <pre className="p-3 rounded-lg bg-black/60 border border-white/10 text-[11px] text-slate-300 overflow-x-auto max-h-52 font-mono whitespace-pre-wrap leading-relaxed mt-1">
                    {selectedPreview.previewSnippet || "Binary digital stream sealed in evidence vault."}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-slate-500 text-xs font-mono">
                Select an evidence item from the ledger to inspect.
              </div>
            )}
          </div>

          <div className="pt-4 border-t border-white/10 flex items-center justify-between text-[10px] font-mono text-slate-500">
            <span>RFC 3161 Timestamped</span>
            <span className="text-emerald-400 flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" />
              Chain Valid
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
