import React, { useState } from "react";
import {
  FileCode,
  FileText,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Copy,
  Check,
  Hash,
  Binary,
  Layers
} from "lucide-react";

export interface AttachmentEvidenceData {
  filename: string;
  content_type: string;
  file_size_bytes: number;
  sha256: string;
  sha1: string;
  md5: string;
  fuzzy_hash?: string;
  entropy_score: number;
  is_executable_or_script: boolean;
  has_macros: boolean;
  has_embedded_scripts: boolean;
  risk_level: string; // "clean" | "suspicious" | "malicious"
  risk_reasons: string[];
}

interface AttachmentTriageCardProps {
  attachments?: AttachmentEvidenceData[];
}

export const AttachmentTriageCard: React.FC<AttachmentTriageCardProps> = ({ attachments = [] }) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleCopy = (hashText: string, id: string) => {
    navigator.clipboard.writeText(hashText);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  if (!attachments || attachments.length === 0) {
    return (
      <div className="p-8 text-center rounded-2xl liquid-glass-panel border border-slate-800 space-y-3">
        <div className="flex justify-center">
          <ShieldCheck className="h-10 w-10 text-emerald-400 opacity-70" />
        </div>
        <div className="font-mono text-xs font-bold text-slate-300">
          ZERO ATTACHMENTS DETECTED IN MESSAGE
        </div>
        <p className="text-xs font-mono text-slate-400 max-w-md mx-auto">
          No MIME binary or document streams found in this email. Threat vectors limited to URL and body social engineering cues.
        </p>
      </div>
    );
  }

  const maliciousCount = attachments.filter((a) => a.risk_level === "malicious").length;
  const suspiciousCount = attachments.filter((a) => a.risk_level === "suspicious").length;

  return (
    <div className="space-y-4">
      {/* Header Summary */}
      <div className="p-4 rounded-xl liquid-glass-panel border border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <FileCode className="h-4 w-4 text-purple-400" />
          <span className="font-mono text-xs font-bold text-slate-200">
            STATIC ATTACHMENT FORENSICS & PAYLOAD TRIAGE ({attachments.length})
          </span>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs">
          {maliciousCount > 0 && (
            <span className="px-2.5 py-0.5 rounded-full font-bold bg-red-500/20 text-red-400 border border-red-500/40">
              🚨 {maliciousCount} Malicious
            </span>
          )}
          {suspiciousCount > 0 && (
            <span className="px-2.5 py-0.5 rounded-full font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
              ⚠️ {suspiciousCount} Suspicious
            </span>
          )}
          {maliciousCount === 0 && suspiciousCount === 0 && (
            <span className="px-2.5 py-0.5 rounded-full font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
              ✓ All Clean
            </span>
          )}
        </div>
      </div>

      {/* Attachment Cards */}
      <div className="grid grid-cols-1 gap-4">
        {attachments.map((att, idx) => {
          const isMalicious = att.risk_level === "malicious";
          const isSuspicious = att.risk_level === "suspicious";

          return (
            <div
              key={idx}
              className={`p-5 rounded-2xl liquid-glass-panel transition-all space-y-4 ${
                isMalicious
                  ? "border-red-500/40 bg-red-950/20 shadow-red-950/40"
                  : isSuspicious
                  ? "border-amber-500/40 bg-amber-950/20"
                  : "border-slate-800 bg-slate-900/40"
              }`}
            >
              {/* File title and status badge */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <FileText
                    className={`h-5 w-5 ${
                      isMalicious ? "text-red-400" : isSuspicious ? "text-amber-400" : "text-cyan-400"
                    }`}
                  />
                  <div>
                    <div className="font-mono text-sm font-bold text-slate-100">
                      {att.filename}
                    </div>
                    <div className="text-[11px] font-mono text-slate-400">
                      {att.content_type} • {formatBytes(att.file_size_bytes)}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase tracking-wider ${
                      isMalicious
                        ? "bg-red-500/20 text-red-400 border border-red-500/40 shadow-lg shadow-red-950/50"
                        : isSuspicious
                        ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                        : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                    }`}
                  >
                    {att.risk_level}
                  </span>
                </div>
              </div>

              {/* Threat Indicators Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1">
                  <div className="text-slate-400 flex items-center gap-1">
                    <Binary className="h-3 w-3 text-cyan-400" />
                    Executable / Script
                  </div>
                  <div
                    className={`font-bold ${
                      att.is_executable_or_script ? "text-red-400" : "text-emerald-400"
                    }`}
                  >
                    {att.is_executable_or_script ? "🚨 DETECTED" : "None"}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1">
                  <div className="text-slate-400 flex items-center gap-1">
                    <Layers className="h-3 w-3 text-purple-400" />
                    VBA Macro Project
                  </div>
                  <div className={`font-bold ${att.has_macros ? "text-red-400" : "text-emerald-400"}`}>
                    {att.has_macros ? "🚨 MACROS FOUND" : "None"}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1">
                  <div className="text-slate-400 flex items-center gap-1">
                    <FileCode className="h-3 w-3 text-amber-400" />
                    Embedded JavaScript
                  </div>
                  <div
                    className={`font-bold ${
                      att.has_embedded_scripts ? "text-red-400" : "text-emerald-400"
                    }`}
                  >
                    {att.has_embedded_scripts ? "🚨 JS ACTION DETECTED" : "None"}
                  </div>
                </div>
              </div>

              {/* Entropy Meter */}
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1.5 font-mono text-xs">
                <div className="flex justify-between items-center text-slate-300">
                  <span className="flex items-center gap-1.5">
                    Shannon Entropy: <span className="font-bold text-cyan-300">{att.entropy_score} / 8.0</span>
                  </span>
                  <span className="text-[11px] text-slate-400">
                    {att.entropy_score > 7.2 ? "⚠️ Packed / Encrypted" : "Unpacked Data"}
                  </span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      att.entropy_score > 7.4
                        ? "bg-red-500"
                        : att.entropy_score > 6.5
                        ? "bg-amber-500"
                        : "bg-cyan-500"
                    }`}
                    style={{ width: `${(att.entropy_score / 8.0) * 100}%` }}
                  />
                </div>
              </div>

              {/* Risk Reasons */}
              {att.risk_reasons && att.risk_reasons.length > 0 && (
                <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/30 space-y-1 font-mono text-xs text-red-300">
                  <div className="font-bold flex items-center gap-1">
                    <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
                    Detected Risk Indicators:
                  </div>
                  <ul className="list-disc list-inside space-y-0.5 text-slate-200">
                    {att.risk_reasons.map((r, rIdx) => (
                      <li key={rIdx}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Cryptographic Hashes Table */}
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 font-mono text-[11px] space-y-2">
                <div className="flex items-center justify-between text-slate-300">
                  <span className="text-slate-400 flex items-center gap-1">
                    <Hash className="h-3 w-3 text-cyan-400" /> SHA-256:
                  </span>
                  <div className="flex items-center gap-2">
                    <code className="text-cyan-300 font-bold truncate max-w-xs md:max-w-md">
                      {att.sha256}
                    </code>
                    <button
                      onClick={() => handleCopy(att.sha256, `sha-${idx}`)}
                      className="text-slate-400 hover:text-white"
                      title="Copy SHA-256 Hash"
                    >
                      {copiedHash === `sha-${idx}` ? (
                        <Check className="h-3 w-3 text-emerald-400" />
                      ) : (
                        <Copy className="h-3 w-3" />
                      )}
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between text-slate-400">
                  <span>MD5:</span>
                  <code>{att.md5}</code>
                </div>

                {att.fuzzy_hash && (
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Fuzzy SimHash:</span>
                    <code className="text-purple-300">{att.fuzzy_hash}</code>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
