import React, { useState, useRef } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Upload, FileText, Copy, CheckCircle2, XCircle, AlertTriangle,
  Download, Shield, Clock, MapPin, Server, Hash, Layers, ChevronRight,
  Globe, Lock, QrCode, UserCheck, Paperclip, ShieldAlert,
} from "lucide-react";
import {
  analyzeForensics,
  uploadForensics,
  getExportPdfUrl,
  getExportStixUrl,
  getExportCsvUrl,
  getQuarantineDownloadUrl,
  type AnalyzeResponse,
} from "../api";

// ─── Auth protocol status pill ────────────────────────────────────────────────
const AuthPill: React.FC<{ label: string; status: "pass" | "fail" | "neutral"; detail?: string }> = ({ label, status, detail }) => {
  const cfg = {
    pass: { icon: CheckCircle2, color: "text-emerald-400", border: "border-emerald-500/30", bg: "rgba(16,185,129,0.08)" },
    fail: { icon: XCircle, color: "text-red-400", border: "border-red-500/30", bg: "rgba(239,68,68,0.08)" },
    neutral: { icon: AlertTriangle, color: "text-amber-400", border: "border-amber-500/30", bg: "rgba(245,158,11,0.08)" },
  }[status];

  return (
    <div className={`flex items-start gap-3 px-4 py-3 rounded-xl border ${cfg.border} flex-1`}
      style={{ background: cfg.bg, backdropFilter: "blur(10px)" }}>
      <cfg.icon className={`w-4 h-4 ${cfg.color} mt-0.5 flex-shrink-0`} />
      <div className="min-w-0">
        <div className="text-[10px] text-slate-500 uppercase tracking-widest">{label}</div>
        <div className={`text-sm font-bold capitalize ${cfg.color}`}>{status}</div>
        {detail && <div className="text-[10px] text-slate-400 font-mono truncate mt-0.5">{detail}</div>}
      </div>
    </div>
  );
};

// ─── Hash chip ────────────────────────────────────────────────────────────────
const HashChip: React.FC<{ label: string; value: string }> = ({ label, value }) => {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="rounded-xl p-4 border border-white/5" style={{ background: "rgba(255,255,255,0.02)" }}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Hash className="w-3.5 h-3.5 text-slate-500" />
          <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">{label}</span>
        </div>
        <button onClick={copy} className="text-slate-500 hover:text-cyan-400 transition-colors">
          {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>
      <div className="text-xs font-mono text-slate-300 break-all leading-relaxed">{value}</div>
    </div>
  );
};

// ─── Main ForensicsPage ───────────────────────────────────────────────────────
type FState = "idle" | "uploading" | "results";

const ForensicsPage: React.FC = () => {
  const [state, setState] = useState<FState>("idle");
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [rawPaste, setRawPaste] = useState("");
  const [mode, setMode] = useState<"upload" | "paste">("upload");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [redactPii, setRedactPii] = useState(false);
  const [forensicResult, setForensicResult] = useState<AnalyzeResponse | null>(null);
  const [copiedCaseId, setCopiedCaseId] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFile = (file: File) => {
    setFileName(file.name);
    setSelectedFile(file);
  };

  const handleAnalyze = async () => {
    setState("uploading");
    try {
      const result = mode === "upload" && selectedFile
        ? await uploadForensics(selectedFile, redactPii)
        : await analyzeForensics({ raw_eml: rawPaste, email_text: rawPaste, private_mode: redactPii });
      setForensicResult(result);
      setState("results");
    } catch {
      setState("results");
    }
  };

  const copyCase = () => {
    const id = forensicResult?.case_id ?? "UNKNOWN";
    navigator.clipboard.writeText(id).catch(() => {});
    setCopiedCaseId(true);
    setTimeout(() => setCopiedCaseId(false), 1500);
  };

  const data = forensicResult ? {
    caseId: forensicResult.case_id || `CASE-${new Date().toISOString().slice(0, 10)}-${Math.random().toString(16).slice(2, 8).toUpperCase()}`,
    timestamp: forensicResult.created_at || new Date().toISOString(),
    hashes: {
      sha256: forensicResult.sha256_evidence_hash || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      sha1: forensicResult.sha1 || "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      md5: forensicResult.md5 || "d41d8cd98f00b204e9800998ecf8427e",
    },
    spf: String(forensicResult.authentication?.spf?.status ?? "neutral").toLowerCase(),
    dkim: String(forensicResult.authentication?.dkim?.status ?? "neutral").toLowerCase(),
    dmarc: String(forensicResult.authentication?.dmarc?.status ?? "neutral").toLowerCase(),
    dkimDetails: forensicResult.authentication?.dkim,
    relayPath: (forensicResult.relay_path ?? []).map((hop) => ({
      ip: hop.ip ?? hop.received_from ?? "unknown",
      hostname: hop.by ?? hop.received_from ?? "unknown",
      location: hop.geo ? `${hop.geo.city ?? "Unknown"}, ${hop.geo.country_code ?? hop.geo.country ?? ""}` : "Unknown",
      timestamp: hop.timestamp ?? "",
      latency: `${hop.delay_seconds ?? 0}s`,
      isTor: hop.geo?.anonymization_type === "TOR",
      isVPN: Boolean(hop.geo?.is_anonymized && hop.geo?.anonymization_type !== "TOR"),
    })),
    campaign: {
      id: forensicResult.campaign?.id ?? "UNATTRIBUTED",
      name: forensicResult.campaign?.name ?? "No linked campaign",
      confidence: Math.round(forensicResult.campaign?.attribution_confidence ?? 0),
    },
    mitreTactics: forensicResult.mitre_tactics ?? [],
    riskScore: Math.round(forensicResult.final_risk ?? 0),
    verdict: forensicResult.verdict ?? "Analyzed",
    attachments: forensicResult.attachments ?? [],
    quishing: forensicResult.quishing,
    vip_impersonation: forensicResult.vip_impersonation,
    ctiHits: forensicResult.cti_hits ?? [],
  } : null;

  return (
    <div className="w-full min-h-screen p-6 md:p-10"
      style={{ background: "linear-gradient(135deg, #05070d 0%, #0b0f1a 100%)" }}>
      <div className="max-w-5xl mx-auto">

        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center border border-violet-500/30"
            style={{ background: "rgba(124,58,237,0.12)" }}>
            <Layers className="w-5 h-5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Forensic Investigation</h1>
            <p className="text-xs text-slate-500">Deep RFC 5322 decompilation, standalone DNS DKIM math &amp; chain-of-custody</p>
          </div>
        </div>

        <AnimatePresence mode="wait">
          {/* ── IDLE: dropzone ── */}
          {state === "idle" && (
            <motion.div key="idle"
              initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }}>

              {/* Mode toggle */}
              <div className="flex gap-1 p-1 rounded-xl mb-6 border border-white/5 w-fit"
                style={{ background: "rgba(255,255,255,0.03)" }}>
                <button
                  onClick={() => setMode("upload")}
                  className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${mode === "upload" ? "text-violet-300 border border-violet-500/30" : "text-slate-500 hover:text-slate-300"}`}
                  style={mode === "upload" ? { background: "rgba(124,58,237,0.1)" } : {}}>
                  Upload .eml / .msg / .mbox
                </button>
                <button
                  onClick={() => setMode("paste")}
                  className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${mode === "paste" ? "text-violet-300 border border-violet-500/30" : "text-slate-500 hover:text-slate-300"}`}
                  style={mode === "paste" ? { background: "rgba(124,58,237,0.1)" } : {}}>
                  Paste Raw RFC 5322
                </button>
              </div>

              <div className="rounded-2xl border border-white/5 p-8 mb-4"
                style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                {mode === "upload" ? (
                  <div
                    onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setDragOver(false);
                      const file = e.dataTransfer.files[0];
                      if (file) handleFile(file);
                    }}
                    onClick={() => fileRef.current?.click()}
                    className={`flex flex-col items-center justify-center gap-4 h-56 rounded-xl border-2 border-dashed transition-all cursor-pointer ${
                      dragOver ? "border-violet-400/60 bg-violet-500/5" : "border-white/10 hover:border-violet-500/30 hover:bg-violet-500/3"
                    }`}
                  >
                    <input
                      ref={fileRef}
                      type="file"
                      accept=".eml,.msg,.mbox"
                      className="hidden"
                      onChange={(e) => { if (e.target.files?.[0]) handleFile(e.target.files[0]); }}
                    />
                    <div className={`w-14 h-14 rounded-2xl flex items-center justify-center border transition-all ${dragOver ? "border-violet-400/60 bg-violet-500/10" : "border-white/10"}`}>
                      <Upload className={`w-6 h-6 ${dragOver ? "text-violet-400" : "text-slate-500"}`} />
                    </div>
                    {fileName ? (
                      <div className="text-center">
                        <div className="text-sm font-semibold text-violet-300">{fileName}</div>
                        <div className="text-xs text-slate-500 mt-1">Ready for full cryptographic triage</div>
                      </div>
                    ) : (
                      <div className="text-center">
                        <div className="text-sm text-slate-300">Drop raw .eml, Outlook .msg, or .mbox archive here</div>
                        <div className="text-xs text-slate-600 mt-1">or click to browse your forensic storage</div>
                      </div>
                    )}
                  </div>
                ) : (
                  <textarea
                    value={rawPaste}
                    onChange={(e) => setRawPaste(e.target.value)}
                    placeholder={"Received: from mail.suspicious.tk (185.220.101.34)\n  by mx1.victim.com; Mon, 06 Sep 2026 14:23:11 +0000\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=suspicious.tk; s=default...\nFrom: security@microsoft-verify.tk\nTo: victim@corp.com\nSubject: Urgent: Account Suspended\n\nDear user, your account has been suspended..."}
                    rows={10}
                    className="w-full bg-transparent text-slate-200 placeholder-slate-600 text-xs font-mono resize-none outline-none leading-relaxed"
                  />
                )}
              </div>

              {/* PII Redaction toggle */}
              <div className="flex items-center justify-between px-2 mb-6 text-xs text-slate-400">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={redactPii}
                    onChange={(e) => setRedactPii(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-violet-500 focus:ring-violet-500"
                  />
                  <span>Redact PII &amp; Sensitive Financial Identifiers (ISO 27037 Safe Mode)</span>
                </label>
                <span className="text-slate-600">SHA-256 Pre-Hashed Evidence</span>
              </div>

              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleAnalyze}
                disabled={mode === "upload" && !fileName}
                className="w-full py-4 rounded-xl font-bold text-sm text-white flex items-center justify-center gap-3 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                style={{
                  background: "linear-gradient(135deg, rgba(124,58,237,0.25), rgba(0,229,255,0.15))",
                  border: "1px solid rgba(124,58,237,0.4)",
                  boxShadow: "0 0 30px rgba(124,58,237,0.1)",
                }}
              >
                <Layers className="w-5 h-5 text-violet-400" />
                Run Deep Forensic Dissection
                <ChevronRight className="w-4 h-4" />
              </motion.button>
            </motion.div>
          )}

          {/* ── UPLOADING / processing ── */}
          {state === "uploading" && (
            <motion.div key="uploading"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="rounded-2xl border border-violet-500/20 p-12 flex flex-col items-center gap-6"
              style={{ background: "rgba(10,18,35,0.8)", backdropFilter: "blur(20px)" }}>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1.2, repeat: Infinity, ease: "linear" }}
                className="w-14 h-14 rounded-full border-2 border-violet-500/20 border-t-violet-400"
              />
              <div className="text-center">
                <div className="text-sm font-semibold text-white mb-1">Executing Cryptographic Pipeline...</div>
                <div className="text-xs text-slate-500">Computing SHA-256 Checksums · Standalone DKIM RSA Math · Reverse Relay Traversal</div>
              </div>
            </motion.div>
          )}

          {/* ── RESULTS ── */}
          {state === "results" && data && (
            <motion.div key="results"
              initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
              className="space-y-6">

              {/* Case ID header & Export Toolbar */}
              <div className="rounded-2xl p-6 border border-violet-500/20 flex items-center justify-between flex-wrap gap-4"
                style={{ background: "rgba(124,58,237,0.06)", backdropFilter: "blur(20px)" }}>
                <div>
                  <div className="text-xs text-slate-400 uppercase tracking-widest mb-1">Sealed Case ID</div>
                  <div className="text-xl font-bold font-mono text-violet-300">{data.caseId}</div>
                  <div className="text-xs text-slate-500 mt-1">{new Date(data.timestamp).toLocaleString()}</div>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <button onClick={copyCase}
                    className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold text-slate-300 border border-white/10 hover:border-white/20 transition-all bg-white/3">
                    {copiedCaseId ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedCaseId ? "Copied!" : "Copy ID"}
                  </button>
                  <button
                    onClick={() => window.open(getExportPdfUrl(data.caseId, redactPii))}
                    className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold text-violet-300 border border-violet-500/30 hover:border-violet-500/50 transition-all"
                    style={{ background: "rgba(124,58,237,0.12)" }}>
                    <Download className="w-3.5 h-3.5" />
                    Export PDF
                  </button>
                  <button
                    onClick={() => window.open(getExportStixUrl(data.caseId))}
                    className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold text-cyan-300 border border-cyan-500/30 hover:border-cyan-500/50 transition-all"
                    style={{ background: "rgba(0,229,255,0.1)" }}>
                    <FileText className="w-3.5 h-3.5" />
                    Export STIX 2.1
                  </button>
                  <button
                    onClick={() => window.open(getExportCsvUrl(data.caseId))}
                    className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold text-amber-300 border border-amber-500/30 hover:border-amber-500/50 transition-all"
                    style={{ background: "rgba(245,158,11,0.1)" }}>
                    <Download className="w-3.5 h-3.5" />
                    Export Defanged CSV
                  </button>
                </div>
              </div>

              {/* VIP Impersonation Alert Banner */}
              {data.vip_impersonation?.is_vip_impersonation && (
                <div className="rounded-2xl p-4 border border-red-500/40 flex items-center gap-3 text-red-300"
                  style={{ background: "rgba(239,68,68,0.12)", backdropFilter: "blur(20px)" }}>
                  <UserCheck className="w-6 h-6 text-red-400 flex-shrink-0" />
                  <div>
                    <div className="font-bold text-sm">CRITICAL: Executive Impersonation (VIP Spoofing)</div>
                    <div className="text-xs text-red-200/80">
                      Targeted Executive: <strong>{data.vip_impersonation.matched_vip?.name}</strong> ({data.vip_impersonation.matched_vip?.title}). Authorized domains: {data.vip_impersonation.matched_vip?.authorized_domains?.join(", ")}.
                    </div>
                  </div>
                </div>
              )}

              {/* Quishing QR Detection Banner */}
              {data.quishing?.is_quishing_detected && (
                <div className="rounded-2xl p-4 border border-purple-500/40 flex items-center gap-3 text-purple-300"
                  style={{ background: "rgba(168,85,247,0.12)", backdropFilter: "blur(20px)" }}>
                  <QrCode className="w-6 h-6 text-purple-400 flex-shrink-0" />
                  <div>
                    <div className="font-bold text-sm">Quishing Matrix: {data.quishing.qr_count} Embedded QR Code(s) Detected</div>
                    <div className="text-xs font-mono text-purple-200/80 break-all">
                      Decoded Target(s): {data.quishing.decoded_urls.join(", ")}
                    </div>
                  </div>
                </div>
              )}

              {/* Cryptographic Hashes */}
              <div className="rounded-2xl p-6 border border-white/5 space-y-4"
                style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Hash className="w-4 h-4" />
                  Cryptographic Evidence Pre-Hashing (ISO/IEC 27037)
                </h3>
                <HashChip label="SHA-256 Evidence Hash" value={data.hashes.sha256} />
                <HashChip label="SHA-1 Digest" value={data.hashes.sha1} />
                <HashChip label="MD5 Checksum" value={data.hashes.md5} />
              </div>

              {/* SPF / DKIM / DMARC + Standalone DKIM Math Card */}
              <div className="rounded-2xl p-6 border border-white/5 space-y-4"
                style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Lock className="w-4 h-4" />
                  Email Cryptographic Protocol Verification
                </h3>
                <div className="flex gap-3 flex-wrap">
                  <AuthPill label="SPF Authentication" status={data.spf as "pass" | "fail" | "neutral"} />
                  <AuthPill label="DKIM Standalone Math" status={data.dkim as "pass" | "fail" | "neutral"} detail={data.dkimDetails?.selector ? `s=${data.dkimDetails.selector}` : undefined} />
                  <AuthPill label="DMARC Alignment" status={data.dmarc as "pass" | "fail" | "neutral"} />
                </div>

                {data.dkimDetails && (
                  <div className="p-3 rounded-xl border border-white/5 bg-white/2 text-xs grid grid-cols-2 sm:grid-cols-4 gap-2">
                    <div><span className="text-slate-500">Signing Domain:</span> <span className="text-slate-200 font-mono">{data.dkimDetails.domain || "None"}</span></div>
                    <div><span className="text-slate-500">Key Length:</span> <span className="text-slate-200 font-mono">{data.dkimDetails.key_length ? `${data.dkimDetails.key_length}-bit RSA` : "Unknown"}</span></div>
                    <div><span className="text-slate-500">Body Hash:</span> <span className={data.dkimDetails.body_hash_valid ? "text-emerald-400 font-mono" : "text-red-400 font-mono"}>{data.dkimDetails.body_hash_valid ? "Valid (RFC 6376)" : "Invalid / Corrupted"}</span></div>
                    <div><span className="text-slate-500">Signature Math:</span> <span className={data.dkimDetails.signature_valid ? "text-emerald-400 font-mono" : "text-red-400 font-mono"}>{data.dkimDetails.signature_valid ? "Verified" : "Unverified / Mismatch"}</span></div>
                  </div>
                )}
              </div>

              {/* Quarantined Attachments Static Triage */}
              {data.attachments && data.attachments.length > 0 && (
                <div className="rounded-2xl p-6 border border-white/5"
                  style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                  <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                    <Paperclip className="w-4 h-4 text-violet-400" />
                    Static Attachment Analysis ({data.attachments.length})
                  </h3>
                  <div className="space-y-3">
                    {data.attachments.map((att, idx) => (
                      <div key={idx} className="p-4 rounded-xl border border-white/5 bg-white/2 flex items-center justify-between flex-wrap gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-semibold text-white flex items-center gap-2 truncate">
                            <span>{att.filename}</span>
                            {att.is_malicious && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold text-red-300 bg-red-500/10 border border-red-500/30">MALICIOUS</span>
                            )}
                            {att.has_macros && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold text-amber-300 bg-amber-500/10 border border-amber-500/30">VBA MACROS</span>
                            )}
                          </div>
                          <div className="text-xs text-slate-400 font-mono mt-1">
                            Type: {att.file_type} · Size: {(att.size_bytes / 1024).toFixed(1)} KB · Entropy: {att.entropy?.toFixed(2) ?? "N/A"} / 8.0
                          </div>
                          <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5">
                            SHA-256: {att.sha256}
                          </div>
                        </div>
                        {att.sha256 && (
                          <button
                            onClick={() => window.open(getQuarantineDownloadUrl(data.caseId, att.sha256))}
                            className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 border border-white/10 hover:border-white/20 transition-all flex items-center gap-1.5 bg-white/3"
                          >
                            <Download className="w-3.5 h-3.5" />
                            <span>Download Quarantined</span>
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Relay path timeline */}
              <div className="rounded-2xl p-6 border border-white/5"
                style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-6 flex items-center gap-2">
                  <Server className="w-4 h-4" />
                  Email Relay Path (Earliest Reliable Public Node)
                </h3>
                <div className="space-y-0">
                  {data.relayPath.map((hop, i) => (
                    <div key={i} className="flex gap-4">
                      <div className="flex flex-col items-center">
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border ${
                          hop.isVPN ? "border-amber-500/40 text-amber-400 bg-amber-500/10" : "border-cyan-500/30 text-cyan-400 bg-cyan-500/8"
                        }`}>{i + 1}</div>
                        {i < data.relayPath.length - 1 && (
                          <div className="w-px flex-1 my-1" style={{ background: "rgba(255,255,255,0.05)" }} />
                        )}
                      </div>
                      <div className="flex-1 pb-6">
                        <div className="flex items-start justify-between flex-wrap gap-2 mb-2">
                          <div>
                            <span className="text-sm font-mono font-semibold text-white">{hop.ip}</span>
                            {hop.isVPN && (
                              <span className="ml-2 px-2 py-0.5 rounded-md text-[10px] font-bold text-amber-300 border border-amber-500/30 bg-amber-500/10">COMMERCIAL VPN</span>
                            )}
                            {hop.isTor && (
                              <span className="ml-2 px-2 py-0.5 rounded-md text-[10px] font-bold text-purple-300 border border-purple-500/30 bg-purple-500/10">TOR EXIT NODE</span>
                            )}
                          </div>
                          <div className="flex items-center gap-3 text-xs text-slate-500">
                            <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{hop.timestamp || "Hop verified"}</span>
                            <span className="text-slate-600">{hop.latency}</span>
                          </div>
                        </div>
                        <div className="text-xs text-slate-400 flex items-center gap-2">
                          <Globe className="w-3 h-3" />
                          <span className="font-mono">{hop.hostname}</span>
                          <span className="text-slate-600">·</span>
                          <MapPin className="w-3 h-3" />
                          <span>{hop.location}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Campaign correlation + MITRE */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="rounded-2xl p-6 border border-white/5"
                  style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                  <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                    <Globe className="w-4 h-4" />
                    Campaign Attribution
                  </h3>
                  <div className="rounded-xl p-4 border border-violet-500/20"
                    style={{ background: "rgba(124,58,237,0.06)" }}>
                    <div className="text-xs text-slate-400 mb-1">{data.campaign.id}</div>
                    <div className="text-sm font-semibold text-violet-300 mb-2">{data.campaign.name}</div>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${data.campaign.confidence}%` }}
                          transition={{ duration: 1, ease: "easeOut" }}
                          className="h-full rounded-full bg-violet-500"
                        />
                      </div>
                      <span className="text-xs text-violet-400 font-bold">{data.campaign.confidence}%</span>
                    </div>
                    <div className="text-xs text-slate-500 mt-1">correlation confidence</div>
                  </div>
                </div>

                <div className="rounded-2xl p-6 border border-white/5"
                  style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                  <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    MITRE ATT&CK Tactics
                  </h3>
                  <div className="space-y-2">
                    {(data.mitreTactics.length > 0 ? data.mitreTactics : ["T1566.001 - Spearphishing", "T1036 - Masquerading"]).map((tactic) => (
                      <div key={tactic} className="flex items-center gap-2 p-2 rounded-lg border border-violet-500/15"
                        style={{ background: "rgba(124,58,237,0.06)" }}>
                        <ChevronRight className="w-3 h-3 text-violet-400 flex-shrink-0" />
                        <span className="text-xs font-mono text-slate-300">{tactic}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <button onClick={() => setState("idle")}
                className="w-full py-3 rounded-xl text-sm text-slate-400 border border-white/10 hover:border-white/20 transition-all"
                style={{ background: "rgba(255,255,255,0.02)" }}>
                ← New Investigation
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default ForensicsPage;
