import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { SocLayout } from "./SocLayout";
import {
  Download,
  ShieldCheck,
  Check,
  Copy,
  FolderArchive,
  ExternalLink,
  Sliders,
  CheckCircle2,
  Mail,
  Lock,
  Zap,
  Globe,
  RefreshCw,
  Info,
  ChevronDown,
  ChevronUp,
  Cpu,
  ArrowRight,
  Sparkles,
  Terminal,
} from "lucide-react";
import { getApiBase } from "../../api";
import { Button, Badge, Card, CardContent } from "../ui";

interface Props {
  onNavigate: (route: string) => void;
}

export const ExtensionDownloadPage: React.FC<Props> = ({ onNavigate }) => {
  const [downloading, setDownloading] = useState<boolean>(false);
  const [downloadSuccess, setDownloadSuccess] = useState<boolean>(false);
  const [copiedChecksum, setCopiedChecksum] = useState<boolean>(false);
  const [copiedUrl, setCopiedUrl] = useState<boolean>(false);
  const [engineStatus, setEngineStatus] = useState<{
    status: "healthy" | "offline" | "checking";
    version?: string;
    service?: string;
    latencyMs?: number;
  }>({ status: "checking" });
  const [checkingEngine, setCheckingEngine] = useState<boolean>(false);
  const [activeFaq, setActiveFaq] = useState<number | null>(null);

  const EXTENSION_VERSION = "1.0.0";
  const EXTENSION_FILE_SIZE = "~35 KB";
  const EXTENSION_SHA256 =
    "df4d4584e37a8ed15c290c2ad7bc8c9f597ea19566072b855106eb8f064a858a";

  // Check backend engine health
  const checkEngine = async () => {
    setCheckingEngine(true);
    const start = performance.now();
    try {
      const res = await fetch(`${getApiBase()}/health`);
      const latency = Math.round(performance.now() - start);
      if (res.ok) {
        const data = await res.json();
        setEngineStatus({
          status: "healthy",
          version: data.version || "2.0.0",
          service: data.service || "SpectraShield Engine",
          latencyMs: latency,
        });
      } else {
        setEngineStatus({ status: "offline", latencyMs: latency });
      }
    } catch {
      setEngineStatus({ status: "offline" });
    } finally {
      setCheckingEngine(false);
    }
  };

  useEffect(() => {
    checkEngine();
  }, []);

  // Trigger download of extension bundle
  const handleDownload = async () => {
    setDownloading(true);
    setDownloadSuccess(false);

    try {
      // 1. Try dynamic backend endpoint first
      const dynamicUrl = `${getApiBase()}/api/extension/download`;
      const fallbackUrl = "/spectrashield-extension.zip";

      let downloadTarget = dynamicUrl;
      try {
        const testRes = await fetch(dynamicUrl, { method: "HEAD" });
        if (!testRes.ok) {
          downloadTarget = fallbackUrl;
        }
      } catch {
        downloadTarget = fallbackUrl;
      }

      // Create synthetic link to trigger native browser save dialog
      const link = document.createElement("a");
      link.href = downloadTarget;
      link.setAttribute("download", "spectrashield-extension.zip");
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 5000);
    } catch (err) {
      console.error("Download failed:", err);
      // Final fallback direct window open
      window.open("/spectrashield-extension.zip", "_blank");
    } finally {
      setDownloading(false);
    }
  };

  const copyToClipboard = (text: string, type: "checksum" | "url") => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => {
          fallbackCopyText(text);
        });
      } else {
        fallbackCopyText(text);
      }
    } catch {
      fallbackCopyText(text);
    }
    if (type === "checksum") {
      setCopiedChecksum(true);
      setTimeout(() => setCopiedChecksum(false), 2500);
    } else {
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2500);
    }
  };

  const fallbackCopyText = (text: string) => {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.opacity = "0";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
      document.execCommand("copy");
    } catch {}
    document.body.removeChild(textArea);
  };

  const toggleFaq = (index: number) => {
    setActiveFaq(activeFaq === index ? null : index);
  };

  const browsers = [
    { name: "Google Chrome", badge: "Primary", supported: true },
    { name: "Brave Browser", badge: "Tested", supported: true },
    { name: "Microsoft Edge", badge: "Supported", supported: true },
    { name: "Opera / GX", badge: "Supported", supported: true },
    { name: "Arc Browser", badge: "Supported", supported: true },
    { name: "Chromium / Vivaldi", badge: "Supported", supported: true },
  ];

  const steps = [
    {
      stepNumber: "01",
      title: "Download & Extract",
      icon: FolderArchive,
      description:
        "Download spectrashield-extension.zip and extract it to a permanent folder on your drive.",
      detailBadge: "Archive: spectrashield-extension.zip",
    },
    {
      stepNumber: "02",
      title: "Open Extensions Page",
      icon: ExternalLink,
      description:
        "Open your Chromium browser and navigate to chrome://extensions in your address bar.",
      actionButton: {
        label: copiedUrl ? "Copied to Clipboard!" : "Copy chrome://extensions",
        onClick: () => copyToClipboard("chrome://extensions", "url"),
      },
      detailBadge: "URL: chrome://extensions",
    },
    {
      stepNumber: "03",
      title: "Enable Developer Mode",
      icon: Sliders,
      description:
        "Toggle Developer mode ON using the switch in the top-right corner of the extensions manager.",
      detailBadge: "Toggle: Developer Mode ON",
    },
    {
      stepNumber: "04",
      title: "Load Unpacked & Protect",
      icon: ShieldCheck,
      description:
        "Click 'Load unpacked' in the top-left toolbar and select the extracted extension/ directory.",
      detailBadge: "Action: Load Unpacked Directory",
    },
  ];

  const capabilities = [
    {
      title: "Gmail In-Inbox Sentinel",
      icon: Mail,
      tag: "Automated Telemetry",
      description:
        "Continuously evaluates incoming thread rows with zero user intervention. Injects dynamic threat badges (Safe, Suspicious, High Risk) and top alert banners over flagged emails.",
    },
    {
      title: "LinkedIn DM Guardian",
      icon: Globe,
      tag: "Social Engineering",
      description:
        "Detects credential lures, urgent executive impersonation, and weaponized links in LinkedIn direct messages while automatically discarding benign internal routes.",
    },
    {
      title: "Toolbar Quick-Scan Sandbox",
      icon: Zap,
      tag: "On-Demand Forensics",
      description:
        "Instantly evaluate arbitrary email snippets, raw MIME headers, and suspicious URLs via the browser toolbar popup with explainable risk breakdown.",
    },
    {
      title: "Zero-Knowledge In-Memory Privacy",
      icon: Lock,
      tag: "Privacy Protocol",
      description:
        "Zero correspondence is ever written to disk or third-party servers. All evaluations execute in-memory with strict private_mode: true protocol.",
    },
  ];

  const permissionsList = [
    {
      permission: "https://mail.google.com/*",
      purpose: "Inspects Gmail inbox rows and opened messages for threat vectors",
      privacy: "In-memory evaluation only. No email text is ever persisted to database.",
    },
    {
      permission: "https://www.linkedin.com/*",
      purpose: "Inspects LinkedIn message threads for credential lures and malicious URLs",
      privacy: "Evaluates external URLs locally; internal LinkedIn paths are discarded.",
    },
    {
      permission: "activeTab & tabs",
      purpose: "Allows on-demand scanning of user-selected suspicious tabs via the popup",
      privacy: "Session-scoped only. No browsing history is captured or recorded.",
    },
    {
      permission: "http://localhost:8000/*",
      purpose: "Local communication with your SpectraShield AI engine",
      privacy: "Strictly connects to your own local/company backend. Zero telemetry to cloud.",
    },
  ];

  const faqs = [
    {
      question: "How do I update the extension after making changes?",
      answer:
        "Whenever extension files or local code are modified, simply visit chrome://extensions in your browser and click the reload icon (🔄) on the SpectraShield extension card. The updated service worker and content scripts reload in under a second.",
    },
    {
      question: "Can I use SpectraShield on Brave, Microsoft Edge, or Arc?",
      answer:
        "Yes! Because SpectraShield is engineered on Chromium Manifest V3, it runs natively on Google Chrome, Brave, Microsoft Edge, Opera, Arc, Vivaldi, and any other Chromium-based browser with developer mode enabled.",
    },
    {
      question: "What happens if my local SpectraShield backend is offline?",
      answer:
        "If the backend server is unreachable, the extension safely displays a non-intrusive offline indicator in the toolbar popup and caches verdicts locally. Once you restart the backend, live scanning resumes automatically without needing a browser reload.",
    },
    {
      question: "Are any emails sent to external cloud AI providers?",
      answer:
        "No. SpectraShield operates on strict zero-trust data minimization. All threat assessments, natural language parsing, and regex tokenizers execute locally on your backend engine. No email bodies or sender identities are dispatched to third parties.",
    },
  ];

  return (
    <SocLayout
      activeNav="extension"
      onNavigate={onNavigate}
      title="Browser Extension"
      subtitle="Client Deployment, In-Browser Phishing Sentinel & Quick-Scan Sandbox"
      badge="MANIFEST V3"
      actions={
        <div className="flex items-center gap-2">
          <Button
            onClick={checkEngine}
            disabled={checkingEngine}
            variant="ghost"
            size="sm"
            className="flex items-center gap-1.5"
            title="Refresh local engine status"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${checkingEngine ? "animate-spin text-accent" : ""}`} />
            <span className="hidden sm:inline">Check Engine</span>
          </Button>
          <Button
            onClick={handleDownload}
            disabled={downloading}
            variant="accent"
            size="sm"
            className="flex items-center gap-1.5 shadow-[0_0_16px_rgba(6,182,212,0.3)]"
          >
            <Download className={`w-3.5 h-3.5 ${downloading ? "animate-bounce" : ""}`} />
            <span>{downloading ? "Packaging..." : "Download (.zip)"}</span>
          </Button>
        </div>
      }
    >
      {/* ─── 1. HERO DOWNLOAD BANNER ────────────────────────────────────────── */}
      <div
        className="relative rounded-2xl border border-cyan-500/25 p-6 md:p-8 overflow-hidden backdrop-blur-xl shadow-2xl"
        style={{
          background:
            "linear-gradient(135deg, rgba(6, 182, 212, 0.1) 0%, rgba(15, 23, 42, 0.6) 50%, rgba(13, 20, 36, 0.8) 100%)",
        }}
      >
        {/* Glow & ambient circles */}
        <div className="absolute -top-24 -right-24 w-72 h-72 rounded-full bg-cyan-500/15 blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-72 h-72 rounded-full bg-indigo-500/15 blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="space-y-3 max-w-2xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5">
                <Sparkles className="w-3 h-3 text-cyan-400" />
                SpectraShield Chromium Client v{EXTENSION_VERSION}
              </span>
              <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                Manifest V3 Verified
              </span>
              <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-semibold bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                In-Memory Privacy Mode
              </span>
            </div>

            <h2 className="text-2xl md:text-3xl font-bold text-white tracking-tight leading-snug">
              Real-Time Phishing Defense <br />
              <span className="bg-gradient-to-r from-cyan-400 via-teal-300 to-indigo-300 bg-clip-text text-transparent">
                Directly Inside Your Browser
              </span>
            </h2>

            <p className="text-xs md:text-sm text-slate-300 leading-relaxed">
              Equip your browser with autonomous threat telemetry. SpectraShield silently inspects
              Gmail inbox rows and LinkedIn message threads, flagging credential harvesting lures,
              spoofed domains, and zero-day phishing before you click.
            </p>

            {/* Quick stats pills */}
            <div className="pt-2 flex flex-wrap items-center gap-4 text-xs text-slate-400 font-mono">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                <span>Format: Unpacked Chromium Extension</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                <span>Size: {EXTENSION_FILE_SIZE}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-400" />
                <span>Protocol: RFC 5322 & MV3</span>
              </div>
            </div>
          </div>

          {/* Download Action Cluster */}
          <div className="w-full lg:w-auto flex-shrink-0 space-y-3">
            <button
              onClick={handleDownload}
              disabled={downloading}
              className="w-full lg:w-64 px-6 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 via-teal-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-semibold text-sm shadow-[0_0_24px_rgba(6,182,212,0.4)] hover:shadow-[0_0_32px_rgba(6,182,212,0.6)] transition-all flex items-center justify-center gap-3 border border-white/20 group cursor-pointer"
            >
              <Download className={`w-5 h-5 transition-transform duration-200 group-hover:-translate-y-0.5 ${downloading ? "animate-bounce" : ""}`} />
              <div className="text-left leading-tight">
                <div className="font-bold text-sm">
                  {downloading ? "Packaging Bundle..." : "Download Extension"}
                </div>
                <div className="text-[10px] text-cyan-100 font-mono font-normal">
                  spectrashield-extension.zip
                </div>
              </div>
            </button>

            {downloadSuccess && (
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                className="p-2.5 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs flex items-center gap-2"
              >
                <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
                <span>Bundle downloaded successfully! Extract and load into your browser.</span>
              </motion.div>
            )}

            {/* Direct Link & Checksum row */}
            <div className="flex items-center justify-between gap-2 px-1 text-[11px] text-slate-400 font-mono">
              <a
                href="/spectrashield-extension.zip"
                download="spectrashield-extension.zip"
                className="hover:text-cyan-300 underline underline-offset-2 transition-colors flex items-center gap-1"
                title="Direct static download link"
              >
                <Download className="w-3 h-3" />
                <span>Direct Link</span>
              </a>
              <span>·</span>
              <button
                onClick={() => copyToClipboard(EXTENSION_SHA256, "checksum")}
                className="hover:text-cyan-300 transition-colors flex items-center gap-1 cursor-pointer"
                title="Copy SHA-256 integrity checksum"
              >
                {copiedChecksum ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy SHA256</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ─── 2. ENGINE CONNECTION STATUS BAR ─────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Connection status card */}
        <div className="p-4 rounded-xl border border-border bg-surface-elevated/40 backdrop-blur-md flex items-center gap-3.5">
          <div
            className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${
              engineStatus.status === "healthy"
                ? "bg-emerald-500/15 border border-emerald-500/30 text-emerald-400"
                : engineStatus.status === "offline"
                ? "bg-red-500/15 border border-red-500/30 text-red-400"
                : "bg-amber-500/15 border border-amber-500/30 text-amber-400"
            }`}
          >
            <Cpu className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="text-xs text-text-muted">Local Backend Status</div>
            <div className="text-sm font-semibold text-foreground flex items-center gap-2">
              <span>
                {engineStatus.status === "healthy"
                  ? "Engine Connected"
                  : engineStatus.status === "offline"
                  ? "Engine Offline"
                  : "Connecting..."}
              </span>
              {engineStatus.latencyMs !== undefined && (
                <span className="text-[10px] font-mono text-cyan-400">
                  {engineStatus.latencyMs}ms
                </span>
              )}
            </div>
            <div className="text-[11px] text-text-muted truncate font-mono">
              Target: {getApiBase()}
            </div>
          </div>
        </div>

        {/* Security & Isolation */}
        <div className="p-4 rounded-xl border border-border bg-surface-elevated/40 backdrop-blur-md flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs text-text-muted">Security Architecture</div>
            <div className="text-sm font-semibold text-foreground">Air-Gapped Telemetry</div>
            <div className="text-[11px] text-text-muted">
              Zero cloud dispatch · 100% localhost
            </div>
          </div>
        </div>

        {/* Browser compatibility summary */}
        <div className="p-4 rounded-xl border border-border bg-surface-elevated/40 backdrop-blur-md flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-indigo-500/15 border border-indigo-500/30 text-indigo-400 flex items-center justify-center flex-shrink-0">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs text-text-muted">Supported Browsers</div>
            <div className="text-sm font-semibold text-foreground">Chromium MV3</div>
            <div className="text-[11px] text-text-muted">
              Chrome, Brave, Edge, Opera, Arc
            </div>
          </div>
        </div>
      </div>

      {/* ─── 3. INTERACTIVE 4-STEP INSTALLATION GUIDE ────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base md:text-lg font-bold text-foreground tracking-tight flex items-center gap-2">
              <span>Quick Installation Walkthrough</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/25">
                4 Easy Steps
              </span>
            </h3>
            <p className="text-xs text-text-muted">
              Load the unpacked extension into your Chromium browser in under 60 seconds.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {steps.map((s, idx) => {
            const Icon = s.icon;
            return (
              <div
                key={idx}
                className="rounded-xl border border-border bg-surface-elevated/50 p-5 space-y-3 relative overflow-hidden transition-all hover:border-cyan-500/30 hover:shadow-lg group"
              >
                <div className="flex items-center justify-between">
                  <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 flex items-center justify-center font-mono font-bold text-xs">
                    {s.stepNumber}
                  </div>
                  <Icon className="w-4 h-4 text-text-muted group-hover:text-accent transition-colors" />
                </div>

                <div className="space-y-1">
                  <h4 className="text-sm font-semibold text-foreground">{s.title}</h4>
                  <p className="text-xs text-text-muted leading-relaxed">{s.description}</p>
                </div>

                {s.actionButton ? (
                  <button
                    onClick={s.actionButton.onClick}
                    className="w-full mt-2 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/25 text-xs font-mono transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <Copy className="w-3 h-3" />
                    <span>{s.actionButton.label}</span>
                  </button>
                ) : (
                  <div className="pt-1">
                    <span className="text-[10px] font-mono text-slate-400 px-2 py-0.5 rounded bg-white/5 border border-white/5 truncate block">
                      {s.detailBadge}
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ─── 4. CAPABILITIES & PROTECTION MODULES GRID ───────────────────────── */}
      <div className="space-y-4">
        <div>
          <h3 className="text-base md:text-lg font-bold text-foreground tracking-tight">
            Active Protection Modules
          </h3>
          <p className="text-xs text-text-muted">
            The multi-vector safeguards enabled by the SpectraShield extension once loaded.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {capabilities.map((c, idx) => {
            const Icon = c.icon;
            return (
              <div
                key={idx}
                className="p-5 rounded-xl border border-border bg-surface-elevated/40 backdrop-blur-md space-y-2.5 hover:border-cyan-500/25 transition-all"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-accent/15 border border-accent/30 text-accent flex items-center justify-center">
                      <Icon className="w-4 h-4" />
                    </div>
                    <span className="font-semibold text-sm text-foreground">{c.title}</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 text-slate-300 border border-white/10">
                    {c.tag}
                  </span>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">{c.description}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* ─── 5. PERMISSIONS TRANSPARENCY MATRIX ─────────────────────────────── */}
      <div className="space-y-4">
        <div>
          <h3 className="text-base md:text-lg font-bold text-foreground tracking-tight">
            Security & Permission Transparency
          </h3>
          <p className="text-xs text-text-muted">
            Full declaration of browser capabilities requested in manifest.json and their privacy boundaries.
          </p>
        </div>

        <div className="rounded-xl border border-border bg-surface-elevated/30 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border bg-surface-muted/30 text-text-muted font-mono text-[11px]">
                  <th className="py-3 px-4 font-semibold">Permission / Host</th>
                  <th className="py-3 px-4 font-semibold">Operational Purpose</th>
                  <th className="py-3 px-4 font-semibold">Privacy Boundary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {permissionsList.map((p, idx) => (
                  <tr key={idx} className="hover:bg-surface-muted/20 transition-colors">
                    <td className="py-3 px-4 font-mono font-medium text-cyan-300">
                      {p.permission}
                    </td>
                    <td className="py-3 px-4 text-text-secondary">{p.purpose}</td>
                    <td className="py-3 px-4 text-text-muted text-[11px] leading-relaxed">
                      {p.privacy}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* ─── 6. BROWSER COMPATIBILITY BADGES ─────────────────────────────────── */}
      <div className="p-5 rounded-xl border border-border bg-surface-elevated/40 space-y-3">
        <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wider">
          Tested Chromium Environments
        </h4>
        <div className="flex flex-wrap items-center gap-3">
          {browsers.map((b, idx) => (
            <div
              key={idx}
              className="px-3 py-1.5 rounded-lg bg-surface-elevated border border-border flex items-center gap-2 text-xs font-medium text-foreground"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>{b.name}</span>
              <span className="text-[9px] font-mono px-1 rounded bg-white/5 text-slate-400">
                {b.badge}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* ─── 7. FREQUENTLY ASKED QUESTIONS (FAQ) ────────────────────────────── */}
      <div className="space-y-4">
        <div>
          <h3 className="text-base md:text-lg font-bold text-foreground tracking-tight">
            Troubleshooting & Deployment FAQ
          </h3>
          <p className="text-xs text-text-muted">
            Common questions regarding unpacked extension management and backend synchronization.
          </p>
        </div>

        <div className="space-y-2.5">
          {faqs.map((f, idx) => {
            const isOpen = activeFaq === idx;
            return (
              <div
                key={idx}
                className="rounded-xl border border-border bg-surface-elevated/30 overflow-hidden transition-colors"
              >
                <button
                  onClick={() => toggleFaq(idx)}
                  className="w-full px-5 py-3.5 text-left flex items-center justify-between gap-4 text-xs md:text-sm font-medium text-foreground hover:bg-surface-muted/20 transition-colors"
                >
                  <span className="font-semibold">{f.question}</span>
                  {isOpen ? (
                    <ChevronUp className="w-4 h-4 text-accent flex-shrink-0" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-text-muted flex-shrink-0" />
                  )}
                </button>
                {isOpen && (
                  <div className="px-5 pb-4 text-xs text-text-muted leading-relaxed border-t border-border/50 pt-3">
                    {f.answer}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </SocLayout>
  );
};
