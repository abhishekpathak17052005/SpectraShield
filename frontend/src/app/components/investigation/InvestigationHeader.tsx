import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Copy,
  Check,
  Clock,
  Mail,
  Download,
  Flag,
} from "lucide-react";
import { InvestigationHeaderMeta, RiskScoreData } from "../../types/investigation";
import { getExportPdfUrl } from "../../api";

function formatRelativeTime(raw: string | undefined): string {
  if (!raw) return "Time unknown";
  if (raw.toLowerCase().startsWith("today") || raw.toLowerCase().startsWith("yesterday")) {
    return raw;
  }
  try {
    const d = new Date(raw);
    if (isNaN(d.getTime())) return raw;
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffSecs = Math.floor(diffMs / 1000);
    if (diffSecs < 60) return `${diffSecs}s ago`;
    const diffMins = Math.floor(diffSecs / 60);
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHrs = Math.floor(diffMins / 60);
    if (diffHrs < 24) return `${diffHrs}h ago`;
    const diffDays = Math.floor(diffHrs / 24);
    if (diffDays < 30) return `${diffDays}d ago`;
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  } catch {
    return raw;
  }
}

interface Props {
  meta: InvestigationHeaderMeta;
  risk: RiskScoreData;
  onMarkSafe?: () => void;
  onReportThreat?: () => void;
  onExportReport?: () => void;
}

export const InvestigationHeader: React.FC<Props> = ({
  meta,
  risk,
  onMarkSafe,
  onReportThreat,
  onExportReport,
}) => {
  const [copiedId, setCopiedId] = useState(false);
  const [displayScore, setDisplayScore] = useState(0);
  const [threatReported, setThreatReported] = useState(false);
  const [markedSafe, setMarkedSafe] = useState(false);

  useEffect(() => {
    let start = 0;
    const target = risk.score;
    const duration = 800;
    const stepTime = 16;
    const totalSteps = duration / stepTime;
    const increment = target / totalSteps;

    const timer = setInterval(() => {
      start += increment;
      if (start >= target) {
        setDisplayScore(target);
        clearInterval(timer);
      } else {
        setDisplayScore(Math.round(start));
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [risk.score]);

  const copyId = () => {
    navigator.clipboard.writeText(meta.investigationId);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const handleReport = () => {
    setThreatReported(true);
    setTimeout(() => setThreatReported(false), 2500);
    onReportThreat?.();
  };

  const handleSafe = () => {
    setMarkedSafe(true);
    setTimeout(() => setMarkedSafe(false), 2500);
    onMarkSafe?.();
  };

  const isHighRisk = risk.score >= 70;
  const isSuspicious = risk.score >= 30 && risk.score < 70;

  // SVG Gauge calculations
  const size = 140;
  const strokeWidth = 10;
  const center = size / 2;
  const radius = center - strokeWidth;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (displayScore / 100) * circumference;

  const gaugeColor = isHighRisk ? "#ef4444" : isSuspicious ? "#f59e0b" : "#10b981";

  return (
    <div className="w-full flex flex-col gap-4">
      {/* ─── TITLE STRIP ────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-white/5">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-300">
            Investigation
          </span>
          <span className="text-slate-600">/</span>
          <span className="text-xs font-mono text-cyan-300">
            {meta.investigationId}
          </span>
        </div>

        <div>
          {meta.isDemoData && (
            <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
              DEMONSTRATION CASE
            </span>
          )}
        </div>
      </div>

      {/* ─── MAIN HEADER CARD ──────────────────────────────────────────────── */}
      <div className="rounded-xl border border-white/5 bg-[#0f172a]/70 p-5 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
        {/* Left: Email Details */}
        <div className="space-y-3 flex-1 min-w-0">
          <div className="space-y-1">
            <h1 className="text-base sm:text-lg font-semibold text-white tracking-tight leading-snug">
              {meta.subject}
            </h1>
            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
              <div className="flex items-center gap-1.5">
                <span className="text-slate-500">From:</span>
                <span className="font-mono text-slate-200 truncate max-w-xs">{meta.sender}</span>
              </div>
              <span>·</span>
              <div className="flex items-center gap-1">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                <span>{formatRelativeTime(meta.receivedTime)}</span>
              </div>
              <span>·</span>
              <div className="flex items-center gap-1">
                <Mail className="w-3.5 h-3.5 text-slate-500" />
                <span className="capitalize">{meta.platform}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={copyId}
              className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1 px-2 py-1 rounded bg-white/5 border border-white/5 transition-colors"
            >
              {copiedId ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{meta.investigationId}</span>
            </button>
            <span className="text-xs font-medium text-red-300">
              {risk.primaryMessage}
            </span>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 pt-2 flex-wrap">
            <button
              onClick={handleSafe}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-colors"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>{markedSafe ? "Marked Safe" : "Mark Safe"}</span>
            </button>

            <button
              onClick={handleReport}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-300 hover:text-red-200 bg-red-500/10 hover:bg-red-500/15 border border-red-500/20 transition-colors"
            >
              <Flag className="w-3.5 h-3.5 text-red-400" />
              <span>{threatReported ? "Escalated" : "Escalate Threat"}</span>
            </button>

            <button
              onClick={() => {
                if (onExportReport) onExportReport();
                else window.open(getExportPdfUrl(meta.investigationId, false));
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export PDF</span>
            </button>
          </div>
        </div>

        {/* Right: Risk Gauge */}
        <div className="flex items-center gap-5 self-center lg:self-auto border-t lg:border-t-0 lg:border-l border-white/5 pt-4 lg:pt-0 lg:pl-6 flex-shrink-0">
          <div className="relative flex items-center justify-center">
            <svg width={size} height={size} className="transform -rotate-90">
              <circle
                cx={center}
                cy={center}
                r={radius}
                stroke="rgba(255, 255, 255, 0.08)"
                strokeWidth={strokeWidth}
                fill="transparent"
              />
              <circle
                cx={center}
                cy={center}
                r={radius}
                stroke={gaugeColor}
                strokeWidth={strokeWidth}
                fill="transparent"
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={offset}
                className="transition-all duration-700"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center leading-none">
              <span className="text-3xl font-semibold text-white">
                {displayScore}
              </span>
              <span className="text-[10px] text-slate-400 mt-1">/ 100</span>
            </div>
          </div>

          <div className="space-y-1">
            <div
              className={`text-xs font-semibold px-2 py-0.5 rounded uppercase inline-block ${
                isHighRisk
                  ? "bg-red-500/15 text-red-300"
                  : isSuspicious
                  ? "bg-amber-500/15 text-amber-300"
                  : "bg-emerald-500/15 text-emerald-300"
              }`}
            >
              {isHighRisk ? "High Risk" : isSuspicious ? "Suspicious" : "Safe"}
            </div>
            <div className="text-xs text-slate-400">
              Confidence: <b className="text-slate-200">{risk.confidence != null ? `${risk.confidence}%` : "—"}</b>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
