import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  AlertTriangle,
  Copy,
  Check,
  ExternalLink,
  Lock,
  RefreshCw,
} from 'lucide-react';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidMorphButton } from '../liquid/LiquidMorphButton';
import { LiquidCausticProgress } from '../liquid/LiquidCausticProgress';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';
import { analyzeEmail, MOCK_QUICK_ANALYZE, AnalyzeResponse } from '../../api';

export const ExtensionPopupView: React.FC<{ onEscalateToSOC?: () => void }> = ({ onEscalateToSOC }) => {
  const [emailInput, setEmailInput] = useState(
    'URGENT: Verify your account now. Click here to avoid suspension. Your Microsoft account has been locked.'
  );
  const [urlInput, setUrlInput] = useState('https://secure-verify-account.tk/login/microsoft');
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<AnalyzeResponse>(MOCK_QUICK_ANALYZE);
  const [actionDone, setActionDone] = useState<string | null>(null);

  const handleScan = async () => {
    setLoading(true);
    try {
      const res = await analyzeEmail({
        email_text: emailInput,
        url: urlInput,
        private_mode: true,
      });
      setAnalysis(res);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  const triggerAction = (msg: string) => {
    setActionDone(msg);
    setTimeout(() => setActionDone(null), 2500);
  };

  const riskScore = Math.round(analysis.final_risk);
  const isHighRisk = riskScore >= 70;

  // SVG Circular Gauge calculation
  const radius = 64;
  const stroke = 10;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const strokeDashoffset = circumference - (riskScore / 100) * circumference;

  return (
    <div className="space-y-8 pb-16 flex flex-col items-center">
      {/* Top Description */}
      <div className="text-center max-w-lg">
        <div className="inline-flex items-center gap-2 mb-2">
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
            Extension Sentinel Widget
          </h1>
          <LiquidGlassBadge variant="forensics" label="400x600 POPUP" size="sm" />
        </div>
        <p className="text-xs md:text-sm text-slate-400">
          Chromium Manifest V3 browser extension interactive simulation with real-time heuristic scoring and inline quarantine.
        </p>
      </div>

      {/* 400x600 Extension Window Frame */}
      <div className="w-full max-w-[400px] min-h-[600px] rounded-3xl border border-white/20 bg-slate-900/95 backdrop-blur-3xl shadow-2xl overflow-hidden flex flex-col relative transition-all duration-300">
        {/* Specular Rim Top Highlight */}
        <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-300 to-transparent z-20" />

        {/* Extension Top Header Bar */}
        <div className="px-5 py-3.5 border-b border-white/10 bg-slate-950/80 backdrop-blur-xl flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-xl bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center shadow-[0_0_10px_rgba(6,182,212,0.3)]">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <span className="font-bold text-sm text-white tracking-tight">SpectraShield</span>
              <span className="ml-1.5 px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                v2.0
              </span>
            </div>
          </div>

          <LiquidGlassBadge
            variant={isHighRisk ? 'critical' : 'safe'}
            label={analysis.verdict}
            size="sm"
          />
        </div>

        {/* Extension Scrollable Body */}
        <div className="p-5 space-y-5 flex-1 overflow-y-auto custom-scrollbar">
          {/* Circular Volumetric Risk Gauge */}
          <div className="flex flex-col items-center justify-center pt-2">
            <div className="relative w-36 h-36 flex items-center justify-center">
              <svg height={radius * 2} width={radius * 2} className="rotate-[-90deg]">
                <circle
                  stroke="rgba(255, 255, 255, 0.08)"
                  fill="transparent"
                  strokeWidth={stroke}
                  r={normalizedRadius}
                  cx={radius}
                  cy={radius}
                />
                <circle
                  stroke={isHighRisk ? '#ef4444' : riskScore > 30 ? '#f59e0b' : '#10b981'}
                  fill="transparent"
                  strokeWidth={stroke}
                  strokeDasharray={circumference + ' ' + circumference}
                  style={{
                    strokeDashoffset,
                    transition: 'stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1)',
                  }}
                  strokeLinecap="round"
                  r={normalizedRadius}
                  cx={radius}
                  cy={radius}
                />
              </svg>

              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-mono font-bold text-white tracking-tight">
                  {riskScore}%
                </span>
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                  Threat Index
                </span>
              </div>
            </div>

            <div className="mt-2 text-center text-xs font-mono text-slate-300">
              Target Impersonation: <span className="text-cyan-300 font-bold">{analysis.risk_breakdown?.brand_match || 'Microsoft'}</span>
            </div>
          </div>

          {/* Granular Sub-Vector Breakdown Bars */}
          <div className="space-y-3 p-4 rounded-2xl bg-slate-950/70 border border-white/10">
            <div className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider">
              Heuristic Sub-Vectors
            </div>
            <LiquidCausticProgress
              label="URL Reputation"
              progress={analysis.breakdown.url_score}
              variant="crimson"
            />
            <LiquidCausticProgress
              label="Cognitive Urgency Cues"
              progress={analysis.breakdown.manipulation_score}
              variant="amber"
            />
            <LiquidCausticProgress
              label="AI Generated Phish Patterns"
              progress={analysis.breakdown.ai_generated_score}
              variant="purple"
            />
          </div>

          {/* Quick Scan Input Fields */}
          <div className="space-y-2">
            <label className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider block">
              Quick Email Payload
            </label>
            <textarea
              value={emailInput}
              onChange={(e) => setEmailInput(e.target.value)}
              rows={2}
              className="w-full p-2.5 rounded-xl bg-slate-950 border border-white/10 font-mono text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-400/60"
            />

            <label className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider block">
              Extracted URL
            </label>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              className="w-full p-2.5 rounded-xl bg-slate-950 border border-white/10 font-mono text-xs text-cyan-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-400/60"
            />

            <LiquidMorphButton
              mode="cyan"
              onClick={handleScan}
              icon={RefreshCw}
              isLoading={loading}
              className="w-full justify-center mt-2"
            >
              Re-Scan Page Elements
            </LiquidMorphButton>
          </div>

          {/* Action Notification Toast */}
          {actionDone && (
            <div className="p-3 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs font-mono text-center font-bold animate-liquid-pop">
              ✓ {actionDone}
            </div>
          )}

          {/* Remediation Action Buttons */}
          <div className="space-y-2 pt-2 border-t border-white/10">
            <div className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider">
              Enforcement Actions
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => triggerAction('Marked as Safe in Local Cache')}
                className="px-3 py-2 rounded-xl bg-slate-800/80 hover:bg-slate-800 text-slate-200 border border-white/10 text-xs font-mono font-bold transition-all"
              >
                Mark Safe
              </button>
              <button
                type="button"
                onClick={() => triggerAction('Quarantined Mailbox Item')}
                className="px-3 py-2 rounded-xl bg-red-600/30 hover:bg-red-600/40 text-red-300 border border-red-500/40 text-xs font-mono font-bold transition-all"
              >
                Quarantine
              </button>
            </div>

            {onEscalateToSOC && (
              <LiquidMorphButton
                mode="crimson"
                onClick={onEscalateToSOC}
                icon={ExternalLink}
                className="w-full justify-center mt-1"
              >
                Escalate Full Case to SOC
              </LiquidMorphButton>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
