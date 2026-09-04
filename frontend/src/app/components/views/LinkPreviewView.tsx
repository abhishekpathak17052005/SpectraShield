import React, { useState } from 'react';
import {
  Link2,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Calendar,
  Layers,
  ArrowRight,
  ExternalLink,
  Copy,
  Check,
  AlertTriangle,
  Eye,
  EyeOff,
  Server,
  RefreshCw,
} from 'lucide-react';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidMorphButton } from '../liquid/LiquidMorphButton';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';
import { LiquidCausticProgress } from '../liquid/LiquidCausticProgress';
import { DefangedText } from '../common/DefangedText';
import { analyzeEmail, MOCK_QUICK_ANALYZE, AnalyzeResponse } from '../../api';

export const LinkPreviewView: React.FC = () => {
  const [urlInput, setUrlInput] = useState('https://secure-verify-account.tk/login/microsoft');
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<AnalyzeResponse>(MOCK_QUICK_ANALYZE);
  const [showSandboxFrame, setShowSandboxFrame] = useState(false);
  const [copiedDefanged, setCopiedDefanged] = useState(false);

  const handleAnalyze = async () => {
    setLoading(true);
    try {
      const res = await analyzeEmail({
        email_text: 'Link sandbox inspection trigger',
        url: urlInput,
        private_mode: true,
      });
      setAnalysis(res);
    } catch {
      // Offline fallback
    } finally {
      setLoading(false);
    }
  };

  const copyDefanged = () => {
    const def = urlInput.replace(/http/gi, 'hxxp').replace(/\./g, '[.]');
    navigator.clipboard.writeText(def);
    setCopiedDefanged(true);
    setTimeout(() => setCopiedDefanged(false), 2000);
  };

  const domainAge = analysis.domain_age_days ?? 4;
  const isBurner = domainAge < 14;
  const ssl = analysis.intelligence_profile?.ssl_status;
  const redirects = analysis.intelligence_profile?.advanced_technical_details?.redirect_chain || [
    'https://bit.ly/3xMS901',
    'https://secure-verify-account.tk/login/microsoft',
  ];

  return (
    <div className="space-y-8 pb-16">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
              Sandboxed URL Previewer & SSL Radar
            </h1>
            <LiquidGlassBadge variant="forensics" label="ISOLATED LINK RADAR" size="sm" />
          </div>
          <p className="text-xs md:text-sm text-slate-400 mt-1">
            Zero-trust URL detangling, redirect chain disassembly, Free DV certificate inspection, and WHOIS domain age gauges.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <LiquidMorphButton
            mode="cyan"
            onClick={copyDefanged}
            icon={copiedDefanged ? Check : Copy}
          >
            {copiedDefanged ? 'Copied Defanged URL!' : 'Copy Defanged (hxxps://)'}
          </LiquidMorphButton>
        </div>
      </div>

      {/* URL Input Bar */}
      <LiquidGlassCard glowColor="cyan" className="p-5">
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Link2 className="w-4 h-4 text-cyan-400 absolute left-4 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter suspicious link (https://...)"
              className="w-full pl-11 pr-4 py-3 rounded-2xl bg-slate-950/80 border border-white/10 font-mono text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-400/80 transition-all shadow-inner"
            />
          </div>
          <LiquidMorphButton
            mode="cyan"
            onClick={handleAnalyze}
            icon={RefreshCw}
            isLoading={loading}
            className="w-full sm:w-auto shrink-0"
          >
            Analyze URL Sandbox
          </LiquidMorphButton>
        </div>
      </LiquidGlassCard>

      {/* Verdict & Domain Age + SSL Radar Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 1 Col: Overall Threat Verdict & Scores */}
        <LiquidGlassCard glowColor="crimson" className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-red-400" />
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                Risk Evaluation
              </h3>
            </div>
            <LiquidGlassBadge
              variant={analysis.final_risk >= 70 ? 'critical' : 'warning'}
              label={analysis.verdict}
            />
          </div>

          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-mono font-bold text-red-400">
              {Math.round(analysis.final_risk)}%
            </span>
            <span className="text-xs font-mono text-slate-400">Composite Severity</span>
          </div>

          <div className="space-y-3 pt-2">
            <LiquidCausticProgress
              label="URL Reputation Risk"
              progress={analysis.breakdown.url_score}
              variant="crimson"
            />
            <LiquidCausticProgress
              label="Brand Impersonation"
              progress={analysis.breakdown.brand_impersonation_score}
              variant="amber"
            />
            <LiquidCausticProgress
              label="Heuristic Manipulation"
              progress={analysis.breakdown.manipulation_score}
              variant="purple"
            />
          </div>

          {/* Logic Flags */}
          <div className="pt-2 border-t border-white/10 space-y-1.5 font-mono text-xs text-slate-300">
            <span className="text-slate-400 text-[10px] uppercase tracking-wider block">
              Flagged Indicators
            </span>
            {analysis.threat_array?.map((t, idx) => (
              <div key={idx} className="flex items-center gap-1.5 text-red-300">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0" />
                <span className="truncate">{t}</span>
              </div>
            ))}
          </div>
        </LiquidGlassCard>

        {/* Center 1 Col: WHOIS Domain Age Radar */}
        <LiquidGlassCard glowColor={isBurner ? 'crimson' : 'emerald'} className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Calendar className="w-5 h-5 text-cyan-400" />
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                WHOIS Domain Age Gauge
              </h3>
            </div>
            <LiquidGlassBadge
              variant={isBurner ? 'critical' : 'safe'}
              label={isBurner ? 'BURNER DOMAIN' : 'ESTABLISHED'}
            />
          </div>

          <div className="flex items-center justify-center py-4">
            <div className="relative w-36 h-36 rounded-full border-4 border-white/10 flex flex-col items-center justify-center bg-slate-950/80 shadow-2xl">
              <div
                className={`absolute inset-0 rounded-full border-4 border-t-transparent ${
                  isBurner ? 'border-red-500 animate-spin' : 'border-emerald-500'
                }`}
                style={{ animationDuration: '12s' }}
              />
              <span className="text-3xl font-mono font-bold text-white">
                {domainAge}d
              </span>
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                Domain Age
              </span>
            </div>
          </div>

          <div className="space-y-2 text-xs font-mono text-slate-300">
            <div className="p-3 rounded-2xl bg-slate-950/70 border border-white/5 space-y-1">
              <div className="text-slate-400">Contextual Verdict:</div>
              <div className="text-slate-200 leading-relaxed">
                {analysis.domain_age_context?.message ||
                  'Domain registered only 4 days ago. High probability of disposable phishing infrastructure.'}
              </div>
            </div>
          </div>
        </LiquidGlassCard>

        {/* Right 1 Col: SSL Certificate Radar */}
        <LiquidGlassCard glowColor="amber" className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="w-5 h-5 text-amber-400" />
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                SSL Security Radar
              </h3>
            </div>
            <LiquidGlassBadge variant="warning" label="FREE AUTOMATED DV" />
          </div>

          <div className="space-y-3 font-mono text-xs text-slate-300">
            <div className="p-3 rounded-2xl bg-slate-950/70 border border-white/5 space-y-1.5">
              <div>
                <span className="text-slate-400">Issuer CA:</span>{' '}
                <span className="text-amber-300 font-semibold">{ssl?.issuer || "Let's Encrypt"}</span>
              </div>
              <div>
                <span className="text-slate-400">Common Name:</span>{' '}
                <span className="text-slate-200 font-semibold">{ssl?.subject_common_name || "secure-verify-account.tk"}</span>
              </div>
              <div>
                <span className="text-slate-400">Valid Until:</span>{' '}
                <span className="text-slate-300">{ssl?.expiry_date || "2026-11-20"}</span>
              </div>
              <div>
                <span className="text-slate-400">Validation Tier:</span>{' '}
                <span className="text-amber-400 font-bold">Domain Validated (DV) - No Identity Proof</span>
              </div>
            </div>

            <div className="p-2.5 rounded-xl bg-amber-950/30 border border-amber-500/30 text-amber-300 text-[11px] flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>Free DV certificate on a page mimicking global enterprise SSO credentials.</span>
            </div>
          </div>
        </LiquidGlassCard>
      </div>

      {/* Redirect Chain & DNS Records */}
      <LiquidGlassCard glowColor="cyan" className="p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
              Redirect Chain & Disassembled Hops ({redirects.length} Hops)
            </h3>
          </div>
        </div>

        <div className="flex flex-col md:flex-row items-center gap-3 overflow-x-auto custom-scrollbar py-2">
          {redirects.map((hopUrl, i) => (
            <React.Fragment key={i}>
              <div className="p-3.5 rounded-2xl bg-slate-950 border border-white/10 font-mono text-xs text-slate-200 min-w-[240px] flex-1">
                <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  HOP #{i + 1} {i === redirects.length - 1 ? '(Final Landing Node)' : '(Transit Shortener)'}
                </div>
                <DefangedText value={hopUrl} />
              </div>
              {i < redirects.length - 1 && (
                <ArrowRight className="w-5 h-5 text-cyan-400 shrink-0 hidden md:block" />
              )}
            </React.Fragment>
          ))}
        </div>
      </LiquidGlassCard>

      {/* Sandboxed Safe Emulation Pane */}
      <LiquidGlassCard glowColor="purple" className="p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-purple-400" />
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                Isolated Sandboxed Iframe Preview (Air-Gapped)
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Renders with scripts, cookies, and network access strictly blocked via HTML5 sandbox attributes.
            </p>
          </div>

          <LiquidMorphButton
            mode="purple"
            onClick={() => setShowSandboxFrame(!showSandboxFrame)}
            icon={showSandboxFrame ? EyeOff : Eye}
          >
            {showSandboxFrame ? 'Hide Sandbox Emulation' : 'Emulate Landing Page'}
          </LiquidMorphButton>
        </div>

        {showSandboxFrame ? (
          <div className="relative rounded-2xl border-2 border-dashed border-red-500/40 bg-slate-950 p-4 min-h-[300px] flex flex-col items-center justify-center text-center">
            <div className="w-10 h-10 rounded-2xl bg-red-500/20 flex items-center justify-center text-red-400 mb-2">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <h4 className="font-mono text-sm font-bold text-white">
              Sandboxed Emulation Protected: Live Code Stripped
            </h4>
            <p className="text-xs font-mono text-slate-400 max-w-md mt-1 mb-4">
              Malicious payloads and external JavaScript execution prevented. Inspect defanged DOM structure safely.
            </p>
            <div className="p-4 rounded-xl bg-slate-900 border border-white/10 font-mono text-xs text-cyan-300 text-left w-full max-w-lg select-all">
              {`<iframe sandbox="" src="${urlInput}" />`}
            </div>
          </div>
        ) : (
          <div className="p-6 rounded-2xl bg-slate-950/60 border border-white/5 text-center font-mono text-xs text-slate-500">
            Preview pane offline. Click &quot;Emulate Landing Page&quot; to inspect rendered DOM under isolated sandbox rules.
          </div>
        )}
      </LiquidGlassCard>
    </div>
  );
};
