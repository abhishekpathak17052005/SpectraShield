import React, { useState } from 'react';
import { QrCode, AlertTriangle, ShieldAlert, Copy, Check, ExternalLink, Eye } from 'lucide-react';
import { QuishingEvidence } from '../../types';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';

interface QuishingPreviewCardProps {
  quishing: QuishingEvidence;
  onInspectUrl?: (url: string) => void;
}

export const QuishingPreviewCard: React.FC<QuishingPreviewCardProps> = ({
  quishing,
  onInspectUrl,
}) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  if (!quishing || !quishing.has_qr_code || quishing.decoded_payloads.length === 0) {
    return null;
  }

  const isMalicious = quishing.risk_level === 'malicious';

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <LiquidGlassCard
      glowColor={isMalicious ? 'crimson' : 'amber'}
      className="p-5 md:p-6 space-y-4 border border-red-500/40 bg-red-950/20 shadow-[0_0_30px_rgba(239,68,68,0.2)]"
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.3)] shrink-0">
            <QrCode className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                Quishing 2D Matrix Phishing Detected
              </h4>
              <LiquidGlassBadge
                variant={isMalicious ? 'critical' : 'warning'}
                label={isMalicious ? 'CRITICAL QUISHING' : 'SUSPICIOUS QR MATRIX'}
                size="sm"
              />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Source:{' '}
              <span className="font-mono text-cyan-400 font-semibold">
                {quishing.source_image_filename || 'Inline CID Image / Attachment'}
              </span>{' '}
              • {quishing.qr_count} QR symbol{quishing.qr_count > 1 ? 's' : ''} decoded
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-red-400 bg-red-500/10 px-3 py-1.5 rounded-xl border border-red-500/20">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          <span>EVASION TACTIC: Optical Text Filter Bypass</span>
        </div>
      </div>

      {/* Decoded Payloads List */}
      <div className="space-y-3">
        {quishing.decoded_payloads.map((payload, idx) => {
          const defanged = quishing.defanged_payloads[idx] || payload;
          const isCopied = copiedIndex === idx;

          return (
            <div
              key={idx}
              className="p-4 rounded-xl bg-slate-950/80 border border-red-500/30 space-y-2.5 transition-all hover:border-red-500/50"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                  Decoded Redirect Target #{idx + 1}:
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleCopy(defanged, idx)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-mono font-medium text-slate-300 hover:text-white bg-slate-900 border border-white/10 hover:border-white/20 transition-colors"
                    title="Copy defanged URL for safe reporting"
                  >
                    {isCopied ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3 text-cyan-400" />
                        <span>Copy Defanged</span>
                      </>
                    )}
                  </button>

                  {onInspectUrl && (
                    <button
                      type="button"
                      onClick={() => onInspectUrl(payload)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-mono font-medium text-cyan-300 hover:text-cyan-200 bg-cyan-950/60 border border-cyan-500/30 hover:border-cyan-500/60 transition-colors"
                      title="Load in Sandboxed Link Inspector"
                    >
                      <Eye className="w-3 h-3" />
                      <span>Inspect URL</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Defanged display box */}
              <div className="p-2.5 rounded-lg bg-red-950/30 border border-red-500/20 font-mono text-xs text-red-300 break-all select-all flex items-center justify-between">
                <span>{defanged}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Security Guidance Note */}
      <div className="p-3 rounded-xl bg-slate-900/40 border border-white/5 text-xs text-slate-400 flex items-start gap-2">
        <span className="font-mono text-cyan-400 font-bold shrink-0">ANALYST NOTE:</span>
        <span>
          Quishing (QR Phishing) lures victims to scan barcodes on secondary mobile devices, evading endpoint perimeter monitoring and DLP controls. Do not scan with unmanaged mobile hardware.
        </span>
      </div>
    </LiquidGlassCard>
  );
};
