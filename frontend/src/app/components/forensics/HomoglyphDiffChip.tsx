import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, ArrowRight, Copy, Check, Binary, Sparkles, ExternalLink } from 'lucide-react';
import { HomoglyphAnalysis } from '../../types';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';
import { DefangedText } from '../common/DefangedText';

interface HomoglyphDiffChipProps {
  homoglyphData?: HomoglyphAnalysis | null;
  className?: string;
}

export const HomoglyphDiffChip: React.FC<HomoglyphDiffChipProps> = ({
  homoglyphData,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  if (!homoglyphData || (!homoglyphData.has_homoglyphs && !homoglyphData.target_brand)) {
    return null;
  }

  const {
    raw_domain,
    normalized_ascii,
    target_brand,
    target_domain,
    substituted_characters,
    is_punycode,
    punycode_ascii,
    verdict
  } = homoglyphData;

  const handleCopy = () => {
    navigator.clipboard.writeText(raw_domain);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <LiquidGlassCard glowColor="amber" className={`p-4 md:p-5 ${className}`}>
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-white/10">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/30 shadow-[0_0_15px_rgba(245,158,11,0.25)]">
            <AlertTriangle className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="font-mono text-xs md:text-sm font-bold text-white uppercase tracking-wider">
                Unicode Homoglyph & Typosquatting Analyzer
              </h4>
              <LiquidGlassBadge
                variant={homoglyphData.has_homoglyphs ? "critical" : "warning"}
                label={verdict}
                size="sm"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Detected deceptive character substitution designed to deceive visual scrutiny.
            </p>
          </div>
        </div>

        {punycode_ascii && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-300 font-mono text-[11px]">
            <Binary className="w-3.5 h-3.5 text-purple-400" />
            <span>Punycode: {punycode_ascii}</span>
          </div>
        )}
      </div>

      {/* Visual Domain Comparison Matrix */}
      <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3.5">
        {/* Deceptive Domain Card */}
        <div className="p-3.5 rounded-2xl bg-red-950/30 border border-red-500/30 backdrop-blur-md relative overflow-hidden">
          <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-red-400/40 to-transparent" />
          <div className="flex items-center justify-between text-[11px] font-mono text-red-300 mb-1.5">
            <span className="font-semibold uppercase tracking-wider">Deceptive Sender Domain</span>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white transition-colors"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copied ? "Copied" : "Copy"}</span>
            </button>
          </div>
          <div className="font-mono text-sm md:text-base font-bold text-red-200 tracking-wide break-all">
            <DefangedText text={raw_domain} />
          </div>
          {substituted_characters.length > 0 && (
            <p className="text-[10px] font-mono text-red-400/90 mt-1">
              ⚠️ Contains {substituted_characters.length} foreign script character{substituted_characters.length > 1 ? 's' : ''}
            </p>
          )}
        </div>

        {/* Legitimate Protected Target Brand */}
        <div className="p-3.5 rounded-2xl bg-emerald-950/20 border border-emerald-500/30 backdrop-blur-md relative overflow-hidden">
          <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-emerald-400/40 to-transparent" />
          <div className="flex items-center justify-between text-[11px] font-mono text-emerald-300 mb-1.5">
            <span className="font-semibold uppercase tracking-wider">Target Protected Brand</span>
            <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 text-[10px] font-bold">
              GENUINE ENTITY
            </span>
          </div>
          <div className="flex items-center gap-2 font-mono text-sm md:text-base font-bold text-emerald-200">
            <span>{target_domain || `${target_brand}.com`}</span>
            {target_brand && (
              <span className="text-xs font-normal text-emerald-400/70">
                ({target_brand.toUpperCase()})
              </span>
            )}
          </div>
          <p className="text-[10px] font-mono text-emerald-400/80 mt-1">
            Protected organizational brand identity
          </p>
        </div>
      </div>

      {/* Substituted Characters Breakdown Table */}
      {substituted_characters.length > 0 && (
        <div className="mt-4 pt-3 border-t border-white/5">
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-300 mb-2.5 font-semibold">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Character Code Point Substitutions:</span>
          </div>

          <div className="flex flex-wrap gap-2">
            {substituted_characters.map((char, i) => (
              <div
                key={i}
                className="px-3 py-2 rounded-xl bg-slate-950/70 border border-amber-500/40 backdrop-blur-xl flex items-center gap-2.5 shadow-sm text-xs font-mono"
              >
                <div className="w-7 h-7 rounded-lg bg-red-500/20 border border-red-500/40 flex items-center justify-center font-bold text-red-300 text-sm">
                  {char.raw_char}
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                <div className="w-7 h-7 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center font-bold text-emerald-300 text-sm">
                  {char.lookalike_char}
                </div>
                <div className="flex flex-col text-[10px] leading-tight">
                  <span className="text-amber-300 font-bold">{char.unicode_hex}</span>
                  <span className="text-slate-400">{char.script} Script</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </LiquidGlassCard>
  );
};
