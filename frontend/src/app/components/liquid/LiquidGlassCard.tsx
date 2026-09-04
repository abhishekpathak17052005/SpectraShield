import React from 'react';

interface LiquidGlassCardProps {
  children: React.ReactNode;
  glowColor?: 'cyan' | 'crimson' | 'purple' | 'amber' | 'emerald' | 'none';
  className?: string;
  onClick?: () => void;
  hoverEffect?: boolean;
}

export const LiquidGlassCard: React.FC<LiquidGlassCardProps> = ({
  children,
  glowColor = 'cyan',
  className = '',
  onClick,
  hoverEffect = true,
}) => {
  const glowGradients = {
    cyan: 'from-cyan-500/15 via-sky-500/5 to-transparent',
    crimson: 'from-red-500/15 via-rose-500/5 to-transparent',
    purple: 'from-purple-500/15 via-violet-500/5 to-transparent',
    amber: 'from-amber-500/15 via-yellow-500/5 to-transparent',
    emerald: 'from-emerald-500/15 via-teal-500/5 to-transparent',
    none: 'from-transparent to-transparent',
  };

  return (
    <div
      onClick={onClick}
      className={`relative overflow-hidden rounded-3xl border border-white/10 dark:border-white/10 bg-slate-900/60 dark:bg-slate-950/70 backdrop-blur-2xl backdrop-saturate-180 shadow-2xl p-5 md:p-6 transition-all duration-500 ${
        hoverEffect ? 'hover:border-white/20 hover:shadow-cyan-950/20' : ''
      } ${onClick ? 'cursor-pointer' : ''} ${className}`}
    >
      {/* Ambient Internal Caustic Flare */}
      {glowColor !== 'none' && (
        <div
          className={`absolute -top-24 -left-24 w-72 h-72 rounded-full bg-gradient-to-br ${glowGradients[glowColor]} blur-3xl pointer-events-none`}
        />
      )}

      {/* Top Specular Rim */}
      <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-white/25 to-transparent" />

      {/* Bottom Subtle Occlusion */}
      <div className="absolute bottom-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-black/40 to-transparent" />

      {/* Content */}
      <div className="relative z-10">{children}</div>
    </div>
  );
};
