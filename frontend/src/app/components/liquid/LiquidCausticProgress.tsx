import React from 'react';

interface LiquidCausticProgressProps {
  progress: number; // 0 to 100
  label: string;
  valueSuffix?: string;
  variant?: 'cyan' | 'crimson' | 'amber' | 'emerald' | 'purple';
  className?: string;
}

export const LiquidCausticProgress: React.FC<LiquidCausticProgressProps> = ({
  progress,
  label,
  valueSuffix = '%',
  variant = 'cyan',
  className = '',
}) => {
  const clamped = Math.min(100, Math.max(0, progress));

  const variantGradients = {
    cyan: 'from-cyan-500 to-blue-600',
    crimson: 'from-red-500 to-rose-600',
    amber: 'from-amber-500 to-yellow-600',
    emerald: 'from-emerald-500 to-teal-600',
    purple: 'from-purple-500 to-indigo-600',
  };

  const textColors = {
    cyan: 'text-cyan-400',
    crimson: 'text-red-400',
    amber: 'text-amber-400',
    emerald: 'text-emerald-400',
    purple: 'text-purple-400',
  };

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div className="flex items-center justify-between text-xs font-mono">
        <span className="text-slate-300">{label}</span>
        <span className={`font-bold ${textColors[variant]}`}>
          {clamped.toFixed(1)}{valueSuffix}
        </span>
      </div>

      <div className="relative h-2.5 w-full overflow-hidden rounded-full border border-white/10 bg-slate-900/80 backdrop-blur-md p-0.5 shadow-inner">
        <div
          className={`relative h-full rounded-full bg-gradient-to-r ${variantGradients[variant]} transition-all duration-700 ease-liquid-apple`}
          style={{ width: `${clamped}%` }}
        >
          {/* Specular Ray Sheen */}
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/35 to-transparent skew-x-12 animate-liquid-sheen" />

          {/* Glowing Leading Head Droplet */}
          <div className="absolute right-0 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-white shadow-[0_0_8px_2px_rgba(255,255,255,0.8)]" />
        </div>
      </div>
    </div>
  );
};
