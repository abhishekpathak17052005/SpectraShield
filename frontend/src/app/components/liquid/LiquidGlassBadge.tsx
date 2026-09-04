import React from 'react';
import { LucideIcon } from 'lucide-react';

interface LiquidGlassBadgeProps {
  label: string;
  variant?: 'safe' | 'warning' | 'critical' | 'forensics' | 'campaign';
  icon?: LucideIcon;
  className?: string;
  size?: 'sm' | 'md';
}

export const LiquidGlassBadge: React.FC<LiquidGlassBadgeProps> = ({
  label,
  variant = 'forensics',
  icon: Icon,
  className = '',
  size = 'md',
}) => {
  const styles = {
    safe: {
      bg: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
      dot: 'bg-emerald-400 shadow-[0_0_10px_2px_rgba(16,185,129,0.6)]',
    },
    warning: {
      bg: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
      dot: 'bg-amber-400 shadow-[0_0_10px_2px_rgba(245,158,11,0.6)]',
    },
    critical: {
      bg: 'bg-red-500/10 text-red-300 border-red-500/30',
      dot: 'bg-red-400 shadow-[0_0_10px_2px_rgba(239,68,68,0.6)]',
    },
    forensics: {
      bg: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
      dot: 'bg-cyan-400 shadow-[0_0_10px_2px_rgba(6,182,212,0.6)]',
    },
    campaign: {
      bg: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
      dot: 'bg-purple-400 shadow-[0_0_10px_2px_rgba(168,85,247,0.6)]',
    },
  };

  const current = styles[variant];
  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-3 py-1 text-xs';

  return (
    <div
      className={`inline-flex items-center gap-1.5 rounded-full border backdrop-blur-xl font-mono shadow-sm select-none ${sizeClass} ${current.bg} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full animate-pulse ${current.dot}`} />
      {Icon && <Icon className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />}
      <span>{label}</span>
    </div>
  );
};
