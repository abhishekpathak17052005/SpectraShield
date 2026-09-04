import React, { useRef, useState, useEffect } from 'react';

export interface SegmentOption {
  id: string;
  label: string;
  icon?: React.ReactNode;
  badge?: string | number;
}

interface LiquidSegmentedControlProps {
  options: SegmentOption[];
  value: string;
  onChange: (id: string) => void;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const LiquidSegmentedControl: React.FC<LiquidSegmentedControlProps> = ({
  options,
  value,
  onChange,
  className = '',
  size = 'md',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [indicatorStyle, setIndicatorStyle] = useState({ left: 0, width: 0, opacity: 0 });

  const sizeClasses = {
    sm: 'p-0.5 text-xs gap-0.5',
    md: 'p-1 text-xs md:text-sm gap-1',
    lg: 'p-1.5 text-sm md:text-base gap-1.5',
  };

  useEffect(() => {
    if (!containerRef.current || !value) return;
    const activeEl = containerRef.current.querySelector<HTMLElement>(`[data-liquid-value="${value}"]`);
    if (activeEl) {
      setIndicatorStyle({
        left: activeEl.offsetLeft,
        width: activeEl.offsetWidth,
        opacity: 1,
      });
    }
  }, [value, options]);

  return (
    <div
      ref={containerRef}
      className={`relative inline-flex items-center rounded-2xl backdrop-blur-2xl bg-slate-900/60 dark:bg-slate-900/80 border border-white/15 dark:border-white/10 shadow-inner ${sizeClasses[size]} ${className}`}
    >
      {/* Sliding Liquid Glass Droplet Indicator */}
      <div
        className="absolute top-1 bottom-1 rounded-xl transition-all duration-500 ease-liquid-apple pointer-events-none overflow-hidden"
        style={{
          left: `${indicatorStyle.left}px`,
          width: `${indicatorStyle.width}px`,
          opacity: indicatorStyle.opacity,
        }}
      >
        {/* Specular Droplet Rim & Caustic Backdrop */}
        <div className="absolute inset-0 bg-white/20 dark:bg-white/10 backdrop-blur-3xl rounded-xl border border-white/30 shadow-lg shadow-cyan-950/40" />
        
        {/* Specular Top Glare */}
        <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-300/90 to-transparent" />
        
        {/* Diagonal Specular Sheen Wave */}
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/25 to-transparent -skew-x-12 animate-liquid-sheen opacity-40" />
      </div>

      {/* Segment Option Buttons */}
      {options.map((opt) => {
        const isSelected = opt.id === value;
        return (
          <button
            key={opt.id}
            type="button"
            data-liquid-value={opt.id}
            onClick={() => onChange(opt.id)}
            className={`relative z-10 px-3.5 py-1.5 rounded-xl font-medium transition-colors duration-300 select-none flex items-center gap-2 ${
              isSelected
                ? 'text-cyan-400 dark:text-cyan-300 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {opt.icon && <span className="transition-transform duration-300">{opt.icon}</span>}
            <span>{opt.label}</span>
            {opt.badge !== undefined && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                {opt.badge}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
};
