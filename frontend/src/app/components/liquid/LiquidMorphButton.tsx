import React from 'react';
import { LucideIcon } from 'lucide-react';

interface LiquidMorphButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  mode?: 'cyan' | 'crimson' | 'purple' | 'emerald' | 'amber';
  isLoading?: boolean;
  disabled?: boolean;
  icon?: LucideIcon;
  className?: string;
  type?: 'button' | 'submit';
}

export const LiquidMorphButton: React.FC<LiquidMorphButtonProps> = ({
  children,
  onClick,
  mode = 'cyan',
  isLoading = false,
  disabled = false,
  icon: Icon,
  className = '',
  type = 'button',
}) => {
  const gradientStyles = {
    cyan: 'from-cyan-600 via-sky-500 to-blue-600 shadow-cyan-950/50',
    crimson: 'from-red-600 via-rose-500 to-red-700 shadow-red-950/50',
    purple: 'from-purple-600 via-violet-500 to-indigo-600 shadow-purple-950/50',
    emerald: 'from-emerald-600 via-teal-500 to-green-600 shadow-emerald-950/50',
    amber: 'from-amber-600 via-yellow-500 to-amber-700 shadow-amber-950/50',
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || isLoading}
      className={`group relative overflow-hidden rounded-2xl px-5 py-2.5 font-sans text-xs md:text-sm font-semibold text-white shadow-xl transition-all duration-500 ease-liquid-apple active:scale-[0.97] hover:shadow-2xl disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
    >
      {/* Fluid Gradient Base */}
      <div className={`absolute inset-0 bg-gradient-to-r ${gradientStyles[mode]} transition-all duration-500`} />

      {/* Internal Glass Reflection Matrix */}
      <div className="absolute inset-0 backdrop-blur-md bg-black/10" />

      {/* Specular Rim Edge Highlights */}
      <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-white/80 to-transparent" />
      <div className="absolute bottom-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-black/40 to-transparent" />

      {/* Continuous Dynamic Specular Refraction Wave */}
      <div className="absolute -inset-full bg-gradient-to-r from-transparent via-white/30 to-transparent skew-x-12 -translate-x-full group-hover:animate-liquid-sheen pointer-events-none" />

      {/* Button Content */}
      <div className="relative z-10 flex items-center justify-center gap-2">
        {isLoading ? (
          <div className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
        ) : (
          Icon && <Icon className="w-4 h-4 transition-transform duration-300 group-hover:scale-110" />
        )}
        <span className="tracking-wide">{children}</span>
      </div>
    </button>
  );
};
