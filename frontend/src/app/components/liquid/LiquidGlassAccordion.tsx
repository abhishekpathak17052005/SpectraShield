import React from 'react';

interface LiquidGlassAccordionProps {
  isOpen: boolean;
  children: React.ReactNode;
  className?: string;
}

export const LiquidGlassAccordion: React.FC<LiquidGlassAccordionProps> = ({
  isOpen,
  children,
  className = '',
}) => {
  return (
    <div
      className={`grid transition-[grid-template-rows,opacity] duration-700 ease-liquid-apple ${
        isOpen ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0 pointer-events-none'
      } ${className}`}
    >
      <div className="overflow-hidden">
        <div className="rounded-2xl border border-white/10 bg-slate-900/60 backdrop-blur-2xl p-5 shadow-xl relative mt-2">
          {/* Top Specular Rim */}
          <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent" />
          {children}
        </div>
      </div>
    </div>
  );
};
