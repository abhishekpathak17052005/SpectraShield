import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface DefangedTextProps {
  value: string;
  className?: string;
  showIcon?: boolean;
}

export const DefangedText: React.FC<DefangedTextProps> = ({
  value,
  className = '',
  showIcon = true,
}) => {
  const [copied, setCopied] = useState(false);

  // Defang if not already defanged
  const defanged = value
    .replace(/\./g, '[.]')
    .replace(/http/gi, 'hxxp')
    .replace(/@/g, '[@]');

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(defanged);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  return (
    <span
      onClick={handleCopy}
      title="Click to copy defanged IOC"
      className={`inline-flex items-center gap-1.5 font-mono text-cyan-300 hover:text-cyan-200 cursor-pointer transition-colors px-1.5 py-0.5 rounded bg-cyan-950/30 hover:bg-cyan-900/40 border border-cyan-800/40 select-all text-xs ${className}`}
    >
      <span>{defanged}</span>
      {showIcon && (
        copied ? (
          <Check className="w-3 h-3 text-emerald-400 shrink-0" />
        ) : (
          <Copy className="w-3 h-3 opacity-60 hover:opacity-100 shrink-0" />
        )
      )}
    </span>
  );
};
