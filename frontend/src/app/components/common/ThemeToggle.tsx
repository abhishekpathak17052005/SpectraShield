import React, { useState, useEffect } from 'react';
import { useTheme } from 'next-themes';
import { Sun, Moon, Laptop } from 'lucide-react';

export const ThemeToggle: React.FC<{ className?: string }> = ({ className = '' }) => {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div className={`w-8 h-8 rounded-full bg-slate-800/40 border border-white/10 ${className}`} />
    );
  }

  const cycleTheme = () => {
    if (theme === 'system') {
      setTheme('dark');
    } else if (theme === 'dark') {
      setTheme('light');
    } else {
      setTheme('system');
    }
  };

  const current = theme || 'system';

  return (
    <button
      type="button"
      onClick={cycleTheme}
      title={`Theme: ${current} (Click to toggle)`}
      aria-label={`Current theme: ${current}`}
      className={`relative p-2 rounded-full backdrop-blur-xl bg-slate-900/60 dark:bg-slate-800/60 hover:bg-slate-800/80 border border-white/15 text-slate-300 hover:text-white transition-all duration-300 shadow-md ${className}`}
    >
      {current === 'light' && <Sun className="w-4 h-4 text-amber-400" />}
      {current === 'dark' && <Moon className="w-4 h-4 text-cyan-400" />}
      {current === 'system' && <Laptop className="w-4 h-4 text-slate-400" />}
    </button>
  );
};
