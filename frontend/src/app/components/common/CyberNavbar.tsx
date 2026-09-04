import React, { useState, useEffect } from 'react';
import { ShieldAlert, Menu, X, Clock, ShieldCheck, Sparkles } from 'lucide-react';
import { LiquidSegmentedControl, SegmentOption } from '../liquid/LiquidSegmentedControl';
import { ThemeToggle } from './ThemeToggle';
import { checkBackendHealth } from '../../api';

interface CyberNavbarProps {
  activeView: string;
  onViewChange: (view: string) => void;
  caseCount?: number;
}

export const CyberNavbar: React.FC<CyberNavbarProps> = ({
  activeView,
  onViewChange,
  caseCount = 142,
}) => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isClosing, setIsClosing] = useState(false);
  const [currentTime, setCurrentTime] = useState('');
  const [isBackendLive, setIsBackendLive] = useState(true);

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 15);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().split(' ')[4] + ' UTC');
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const verifyHealth = async () => {
      const live = await checkBackendHealth();
      setIsBackendLive(live);
    };
    verifyHealth();
    const interval = setInterval(verifyHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const navOptions: SegmentOption[] = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'forensics', label: 'Forensic Ops', badge: '2.0' },
    { id: 'graph', label: 'Threat Graph' },
    { id: 'linkpreview', label: 'Link Sandbox' },
    { id: 'sentinel', label: 'Inboxes' },
    { id: 'popup', label: 'Extension' },
    { id: 'styleguide', label: 'Design System' },
  ];

  const closeMobileMenu = () => {
    setIsClosing(true);
    setTimeout(() => {
      setMobileOpen(false);
      setIsClosing(false);
    }, 280);
  };

  return (
    <>
      <header
        className={`fixed top-0 left-0 right-0 z-50 w-full h-16 transition-all duration-500 ease-liquid-apple ${
          isScrolled
            ? 'bg-slate-950/85 dark:bg-slate-950/90 backdrop-blur-3xl border-b border-white/10 shadow-2xl'
            : 'bg-slate-950/50 backdrop-blur-xl border-b border-white/5'
        }`}
      >
        <div className="max-w-7xl mx-auto h-full px-4 flex items-center justify-between gap-3">
          {/* Logo & Platform Title */}
          <div
            onClick={() => onViewChange('dashboard')}
            className="flex items-center gap-3 cursor-pointer select-none group"
          >
            <div className="w-9 h-9 rounded-2xl bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.3)] group-hover:scale-105 transition-transform duration-300">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-bold tracking-tight text-white text-base md:text-lg">
                  SpectraShield
                </span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                  2.0
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400 hidden sm:block">
                SIH PS: 26106 | Forensic Ops
              </p>
            </div>
          </div>

          {/* Desktop Liquid Segmented Control Switcher */}
          <div className="hidden lg:block">
            <LiquidSegmentedControl
              options={navOptions}
              value={activeView}
              onChange={onViewChange}
              size="md"
            />
          </div>

          {/* Right Status Controls & Mobile Menu Toggle */}
          <div className="flex items-center gap-2.5">
            {/* Live UTC SOC Clock */}
            <div className="hidden xl:flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900/60 border border-white/10 text-xs font-mono text-slate-300 shadow-sm">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>{currentTime}</span>
            </div>

            {/* Backend Connectivity Status */}
            <div
              title={isBackendLive ? 'Backend API connected (FastAPI port 8000)' : 'Running in Offline Mock Mode (Safe Preview)'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900/60 border border-white/10 text-xs font-mono select-none"
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  isBackendLive
                    ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]'
                    : 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.8)]'
                }`}
              />
              <span className="hidden sm:inline text-slate-300">
                {isBackendLive ? 'API Live' : 'Offline Mock'}
              </span>
            </div>

            {/* Theme Switcher */}
            <ThemeToggle />

            {/* Mobile Hamburger Button */}
            <button
              type="button"
              onClick={() => (mobileOpen ? closeMobileMenu() : setMobileOpen(true))}
              className="p-2 rounded-xl bg-slate-900/80 border border-white/10 text-slate-300 hover:text-white lg:hidden transition-colors"
              aria-label="Toggle navigation menu"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Floating Liquid Glass Island Drawer */}
      {mobileOpen && (
        <>
          <div
            onClick={closeMobileMenu}
            className={`fixed top-16 inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden ${
              isClosing ? 'animate-fade-out' : 'animate-fade-in'
            }`}
          />
          <div
            className={`fixed top-20 inset-x-4 max-w-md mx-auto z-50 lg:hidden rounded-3xl border border-white/15 bg-slate-900/95 backdrop-blur-3xl p-5 shadow-2xl space-y-2 ${
              isClosing ? 'animate-liquid-dismiss' : 'animate-liquid-pop'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider">
                Select Operations Module
              </div>
              <span className="text-[10px] font-mono text-slate-400">
                {currentTime}
              </span>
            </div>

            {navOptions.map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => {
                  onViewChange(opt.id);
                  closeMobileMenu();
                }}
                className={`w-full flex items-center justify-between px-4 py-3 rounded-2xl text-sm font-medium transition-all ${
                  activeView === opt.id
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold shadow-md'
                    : 'text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <span>{opt.label}</span>
                {opt.badge && (
                  <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-cyan-500/30 text-cyan-300">
                    {opt.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
        </>
      )}
    </>
  );
};
