import React, { useState, useEffect } from 'react';
import { ThemeProvider } from './components/ThemeProvider';
import { CyberNavbar } from './components/common/CyberNavbar';
import { DashboardView } from './components/views/DashboardView';
import { ForensicOpsView } from './components/views/ForensicOpsView';
import { ThreatGraphView } from './components/views/ThreatGraphView';
import { LinkPreviewView } from './components/views/LinkPreviewView';
import { SentinelInboxesView } from './components/views/SentinelInboxesView';
import { ExtensionPopupView } from './components/views/ExtensionPopupView';
import { StyleGuideView } from './components/views/StyleGuideView';

const AppContent: React.FC = () => {
  const [activeView, setActiveView] = useState<string>('dashboard');
  const [forensicPayload, setForensicPayload] = useState<string>('');

  useEffect(() => {
    document.title = 'SpectraShield 2.0 — Forensic Threat Intelligence';
  }, []);

  // Check URL parameters for direct deep linking
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const viewParam = params.get('view');
    const textParam = params.get('email_text');

    if (viewParam) {
      setActiveView(viewParam);
    }
    if (textParam) {
      setForensicPayload(textParam);
      setActiveView('forensics');
    }
  }, []);

  // Keyboard shortcut listener for SOC analysts (Keys 1-7)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Only if not typing inside an input or textarea
      if (['INPUT', 'TEXTAREA'].includes((e.target as HTMLElement)?.tagName)) return;

      const keyMap: Record<string, string> = {
        '1': 'dashboard',
        '2': 'forensics',
        '3': 'graph',
        '4': 'linkpreview',
        '5': 'sentinel',
        '6': 'popup',
        '7': 'styleguide',
      };

      if (keyMap[e.key]) {
        setActiveView(keyMap[e.key]);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleEscalateToForensics = (rawHeaders: string, emailBody: string) => {
    const combined = `${rawHeaders}\n\n${emailBody}`;
    setForensicPayload(combined);
    setActiveView('forensics');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleDashboardPivot = (emailText?: string) => {
    if (emailText) {
      setForensicPayload(emailText);
    }
    setActiveView('forensics');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans relative overflow-x-hidden selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Ambient Liquid Optical Caustic Flares (Background Depth) */}
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <div className="absolute top-[-10%] left-[15%] w-[600px] h-[600px] rounded-full bg-cyan-600/10 blur-[140px] animate-liquid-caustic" />
        <div className="absolute top-[35%] right-[-5%] w-[550px] h-[550px] rounded-full bg-purple-600/10 blur-[150px] animate-liquid-caustic" style={{ animationDelay: '3s' }} />
        <div className="absolute bottom-[-10%] left-[-5%] w-[600px] h-[600px] rounded-full bg-red-600/10 blur-[160px] animate-liquid-caustic" style={{ animationDelay: '5s' }} />
        {/* Subtle Cyber Grid Gridlines */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-70" />
      </div>

      {/* Top Fixed Liquid Cyber Navbar */}
      <CyberNavbar
        activeView={activeView}
        onViewChange={setActiveView}
      />

      {/* Master Content View Canvas */}
      <main className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 min-h-[calc(100vh-6rem)]">
        {activeView === 'dashboard' && (
          <DashboardView onNavigateToForensics={handleDashboardPivot} />
        )}
        {activeView === 'forensics' && (
          <ForensicOpsView initialText={forensicPayload} />
        )}
        {activeView === 'graph' && (
          <ThreatGraphView />
        )}
        {activeView === 'linkpreview' && (
          <LinkPreviewView />
        )}
        {activeView === 'sentinel' && (
          <SentinelInboxesView onEscalateToSOC={handleEscalateToForensics} />
        )}
        {activeView === 'popup' && (
          <ExtensionPopupView onEscalateToSOC={() => setActiveView('forensics')} />
        )}
        {activeView === 'styleguide' && (
          <StyleGuideView />
        )}
      </main>

      {/* Persistent Bottom SOC Status Ribbon */}
      <footer className="relative z-10 border-t border-white/10 bg-slate-950/80 backdrop-blur-2xl py-4 px-6 mt-12 text-xs font-mono text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2 text-center sm:text-left">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-slate-300 font-bold">SpectraShield 2.0 (Forensic Edition)</span>
            <span className="text-slate-500">|</span>
            <span>SIH PS ID: 26106</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400 text-[11px]">
            <span>ISO/IEC 27037 Digital Evidence</span>
            <span>•</span>
            <span>Keyboard Shortcuts: 1-7 to switch views</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default function App() {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem>
      <AppContent />
    </ThemeProvider>
  );
}