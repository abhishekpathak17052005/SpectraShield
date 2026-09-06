import React from 'react';
import {
  X,
  User,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  QrCode,
  LogOut,
  Sparkles,
  CheckCircle2,
  XCircle,
  Clock,
  Fingerprint,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { EnterpriseRole } from '../../types';

export const UserProfileDrawer: React.FC = () => {
  const {
    user,
    role,
    permissions,
    isProfileDrawerOpen,
    closeProfileDrawer,
    openLoginModal,
    switchRole,
    logout,
  } = useAuth();

  if (!isProfileDrawerOpen) return null;

  const roleConfig: Record<EnterpriseRole, { name: string; badge: string; color: string; border: string; glow: string }> = {
    SUPER_ADMIN: {
      name: 'Chief Information Security Officer',
      badge: 'SUPER_ADMIN',
      color: 'bg-amber-500/20 text-amber-300',
      border: 'border-amber-500/40',
      glow: 'shadow-[0_0_20px_rgba(245,158,11,0.25)]',
    },
    FORENSIC_ANALYST: {
      name: 'Lead Forensic Investigator',
      badge: 'FORENSIC_ANALYST',
      color: 'bg-emerald-500/20 text-emerald-300',
      border: 'border-emerald-500/40',
      glow: 'shadow-[0_0_20px_rgba(16,185,129,0.25)]',
    },
    SOC_OPERATOR: {
      name: 'SOC Tier-1 Monitoring Operator',
      badge: 'SOC_OPERATOR',
      color: 'bg-cyan-500/20 text-cyan-300',
      border: 'border-cyan-500/40',
      glow: 'shadow-[0_0_20px_rgba(6,182,212,0.25)]',
    },
    AUDITOR: {
      name: 'Compliance & Regulatory Auditor',
      badge: 'AUDITOR',
      color: 'bg-violet-500/20 text-violet-300',
      border: 'border-violet-500/40',
      glow: 'shadow-[0_0_20px_rgba(139,92,246,0.25)]',
    },
  };

  const currentRoleCfg = roleConfig[role] || roleConfig.FORENSIC_ANALYST;

  const allSystemPermissions = [
    { key: 'cases:read', label: 'View Forensic Dossiers & Cases' },
    { key: 'cases:write', label: 'Create & Annotate Cases' },
    { key: 'cases:assign', label: 'Assign Lead Investigators' },
    { key: 'cases:status', label: 'Transition Triage Status' },
    { key: 'analysis:execute', label: 'Execute Deep Packet Analysis' },
    { key: 'sandbox:execute', label: 'Run Link Sandbox & Emulation' },
    { key: 'reports:generate', label: 'Export Court PDF & STIX Dossiers' },
    { key: 'audit:read', label: 'Audit ISO 27037 Blockchain Ledger' },
    { key: 'users:manage', label: 'Enterprise RBAC Directory Administration' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Liquid Backdrop Blur */}
      <div
        onClick={closeProfileDrawer}
        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300 animate-fade-in"
      />

      {/* Slide-over Drawer Card */}
      <div className="relative w-full max-w-md h-full bg-slate-950/95 border-l border-white/15 shadow-2xl backdrop-blur-3xl p-6 flex flex-col z-10 animate-fade-in overflow-y-auto">
        {/* Top bar */}
        <div className="flex items-center justify-between pb-4 border-b border-white/10">
          <div className="flex items-center gap-2">
            <Fingerprint className="w-5 h-5 text-cyan-400" />
            <span className="font-bold text-white text-base">Analyst Dossier</span>
          </div>
          <button
            onClick={closeProfileDrawer}
            className="p-1.5 rounded-xl bg-slate-900 border border-white/10 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* User Card */}
        <div className={`mt-6 p-5 rounded-3xl border ${currentRoleCfg.border} bg-slate-900/80 ${currentRoleCfg.glow} relative overflow-hidden`}>
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-cyan-500/30 to-blue-500/30 border border-cyan-400/40 flex items-center justify-center text-xl font-bold text-white font-mono shadow-inner">
              {user?.name ? user.name.charAt(0) : 'S'}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="font-bold text-white text-base">{user?.name || 'Forensic Specialist'}</h4>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">{user?.email || 'analyst@spectrashield.soc'}</p>
              <div className="mt-2 flex items-center gap-2">
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${currentRoleCfg.color} ${currentRoleCfg.border}`}>
                  {currentRoleCfg.badge}
                </span>
                {user?.is_demo_fallback && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-blue-500/20 text-blue-300 border border-blue-500/30">
                    DEMO SIMULATION
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* 2FA Security Status Card */}
        <div className="mt-4 p-4 rounded-2xl bg-slate-900/60 border border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/20 border border-cyan-400/30 flex items-center justify-center">
              <KeyRound className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <div className="text-xs font-semibold text-white">Two-Factor Auth (RFC 6238)</div>
              <div className="text-[11px] font-mono text-slate-400">
                {user?.totp_enabled ? 'Active (Google Authenticator)' : 'Inactive (Recommended)'}
              </div>
            </div>
          </div>
          <button
            onClick={() => {
              closeProfileDrawer();
              openLoginModal();
            }}
            className="px-2.5 py-1.5 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-xs font-mono text-cyan-300 hover:bg-cyan-500/30 transition-all"
          >
            {user?.totp_enabled ? 'Manage' : 'Setup 2FA'}
          </button>
        </div>

        {/* Permissions Checklist */}
        <div className="mt-6 flex-1">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              RBAC Authorization Matrix
            </span>
            <span className="text-[10px] font-mono text-cyan-400">
              {permissions.length} Active Grants
            </span>
          </div>

          <div className="space-y-2">
            {allSystemPermissions.map((p) => {
              const isGranted = role === 'SUPER_ADMIN' || permissions.includes(p.key);
              return (
                <div
                  key={p.key}
                  className={`p-2.5 rounded-xl border flex items-center justify-between text-xs transition-colors ${
                    isGranted
                      ? 'bg-slate-900/70 border-white/10 text-slate-200'
                      : 'bg-slate-950/40 border-white/5 text-slate-500'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    {isGranted ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-slate-600 shrink-0" />
                    )}
                    <span>{p.label}</span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">{p.key}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Quick Role Switcher Buttons */}
        <div className="mt-6 pt-4 border-t border-white/10">
          <div className="text-xs font-mono text-slate-400 mb-2.5 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Fast Role Simulator (Demo Mode)</span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {(['SUPER_ADMIN', 'FORENSIC_ANALYST', 'SOC_OPERATOR', 'AUDITOR'] as EnterpriseRole[]).map((r) => (
              <button
                key={r}
                onClick={() => switchRole(r)}
                className={`py-2 px-2.5 rounded-xl text-[11px] font-mono font-medium border transition-all text-left truncate ${
                  role === r
                    ? 'bg-cyan-500/20 border-cyan-400 text-cyan-300 font-bold shadow-sm'
                    : 'bg-slate-900/60 border-white/10 text-slate-400 hover:text-white'
                }`}
              >
                {r.replace('_', ' ')}
              </button>
            ))}
          </div>
        </div>

        {/* Actions footer */}
        <div className="mt-6 pt-4 border-t border-white/10 flex gap-2">
          <button
            onClick={() => {
              closeProfileDrawer();
              openLoginModal();
            }}
            className="flex-1 py-2.5 rounded-2xl bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 text-xs font-semibold transition-all flex items-center justify-center gap-2 cursor-pointer"
          >
            <User className="w-3.5 h-3.5" />
            <span>Switch Account</span>
          </button>
          <button
            onClick={() => {
              logout();
              closeProfileDrawer();
            }}
            className="py-2.5 px-3 rounded-2xl bg-rose-500/15 border border-rose-500/30 text-rose-300 hover:bg-rose-500/25 text-xs font-semibold transition-all flex items-center justify-center gap-1.5 cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>
        </div>
      </div>
    </div>
  );
};
