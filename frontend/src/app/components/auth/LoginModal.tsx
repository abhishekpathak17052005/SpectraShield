import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Mail,
  KeyRound,
  QrCode,
  X,
  Sparkles,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  UserCheck,
  Eye,
  EyeOff,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { EnterpriseRole } from '../../types';
import { setup2FA } from '../../api';

export const LoginModal: React.FC = () => {
  const {
    isLoginModalOpen,
    closeLoginModal,
    login,
    verify2FACode,
    switchRole,
    role: currentRole,
  } = useAuth();

  const [activeTab, setActiveTab] = useState<'credentials' | 'simulate' | '2fa_setup'>('credentials');
  const [email, setEmail] = useState('analyst@spectrashield.soc');
  const [password, setPassword] = useState('Analyst@Spectra2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // 2FA Challenge state
  const [requires2FA, setRequires2FA] = useState(false);
  const [tempToken, setTempToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState(['', '', '', '', '', '']);

  // 2FA Setup state
  const [setupData, setSetupData] = useState<{
    secret: string;
    qr_code_base64: string;
    manual_entry_key: string;
  } | null>(null);

  if (!isLoginModalOpen) return null;

  const handleOtpChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return;
    const newCode = [...totpCode];
    newCode[index] = value.slice(-1);
    setTotpCode(newCode);

    // Auto-advance to next slot
    if (value && index < 5) {
      const nextInput = document.getElementById(`otp-input-${index + 1}`);
      nextInput?.focus();
    }
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !totpCode[index] && index > 0) {
      const prevInput = document.getElementById(`otp-input-${index - 1}`);
      prevInput?.focus();
    }
  };

  const handleOtpPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (!pasted) return;
    const newCode = [...totpCode];
    for (let i = 0; i < 6; i++) {
      newCode[i] = pasted[i] || '';
    }
    setTotpCode(newCode);
    const lastFilled = Math.min(pasted.length, 5);
    document.getElementById(`otp-input-${lastFilled}`)?.focus();
  };

  const handleSubmitLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);

    try {
      const res = await login(email, password);
      if (res.requires_2fa && res.temp_token) {
        setRequires2FA(true);
        setTempToken(res.temp_token);
        setSuccessMsg("Primary password verified. Enter 6-digit TOTP code.");
      } else if (res.status === "SUCCESS") {
        setSuccessMsg("Authenticated successfully.");
        setTimeout(() => closeLoginModal(), 400);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to authenticate.");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async () => {
    const fullCode = totpCode.join('');
    if (fullCode.length !== 6) {
      setErrorMsg("Please enter all 6 digits.");
      return;
    }

    setErrorMsg(null);
    setLoading(true);
    try {
      if (activeTab === '2fa_setup' && setupData) {
        await verify2FACode(fullCode, setupData.secret);
        setSuccessMsg("2FA successfully enabled on your account!");
        setTimeout(() => {
          setActiveTab('credentials');
          closeLoginModal();
        }, 800);
      } else {
        await verify2FACode(fullCode, undefined, tempToken || undefined);
        setSuccessMsg("2FA Verification confirmed!");
        setTimeout(() => closeLoginModal(), 400);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Invalid 6-digit code. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleStart2FASetup = async () => {
    setErrorMsg(null);
    setLoading(true);
    try {
      const data = await setup2FA();
      setSetupData(data);
      setActiveTab('2fa_setup');
      setTotpCode(['', '', '', '', '', '']);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to initiate 2FA setup.");
    } finally {
      setLoading(false);
    }
  };

  const rolesList: { role: EnterpriseRole; title: string; color: string; desc: string; badge: string }[] = [
    {
      role: 'SUPER_ADMIN',
      title: 'Chief InfoSec Officer',
      color: 'from-amber-500/20 to-orange-500/20 border-amber-500/40 text-amber-300',
      badge: 'Tier 1 - Full Authority',
      desc: 'Complete read/write permissions, case assignments, policy changes, and identity management.'
    },
    {
      role: 'FORENSIC_ANALYST',
      title: 'Lead Forensic Investigator',
      color: 'from-emerald-500/20 to-teal-500/20 border-emerald-500/40 text-emerald-300',
      badge: 'Tier 2 - Forensic Core',
      desc: 'Deep packet triage, case notes, email header forensics, sandbox execution, and dossier generation.'
    },
    {
      role: 'SOC_OPERATOR',
      title: 'Tier-1 SOC Operator',
      color: 'from-cyan-500/20 to-blue-500/20 border-cyan-500/40 text-cyan-300',
      badge: 'Tier 3 - Threat Monitor',
      desc: 'Real-time telemetry monitoring, email scanning, and alert triage. Cannot modify case lifecycle.'
    },
    {
      role: 'AUDITOR',
      title: 'Compliance & Regulatory Auditor',
      color: 'from-violet-500/20 to-purple-500/20 border-violet-500/40 text-violet-300',
      badge: 'Tier 4 - Non-Repudiation',
      desc: 'Read-only access to cryptographic audit ledgers, chain-of-custody certificates, and user directory.'
    }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Liquid Backdrop Blur */}
      <div
        onClick={closeLoginModal}
        className="fixed inset-0 bg-black/75 backdrop-blur-md transition-opacity duration-300 animate-fade-in"
      />

      {/* Liquid Glass Modal Card */}
      <div className="relative w-full max-w-xl rounded-3xl border border-white/15 bg-slate-950/90 backdrop-blur-3xl shadow-[0_0_60px_rgba(6,182,212,0.18)] p-6 md:p-8 z-10 animate-liquid-pop overflow-hidden">
        {/* Specular Radial Refraction */}
        <div className="absolute -top-32 -right-32 w-64 h-64 rounded-full bg-cyan-500/15 blur-3xl pointer-events-none" />
        <div className="absolute -bottom-32 -left-32 w-64 h-64 rounded-full bg-blue-600/15 blur-3xl pointer-events-none" />

        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.3)]">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-white tracking-tight">Enterprise Identity</h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  SEC-02
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">4-Tier RBAC & RFC 6238 2FA</p>
            </div>
          </div>
          <button
            onClick={closeLoginModal}
            className="p-2 rounded-xl bg-slate-900/80 border border-white/10 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Selection */}
        <div className="flex rounded-2xl bg-slate-900/90 border border-white/10 p-1 mb-6">
          <button
            type="button"
            onClick={() => {
              setActiveTab('credentials');
              setRequires2FA(false);
            }}
            className={`flex-1 py-2 px-3 rounded-xl text-xs font-semibold transition-all flex items-center justify-center gap-1.5 ${
              activeTab === 'credentials'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>Credentials</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('simulate')}
            className={`flex-1 py-2 px-3 rounded-xl text-xs font-semibold transition-all flex items-center justify-center gap-1.5 ${
              activeTab === 'simulate'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Role Switcher (Demo)</span>
          </button>
        </div>

        {/* Feedback Messages */}
        {errorMsg && (
          <div className="mb-4 p-3 rounded-2xl bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}
        {successMsg && (
          <div className="mb-4 p-3 rounded-2xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* TAB 1: Enterprise Credentials & 2FA Challenge */}
        {activeTab === 'credentials' && (
          <div>
            {!requires2FA ? (
              <form onSubmit={handleSubmitLogin} className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5">Enterprise Email</label>
                  <div className="relative">
                    <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="analyst@spectrashield.soc"
                      className="w-full pl-10 pr-4 py-2.5 rounded-2xl bg-slate-900/80 border border-white/10 text-white text-sm focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 font-mono"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5">Password (Bcrypt Work Factor 12)</label>
                  <div className="relative">
                    <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      className="w-full pl-10 pr-10 py-2.5 rounded-2xl bg-slate-900/80 border border-white/10 text-white text-sm focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-3 rounded-2xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-sm shadow-[0_0_25px_rgba(6,182,212,0.4)] transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    {loading ? (
                      <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    ) : (
                      <>
                        <span>Authenticate Session</span>
                        <ArrowRight className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </div>

                <div className="pt-3 border-t border-white/10 flex items-center justify-between text-xs text-slate-400">
                  <span>Need to enable 2FA?</span>
                  <button
                    type="button"
                    onClick={handleStart2FASetup}
                    className="text-cyan-400 hover:underline flex items-center gap-1 font-mono"
                  >
                    <QrCode className="w-3.5 h-3.5" />
                    <span>Setup Google Authenticator</span>
                  </button>
                </div>
              </form>
            ) : (
              /* 2FA OTP Challenge Screen */
              <div className="space-y-5 text-center">
                <div className="w-12 h-12 rounded-2xl bg-cyan-500/20 border border-cyan-400/40 mx-auto flex items-center justify-center">
                  <KeyRound className="w-6 h-6 text-cyan-400" />
                </div>
                <div>
                  <h4 className="text-base font-bold text-white">Two-Factor Authentication</h4>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Enter the 6-digit verification code from Google Authenticator / Authy
                  </p>
                </div>

                {/* 6 Digit Input Slots */}
                <div className="flex justify-center gap-2 md:gap-3 py-2">
                  {totpCode.map((digit, idx) => (
                    <input
                      key={idx}
                      id={`otp-input-${idx}`}
                      type="text"
                      maxLength={1}
                      inputMode="numeric"
                      value={digit}
                      onChange={(e) => handleOtpChange(idx, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                      onPaste={handleOtpPaste}
                      className="w-11 h-13 md:w-12 md:h-14 text-center text-xl font-mono font-bold rounded-2xl bg-slate-900/90 border border-cyan-500/40 text-white focus:outline-none focus:border-cyan-400 focus:ring-4 focus:ring-cyan-500/30 transition-all shadow-inner"
                    />
                  ))}
                </div>

                <button
                  type="button"
                  onClick={handleVerifyOtp}
                  disabled={loading || totpCode.join('').length !== 6}
                  className="w-full py-3 rounded-2xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-white font-semibold text-sm shadow-[0_0_25px_rgba(16,185,129,0.4)] transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  {loading ? (
                    <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <>
                      <ShieldCheck className="w-4 h-4" />
                      <span>Verify & Complete Login</span>
                    </>
                  )}
                </button>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: 1-Click Role Simulation */}
        {activeTab === 'simulate' && (
          <div className="space-y-3">
            <p className="text-xs text-slate-400 font-mono mb-2">
              Select an enterprise role below to simulate credentials and test RBAC route guards instantly:
            </p>

            <div className="grid grid-cols-1 gap-2.5 max-h-[380px] overflow-y-auto pr-1">
              {rolesList.map((r) => {
                const isActive = currentRole === r.role;
                return (
                  <div
                    key={r.role}
                    onClick={() => {
                      switchRole(r.role);
                      setSuccessMsg(`Simulated ${r.role} identity`);
                      setTimeout(() => closeLoginModal(), 400);
                    }}
                    className={`p-3.5 rounded-2xl border bg-gradient-to-r ${r.color} cursor-pointer transition-all duration-300 hover:scale-[1.01] flex items-start justify-between gap-3 ${
                      isActive ? 'ring-2 ring-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.3)]' : 'hover:border-white/30'
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-sm text-white">{r.title}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-black/40 border border-white/10">
                          {r.role}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 mt-1">{r.desc}</p>
                      <span className="inline-block mt-2 text-[10px] font-mono text-cyan-300">
                        {r.badge}
                      </span>
                    </div>

                    <div className="pt-1">
                      {isActive ? (
                        <div className="w-6 h-6 rounded-full bg-emerald-500/20 border border-emerald-400 flex items-center justify-center">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        </div>
                      ) : (
                        <div className="px-2.5 py-1 rounded-xl bg-slate-900/60 border border-white/15 text-[11px] font-mono text-slate-300 hover:text-white">
                          Switch
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* TAB 3: 2FA QR Code Setup */}
        {activeTab === '2fa_setup' && setupData && (
          <div className="space-y-4 text-center">
            <div className="w-10 h-10 rounded-2xl bg-cyan-500/20 border border-cyan-400/40 mx-auto flex items-center justify-center">
              <QrCode className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h4 className="text-base font-bold text-white">Scan QR Code</h4>
              <p className="text-xs text-slate-400 font-mono mt-1">
                Scan with Google Authenticator or enter manual key
              </p>
            </div>

            {/* QR Code Display */}
            <div className="inline-block p-3 rounded-2xl bg-white shadow-xl mx-auto">
              <img
                src={setupData.qr_code_base64}
                alt="2FA QR Code"
                className="w-40 h-40 object-contain"
              />
            </div>

            {/* Secret key */}
            <div className="px-3 py-2 rounded-xl bg-slate-900/90 border border-white/10 font-mono text-xs text-cyan-300 select-all">
              Key: {setupData.manual_entry_key}
            </div>

            {/* Verification OTP input */}
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-2">
                Enter generated 6-digit code to activate:
              </label>
              <div className="flex justify-center gap-2 py-1">
                {totpCode.map((digit, idx) => (
                  <input
                    key={idx}
                    id={`otp-input-${idx}`}
                    type="text"
                    maxLength={1}
                    inputMode="numeric"
                    value={digit}
                    onChange={(e) => handleOtpChange(idx, e.target.value)}
                    onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                    onPaste={handleOtpPaste}
                    className="w-10 h-12 text-center text-lg font-mono font-bold rounded-xl bg-slate-900/90 border border-cyan-500/40 text-white focus:outline-none focus:border-cyan-400"
                  />
                ))}
              </div>
            </div>

            <button
              type="button"
              onClick={handleVerifyOtp}
              disabled={loading || totpCode.join('').length !== 6}
              className="w-full py-2.5 rounded-2xl bg-emerald-500 hover:bg-emerald-400 text-white font-semibold text-sm transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>Verify & Activate 2FA</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
