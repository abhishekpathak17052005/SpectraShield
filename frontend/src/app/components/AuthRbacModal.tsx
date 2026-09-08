import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield, UserCheck, Key, Lock, CheckCircle2, AlertTriangle,
  X, RefreshCw, Smartphone, QrCode, LogOut, Check,
} from "lucide-react";
import {
  login,
  getMe,
  simulateRole,
  setup2fa,
  verify2fa,
  disable2fa,
  logout,
  getAuthToken,
  getStoredSimulatedRole,
  type UserProfile,
} from "../api";

interface AuthRbacModalProps {
  isOpen: boolean;
  onClose: () => void;
  onUserChanged?: (user: UserProfile | null) => void;
}

const ROLES = [
  { id: "SUPER_ADMIN", label: "Super Admin", color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/30", desc: "Full permissions: triage, audit, exports, VIP roster, & user management" },
  { id: "FORENSIC_ANALYST", label: "Forensic Analyst", color: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/30", desc: "Perform deep forensics, add notes, and export dossiers" },
  { id: "SOC_OPERATOR", label: "SOC Operator", color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30", desc: "Triage inbound threats and update case status" },
  { id: "AUDITOR", label: "Auditor", color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", desc: "Read-only inspection of SHA-256 chain-of-custody audit ledgers" },
];

export const AuthRbacModal: React.FC<AuthRbacModalProps> = ({
  isOpen,
  onClose,
  onUserChanged,
}) => {
  const [tab, setTab] = useState<"profile" | "login" | "simulate" | "2fa">("profile");
  const [user, setUser] = useState<UserProfile | null>(null);
  const [email, setEmail] = useState("admin@spectrashield.soc");
  const [password, setPassword] = useState("SpectraAdmin2026!");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // 2FA state
  const [totpData, setTotpData] = useState<{ secret: string; otpauth_url: string; qr_svg?: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [totpVerifying, setTotpVerifying] = useState(false);

  const fetchProfile = () => {
    getMe()
      .then((u) => {
        setUser(u);
        onUserChanged?.(u);
      })
      .catch(() => {
        setUser(null);
        onUserChanged?.(null);
      });
  };

  useEffect(() => {
    if (isOpen) {
      fetchProfile();
    }
  }, [isOpen]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await login(email, password);
      setUser(res.user);
      onUserChanged?.(res.user);
      setSuccess("Authenticated successfully as " + res.user.role);
      setTimeout(() => { setSuccess(null); setTab("profile"); }, 1500);
    } catch (err: any) {
      setError(err.message || "Login failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleSimulate = async (roleId: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await simulateRole(roleId);
      setUser(res.user);
      onUserChanged?.(res.user);
      setSuccess(`Simulating role: ${roleId}`);
      setTimeout(() => setSuccess(null), 2000);
    } catch (err: any) {
      setError(err.message || "Role simulation failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleStart2fa = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await setup2fa();
      setTotpData(data);
      setTab("2fa");
    } catch (err: any) {
      setError(err.message || "Failed to initialize 2FA.");
    } finally {
      setLoading(false);
    }
  };

  const handleVerify2fa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode.trim()) return;
    setTotpVerifying(true);
    setError(null);
    try {
      await verify2fa(totpCode.trim());
      setSuccess("2FA Authenticator verified & activated!");
      fetchProfile();
      setTimeout(() => { setSuccess(null); setTab("profile"); }, 2000);
    } catch (err: any) {
      setError(err.message || "Invalid 6-digit TOTP code.");
    } finally {
      setTotpVerifying(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    setUser(null);
    onUserChanged?.(null);
    setTab("login");
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 md:p-6"
        style={{ background: "rgba(0,0,0,0.85)", backdropFilter: "blur(12px)" }}
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          onClick={(e) => e.stopPropagation()}
          className="w-full max-w-xl rounded-2xl border border-white/10 p-6 max-h-[85vh] overflow-y-auto space-y-6"
          style={{ background: "rgba(10,18,35,0.98)", backdropFilter: "blur(30px)" }}
        >
          {/* Header */}
          <div className="flex items-center justify-between pb-4 border-b border-white/5">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center border border-purple-500/30 bg-purple-500/10">
                <Shield className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">Zero-Trust Identity &amp; RBAC Control</h2>
                <p className="text-xs text-slate-500">JWT Bearer tokens, 4-tier roles &amp; RFC 6238 TOTP 2FA</p>
              </div>
            </div>
            <button onClick={onClose} className="text-slate-500 hover:text-white p-1">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Tabs */}
          <div className="flex gap-1 p-1 rounded-xl border border-white/5 bg-white/2">
            {[
              { id: "profile", label: "Analyst Profile" },
              { id: "simulate", label: "1-Click Role Simulation" },
              { id: "2fa", label: "2FA TOTP" },
              { id: "login", label: "Login / Switch" },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id as any)}
                className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all ${
                  tab === t.id
                    ? "text-purple-300 bg-purple-500/15 border border-purple-500/30"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Messages */}
          {error && (
            <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-red-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
          {success && (
            <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
              <span>{success}</span>
            </div>
          )}

          {/* Tab 1: Profile */}
          {tab === "profile" && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl border border-white/5 bg-white/2 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-xs text-slate-500">Authenticated Analyst</div>
                    <div className="text-sm font-bold text-white">{user?.name || "SOC Lead Investigator"}</div>
                    <div className="text-xs font-mono text-slate-400">{user?.email || "admin@spectrashield.soc"}</div>
                  </div>
                  <div className="text-right">
                    <span className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold text-purple-300 bg-purple-500/15 border border-purple-500/30">
                      {user?.role || "SUPER_ADMIN"}
                    </span>
                  </div>
                </div>

                <div className="pt-3 border-t border-white/5 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <Smartphone className="w-4 h-4 text-cyan-400" />
                    <span>2FA Status:</span>
                    <span className={user?.is_2fa_enabled ? "text-emerald-400 font-bold" : "text-amber-400"}>
                      {user?.is_2fa_enabled ? "Active (TOTP)" : "Disabled / Optional"}
                    </span>
                  </div>
                  {!user?.is_2fa_enabled && (
                    <button
                      onClick={handleStart2fa}
                      className="text-cyan-400 hover:text-cyan-300 font-semibold underline"
                    >
                      Enable 2FA
                    </button>
                  )}
                </div>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => setTab("simulate")}
                  className="flex-1 py-2.5 rounded-xl text-xs font-semibold text-purple-300 border border-purple-500/30 bg-purple-500/10 hover:bg-purple-500/20 transition-all flex items-center justify-center gap-2"
                >
                  <UserCheck className="w-4 h-4" />
                  <span>Simulate Lower Role</span>
                </button>
                <button
                  onClick={handleLogout}
                  className="py-2.5 px-4 rounded-xl text-xs font-semibold text-red-400 border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 transition-all flex items-center gap-2"
                >
                  <LogOut className="w-4 h-4" />
                  <span>Logout</span>
                </button>
              </div>
            </div>
          )}

          {/* Tab 2: 1-Click Role Simulation */}
          {tab === "simulate" && (
            <div className="space-y-3">
              <div className="text-xs text-slate-400">
                Audit endpoint security without modifying database state by simulating least-privilege roles:
              </div>
              <div className="space-y-2">
                {ROLES.map((r) => (
                  <button
                    key={r.id}
                    onClick={() => handleSimulate(r.id)}
                    disabled={loading}
                    className={`w-full p-3.5 rounded-xl border text-left transition-all flex items-center justify-between ${
                      user?.role === r.id
                        ? `${r.border} ${r.bg} shadow-lg`
                        : "border-white/5 bg-white/2 hover:border-white/20"
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`text-xs font-bold ${r.color}`}>{r.label}</span>
                        {user?.role === r.id && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20">Active</span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400">{r.desc}</div>
                    </div>
                    <Check className={`w-4 h-4 ${user?.role === r.id ? "text-purple-400" : "text-slate-700"}`} />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Tab 3: 2FA TOTP */}
          {tab === "2fa" && (
            <div className="space-y-4">
              {totpData ? (
                <div className="p-4 rounded-xl border border-white/5 bg-white/2 space-y-4 text-center">
                  <div className="text-xs text-slate-400">Scan this QR code with Google Authenticator or Authy:</div>
                  {totpData.qr_svg ? (
                    <div
                      className="mx-auto w-44 h-44 p-2 bg-white rounded-xl flex items-center justify-center"
                      dangerouslySetInnerHTML={{ __html: totpData.qr_svg }}
                    />
                  ) : (
                    <div className="p-3 bg-slate-900 border border-slate-700 rounded-xl font-mono text-xs text-cyan-300 break-all">
                      Secret: {totpData.secret}
                    </div>
                  )}

                  <form onSubmit={handleVerify2fa} className="flex gap-2 max-w-xs mx-auto">
                    <input
                      type="text"
                      maxLength={6}
                      value={totpCode}
                      onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                      placeholder="000000"
                      className="flex-1 bg-slate-900 border border-slate-700 rounded-xl text-center font-mono text-sm tracking-widest text-white outline-none focus:border-cyan-500"
                    />
                    <button
                      type="submit"
                      disabled={totpVerifying || totpCode.length !== 6}
                      className="px-4 py-2 bg-purple-500/20 text-purple-300 border border-purple-500/40 rounded-xl text-xs font-bold hover:bg-purple-500/30 transition-all disabled:opacity-40"
                    >
                      {totpVerifying ? <RefreshCw className="w-4 h-4 animate-spin" /> : "Verify"}
                    </button>
                  </form>
                </div>
              ) : (
                <div className="text-center py-8 space-y-3">
                  <Smartphone className="w-10 h-10 text-cyan-400 mx-auto opacity-70" />
                  <div className="text-sm font-semibold text-white">RFC 6238 Time-Based One-Time Password</div>
                  <p className="text-xs text-slate-500 max-w-sm mx-auto">
                    Enhance SOC console access security by enforcing two-factor authentication with 30-second rotating TOTP codes.
                  </p>
                  <button
                    onClick={handleStart2fa}
                    disabled={loading}
                    className="px-5 py-2.5 bg-purple-500/20 text-purple-300 border border-purple-500/40 rounded-xl text-xs font-bold hover:bg-purple-500/30 transition-all"
                  >
                    Setup TOTP Authenticator
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Login */}
          {tab === "login" && (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Analyst Email Address</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white outline-none focus:border-purple-500"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white outline-none focus:border-purple-500"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 bg-purple-500/20 text-purple-300 border border-purple-500/40 hover:bg-purple-500/30 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
                <span>Authenticate Session</span>
              </button>
            </form>
          )}
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default AuthRbacModal;
