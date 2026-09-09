import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { UserCheck, Plus, X, Shield, RefreshCw, CheckCircle2, AlertTriangle } from "lucide-react";
import { getVipRoster, addVipExecutive, type VipExecutive } from "../api";

interface VipRosterModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const VipRosterModal: React.FC<VipRosterModalProps> = ({ isOpen, onClose }) => {
  const [roster, setRoster] = useState<VipExecutive[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [title, setTitle] = useState("");
  const [domains, setDomains] = useState("");
  const [adding, setAdding] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchRoster = () => {
    setLoading(true);
    getVipRoster()
      .then((res) => {
        setRoster(res.roster || []);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    if (isOpen) {
      fetchRoster();
    }
  }, [isOpen]);

  const handleAddVip = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !title.trim()) return;

    setAdding(true);
    setError(null);
    try {
      const authorized = domains
        .split(",")
        .map((d) => d.trim())
        .filter(Boolean);

      await addVipExecutive({
        name: name.trim(),
        title: title.trim(),
        authorized_domains: authorized.length > 0 ? authorized : ["corp.com"],
      });

      setName("");
      setTitle("");
      setDomains("");
      setSuccess("Protected executive registered successfully!");
      fetchRoster();
      setTimeout(() => setSuccess(null), 2500);
    } catch (err: any) {
      setError(err.message || "Failed to add executive.");
    } finally {
      setAdding(false);
    }
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
          className="w-full max-w-2xl rounded-2xl border border-white/10 p-6 max-h-[85vh] overflow-y-auto space-y-6"
          style={{ background: "rgba(10,18,35,0.98)", backdropFilter: "blur(30px)" }}
        >
          {/* Header */}
          <div className="flex items-center justify-between pb-4 border-b border-white/5">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center border border-red-500/30 bg-red-500/10">
                <UserCheck className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">Protected VIP Executive Roster</h2>
                <p className="text-xs text-slate-500">Defend against Executive Display-Name Spoofing &amp; BEC</p>
              </div>
            </div>
            <button onClick={onClose} className="text-slate-500 hover:text-white p-1">
              <X className="w-5 h-5" />
            </button>
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

          {/* Add Executive Form */}
          <form onSubmit={handleAddVip} className="p-4 rounded-xl border border-white/5 bg-white/2 space-y-3">
            <div className="text-xs font-semibold text-slate-300 flex items-center gap-2">
              <Plus className="w-3.5 h-3.5 text-cyan-400" />
              <span>Register New Protected Executive Identity</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-slate-500 mb-1 block">Full Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Satya Nadella"
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2 text-xs text-white outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="text-[10px] text-slate-500 mb-1 block">Executive Title / Role</label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Chief Executive Officer (CEO)"
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2 text-xs text-white outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div>
              <label className="text-[10px] text-slate-500 mb-1 block">Authorized Sending Domains (Comma-separated)</label>
              <input
                type="text"
                value={domains}
                onChange={(e) => setDomains(e.target.value)}
                placeholder="e.g. microsoft.com, executive.ms"
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2 text-xs font-mono text-cyan-300 outline-none focus:border-cyan-500"
              />
            </div>

            <button
              type="submit"
              disabled={adding || !name.trim() || !title.trim()}
              className="px-4 py-2 bg-red-500/20 text-red-300 border border-red-500/40 hover:bg-red-500/30 rounded-xl text-xs font-bold transition-all flex items-center gap-2 disabled:opacity-40"
            >
              {adding ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
              <span>Add to Protected Roster</span>
            </button>
          </form>

          {/* Roster List */}
          <div className="space-y-3">
            <div className="text-xs text-slate-400 uppercase tracking-widest font-semibold flex items-center justify-between">
              <span>Monitored Executives ({roster.length})</span>
              {loading && <RefreshCw className="w-3 h-3 animate-spin text-cyan-400" />}
            </div>

            <div className="space-y-2 max-h-52 overflow-y-auto">
              {roster.map((vip: any, i) => {
                const authorizedList = Array.isArray(vip.authorized_domains)
                  ? vip.authorized_domains
                  : Array.isArray(vip.trusted_domains)
                  ? vip.trusted_domains
                  : [];

                return (
                  <div key={vip.id || i} className="p-3.5 rounded-xl border border-white/5 bg-white/2 flex items-center justify-between flex-wrap gap-2">
                    <div>
                      <div className="text-xs font-bold text-white flex items-center gap-2">
                        <span>{vip.name}</span>
                        <span className="text-[10px] text-slate-400 font-normal">({vip.title})</span>
                      </div>
                      <div className="text-[10px] font-mono text-cyan-400/80 mt-0.5">
                        Authorized: {authorizedList.length > 0 ? authorizedList.join(", ") : "All Corporate Domains"}
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold text-red-300 bg-red-500/10 border border-red-500/20">
                      PROTECTED
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default VipRosterModal;
