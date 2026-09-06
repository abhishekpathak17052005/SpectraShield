import React, { useState, useEffect } from "react";
import { 
  ShieldAlert, 
  UserCheck, 
  Plus, 
  X, 
  Mail, 
  Building2, 
  Check, 
  Loader2,
  Users
} from "lucide-react";
import { LiquidGlassCard } from "../liquid/LiquidGlassCard";
import { LiquidGlassBadge } from "../liquid/LiquidGlassBadge";
import { VipRosterEntry } from "../../types";
import { fetchVipRoster, addVipRosterEntry } from "../../api";

interface VipRosterModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const VipRosterModal: React.FC<VipRosterModalProps> = ({ isOpen, onClose }) => {
  const [roster, setRoster] = useState<VipRosterEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [showAddForm, setShowAddForm] = useState<boolean>(false);
  const [saving, setSaving] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Form state
  const [name, setName] = useState<string>("");
  const [title, setTitle] = useState<string>("");
  const [domains, setDomains] = useState<string>("");
  const [emails, setEmails] = useState<string>("");

  useEffect(() => {
    if (isOpen) {
      loadRoster();
    }
  }, [isOpen]);

  const loadRoster = async () => {
    setLoading(true);
    try {
      const data = await fetchVipRoster();
      setRoster(data);
    } catch (err) {
      console.error("Failed to load VIP roster:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleAddVip = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !title.trim()) {
      setErrorMsg("Name and Title are mandatory fields.");
      return;
    }

    setSaving(true);
    setErrorMsg(null);
    try {
      const parsedDomains = domains.split(",").map(d => d.trim().toLowerCase()).filter(Boolean);
      const parsedEmails = emails.split(",").map(e => e.trim().toLowerCase()).filter(Boolean);

      const newEntry: VipRosterEntry = {
        name: name.trim(),
        title: title.trim(),
        authorized_domains: parsedDomains,
        authorized_emails: parsedEmails
      };

      const res = await addVipRosterEntry(newEntry);
      setRoster(prev => [...prev, res]);
      setShowAddForm(false);
      setName("");
      setTitle("");
      setDomains("");
      setEmails("");
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to add VIP entry");
    } finally {
      setSaving(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-2xl">
        <LiquidGlassCard glowColor="amber" className="p-6 max-h-[85vh] flex flex-col space-y-4">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-amber-500/15 border border-amber-500/30 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.25)]">
                <Users className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold tracking-wide text-white font-mono">
                    VIP EXECUTIVE ROSTER MANAGEMENT
                  </h3>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                    NLP-03 GUARD
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Protects C-Suite executives from display-name spoofing and unauthorized wire/invoice authorizations.
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-all"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Action Bar */}
          <div className="flex items-center justify-between">
            <div className="text-xs font-mono text-slate-400">
              Registered Executives: <span className="text-amber-400 font-bold">{roster.length}</span>
            </div>
            <button
              onClick={() => setShowAddForm(!showAddForm)}
              className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 transition-all flex items-center gap-1.5 shadow-[0_0_10px_rgba(245,158,11,0.2)]"
            >
              <Plus className="w-3.5 h-3.5" />
              {showAddForm ? "Cancel" : "Add Executive"}
            </button>
          </div>

          {/* Add Form Accordion */}
          {showAddForm && (
            <form onSubmit={handleAddVip} className="p-4 rounded-xl bg-slate-950/70 border border-amber-500/30 space-y-3 animate-fade-in">
              <h4 className="text-xs font-bold font-mono text-amber-300">
                REGISTER PROTECTED EXECUTIVE
              </h4>
              
              {errorMsg && (
                <div className="p-2.5 rounded-lg bg-rose-500/20 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4" />
                  <span>{errorMsg}</span>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-mono text-slate-400 block mb-1">
                    Full Display Name *
                  </label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Satya Nadella"
                    className="w-full px-3 py-1.5 bg-slate-900 border border-white/10 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500/60"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-mono text-slate-400 block mb-1">
                    Corporate Title *
                  </label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="e.g. Chief Executive Officer"
                    className="w-full px-3 py-1.5 bg-slate-900 border border-white/10 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500/60"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-mono text-slate-400 block mb-1">
                    Authorized Domains (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={domains}
                    onChange={(e) => setDomains(e.target.value)}
                    placeholder="e.g. microsoft.com, corp.microsoft.com"
                    className="w-full px-3 py-1.5 bg-slate-900 border border-white/10 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500/60"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-mono text-slate-400 block mb-1">
                    Authorized Emails (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={emails}
                    onChange={(e) => setEmails(e.target.value)}
                    placeholder="e.g. satya@microsoft.com"
                    className="w-full px-3 py-1.5 bg-slate-900 border border-white/10 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500/60"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddForm(false)}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono text-slate-400 hover:text-white bg-white/5 border border-white/10"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-1.5 rounded-lg text-xs font-mono font-semibold bg-amber-500/30 hover:bg-amber-500/40 text-amber-200 border border-amber-500/50 transition-all flex items-center gap-1.5"
                >
                  {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                  Save to Roster
                </button>
              </div>
            </form>
          )}

          {/* Roster List (Scrollable) */}
          <div className="overflow-y-auto space-y-2.5 pr-1 flex-1">
            {loading ? (
              <div className="p-8 text-center text-slate-400 text-xs font-mono flex items-center justify-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-amber-400" />
                Loading VIP roster entries...
              </div>
            ) : roster.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs font-mono">
                No VIP executives registered. Click "Add Executive" above.
              </div>
            ) : (
              roster.map((vip, i) => (
                <div
                  key={`${vip.name}-${i}`}
                  className="p-3.5 rounded-xl border border-white/10 bg-slate-950/40 backdrop-blur-md flex flex-col md:flex-row md:items-center justify-between gap-3 hover:border-amber-500/30 transition-all"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <UserCheck className="w-4 h-4 text-amber-400" />
                      <span className="text-xs font-bold font-mono text-white">
                        {vip.name}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
                        {vip.title}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2 text-[11px] font-mono text-slate-400 pl-6">
                      <span className="flex items-center gap-1">
                        <Building2 className="w-3 h-3 text-slate-500" />
                        {vip.authorized_domains.join(", ") || "Any corporate domain"}
                      </span>
                      {vip.authorized_emails.length > 0 && (
                        <span className="flex items-center gap-1">
                          <Mail className="w-3 h-3 text-slate-500" />
                          {vip.authorized_emails.join(", ")}
                        </span>
                      )}
                    </div>
                  </div>

                  <LiquidGlassBadge
                    variant="safe"
                    label="PROTECTED"
                    icon={ShieldAlert}
                    size="sm"
                  />
                </div>
              ))
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between border-t border-white/10 pt-3 text-[11px] font-mono text-slate-400">
            <span>Any inbound email matching VIP names without matching authorized sender domain triggers EXECUTIVE_IMPERSONATION.</span>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 text-white font-mono text-xs transition-all"
            >
              Done
            </button>
          </div>
        </LiquidGlassCard>
      </div>
    </div>
  );
};
