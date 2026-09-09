import React, { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Search, Globe, ShieldAlert, CheckCircle2, XCircle, AlertTriangle, X, RefreshCw, Server } from "lucide-react";
import { lookupCti, type CtiIndicatorHit } from "../api";

interface CtiLookupModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialQuery?: string;
}

export const CtiLookupModal: React.FC<CtiLookupModalProps> = ({
  isOpen,
  onClose,
  initialQuery = "",
}) => {
  const [query, setQuery] = useState(initialQuery);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    indicator: string;
    records: CtiIndicatorHit[];
    total_hits: number;
    malicious_hits: number;
    vpn_or_tor: boolean;
  } | null>(null);
  const [searched, setSearched] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await lookupCti(query.trim());
      setResult(res);
      setSearched(true);
    } catch (err: any) {
      setError(err.message || "Threat intelligence lookup failed.");
      setSearched(true);
    } finally {
      setLoading(false);
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
              <div className="w-9 h-9 rounded-xl flex items-center justify-center border border-cyan-500/30 bg-cyan-500/10">
                <Globe className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">Cyber Threat Intelligence (CTI) Lookup</h2>
                <p className="text-xs text-slate-500">Triangulate AbuseIPDB, Safe Browsing, URLhaus &amp; VPN/Tor Feeds</p>
              </div>
            </div>
            <button onClick={onClose} className="text-slate-500 hover:text-white p-1">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Search Input Bar */}
          <form onSubmit={handleSearch} className="flex gap-2">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Enter IP (e.g. 185.220.101.5), Domain, URL, or File Hash..."
                className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-white/10 bg-slate-900 text-sm font-mono text-slate-200 placeholder-slate-600 outline-none focus:border-cyan-500 transition-all"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !query.trim()}
              className="px-5 py-2.5 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-xl text-xs font-bold hover:bg-cyan-500/30 transition-all flex items-center gap-2 disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              <span>Query CTI</span>
            </button>
          </form>

          {/* Quick Examples */}
          <div className="flex items-center gap-2 text-[11px] text-slate-500 flex-wrap">
            <span>Quick test indicators:</span>
            {["185.220.101.5", "1.1.1.1", "secure-microsoft-verify.tk", "paypal-update.xyz"].map((ex) => (
              <button
                key={ex}
                type="button"
                onClick={() => { setQuery(ex); lookupCti(ex).then(setResult).catch(() => {}); setSearched(true); }}
                className="px-2 py-0.5 rounded-md border border-white/5 bg-white/3 hover:text-cyan-300 hover:border-cyan-500/30 transition-all font-mono"
              >
                {ex}
              </button>
            ))}
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Results Display */}
          {searched && result && (
            <div className="space-y-4">
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3.5 rounded-xl border border-white/5 bg-white/2">
                  <div className="text-[10px] text-slate-500 uppercase mb-1">Target Indicator</div>
                  <div className="text-xs font-bold font-mono text-white truncate">{result.indicator}</div>
                </div>
                <div className="p-3.5 rounded-xl border border-white/5 bg-white/2">
                  <div className="text-[10px] text-slate-500 uppercase mb-1">Malicious Hits</div>
                  <div className={`text-sm font-bold font-mono ${result.malicious_hits > 0 ? "text-red-400" : "text-emerald-400"}`}>
                    {result.malicious_hits} / {result.total_hits} Feeds
                  </div>
                </div>
                <div className="p-3.5 rounded-xl border border-white/5 bg-white/2">
                  <div className="text-[10px] text-slate-500 uppercase mb-1">Anonymization</div>
                  <div className={`text-xs font-bold ${result.vpn_or_tor ? "text-amber-300" : "text-slate-300"}`}>
                    {result.vpn_or_tor ? "VPN / Tor Match" : "Direct Public IP"}
                  </div>
                </div>
              </div>

              {/* Records List */}
              <div className="space-y-2">
                <div className="text-xs text-slate-400 uppercase tracking-widest font-semibold">Feed Detections &amp; Intelligence</div>
                {(!result.records || result.records.length === 0) ? (
                  <div className="p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 text-emerald-300 text-xs flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Clean Indicator: No active malicious reports or blacklist hits found.</span>
                  </div>
                ) : (
                  result.records.map((rec: any, idx) => {
                    const sourceText = Array.isArray(rec.sources)
                      ? rec.sources.join(", ")
                      : (rec.source || rec.sources || "CTI Feed");
                    const categoryText = (rec.threat_category || (rec.is_malicious ? "THREAT_DETECTED" : "CLEAN")).replace(/_/g, " ");
                    const confVal = typeof rec.confidence_score === "number"
                      ? rec.confidence_score
                      : typeof rec.confidence === "number"
                      ? (rec.confidence > 1 ? rec.confidence : rec.confidence * 100)
                      : 0;

                    return (
                      <div key={idx} className="p-4 rounded-xl border border-white/5 bg-white/2 flex items-start gap-3">
                        {rec.is_malicious ? (
                          <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                        ) : (
                          <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                        )}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-2 mb-1 flex-wrap">
                            <span className="text-xs font-bold text-white">{categoryText}</span>
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold text-cyan-300 bg-cyan-500/10 border border-cyan-500/20">
                              {sourceText}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400 font-mono">
                            Threat Confidence: {confVal.toFixed(0)}%
                          </div>
                          {rec.details && typeof rec.details === "object" && (
                            <div className="text-[10px] text-slate-500 mt-1 font-mono">
                              {Object.entries(rec.details).map(([k, val]) => `${k}: ${val}`).join(" · ")}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default CtiLookupModal;
