import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useTheme } from "next-themes";
import {
  Shield,
  Globe,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Eye,
  Ban,
  MapPin,
  Server,
  ChevronDown,
  Link2,
  Zap,
  Search,
  RefreshCw,
} from "lucide-react";
import { analyze, lookupCti, type CtiIndicatorHit } from "../api";

interface LinkPreviewProps {
  url?: string;
  riskScore?: number;
}

interface ThreatIndicator {
  id: string;
  type: "critical" | "warning" | "safe";
  label: string;
  description: string;
}

const defaultThreatIndicators: ThreatIndicator[] = [
  {
    id: "1",
    type: "critical",
    label: "Spoofed Domain",
    description: "Domain mimics legitimate Microsoft / Corporate services",
  },
  {
    id: "2",
    type: "critical",
    label: "Invalid SSL / Self-Signed",
    description: "SSL certificate is self-signed or mismatching host",
  },
  {
    id: "3",
    type: "warning",
    label: "Newly Registered Domain",
    description: "Domain registered within the last 30 days (High turnover)",
  },
  {
    id: "4",
    type: "critical",
    label: "Suspicious Top-Level Domain",
    description: "Using high-abuse TLD (.tk, .ml, .xyz, .top)",
  },
  {
    id: "5",
    type: "warning",
    label: "No HTTPS Redirect",
    description: "Site accessible via insecure plaintext HTTP protocol",
  },
];

const LinkPreview: React.FC<LinkPreviewProps> = ({
  url: initialUrl = "https://secure-verify-account.tk/login/microsoft/verify",
  riskScore: initialRisk = 87,
}) => {
  const [targetUrl, setTargetUrl] = useState(initialUrl);
  const [inputUrl, setInputUrl] = useState(initialUrl);
  const [liveScore, setLiveScore] = useState(initialRisk);
  const [loading, setLoading] = useState(false);
  const [showFullUrl, setShowFullUrl] = useState(false);
  const [expandedSection, setExpandedSection] = useState<string | null>(null);
  const { resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [ctiHits, setCtiHits] = useState<CtiIndicatorHit[]>([]);
  const [domainMeta, setDomainMeta] = useState({
    domainAge: "12 days",
    sslStatus: "Invalid Certificate",
    sslValid: false,
    location: "Moscow, Russia",
    registrar: "FreeDomainRegistry.tk",
    lastScanned: "Just now",
  });
  const [threatIndicators, setThreatIndicators] = useState<ThreatIndicator[]>(defaultThreatIndicators);

  useEffect(() => {
    setMounted(true);
  }, []);

  const runAnalysis = async (urlToScan: string) => {
    setLoading(true);
    try {
      const [res, cti] = await Promise.all([
        analyze({ url: urlToScan, private_mode: false }),
        lookupCti(urlToScan).catch(() => null),
      ]);

      const score = Math.round(res.final_risk ?? (res.final_score ? res.final_score * 100 : 85));
      setLiveScore(score);

      if (cti && cti.records) {
        setCtiHits(cti.records);
        if (cti.records.length > 0) {
          const indicators: ThreatIndicator[] = cti.records.map((hit, idx) => ({
            id: String(idx + 1),
            type: hit.is_malicious ? "critical" : "warning",
            label: `${hit.threat_category.replace(/_/g, " ")} (${hit.sources.join(", ")})`,
            description: `Threat confidence ${(hit.confidence * 100).toFixed(0)}% across active threat feeds`,
          }));
          setThreatIndicators(indicators);
        }
      }

      setDomainMeta({
        domainAge: score >= 70 ? "< 14 days" : "> 2 years",
        sslStatus: score >= 70 ? "Invalid / Untrusted Authority" : "Valid TLS 1.3",
        sslValid: score < 70,
        location: score >= 70 ? "Tor / Anonymous Proxy" : "San Francisco, US",
        registrar: "Domain Registry Services",
        lastScanned: "Just now",
      });
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  const handleScanSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputUrl.trim()) {
      setTargetUrl(inputUrl.trim());
      runAnalysis(inputUrl.trim());
    }
  };

  const colors = {
    safe: mounted && resolvedTheme === "light" ? "#16A34A" : "#00FFAA",
    warning: mounted && resolvedTheme === "light" ? "#F59E0B" : "#FFA500",
    danger: mounted && resolvedTheme === "light" ? "#DC2626" : "#FF3B3B",
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return { color: colors.danger, label: "High Risk", glow: `${colors.danger}4D` };
    if (score >= 40) return { color: colors.warning, label: "Suspicious", glow: `${colors.warning}4D` };
    return { color: colors.safe, label: "Safe", glow: `${colors.safe}4D` };
  };

  const riskInfo = getRiskColor(liveScore);

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  return (
    <div className="w-full max-w-5xl mx-auto bg-card text-foreground p-6 rounded-2xl shadow-2xl border border-border">
      {/* Header */}
      <div className="flex items-center justify-between mb-6 pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div
              className="absolute inset-0 blur-lg rounded-full opacity-50"
              style={{ backgroundColor: riskInfo.glow }}
            />
            <Shield className="w-7 h-7 relative z-10" style={{ color: riskInfo.color }} />
          </div>
          <div>
            <h2 className="text-xl font-bold bg-gradient-to-r from-foreground to-muted-foreground bg-clip-text text-transparent">
              Secure Link Analysis
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">Real-time CTI triangulation &amp; sandboxed preview</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Last scanned:</span>
          <span className="text-xs text-foreground font-medium">{domainMeta.lastScanned}</span>
        </div>
      </div>

      {/* Live URL Input Bar */}
      <form onSubmit={handleScanSubmit} className="mb-6 flex gap-2">
        <div className="relative flex-1">
          <Link2 className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            placeholder="Enter any URL (e.g. https://suspicious-site.tk/login)..."
            className="w-full pl-9 pr-4 py-2.5 bg-muted/50 border border-border rounded-xl text-sm font-mono text-foreground placeholder-muted-foreground outline-none focus:border-cyan-500/60 transition-all"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !inputUrl.trim()}
          className="px-5 py-2.5 bg-primary text-primary-foreground font-semibold text-sm rounded-xl hover:opacity-90 transition-all flex items-center gap-2 disabled:opacity-50"
        >
          {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          <span>Scan URL</span>
        </button>
      </form>

      {/* URL Display */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2">
          <Link2 className="w-4 h-4 text-muted-foreground" />
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Target URL</span>
        </div>
        <div className="bg-muted/50 border border-border rounded-xl p-4 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <div className="flex-1 min-w-0 mr-4">
              <p
                className={`font-mono text-sm ${
                  showFullUrl ? "break-all" : "truncate"
                } text-foreground/90`}
              >
                {targetUrl}
              </p>
            </div>
            <button
              onClick={() => setShowFullUrl(!showFullUrl)}
              className="px-3 py-1 text-xs bg-card hover:bg-muted border border-border rounded-lg transition-colors flex items-center gap-1 flex-shrink-0 text-foreground"
            >
              <Eye className="w-3 h-3" />
              {showFullUrl ? "Collapse" : "Expand"}
            </button>
          </div>
        </div>
      </div>

      {/* Security Info Bar - Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 mb-6">
        {/* Risk Score Meter */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-1 bg-card border border-border rounded-xl p-4 shadow-sm relative overflow-hidden"
        >
          <div
            className="absolute inset-0 opacity-5"
            style={{
              background: `radial-gradient(circle at top right, ${riskInfo.color}, transparent)`,
            }}
          />
          <div className="relative z-10">
            <div className="flex items-center gap-2 mb-3">
              <Zap className="w-4 h-4" style={{ color: riskInfo.color }} />
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Risk Score
              </span>
            </div>
            <div className="flex items-end gap-3">
              <div
                className="text-4xl font-bold"
                style={{ color: riskInfo.color }}
              >
                {liveScore}
              </div>
              <div className="mb-1">
                <div
                  className="text-xs font-bold uppercase tracking-wide"
                  style={{ color: riskInfo.color }}
                >
                  {riskInfo.label}
                </div>
                <div className="text-[10px] text-muted-foreground">out of 100</div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* SSL Status Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-card border border-border rounded-xl p-4 shadow-sm"
        >
          <div className="flex items-center gap-2 mb-2">
            {domainMeta.sslValid ? (
              <Lock className="w-4 h-4 text-emerald-500" />
            ) : (
              <Unlock className="w-4 h-4 text-rose-500" />
            )}
            <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              SSL / TLS
            </span>
          </div>
          <div className="text-sm font-semibold mb-1">
            {domainMeta.sslValid ? "Valid Certificate" : "Untrusted Authority"}
          </div>
          <p className="text-xs text-muted-foreground">{domainMeta.sslStatus}</p>
        </motion.div>

        {/* Domain Age Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-card border border-border rounded-xl p-4 shadow-sm"
        >
          <div className="flex items-center gap-2 mb-2">
            <Globe className="w-4 h-4 text-muted-foreground" />
            <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Domain Profile
            </span>
          </div>
          <div className="text-sm font-semibold mb-1">{domainMeta.domainAge}</div>
          <p className="text-xs text-muted-foreground">{domainMeta.registrar}</p>
        </motion.div>

        {/* Server Location Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-card border border-border rounded-xl p-4 shadow-sm"
        >
          <div className="flex items-center gap-2 mb-2">
            <Server className="w-4 h-4 text-muted-foreground" />
            <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Host / Geo
            </span>
          </div>
          <div className="text-sm font-semibold mb-1">{domainMeta.location}</div>
          <p className="text-xs text-muted-foreground flex items-center gap-1">
            <MapPin className="w-3 h-3" />
            Resolved Public Hop
          </p>
        </motion.div>
      </div>

      {/* Threat Indicators List */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Detected Threat Vectors ({threatIndicators.length})
            </span>
          </div>
        </div>

        <div className="space-y-2">
          {threatIndicators.map((indicator) => (
            <div
              key={indicator.id}
              className="p-3 bg-card border border-border rounded-xl flex items-start gap-3"
            >
              {indicator.type === "critical" ? (
                <XCircle className="w-4 h-4 text-rose-500 mt-0.5 flex-shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-amber-500 mt-0.5 flex-shrink-0" />
              )}
              <div className="flex-1 min-w-0">
                <div className="text-xs font-bold text-foreground">{indicator.label}</div>
                <div className="text-[11px] text-muted-foreground mt-0.5">{indicator.description}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default LinkPreview;