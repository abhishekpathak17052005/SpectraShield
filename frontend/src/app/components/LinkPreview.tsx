import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useTheme } from "next-themes";
import {
  Shield,
  ShieldAlert,
  Globe,
  Lock,
  Unlock,
  Calendar,
  AlertTriangle,
  CheckCircle2,
  CircleHelp,
  XCircle,
  ExternalLink,
  Eye,
  Ban,
  MapPin,
  Server,
  ChevronDown,
  Link2,
  Zap,
} from "lucide-react";
import type { IntelligenceProfile, DomainAgeContext, SSLContext } from "../api";

interface LinkPreviewProps {
  url?: string;
  riskScore?: number;
  scannedAt?: string;
  domainAgeDays?: number | null;
  domainAgeContext?: DomainAgeContext;
  sslContext?: SSLContext;
  intelligenceProfile?: IntelligenceProfile;
  riskBreakdown?: {
    brand_match?: string;
    logic_flags?: string[];
    global_reputation?: { flagged?: number; total?: number };
    local_score?: number;
    external_score?: number;
    ssl_age_score?: number;
  };
  threatArray?: string[];
}

interface ThreatIndicator {
  id: string;
  type: "critical" | "warning" | "safe";
  label: string;
  description: string;
}

const LinkPreview: React.FC<LinkPreviewProps> = ({
  url = "https://secure-verify-account.tk/login/microsoft/verify",
  riskScore = 87,
  scannedAt,
  domainAgeDays,
  domainAgeContext,
  sslContext,
  intelligenceProfile,
  riskBreakdown,
  threatArray,
}) => {
  const [showFullUrl, setShowFullUrl] = useState(false);
  const [expandedSection, setExpandedSection] = useState<string | null>(null);
  const { resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const [relativeNow, setRelativeNow] = useState<number>(Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setRelativeNow(Date.now());
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  const formatUnit = (value: number, unit: string): string => {
    return `${value} ${unit}${value === 1 ? "" : "s"} ago`;
  };

  const formatLastScanned = (timestamp?: string): string => {
    if (!timestamp) return "Unknown";
    const parsed = new Date(timestamp);
    const scannedMs = parsed.getTime();
    if (!Number.isFinite(scannedMs)) return "Unknown";

    const diffSeconds = Math.max(0, Math.floor((relativeNow - scannedMs) / 1000));
    if (diffSeconds < 5) return "just now";
    if (diffSeconds < 60) return formatUnit(diffSeconds, "second");

    const diffMinutes = Math.floor(diffSeconds / 60);
    if (diffMinutes < 60) return formatUnit(diffMinutes, "minute");

    const diffHours = Math.floor(diffMinutes / 60);
    if (diffHours < 24) return formatUnit(diffHours, "hour");

    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 30) return formatUnit(diffDays, "day");

    const diffMonths = Math.floor(diffDays / 30);
    if (diffMonths < 12) return formatUnit(diffMonths, "month");

    const diffYears = Math.floor(diffDays / 365);
    return formatUnit(diffYears, "year");
  };

  const colors = {
    safe: mounted && resolvedTheme === "light" ? "#16A34A" : "#00FFAA",
    warning: mounted && resolvedTheme === "light" ? "#F59E0B" : "#FFA500",
    danger: mounted && resolvedTheme === "light" ? "#DC2626" : "#FF3B3B",
  };

  const tech = intelligenceProfile?.advanced_technical_details;
  const domainAgeValue = domainAgeDays ?? tech?.domain_age_days ?? null;
  const domainAge = domainAgeValue != null ? `${domainAgeValue} days` : "Unknown";
  const deriveDomainAgeContext = (days: number | null): DomainAgeContext => {
    if (days == null) {
      return {
        bucket: "unknown",
        label: "Unknown",
        color: "neutral",
        message: "Domain age could not be verified.",
        risk_modifier_pct: 0,
      };
    }
    if (days <= 30) {
      return {
        bucket: "burner_domain",
        label: "Burner Domain",
        color: "red",
        message: "Extreme Risk: This domain was created in the last month. Common in phishing.",
        risk_modifier_pct: 50,
      };
    }
    if (days <= 180) {
      return {
        bucket: "new_entity",
        label: "New Entity",
        color: "orange",
        message: "High Risk: Relatively new domain. Proceed with caution.",
        risk_modifier_pct: 25,
      };
    }
    if (days <= 1095) {
      return {
        bucket: "emerging",
        label: "Emerging",
        color: "yellow",
        message: "Moderate: Established for over 6 months but lacks a long-term reputation.",
        risk_modifier_pct: 0,
      };
    }
    if (days <= 3650) {
      return {
        bucket: "verified_legacy",
        label: "Verified Legacy",
        color: "green",
        message: "Safe: Stable domain with over 3 years of active history.",
        risk_modifier_pct: -15,
      };
    }
    return {
      bucket: "institutional",
      label: "Institutional",
      color: "cyan",
      message: "Trusted: Highly established domain (10+ years). Extremely low risk.",
      risk_modifier_pct: -30,
    };
  };

  const effectiveDomainAgeContext = domainAgeContext ?? deriveDomainAgeContext(domainAgeValue);
  const domainColorMap: Record<string, {
    text: string;
    icon: string;
    panel: string;
    chip: string;
    tone: string;
  }> = {
    red: {
      text: "text-red-500",
      icon: "text-red-500",
      panel: "from-red-500/15",
      chip: "bg-red-500/15 text-red-400 border-red-500/35",
      tone: "Extreme Risk",
    },
    orange: {
      text: "text-orange-500",
      icon: "text-orange-500",
      panel: "from-orange-500/15",
      chip: "bg-orange-500/15 text-orange-400 border-orange-500/35",
      tone: "High Risk",
    },
    yellow: {
      text: "text-yellow-400",
      icon: "text-yellow-400",
      panel: "from-yellow-400/15",
      chip: "bg-yellow-400/15 text-yellow-300 border-yellow-400/35",
      tone: "Moderate",
    },
    green: {
      text: "text-emerald-500",
      icon: "text-emerald-500",
      panel: "from-emerald-500/15",
      chip: "bg-emerald-500/15 text-emerald-400 border-emerald-500/35",
      tone: "Safe",
    },
    cyan: {
      text: "text-cyan-400",
      icon: "text-cyan-400",
      panel: "from-cyan-400/15",
      chip: "bg-cyan-400/15 text-cyan-300 border-cyan-400/35",
      tone: "Trusted",
    },
    neutral: {
      text: "text-slate-400",
      icon: "text-slate-400",
      panel: "from-slate-400/15",
      chip: "bg-slate-400/12 text-slate-300 border-slate-400/35",
      tone: "Unknown",
    },
  };
  const domainAgeVisual = domainColorMap[effectiveDomainAgeContext.color] ?? domainColorMap.neutral;
  const modifier = effectiveDomainAgeContext.risk_modifier_pct ?? 0;
  const modifierText = `${modifier > 0 ? "+" : ""}${modifier}% Risk score`;
  const sslExpiry = intelligenceProfile?.ssl_status?.expiry_date || "Unknown";

  const parseIsoDate = (value?: string | null): Date | null => {
    if (!value) return null;
    const parsed = new Date(value);
    return Number.isFinite(parsed.getTime()) ? parsed : null;
  };

  const deriveSslContext = (): SSLContext => {
    if (sslContext) {
      return sslContext;
    }

    const status = intelligenceProfile?.ssl_status;
    const valid = !!status?.is_valid;
    const validationError = String(status?.validation_error || "").toLowerCase();
    const expiryDt = parseIsoDate(status?.expiry_date);
    const now = new Date();

    if (valid && expiryDt) {
      const daysLeft = Math.max(0, Math.floor((expiryDt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)));
      if (daysLeft < 7) {
        return {
          bucket: "expiring_soon",
          label: "Expiring Soon",
          badge: "SSL WARNING",
          severity: "warning",
          color: "amber",
          symbol: "~!",
          message: "Certificate expires in under 7 days. Revalidation risk is elevated.",
          risk_modifier_pct: 15,
        };
      }
    }

    if (valid) {
      const marker = `${String(status?.issuer || "").toLowerCase()} ${String(status?.subject_organization || "").toLowerCase()}`;
      if (marker.includes("extended validation") || marker.includes("ev ssl")) {
        return {
          bucket: "ev",
          label: "EV Certificate",
          badge: "ULTRA SAFE",
          severity: "safe",
          color: "emerald",
          symbol: "EV+",
          message: "Extended Validation certificate detected. Strong ownership signal.",
          risk_modifier_pct: -40,
        };
      }
      return {
        bucket: "valid_ov_dv",
        label: "Valid OV/DV",
        badge: "NEUTRAL",
        severity: "neutral",
        color: "cyan",
        symbol: "DV/OV",
        message: "Certificate is valid. SSL alone does not imply trustworthiness.",
        risk_modifier_pct: 0,
      };
    }

    if (["hostname", "doesn't match", "does not match", "name mismatch"].some((m) => validationError.includes(m))) {
      return {
        bucket: "name_mismatch",
        label: "Name Mismatch",
        badge: "CRITICAL",
        severity: "critical",
        color: "red",
        symbol: "CN!",
        message: "Certificate hostname mismatch. This is a high-confidence phishing indicator.",
        risk_modifier_pct: 80,
      };
    }

    if (status?.is_self_signed || ["self signed", "unknown ca", "unable to get local issuer", "self-signed"].some((m) => validationError.includes(m))) {
      return {
        bucket: "self_signed_untrusted",
        label: "Self-Signed / Untrusted",
        badge: "CRITICAL",
        severity: "critical",
        color: "orange",
        symbol: "CA!",
        message: "Certificate is self-signed or untrusted by the browser trust chain.",
        risk_modifier_pct: 50,
      };
    }

    if (expiryDt && expiryDt.getTime() <= now.getTime()) {
      return {
        bucket: "expired",
        label: "Expired",
        badge: "CRITICAL",
        severity: "critical",
        color: "red",
        symbol: "EXP!",
        message: "Certificate has expired and no longer provides valid transport assurance.",
        risk_modifier_pct: 60,
      };
    }

    return {
      bucket: "self_signed_untrusted",
      label: "Untrusted SSL",
      badge: "CRITICAL",
      severity: "critical",
      color: "orange",
      symbol: "TLS!",
      message: "SSL validation failed. Treat this destination as unsafe until verified.",
      risk_modifier_pct: 50,
    };
  };

  const effectiveSslContext = deriveSslContext();
  const sslModifier = effectiveSslContext.risk_modifier_pct ?? 0;
  const sslModifierText = `${sslModifier > 0 ? "+" : ""}${sslModifier}% Risk score`;
  const sslToneMap: Record<string, {
    text: string;
    icon: string;
    panel: string;
    chip: string;
  }> = {
    emerald: {
      text: "text-emerald-500",
      icon: "text-emerald-500",
      panel: "from-emerald-500/15",
      chip: "bg-emerald-500/15 text-emerald-400 border-emerald-500/35",
    },
    cyan: {
      text: "text-cyan-400",
      icon: "text-cyan-400",
      panel: "from-cyan-400/15",
      chip: "bg-cyan-400/15 text-cyan-300 border-cyan-400/35",
    },
    amber: {
      text: "text-amber-400",
      icon: "text-amber-400",
      panel: "from-amber-400/15",
      chip: "bg-amber-400/15 text-amber-300 border-amber-400/35",
    },
    red: {
      text: "text-red-500",
      icon: "text-red-500",
      panel: "from-red-500/15",
      chip: "bg-red-500/15 text-red-400 border-red-500/35",
    },
    orange: {
      text: "text-orange-500",
      icon: "text-orange-500",
      panel: "from-orange-500/15",
      chip: "bg-orange-500/15 text-orange-400 border-orange-500/35",
    },
    neutral: {
      text: "text-slate-400",
      icon: "text-slate-400",
      panel: "from-slate-400/15",
      chip: "bg-slate-400/12 text-slate-300 border-slate-400/35",
    },
  };
  const sslVisual = sslToneMap[effectiveSslContext.color] ?? sslToneMap.neutral;
  const sslIsSafe = effectiveSslContext.severity === "safe";
  const sslIsWarning = effectiveSslContext.severity === "warning";
  const sslIsTrustedNeutral = effectiveSslContext.bucket === "valid_ov_dv";
  const sslIssuer = intelligenceProfile?.ssl_status?.issuer || "Unknown";
  const location = intelligenceProfile?.location_data?.country || "Unknown";
  const isp = intelligenceProfile?.location_data?.isp || "Unknown";
  const ipAddress = intelligenceProfile?.location_data?.ip_address || "Unknown";
  const dnsA = tech?.dns_records?.a || [];
  const dnsMX = tech?.dns_records?.mx || [];
  const redirectHops = typeof tech?.redirect_hops === "number" ? tech.redirect_hops : 0;
  const pageTitle = tech?.page_title || "Unknown";
  const registrar = (tech?.whois && String((tech.whois as Record<string, unknown>).registrar || "")) || "Unknown";
  const lastScanned = formatLastScanned(scannedAt);

  const sourceThreats = threatArray && threatArray.length > 0
    ? threatArray
    : (intelligenceProfile?.threat_array || []);

  const threatIndicators: ThreatIndicator[] = sourceThreats.map((item, index) => {
    const text = String(item || "");
    const lower = text.toLowerCase();
    const isCritical = /brand mimicry|virus|hidden redirection|ip host|homograph|critical/.test(lower);
    return {
      id: String(index + 1),
      type: isCritical ? "critical" : "warning",
      label: text,
      description: isCritical ? "High-confidence heuristic or reputation signal." : "Suspicious heuristic signal detected.",
    };
  });

  const getRiskColor = (score: number) => {
    if (score >= 70) return { color: colors.danger, label: "High Risk", glow: `${colors.danger}4D` }; // 4D = 30% alpha
    if (score >= 40) return { color: colors.warning, label: "Suspicious", glow: `${colors.warning}4D` };
    return { color: colors.safe, label: "Safe", glow: `${colors.safe}4D` };
  };

  const riskInfo = getRiskColor(riskScore);

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
            <p className="text-xs text-muted-foreground mt-0.5">Real-time threat detection & sandboxed preview</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Last scanned:</span>
          <span className="text-xs text-foreground font-medium">{lastScanned}</span>
        </div>
      </div>

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
                {url}
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

      {/* Security Overview */}
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
                Severity Score
              </span>
            </div>
            <div className="flex items-end gap-3">
              <div
                className="text-4xl font-bold"
                style={{ color: riskInfo.color }}
              >
                {riskScore}
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
            {/* Mini progress bar */}
            <div className="mt-3 h-1.5 bg-muted rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${riskScore}%` }}
                transition={{ duration: 1, ease: "easeOut" }}
                className="h-full rounded-full"
                style={{
                  background: `linear-gradient(90deg, ${riskInfo.color}, ${riskInfo.glow})`,
                  boxShadow: `0 0 10px ${riskInfo.glow}`,
                }}
              />
            </div>
          </div>
        </motion.div>

        {/* Domain Age */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-card border border-border rounded-xl p-4 shadow-sm relative overflow-hidden"
        >
          <div className={`absolute inset-0 bg-gradient-to-br ${domainAgeVisual.panel} to-transparent opacity-50`} />
          <div className="relative z-10">
            <div className="flex items-center gap-2 mb-3">
              <Calendar className={`w-4 h-4 ${domainAgeVisual.icon}`} />
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Domain Age
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <div className={`text-2xl font-bold ${domainAgeVisual.text}`}>{domainAge}</div>
                <div className="mt-1 flex items-center gap-2">
                  <span className={`text-xs font-semibold ${domainAgeVisual.text}`}>{effectiveDomainAgeContext.label}</span>
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${domainAgeVisual.chip}`}>
                    {domainAgeVisual.tone}
                  </span>
                </div>
              </div>
              {effectiveDomainAgeContext.bucket === "unknown" ? (
                <CircleHelp className={`w-5 h-5 ${domainAgeVisual.icon}`} />
              ) : modifier > 0 ? (
                <AlertTriangle className={`w-5 h-5 ${domainAgeVisual.icon}`} />
              ) : (
                <CheckCircle2 className={`w-5 h-5 ${domainAgeVisual.icon}`} />
              )}
            </div>
            <div className="mt-2 text-xs text-muted-foreground leading-relaxed">
              {effectiveDomainAgeContext.message}
            </div>
            <div className={`mt-1 text-[11px] font-semibold ${domainAgeVisual.text}`}>{modifierText}</div>
          </div>
        </motion.div>

        {/* SSL Status */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-card border border-border rounded-xl p-4 shadow-sm relative overflow-hidden"
        >
          <div className={`absolute inset-0 bg-gradient-to-br ${sslVisual.panel} to-transparent opacity-50`} />
          <div className="relative z-10">
            <div className="flex items-center gap-2 mb-3">
              {sslIsSafe ? (
                <Lock className={`w-4 h-4 ${sslVisual.icon}`} />
              ) : sslIsWarning ? (
                <AlertTriangle className={`w-4 h-4 ${sslVisual.icon}`} />
              ) : (
                <Unlock className={`w-4 h-4 ${sslVisual.icon}`} />
              )}
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                SSL Status
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <div className={`text-sm font-bold ${sslVisual.text}`}>{effectiveSslContext.label}</div>
                <div className="mt-1">
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${sslVisual.chip}`}>
                    {effectiveSslContext.badge}
                  </span>
                </div>
              </div>
              {sslIsSafe || sslIsTrustedNeutral ? (
                <CheckCircle2 className={`w-5 h-5 ${sslVisual.icon}`} />
              ) : sslIsWarning ? (
                <AlertTriangle className={`w-5 h-5 ${sslVisual.icon}`} />
              ) : (
                <XCircle className={`w-5 h-5 ${sslVisual.icon}`} />
              )}
            </div>
            <div className="mt-2 text-xs text-muted-foreground leading-relaxed">{effectiveSslContext.message}</div>
            <div className={`mt-1 text-[11px] font-semibold ${sslVisual.text}`}>
              {sslModifierText}
            </div>
            <div className="mt-1 text-[10px] text-muted-foreground truncate">Issuer: {sslIssuer}</div>
          </div>
        </motion.div>

        {/* Location Info */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-card border border-border rounded-xl p-4 shadow-sm relative overflow-hidden"
        >
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-50" />
          <div className="relative z-10">
            <div className="flex items-center gap-2 mb-3">
              <MapPin className="w-4 h-4 text-primary" />
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Location
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div className="text-sm font-bold text-primary flex items-center gap-2">
                <span>🏳️</span>
                <span>{location}</span>
              </div>
              <Globe className="w-5 h-5 text-primary/50" />
            </div>
            <div className="mt-2 text-xs text-muted-foreground">
              ISP: {isp}
            </div>
          </div>
        </motion.div>
      </div>

      {/* Threat Indicators */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="mb-6"
      >
        <div className="flex items-center gap-2 mb-3">
          <ShieldAlert className="w-4 h-4 text-destructive" />
          <span className="text-sm font-semibold text-foreground/80">Detected Threats</span>
          <span className="ml-auto text-xs bg-destructive/10 text-destructive px-2 py-1 rounded-full border border-destructive/20">
            {threatIndicators.filter(t => t.type === 'critical').length} Critical
          </span>
        </div>
        <div className="bg-muted/50 border border-border rounded-xl p-4 backdrop-blur-sm">
          <div className="space-y-2">
            {threatIndicators.map((threat, index) => (
              <motion.div
                key={threat.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.6 + index * 0.05 }}
                className={`flex items-start gap-3 p-3 rounded-lg border ${
                  threat.type === "critical"
                    ? "bg-destructive/5 border-destructive/20"
                    : threat.type === "warning"
                    ? "bg-warning/5 border-warning/20"
                    : "bg-safe/5 border-safe/20"
                }`}
              >
                <div className="flex-shrink-0 mt-0.5">
                  {threat.type === "critical" ? (
                    <XCircle className="w-4 h-4 text-destructive" />
                  ) : threat.type === "warning" ? (
                    <AlertTriangle className="w-4 h-4 text-warning" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-safe" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div
                    className={`text-sm font-semibold ${
                      threat.type === "critical"
                        ? "text-destructive"
                        : threat.type === "warning"
                        ? "text-warning"
                        : "text-safe"
                    }`}
                  >
                    {threat.label}
                  </div>
                  <div className="text-xs text-muted-foreground mt-0.5">{threat.description}</div>
                </div>
              </motion.div>
            ))}
            {threatIndicators.length === 0 && (
              <div className="text-xs text-muted-foreground">No explicit threat flags were triggered.</div>
            )}
          </div>
        </div>
      </motion.div>

      {/* Sandboxed Preview Window */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        className="mb-6"
      >
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Eye className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm font-semibold text-foreground/80">Sandboxed Preview</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Server className="w-3 h-3" />
            <span>Isolated Environment</span>
          </div>
        </div>
        <div className="bg-muted/50 border-2 border-border rounded-xl overflow-hidden backdrop-blur-sm relative">
          {/* Browser Chrome */}
          <div className="bg-muted border-b border-border px-4 py-2 flex items-center gap-3">
            <div className="flex gap-2">
              <div className="w-3 h-3 rounded-full bg-destructive/80" />
              <div className="w-3 h-3 rounded-full bg-warning/80" />
              <div className="w-3 h-3 rounded-full bg-safe/80" />
            </div>
            <div className="flex-1 bg-background/50 rounded-lg px-3 py-1.5 flex items-center gap-2">
              <Lock className="w-3 h-3 text-muted-foreground" />
              <span className="text-xs text-muted-foreground font-mono truncate">{url}</span>
            </div>
          </div>

          {/* Preview Content - Simulated Phishing Page */}
          <div className="relative bg-white p-8 min-h-[400px]">
            {/* Warning Overlay */}
            <div className="absolute inset-0 bg-gradient-to-b from-destructive/10 via-transparent to-transparent pointer-events-none" />
            
            {/* Simulated Login Form */}
            <div className="max-w-md mx-auto">
              <div className="text-center mb-6">
                <div className="w-16 h-16 bg-blue-600 rounded-lg mx-auto mb-4 flex items-center justify-center text-white text-2xl font-bold">
                  M
                </div>
                <h1 className="text-2xl font-semibold text-gray-900 mb-2">Sign in to your account</h1>
                <p className="text-sm text-gray-600">Enter your credentials to continue</p>
              </div>

              <div className="space-y-4 opacity-50 pointer-events-none">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                  <input
                    type="text"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg bg-white"
                    placeholder="user@example.com"
                    disabled
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                  <input
                    type="password"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg bg-white"
                    placeholder="••••••••"
                    disabled
                  />
                </div>
                <button className="w-full bg-blue-600 text-white py-2 rounded-lg font-medium">
                  Sign in
                </button>
              </div>

              {/* Warning Badge Overlay */}
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10">
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ delay: 0.8, type: "spring" }}
                  className="bg-destructive/95 backdrop-blur-md text-destructive-foreground px-6 py-4 rounded-xl shadow-2xl border-2 border-destructive"
                >
                  <div className="flex items-center gap-3">
                    <ShieldAlert className="w-8 h-8" />
                    <div>
                      <div className="font-bold text-lg">Preview Disabled</div>
                      <div className="text-sm opacity-90">High-risk phishing detected</div>
                    </div>
                  </div>
                </motion.div>
              </div>
            </div>

            {/* Watermark */}
            <div className="absolute bottom-4 right-4 text-xs text-gray-400 flex items-center gap-1">
              <Shield className="w-3 h-3" />
              <span>SpectraShield Protected</span>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Advanced Details (Expandable) */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.8 }}
        className="mb-6"
      >
        <button
          onClick={() => toggleSection("advanced")}
          className="w-full flex items-center justify-between p-4 bg-card hover:bg-muted/50 border border-border rounded-xl transition-colors"
        >
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm font-semibold text-foreground/80">Advanced Technical Details</span>
          </div>
          <ChevronDown
            className={`w-4 h-4 text-muted-foreground transition-transform ${
              expandedSection === "advanced" ? "rotate-180" : ""
            }`}
          />
        </button>
        <AnimatePresence>
          {expandedSection === "advanced" && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="overflow-hidden"
            >
              <div className="grid grid-cols-2 gap-4 p-4 bg-muted/30 border border-border border-t-0 rounded-b-xl">
                <div>
                  <div className="text-xs text-muted-foreground mb-1">IP Address</div>
                  <div className="text-sm text-foreground/80 font-mono">{ipAddress}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Page Title</div>
                  <div className="text-sm text-foreground/80 font-mono truncate">{pageTitle}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Redirect Hops</div>
                  <div className="text-sm text-foreground/80 font-mono">{redirectHops}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Registrar</div>
                  <div className="text-sm text-foreground/80 font-mono truncate">{registrar || "Unknown"}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground mb-1">DNS A</div>
                  <div className="text-sm text-foreground/80 font-mono break-all">{dnsA.length ? dnsA.join(", ") : "N/A"}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground mb-1">DNS MX</div>
                  <div className="text-sm text-foreground/80 font-mono break-all">{dnsMX.length ? dnsMX.join(", ") : "N/A"}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground mb-1">SSL Expiry</div>
                  <div className="text-sm text-foreground/80 font-mono break-all">{sslExpiry}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Triggered Heuristics</div>
                  <div className="text-sm text-foreground/80 font-mono break-all">
                    {riskBreakdown?.logic_flags && riskBreakdown.logic_flags.length
                      ? riskBreakdown.logic_flags.join(", ")
                      : "None"}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Action Buttons */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.9 }}
        className="flex gap-3"
      >
        <button className="flex-1 bg-destructive/10 hover:bg-destructive/20 border-2 border-destructive/30 hover:border-destructive/50 text-destructive px-6 py-3 rounded-xl font-semibold transition-all flex items-center justify-center gap-2 group">
          <Ban className="w-5 h-5 group-hover:rotate-12 transition-transform" />
          Block & Report
        </button>
        <button className="flex-1 bg-card hover:bg-muted border-2 border-border hover:border-foreground/20 text-foreground/80 px-6 py-3 rounded-xl font-semibold transition-all flex items-center justify-center gap-2 group">
          <ExternalLink className="w-5 h-5 group-hover:translate-x-1 group-hover:-translate-y-1 transition-transform" />
          Open Anyway (Unsafe)
        </button>
      </motion.div>
    </div>
  );
};

export default LinkPreview;