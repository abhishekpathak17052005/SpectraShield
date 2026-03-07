import React, { useState, useEffect, useMemo } from "react";
import { motion } from "motion/react";
import { useTheme } from "next-themes";
import {
  TrendingUp,
  Shield,
  AlertTriangle,
  Activity,
  Calendar,
  Database,
  Globe,
  Ban,
  Clock,
  BarChart3,
  Trash2,
} from "lucide-react";
import { getHistory, deleteScan, clearHistory, type HistoryRecord } from "../api";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

// Parse ISO timestamps and legacy "YYYY-MM-DD HH:MM:SS" into Date.
const parseTimestamp = (ts: string): Date | null => {
  if (!ts) return null;

  const direct = new Date(ts);
  if (Number.isFinite(direct.getTime())) return direct;

  const [d, t] = ts.split(" ");
  const [y, mo, day] = (d || "").split("-").map(Number);
  const [h, m, s] = (t || "0:0:0").split(":").map(Number);
  const parsed = new Date(y, (mo || 1) - 1, day || 1, h || 0, m || 0, s || 0);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
};

const DAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTH_LABELS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const getDaysForRange = (range: "7d" | "30d" | "90d"): number => {
  if (range === "30d") return 30;
  if (range === "90d") return 90;
  return 7;
};

const isWithinLastNDays = (date: Date, days: number, now: Date): boolean => {
  const start = new Date(now);
  start.setHours(0, 0, 0, 0);
  start.setDate(start.getDate() - (days - 1));
  return date >= start && date <= now;
};

const impersonatedBrands = [
  { name: "Microsoft", count: 1234, color: "#00A4EF" },
  { name: "PayPal", count: 987, color: "#0070BA" },
  { name: "Amazon", count: 856, color: "#FF9900" },
  { name: "Apple", count: 745, color: "#A2AAAD" },
  { name: "Google", count: 623, color: "#4285F4" },
  { name: "Netflix", count: 512, color: "#E50914" },
  { name: "Facebook", count: 489, color: "#1877F2" },
  { name: "LinkedIn", count: 367, color: "#0A66C2" },
];

const flaggedDomains = [
  {
    id: 1,
    domain: "secure-microsoft-verify.tk",
    riskScore: 94,
    threats: 8,
    firstSeen: "2 hours ago",
    status: "blocked",
  },
  {
    id: 2,
    domain: "paypal-security-update.xyz",
    riskScore: 91,
    threats: 7,
    firstSeen: "4 hours ago",
    status: "blocked",
  },
  {
    id: 3,
    domain: "amazon-delivery-track.ru",
    riskScore: 87,
    threats: 6,
    firstSeen: "6 hours ago",
    status: "monitoring",
  },
  {
    id: 4,
    domain: "apple-id-suspended.net",
    riskScore: 89,
    threats: 7,
    firstSeen: "8 hours ago",
    status: "blocked",
  },
  {
    id: 5,
    domain: "google-account-recovery.ml",
    riskScore: 92,
    threats: 8,
    firstSeen: "10 hours ago",
    status: "blocked",
  },
  {
    id: 6,
    domain: "banking-verify-identity.ga",
    riskScore: 88,
    threats: 6,
    firstSeen: "12 hours ago",
    status: "monitoring",
  },
];


type RiskFilter = "all" | "low" | "medium" | "high";

const Dashboard: React.FC = () => {
  const [timeRange, setTimeRange] = useState<"7d" | "30d" | "90d">("7d");
  const { resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    getHistory()
      .then((records) => {
        setHistory(records);
      })
      .catch(() => setHistory([]))
      .finally(() => setHistoryLoading(false));
  }, []);

  const handleDeleteScan = (scanId: string) => {
    deleteScan(scanId)
      .then(() => setHistory((prev) => prev.filter((r) => r.id !== scanId)))
      .catch(() => {});
  };

  const handleClearAll = () => {
    setClearing(true);
    clearHistory()
      .then(() => setHistory([]))
      .catch(() => {})
      .finally(() => setClearing(false));
  };

  const rangeHistory = useMemo(() => {
    const daysToInclude = getDaysForRange(timeRange);
    const now = new Date();
    return history.filter((r) => {
      const parsed = parseTimestamp(r.timestamp);
      if (!parsed) return false;
      return isWithinLastNDays(parsed, daysToInclude, now);
    });
  }, [history, timeRange]);

  const filteredHistory = useMemo(() => {
    if (riskFilter === "all") return rangeHistory;

    return rangeHistory.filter((r) => {
      if (riskFilter === "low") return r.final_risk < 35;
      if (riskFilter === "medium") return r.final_risk >= 35 && r.final_risk < 70;
      return r.final_risk >= 70;
    });
  }, [rangeHistory, riskFilter]);

  const weeklyDetectionData = useMemo(() => {
    const daysToInclude = getDaysForRange(timeRange);
    const days = Array.from({ length: daysToInclude }, (_, i) => {
      const d = new Date();
      d.setDate(d.getDate() - (daysToInclude - 1 - i));
      return d;
    });

    return days.map((d) => {
      const dayKey = d.toISOString().slice(0, 10);
      const dayLabel = daysToInclude <= 14
        ? `${DAY_LABELS[d.getDay()]} ${d.getDate()}`
        : `${d.getDate()} ${MONTH_LABELS[d.getMonth()]}`;

      const onDay = rangeHistory.filter((r) => {
        const t = parseTimestamp(r.timestamp);
        return !!t && t.toISOString().slice(0, 10) === dayKey;
      });
      const detected = onDay.length;
      const blocked = onDay.filter((r) => r.final_risk >= 70).length;
      return { day: dayLabel, dateKey: dayKey, detected, blocked };
    });
  }, [rangeHistory, timeRange]);

  const heatmapData = useMemo(() => {
    const grid: number[][] = Array(7).fill(null).map(() => Array(24).fill(0));
    rangeHistory.forEach((r) => {
      const t = parseTimestamp(r.timestamp);
      if (!t) return;
      const dayIndex = t.getDay();
      const hour = t.getHours();
      grid[dayIndex][hour] += 1;
    });
    const data: { day: string; dayIndex: number; hour: number; value: number }[] = [];
    DAY_LABELS.forEach((day, dayIndex) => {
      for (let hour = 0; hour < 24; hour++) {
        data.push({ day, dayIndex, hour, value: grid[dayIndex][hour] });
      }
    });
    return data;
  }, [rangeHistory]);

  const threatTrendData = useMemo(() => {
    const daysToInclude = getDaysForRange(timeRange);
    const days = Array.from({ length: daysToInclude }, (_, i) => {
      const d = new Date();
      d.setDate(d.getDate() - (daysToInclude - 1 - i));
      return d;
    });

    return days.map((d) => {
      const dayKey = d.toISOString().slice(0, 10);
      const label = daysToInclude <= 14
        ? DAY_LABELS[d.getDay()]
        : `${d.getDate()} ${MONTH_LABELS[d.getMonth()]}`;
      const inDay = rangeHistory.filter((r) => {
        const t = parseTimestamp(r.timestamp);
        return !!t && t.toISOString().slice(0, 10) === dayKey;
      });

      const high = inDay.filter((r) => r.final_risk >= 70).length;
      const medium = inDay.filter((r) => r.final_risk >= 35 && r.final_risk < 70).length;
      const low = inDay.filter((r) => r.final_risk < 35).length;
      return { month: label, monthKey: dayKey, high, medium, low };
    });
  }, [rangeHistory, timeRange]);

  const recentActivityChartData = useMemo(() => {
    return weeklyDetectionData.map(({ day, detected }) => ({ day, scans: detected }));
  }, [weeklyDetectionData]);

  // Theme colors for charts
  const colors = {
    safe: mounted && resolvedTheme === "light" ? "#16A34A" : "#00FFAA",
    warning: mounted && resolvedTheme === "light" ? "#F59E0B" : "#FFA500",
    danger: mounted && resolvedTheme === "light" ? "#DC2626" : "#FF3B3B",
    primary: mounted && resolvedTheme === "light" ? "#0F172A" : "#F8FAFC",
    grid: mounted && resolvedTheme === "light" ? "#E2E8F0" : "#1E293B",
    text: mounted && resolvedTheme === "light" ? "#64748B" : "#94A3B8",
    tooltipBg: mounted && resolvedTheme === "light" ? "#FFFFFF" : "#1E293B",
    tooltipBorder: mounted && resolvedTheme === "light" ? "#E2E8F0" : "#334155",
  };

  // Statistics from backend history
  const totalDetections = rangeHistory.length;
  const blockedThreats = rangeHistory.filter((r) => r.final_risk >= 70).length;
  const highRiskPct = totalDetections > 0 ? Math.round((blockedThreats / totalDetections) * 100) : 0;
  const avgRiskScore = totalDetections > 0
    ? Math.round(rangeHistory.reduce((s, r) => s + r.final_risk, 0) / totalDetections)
    : 0;
  const blockRate = totalDetections > 0 ? Math.round((blockedThreats / totalDetections) * 1000) / 10 : 0;
  const systemStatus = highRiskPct >= 50 ? "Critical" : highRiskPct >= 20 ? "Elevated" : "Stable";
  const stats = {
    totalDetections,
    blockedThreats,
    avgRiskScore,
    highRiskPct,
    activeThreats: rangeHistory.filter((r) => r.final_risk >= 70).length,
    detectionChange: 0,
    blockRate,
    systemStatus,
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return colors.danger;
    if (score >= 50) return colors.warning;
    return colors.safe;
  };

  const getHeatmapColor = (value: number) => {
    // Hex to RGB for opacity handling would be better, but approximating with strings
    if (value < 20) return `${colors.safe}20`; // 10-20% opacity
    if (value < 40) return `${colors.safe}50`;
    if (value < 60) return `${colors.warning}60`;
    if (value < 80) return `${colors.danger}80`;
    return colors.danger;
  };

  return (
    <div className="w-full min-h-screen bg-background text-foreground p-8 overflow-auto transition-colors duration-300">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/30 blur-xl rounded-full" />
              <Shield className="w-10 h-10 text-primary relative z-10" />
            </div>
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-foreground via-primary to-muted-foreground bg-clip-text text-transparent">
                SpectraShield AI Analytics
              </h1>
              <p className="text-sm text-muted-foreground mt-1">Real-time threat intelligence dashboard</p>
            </div>
          </div>

          {/* Time Range Selector */}
          <div className="flex gap-2 bg-muted/50 border border-border rounded-xl p-1 backdrop-blur-sm">
            {(["7d", "30d", "90d"] as const).map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                  timeRange === range
                    ? "bg-primary/10 text-primary border border-primary/20"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {range === "7d" ? "7 Days" : range === "30d" ? "30 Days" : "90 Days"}
              </button>
            ))}
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {/* System Status */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className={`relative bg-card border rounded-xl p-6 shadow-sm overflow-hidden group transition-all ${
              stats.systemStatus === "Critical" ? "border-destructive/50" : stats.systemStatus === "Elevated" ? "border-warning/50" : "border-safe/50"
            } border-border`}
          >
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-3">
                <Shield className={`w-5 h-5 ${stats.systemStatus === "Critical" ? "text-destructive" : stats.systemStatus === "Elevated" ? "text-warning" : "text-safe"}`} />
                {stats.systemStatus === "Critical" && <div className="w-2 h-2 rounded-full bg-destructive animate-pulse" />}
              </div>
              <div className="text-2xl font-bold text-foreground mb-1">{stats.systemStatus}</div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider">System Status</div>
            </div>
          </motion.div>

          {/* Total Scans */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="relative bg-card border border-border rounded-xl p-6 shadow-sm overflow-hidden group hover:border-primary/50 transition-all"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-3">
                <Activity className="w-5 h-5 text-primary" />
                <div className="flex items-center gap-1 text-xs">
                  <TrendingUp className="w-3 h-3 text-safe" />
                  <span className="text-safe font-semibold">+{stats.detectionChange}%</span>
                </div>
              </div>
              <div className="text-3xl font-bold text-foreground mb-1">
                {stats.totalDetections.toLocaleString()}
              </div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider">Total Scans</div>
            </div>
          </motion.div>

          {/* Blocked Threats */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="relative bg-card border border-border rounded-xl p-6 shadow-sm overflow-hidden group hover:border-safe/50 transition-all"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-safe/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-3">
                <Ban className="w-5 h-5 text-safe" />
                <div className="text-xs">
                  <span className="text-safe font-semibold">{stats.blockRate}%</span>
                  <span className="text-muted-foreground ml-1">rate</span>
                </div>
              </div>
              <div className="text-3xl font-bold text-foreground mb-1">
                {stats.blockedThreats.toLocaleString()}
              </div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider">Blocked Threats</div>
            </div>
          </motion.div>

          {/* Avg Risk Score */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="relative bg-card border border-border rounded-xl p-6 shadow-sm overflow-hidden group hover:border-destructive/50 transition-all"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-destructive/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-3">
                <BarChart3 className="w-5 h-5 text-destructive" />
                <div className="text-xs">
                  <span className="text-destructive font-semibold">High</span>
                </div>
              </div>
              <div className="text-3xl font-bold text-foreground mb-1">{stats.avgRiskScore}</div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider">Avg Risk Score</div>
            </div>
          </motion.div>

          {/* High Risk % */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35 }}
            className="relative bg-card border border-border rounded-xl p-6 shadow-sm overflow-hidden group hover:border-destructive/50 transition-all"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-destructive/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-3">
                <AlertTriangle className="w-5 h-5 text-destructive" />
                <span className="text-destructive font-semibold text-sm">{stats.highRiskPct}%</span>
              </div>
              <div className="text-3xl font-bold text-foreground mb-1">{stats.highRiskPct}%</div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider">High Risk %</div>
            </div>
          </motion.div>

          {/* Active Threats */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="relative bg-card border border-border rounded-xl p-6 shadow-sm overflow-hidden group hover:border-warning/50 transition-all"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-warning/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-3">
                <AlertTriangle className="w-5 h-5 text-warning" />
                <div className="w-2 h-2 rounded-full bg-warning animate-pulse" />
              </div>
              <div className="text-3xl font-bold text-foreground mb-1">{stats.activeThreats}</div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider">Active Threats</div>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Weekly Detection Graph - Spans 2 columns */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="lg:col-span-2 bg-card border border-border rounded-xl p-6 shadow-sm"
        >
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <Activity className="w-5 h-5 text-primary" />
              <h3 className="text-lg font-semibold text-foreground">Phishing Detection ({getDaysForRange(timeRange)} Days)</h3>
            </div>
            <div className="flex gap-4 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-sm bg-primary" />
                <span className="text-muted-foreground">Detected</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-sm bg-safe" />
                <span className="text-muted-foreground">Blocked</span>
              </div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={weeklyDetectionData}>
              <defs>
                <linearGradient id="colorDetected" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.primary} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.primary} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.safe} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.safe} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} opacity={0.5} />
              <XAxis dataKey="day" stroke={colors.text} style={{ fontSize: "12px" }} />
              <YAxis stroke={colors.text} style={{ fontSize: "12px" }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: colors.tooltipBg,
                  border: `1px solid ${colors.tooltipBorder}`,
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: colors.text
                }}
              />
              <Area
                type="monotone"
                dataKey="detected"
                stroke={colors.primary}
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorDetected)"
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke={colors.safe}
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorBlocked)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Most Impersonated Brands */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="bg-card border border-border rounded-xl p-6 shadow-sm"
        >
          <div className="flex items-center gap-3 mb-6">
            <Globe className="w-5 h-5 text-destructive" />
            <h3 className="text-lg font-semibold text-foreground">Top Impersonated Brands</h3>
          </div>
          <div className="space-y-3">
            {impersonatedBrands.slice(0, 6).map((brand, index) => (
              <motion.div
                key={brand.name}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.7 + index * 0.05 }}
                className="flex items-center gap-3"
              >
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-foreground/80">{brand.name}</span>
                    <span className="text-xs text-muted-foreground">{brand.count}</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(brand.count / impersonatedBrands[0].count) * 100}%` }}
                      transition={{ duration: 1, delay: 0.7 + index * 0.05 }}
                      className="h-full rounded-full"
                      style={{
                        backgroundColor: brand.color,
                        boxShadow: `0 0 10px ${brand.color}40`,
                      }}
                    />
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Second Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Risk Heatmap */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
          className="bg-card border border-border rounded-xl p-6 shadow-sm"
        >
          <div className="flex items-center gap-3 mb-6">
            <Calendar className="w-5 h-5 text-warning" />
            <h3 className="text-lg font-semibold text-foreground">Risk Heatmap</h3>
          </div>
          <div className="space-y-1">
            {(() => {
              const maxHeat = Math.max(1, ...heatmapData.map((d) => d.value));
              return DAY_LABELS.map((day, dayIndex) => (
                <div key={day} className="flex items-center gap-2">
                  <span className="text-[10px] text-muted-foreground w-8">{day}</span>
                  <div className="flex gap-0.5 flex-1">
                    {Array.from({ length: 24 }).map((_, hour) => {
                      const dataPoint = heatmapData.find(
                        (d) => d.dayIndex === dayIndex && d.hour === hour
                      );
                      const count = dataPoint?.value ?? 0;
                      const normalized = maxHeat > 0 ? (count / maxHeat) * 100 : 0;
                      return (
                        <div
                          key={hour}
                          className="flex-1 h-5 rounded-sm transition-all hover:scale-110 cursor-pointer"
                          style={{
                            backgroundColor: getHeatmapColor(normalized),
                            border: `1px solid ${colors.grid}`,
                          }}
                          title={`${day} ${hour}:00 - Scans: ${count}`}
                        />
                      );
                    })}
                  </div>
                </div>
              ));
            })()}
          </div>
        </motion.div>

        {/* Threat Trend Lines - Spans 2 columns */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.9 }}
          className="lg:col-span-2 bg-card border border-border rounded-xl p-6 shadow-sm"
        >
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <TrendingUp className="w-5 h-5 text-safe" />
              <h3 className="text-lg font-semibold text-foreground">Threat Trends ({getDaysForRange(timeRange)} Days)</h3>
            </div>
            <div className="flex gap-4 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-destructive" />
                <span className="text-muted-foreground">High</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-warning" />
                <span className="text-muted-foreground">Medium</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-safe" />
                <span className="text-muted-foreground">Low</span>
              </div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={threatTrendData}>
              <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} opacity={0.5} />
              <XAxis dataKey="month" stroke={colors.text} style={{ fontSize: "12px" }} />
              <YAxis stroke={colors.text} style={{ fontSize: "12px" }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: colors.tooltipBg,
                  border: `1px solid ${colors.tooltipBorder}`,
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: colors.text
                }}
              />
              <Line
                type="monotone"
                dataKey="high"
                stroke={colors.danger}
                strokeWidth={2}
                dot={{ fill: colors.danger, r: 4 }}
                activeDot={{ r: 6 }}
              />
              <Line
                type="monotone"
                dataKey="medium"
                stroke={colors.warning}
                strokeWidth={2}
                dot={{ fill: colors.warning, r: 4 }}
                activeDot={{ r: 6 }}
              />
              <Line
                type="monotone"
                dataKey="low"
                stroke={colors.safe}
                strokeWidth={2}
                dot={{ fill: colors.safe, r: 4 }}
                activeDot={{ r: 6 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      {/* Recent Scans (from backend history) */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.0 }}
        className="bg-card border border-border rounded-xl p-6 shadow-sm"
      >
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Database className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-semibold text-foreground">Recent Activity</h3>
          </div>
          <div className="flex items-center gap-3">
            <label className="text-sm text-muted-foreground">Risk:</label>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value as RiskFilter)}
              aria-label="Filter scans by risk"
              title="Filter scans by risk"
              className="bg-muted/50 border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
            >
              <option value="all">All</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
            <button
              onClick={handleClearAll}
              disabled={history.length === 0 || clearing}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium bg-destructive/10 text-destructive border border-destructive/30 hover:bg-destructive/20 disabled:opacity-50 disabled:pointer-events-none"
            >
              <Trash2 className="w-4 h-4" />
              {clearing ? "Clearing..." : "Clear all scanning data"}
            </button>
          </div>
        </div>

        {recentActivityChartData.some((d) => d.scans > 0) && (
          <div className="mb-6">
            <h4 className="text-sm font-medium text-muted-foreground mb-3">Scans over last {getDaysForRange(timeRange)} days</h4>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={recentActivityChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke={colors.grid} opacity={0.5} />
                <XAxis dataKey="day" stroke={colors.text} style={{ fontSize: "11px" }} />
                <YAxis stroke={colors.text} style={{ fontSize: "11px" }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: colors.tooltipBg,
                    border: `1px solid ${colors.tooltipBorder}`,
                    borderRadius: "8px",
                    fontSize: "12px",
                    color: colors.text
                  }}
                />
                <Bar dataKey="scans" fill={colors.primary} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        <div className="overflow-x-auto">
          {historyLoading ? (
            <div className="py-8 text-center text-muted-foreground text-sm">Loading scan history...</div>
          ) : filteredHistory.length === 0 ? (
            <div className="py-8 text-center text-muted-foreground text-sm">
              {rangeHistory.length === 0
                ? `No scans found in the selected time range (${timeRange === "7d" ? "7 Days" : timeRange === "30d" ? "30 Days" : "90 Days"}).`
                : history.length === 0
                ? "No scans yet. Run an analysis from the popup view."
                : `No scans match the selected risk filter (${riskFilter}).`}
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Scan ID</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Risk Score</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Verdict</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Threat Category</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Confidence</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Time</th>
                  <th className="text-right py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredHistory.map((record, index) => (
                  <motion.tr
                    key={record.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.1 + index * 0.03 }}
                    className="border-b border-border hover:bg-muted/30 transition-colors"
                  >
                    <td className="py-4 px-4">
                      <span className="text-sm font-mono text-foreground/80">{record.id}</span>
                    </td>
                    <td className="py-4 px-4">
                      <div className="flex items-center gap-2">
                        <div
                          className="text-sm font-bold"
                          style={{ color: getRiskColor(record.final_risk) }}
                        >
                          {Math.round(record.final_risk)}
                        </div>
                        <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${record.final_risk}%`,
                              backgroundColor: getRiskColor(record.final_risk),
                            }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-4 px-4 text-sm text-foreground/80">{record.verdict}</td>
                    <td className="py-4 px-4 text-xs text-foreground/80">{record.threat_category ?? "—"}</td>
                    <td className="py-4 px-4 text-xs text-muted-foreground">{record.confidence_level}</td>
                    <td className="py-4 px-4">
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Clock className="w-3 h-3" />
                        {record.timestamp}
                      </div>
                    </td>
                    <td className="py-4 px-4 text-right">
                      <button
                        onClick={() => handleDeleteScan(record.id)}
                        className="text-destructive hover:text-destructive/80 transition-colors text-xs font-medium inline-flex items-center gap-1"
                      >
                        <Trash2 className="w-3 h-3" />
                        Delete
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>
    </div>
  );
};

export default Dashboard;