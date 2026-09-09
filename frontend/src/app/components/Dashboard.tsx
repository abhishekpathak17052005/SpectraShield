import React, { useState, useEffect, useId } from "react";
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
  Eye,
  Ban,
  Clock,
  BarChart3,
} from "lucide-react";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { getDashboardHeatmap, getDashboardTopBrands, getHistory } from "../api";

// Mock data for charts
const weeklyDetectionData = [
  { day: "Mon", detected: 234, blocked: 198 },
  { day: "Tue", detected: 456, blocked: 412 },
  { day: "Wed", detected: 389, blocked: 356 },
  { day: "Thu", detected: 512, blocked: 487 },
  { day: "Fri", detected: 678, blocked: 621 },
  { day: "Sat", detected: 289, blocked: 267 },
  { day: "Sun", detected: 198, blocked: 184 },
];

const threatTrendData = [
  { month: "Jan", phishing: 1245, malware: 432, spoofing: 789 },
  { month: "Feb", phishing: 1567, malware: 523, spoofing: 891 },
  { month: "Mar", phishing: 1423, malware: 498, spoofing: 834 },
  { month: "Apr", phishing: 1789, malware: 612, spoofing: 967 },
  { month: "May", phishing: 2134, malware: 734, spoofing: 1123 },
  { month: "Jun", phishing: 2456, malware: 823, spoofing: 1289 },
];

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

// Risk heatmap data (7 days x 24 hours)
const generateHeatmapData = () => {
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const hours = Array.from({ length: 24 }, (_, i) => i);
  const data: { day: string; dayIndex: number; hour: number; value: number }[] = [];

  days.forEach((day, dayIndex) => {
    hours.forEach((hour) => {
      const value = Math.floor(Math.random() * 100);
      data.push({ day, dayIndex, hour, value });
    });
  });

  return data;
};

const heatmapData = generateHeatmapData();

const Dashboard: React.FC = () => {
  const [timeRange, setTimeRange] = useState<"7d" | "30d" | "90d">("7d");
  const { resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [brands, setBrands] = useState(impersonatedBrands);
  const [liveHeatmap, setLiveHeatmap] = useState(heatmapData);
  const [stats, setStats] = useState({
    totalDetections: 2756, blockedThreats: 2525, avgRiskScore: 84,
    activeThreats: 12, detectionChange: 23.5, blockRate: 91.6,
  });
  const uid = useId();
  const gradDetected = `${uid}-detected`;
  const gradBlocked = `${uid}-blocked`;

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    const days = timeRange === "7d" ? 7 : timeRange === "30d" ? 30 : 90;
    Promise.all([getHistory(), getDashboardTopBrands(days), getDashboardHeatmap(days)])
      .then(([history, topBrands, heatmap]) => {
        if (history.length) {
          const scores = history.map((item) => Number(item.final_risk ?? 0));
          const blocked = scores.filter((score) => score >= 70).length;
          setStats({
            totalDetections: scores.length,
            blockedThreats: blocked,
            avgRiskScore: Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length),
            activeThreats: new Set(history.map((item) => item.verdict ?? "unknown")).size,
            detectionChange: 0,
            blockRate: Math.round((blocked / scores.length) * 1000) / 10,
          });
        }
        if (topBrands.brands.length) {
          setBrands(topBrands.brands.map((brand, index) => ({
            ...brand,
            color: impersonatedBrands[index % impersonatedBrands.length].color,
          })));
        }
        if (heatmap.cells.length) {
          setLiveHeatmap(heatmap.cells.map((cell) => ({
            day: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][cell.dayIndex] ?? "Sun",
            dayIndex: cell.dayIndex,
            hour: cell.hour,
            value: cell.value,
          })));
        }
      })
      .catch(() => {
        // Keep the dashboard's local data when the backend is unavailable.
      });
  }, [timeRange]);

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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Total Detections */}
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
              <div className="text-xs text-muted-foreground uppercase tracking-wider">Total Detections</div>
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
              <h3 className="text-lg font-semibold text-foreground">Weekly Phishing Detection</h3>
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
                <linearGradient id={gradDetected} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.primary} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.primary} stopOpacity={0} />
                </linearGradient>
                <linearGradient id={gradBlocked} x1="0" y1="0" x2="0" y2="1">
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
                fill={`url(#${gradDetected})`}
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke={colors.safe}
                strokeWidth={2}
                fillOpacity={1}
                fill={`url(#${gradBlocked})`}
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
            {brands.slice(0, 6).map((brand, index) => (
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
                      animate={{ width: `${(brand.count / brands[0].count) * 100}%` }}
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
            {["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((day, dayIndex) => (
              <div key={day} className="flex items-center gap-2">
                <span className="text-[10px] text-muted-foreground w-8">{day}</span>
                <div className="flex gap-0.5 flex-1">
                  {Array.from({ length: 24 }).map((_, hour) => {
                    const dataPoint = liveHeatmap.find(
                      (d) => d.dayIndex === dayIndex && d.hour === hour
                    );
                    return (
                      <div
                        key={hour}
                        className="flex-1 h-5 rounded-sm transition-all hover:scale-110 cursor-pointer"
                        style={{
                          backgroundColor: getHeatmapColor(dataPoint?.value || 0),
                          border: `1px solid ${colors.grid}`,
                        }}
                        title={`${day} ${hour}:00 - Risk: ${dataPoint?.value || 0}`}
                      />
                    );
                  })}
                </div>
              </div>
            ))}
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
              <h3 className="text-lg font-semibold text-foreground">Threat Trends (6 Months)</h3>
            </div>
            <div className="flex gap-4 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-destructive" />
                <span className="text-muted-foreground">Phishing</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-warning" />
                <span className="text-muted-foreground">Malware</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-primary" />
                <span className="text-muted-foreground">Spoofing</span>
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
                dataKey="phishing"
                stroke={colors.danger}
                strokeWidth={2}
                dot={{ fill: colors.danger, r: 4 }}
                activeDot={{ r: 6 }}
              />
              <Line
                type="monotone"
                dataKey="malware"
                stroke={colors.warning}
                strokeWidth={2}
                dot={{ fill: colors.warning, r: 4 }}
                activeDot={{ r: 6 }}
              />
              <Line
                type="monotone"
                dataKey="spoofing"
                stroke={colors.primary}
                strokeWidth={2}
                dot={{ fill: colors.primary, r: 4 }}
                activeDot={{ r: 6 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      {/* Flagged Domains Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.0 }}
        className="bg-card border border-border rounded-xl p-6 shadow-sm"
      >
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Database className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-semibold text-foreground">Recent Flagged Domains</h3>
          </div>
          <button className="text-xs text-primary hover:text-primary/80 transition-colors flex items-center gap-1">
            View All
            <Eye className="w-3 h-3" />
          </button>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Domain
                </th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Risk Score
                </th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Threats
                </th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  First Seen
                </th>
                <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Status
                </th>
                <th className="text-right py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {flaggedDomains.map((domain, index) => (
                <motion.tr
                  key={domain.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 1.1 + index * 0.05 }}
                  className="border-b border-border hover:bg-muted/30 transition-colors"
                >
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm font-mono text-foreground/80">{domain.domain}</span>
                    </div>
                  </td>
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-2">
                      <div
                        className="text-sm font-bold"
                        style={{ color: getRiskColor(domain.riskScore) }}
                      >
                        {domain.riskScore}
                      </div>
                      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${domain.riskScore}%`,
                            backgroundColor: getRiskColor(domain.riskScore),
                          }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="py-4 px-4">
                    <span className="inline-flex items-center gap-1 px-2 py-1 bg-destructive/10 border border-destructive/20 rounded-md text-xs text-destructive font-semibold">
                      <AlertTriangle className="w-3 h-3" />
                      {domain.threats}
                    </span>
                  </td>
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Clock className="w-3 h-3" />
                      {domain.firstSeen}
                    </div>
                  </td>
                  <td className="py-4 px-4">
                    <span
                      className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-semibold ${
                        domain.status === "blocked"
                          ? "bg-destructive/10 border border-destructive/20 text-destructive"
                          : "bg-warning/10 border border-warning/20 text-warning"
                      }`}
                    >
                      {domain.status === "blocked" ? "Blocked" : "Monitoring"}
                    </span>
                  </td>
                  <td className="py-4 px-4 text-right">
                    <button className="text-primary hover:text-primary/80 transition-colors text-xs font-medium">
                      View Details →
                    </button>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>
    </div>
  );
};

export default Dashboard;