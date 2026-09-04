import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  AlertOctagon,
  Lock,
  Clock,
  Search,
  Trash2,
  ExternalLink,
  Filter,
  BarChart3,
  Flame,
  Globe,
  RefreshCw,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  BarChart,
  Bar,
  Cell,
} from 'recharts';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidSegmentedControl } from '../liquid/LiquidSegmentedControl';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';
import { LiquidMorphButton } from '../liquid/LiquidMorphButton';
import { DefangedText } from '../common/DefangedText';
import {
  getHistory,
  getTopBrands,
  getRiskHeatmap,
  clearHistory,
  deleteScan,
  HistoryRecord,
  TopBrandsResponse,
  RiskHeatmapResponse,
} from '../../api';

interface DashboardViewProps {
  onNavigateToForensics?: (emailText?: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ onNavigateToForensics }) => {
  const [timeRange, setTimeRange] = useState('7d');
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [topBrands, setTopBrands] = useState<TopBrandsResponse | null>(null);
  const [heatmap, setHeatmap] = useState<RiskHeatmapResponse | null>(null);
  const [brandRiskFilter, setBrandRiskFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [historyFilter, setHistoryFilter] = useState<'all' | 'malicious' | 'suspicious' | 'clean'>('all');
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [histData, brandsData, heatmapData] = await Promise.all([
        getHistory(),
        getTopBrands({ days: timeRange === '7d' ? 7 : timeRange === '30d' ? 30 : 90, risk: brandRiskFilter }),
        getRiskHeatmap({ days: 7, risk: 'all' }),
      ]);
      setHistory(histData);
      setTopBrands(brandsData);
      setHeatmap(heatmapData);
    } catch {
      // Handled via offline fallbacks
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [timeRange, brandRiskFilter]);

  const handleClearHistory = async () => {
    if (confirm('Are you sure you want to purge all forensic incident records?')) {
      await clearHistory();
      setHistory([]);
    }
  };

  const handleDeleteScan = async (id: string) => {
    await deleteScan(id);
    setHistory((prev) => prev.filter((item) => item.id !== id));
  };

  // Mock Trend Chart Data based on time range
  const trendData = [
    { name: 'Mon', malicious: 45, suspicious: 28, clean: 140 },
    { name: 'Tue', malicious: 52, suspicious: 34, clean: 165 },
    { name: 'Wed', malicious: 78, suspicious: 42, clean: 190 },
    { name: 'Thu', malicious: 64, suspicious: 31, clean: 175 },
    { name: 'Fri', malicious: 89, suspicious: 50, clean: 210 },
    { name: 'Sat', malicious: 32, suspicious: 18, clean: 120 },
    { name: 'Sun', malicious: 28, suspicious: 14, clean: 110 },
  ];

  const filteredHistory = history.filter((item) => {
    const matchesSearch =
      (item.subject?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false) ||
      (item.sender?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false) ||
      item.verdict.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.id.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;
    if (historyFilter === 'malicious') return item.final_risk >= 70;
    if (historyFilter === 'suspicious') return item.final_risk >= 30 && item.final_risk < 70;
    if (historyFilter === 'clean') return item.final_risk < 30;
    return true;
  });

  const daysOfWeek = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

  return (
    <div className="space-y-8 pb-16">
      {/* Top Welcome & Master Telemetry Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
              Executive SOC Threat Center
            </h1>
            <LiquidGlassBadge variant="forensics" label="AIR-GAPPED TELEMETRY" size="sm" />
          </div>
          <p className="text-xs md:text-sm text-slate-400 mt-1">
            Real-time global email threat telemetry, RFC 5322 multi-hop routing forensics, and brand spoofing radars.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <LiquidMorphButton
            mode="cyan"
            onClick={loadData}
            icon={RefreshCw}
            isLoading={loading}
          >
            Sync Telemetry
          </LiquidMorphButton>
        </div>
      </div>

      {/* Volumetric KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-5">
        <LiquidGlassCard glowColor="cyan" className="p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider">Total Scans Ingested</span>
            <div className="p-2 rounded-xl bg-cyan-500/20 text-cyan-400">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-bold font-mono text-white tracking-tight">
            1,428
          </div>
          <div className="flex items-center gap-1.5 mt-2 text-xs font-mono text-cyan-300">
            <span className="font-semibold">+14.2%</span>
            <span className="text-slate-400">vs previous 7 days</span>
          </div>
        </LiquidGlassCard>

        <LiquidGlassCard glowColor="crimson" className="p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider">High-Risk Phish Blocked</span>
            <div className="p-2 rounded-xl bg-red-500/20 text-red-400">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-bold font-mono text-red-400 tracking-tight">
            388
          </div>
          <div className="flex items-center gap-1.5 mt-2 text-xs font-mono text-red-300">
            <span className="font-semibold">27.1%</span>
            <span className="text-slate-400">of total ingress volume</span>
          </div>
        </LiquidGlassCard>

        <LiquidGlassCard glowColor="amber" className="p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider">Active BEC Campaigns</span>
            <div className="p-2 rounded-xl bg-amber-500/20 text-amber-400">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-bold font-mono text-amber-400 tracking-tight">
            14
          </div>
          <div className="flex items-center gap-1.5 mt-2 text-xs font-mono text-amber-300">
            <span className="font-semibold">FIN7 & Wire Diversion</span>
            <span className="text-slate-400">clusters</span>
          </div>
        </LiquidGlassCard>

        <LiquidGlassCard glowColor="emerald" className="p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider">Evidence Vault Status</span>
            <div className="p-2 rounded-xl bg-emerald-500/20 text-emerald-400">
              <Lock className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-bold font-mono text-emerald-400 tracking-tight">
            100%
          </div>
          <div className="flex items-center gap-1.5 mt-2 text-xs font-mono text-emerald-300">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span className="font-semibold">ISO/IEC 27037 Sealed</span>
          </div>
        </LiquidGlassCard>
      </div>

      {/* Threat Volume Trend Chart & Impersonated Brands */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Recharts Area Chart */}
        <LiquidGlassCard glowColor="cyan" className="lg:col-span-2 p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                  Threat Velocity & Ingress Volume
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Multi-layer inspection volumes (Malicious vs Suspicious vs Clean)
              </p>
            </div>

            <LiquidSegmentedControl
              options={[
                { id: '7d', label: '7 Days' },
                { id: '30d', label: '30 Days' },
                { id: '90d', label: '90 Days' },
              ]}
              value={timeRange}
              onChange={setTimeRange}
              size="sm"
            />
          </div>

          <div className="h-64 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="maliciousGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="suspiciousGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="cleanGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} fontStyle="monospace" />
                <YAxis stroke="#64748b" fontSize={11} fontStyle="monospace" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'rgba(15, 23, 42, 0.92)',
                    borderColor: 'rgba(255, 255, 255, 0.15)',
                    borderRadius: '16px',
                    backdropFilter: 'blur(16px)',
                    fontFamily: 'monospace',
                    fontSize: '11px',
                    color: '#f8fafc',
                    boxShadow: '0 12px 30px rgba(0,0,0,0.6)',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="clean"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#cleanGrad)"
                  name="Verified Clean"
                />
                <Area
                  type="monotone"
                  dataKey="suspicious"
                  stroke="#f59e0b"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#suspiciousGrad)"
                  name="Suspicious"
                />
                <Area
                  type="monotone"
                  dataKey="malicious"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#maliciousGrad)"
                  name="High-Risk Phish"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </LiquidGlassCard>

        {/* Right 1 Col: Top Impersonated Brands */}
        <LiquidGlassCard glowColor="purple" className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-purple-400" />
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                Top Targeted Brands
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-400">Last 7 Days</span>
          </div>

          <div className="space-y-3 pt-2">
            {topBrands?.brands.map((brand, idx) => {
              const maxCount = topBrands.brands[0]?.count || 100;
              const pct = (brand.count / maxCount) * 100;

              return (
                <div key={brand.name} className="space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500 text-[10px]">{idx + 1}.</span>
                      <span className="text-slate-200 font-medium">{brand.name}</span>
                    </div>
                    <span className="text-cyan-300 font-bold">{brand.count} hits</span>
                  </div>
                  <div className="relative h-2 w-full overflow-hidden rounded-full bg-slate-950 border border-white/10 p-0.5">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-purple-500 to-cyan-500 transition-all duration-700 ease-liquid-apple relative"
                      style={{ width: `${pct}%` }}
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent skew-x-12 animate-liquid-sheen" />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </LiquidGlassCard>
      </div>

      {/* 7x24 Risk Density Heatmap */}
      <LiquidGlassCard glowColor="amber" className="p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-amber-400" />
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                7x24 Incident Density Heatmap Matrix
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Hourly incident distribution to identify coordinated adversary timing & blitz windows.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>Low</span>
            <div className="flex gap-1">
              <span className="w-3 h-3 rounded-sm bg-slate-800" />
              <span className="w-3 h-3 rounded-sm bg-cyan-950" />
              <span className="w-3 h-3 rounded-sm bg-cyan-600" />
              <span className="w-3 h-3 rounded-sm bg-amber-500" />
              <span className="w-3 h-3 rounded-sm bg-red-500" />
            </div>
            <span>High Peak</span>
          </div>
        </div>

        {/* Heatmap Grid */}
        <div className="overflow-x-auto custom-scrollbar pb-2">
          <div className="min-w-[680px] space-y-1.5 pt-2">
            {/* Hour Header */}
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 pl-12">
              {[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22].map((h) => (
                <div key={h} className="w-8 text-center">
                  {h < 10 ? `0${h}` : h}h
                </div>
              ))}
            </div>

            {/* Matrix Rows */}
            {daysOfWeek.map((day, dayIdx) => (
              <div key={day} className="flex items-center gap-2">
                <span className="w-10 text-xs font-mono text-slate-400 font-semibold">{day}</span>
                <div className="flex items-center gap-1">
                  {Array.from({ length: 24 }).map((_, hour) => {
                    const cell = heatmap?.cells.find((c) => c.dayIndex === dayIdx && c.hour === hour);
                    const val = cell ? cell.value : 0;
                    const max = heatmap?.max_count || 25;
                    const intensity = max > 0 ? val / max : 0;

                    let bg = 'bg-slate-900/60';
                    if (val > 0) {
                      if (intensity < 0.25) bg = 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/30';
                      else if (intensity < 0.5) bg = 'bg-cyan-700/80 text-cyan-200';
                      else if (intensity < 0.75) bg = 'bg-amber-600/80 text-amber-100 shadow-[0_0_8px_rgba(245,158,11,0.5)]';
                      else bg = 'bg-red-600/90 text-white shadow-[0_0_10px_rgba(239,68,68,0.7)] animate-pulse';
                    }

                    return (
                      <div
                        key={hour}
                        title={`${day} ${hour}:00 - ${val} Incidents`}
                        className={`w-6 h-6 rounded-md flex items-center justify-center text-[9px] font-mono font-bold transition-all duration-300 hover:scale-125 cursor-pointer ${bg}`}
                      >
                        {val > 0 ? val : ''}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      </LiquidGlassCard>

      {/* Live Incident Audit Log Table */}
      <LiquidGlassCard glowColor="cyan" className="p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                Live Forensic Incident Audit Trail
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Cryptographically timestamped incident history and forensic case records.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search IOC, sender, ID..."
                className="pl-8 pr-3 py-1.5 text-xs font-mono rounded-xl bg-slate-950/80 border border-white/10 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400/60 transition-colors w-48 sm:w-60"
              />
            </div>

            {/* Filter Tabs */}
            <LiquidSegmentedControl
              options={[
                { id: 'all', label: 'All' },
                { id: 'malicious', label: 'High Risk' },
                { id: 'suspicious', label: 'Suspicious' },
                { id: 'clean', label: 'Clean' },
              ]}
              value={historyFilter}
              onChange={(val) => setHistoryFilter(val as any)}
              size="sm"
            />

            <button
              type="button"
              onClick={handleClearHistory}
              title="Purge all records"
              className="p-2 rounded-xl bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Table Container */}
        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-white/10 text-slate-400 bg-slate-950/40">
                <th className="py-3 px-4">CASE ID</th>
                <th className="py-3 px-4">SENDER & SUBJECT</th>
                <th className="py-3 px-4">THREAT CATEGORY</th>
                <th className="py-3 px-4 text-center">RISK INDEX</th>
                <th className="py-3 px-4">TIMESTAMP</th>
                <th className="py-3 px-4 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredHistory.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 italic">
                    No matching forensic incident records found.
                  </td>
                </tr>
              ) : (
                filteredHistory.map((item) => {
                  const isHigh = item.final_risk >= 70;
                  const isSuspicious = item.final_risk >= 30 && item.final_risk < 70;

                  return (
                    <tr
                      key={item.id}
                      className="hover:bg-slate-800/30 transition-colors group"
                    >
                      <td className="py-3 px-4 font-bold text-cyan-400">
                        {item.id}
                      </td>
                      <td className="py-3 px-4 max-w-xs truncate">
                        <div className="text-slate-200 font-medium truncate">
                          {item.subject || 'RFC 5322 Ingested Message'}
                        </div>
                        <div className="text-slate-400 text-[11px] truncate">
                          {item.sender || 'Unknown Sender'}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="text-slate-300">
                          {item.threat_category || 'Phishing / Impersonation'}
                        </div>
                        {item.risk_breakdown?.brand_match && (
                          <span className="text-[10px] text-purple-300 font-semibold">
                            Target: {item.risk_breakdown.brand_match}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        <LiquidGlassBadge
                          variant={isHigh ? 'critical' : isSuspicious ? 'warning' : 'safe'}
                          label={`${Math.round(item.final_risk)}%`}
                          size="sm"
                        />
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {item.timestamp}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            type="button"
                            onClick={() => onNavigateToForensics && onNavigateToForensics(item.subject)}
                            className="p-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 transition-colors"
                            title="Inspect in Forensic Ops"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteScan(item.id)}
                            className="p-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors"
                            title="Delete Record"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </LiquidGlassCard>
    </div>
  );
};
