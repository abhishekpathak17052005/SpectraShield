import React, { useState } from "react";
import { motion } from "motion/react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Cpu,
  Layers,
  Radio,
  ArrowRight,
  Activity,
} from "lucide-react";

interface ThreatActivityFieldProps {
  engineOnline: boolean;
  highRiskCount: number;
  suspiciousCount: number;
  safeCount: number;
  totalCount: number;
  openCasesCount: number;
  onNavigate: (route: string) => void;
}

export const ThreatActivityField: React.FC<ThreatActivityFieldProps> = ({
  engineOnline,
  highRiskCount,
  suspiciousCount,
  safeCount,
  totalCount,
  openCasesCount,
  onNavigate,
}) => {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const nodes = [
    {
      id: "high_risk",
      title: "Critical / High Risk",
      count: highRiskCount,
      subtitle: "Requires immediate triage",
      color: "red",
      icon: ShieldAlert,
      glow: "rgba(239, 68, 68, 0.4)",
      borderColor: "border-red-500/40",
      textColor: "text-red-400",
      bgColor: "bg-red-500/10",
      badgeColor: "bg-red-500/20 text-red-300 border-red-500/30",
      route: "/investigations",
    },
    {
      id: "suspicious",
      title: "Suspicious Activity",
      count: suspiciousCount,
      subtitle: "Heuristic anomalies",
      color: "amber",
      icon: AlertTriangle,
      glow: "rgba(245, 158, 11, 0.35)",
      borderColor: "border-amber-500/40",
      textColor: "text-amber-400",
      bgColor: "bg-amber-500/10",
      badgeColor: "bg-amber-500/20 text-amber-300 border-amber-500/30",
      route: "/investigations",
    },
    {
      id: "safe",
      title: "Verified Clean",
      count: safeCount,
      subtitle: "DKIM & SPF valid",
      color: "emerald",
      icon: ShieldCheck,
      glow: "rgba(16, 185, 129, 0.3)",
      borderColor: "border-emerald-500/40",
      textColor: "text-emerald-400",
      bgColor: "bg-emerald-500/10",
      badgeColor: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
      route: "/investigations",
    },
    {
      id: "pipeline",
      title: "Vault / Pipeline",
      count: totalCount,
      subtitle: `${openCasesCount} active cases`,
      color: "cyan",
      icon: Layers,
      glow: "rgba(6, 182, 212, 0.35)",
      borderColor: "border-cyan-500/40",
      textColor: "text-cyan-400",
      bgColor: "bg-cyan-500/10",
      badgeColor: "bg-cyan-500/20 text-cyan-300 border-cyan-500/30",
      route: "/investigations",
    },
  ];

  return (
    <div className="relative rounded-2xl border border-cyan-500/20 bg-gradient-to-b from-[#0c1222]/90 via-[#090e1c]/90 to-[#070b16]/95 overflow-hidden shadow-2xl p-5 md:p-6">
      {/* Background Subtle Radar Grid */}
      <div 
        className="pointer-events-none absolute inset-0 opacity-20"
        style={{
          backgroundImage: "radial-gradient(circle at 50% 50%, rgba(6, 182, 212, 0.15) 0%, transparent 65%)",
        }}
      />

      {/* Header bar of the security field */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-white/5 relative z-10">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Radio className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white tracking-wide uppercase flex items-center gap-2">
              <span>Threat Activity Security Field</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-normal">
                REAL-TIME TELEMETRY
              </span>
            </h2>
            <p className="text-[11px] text-slate-400">
              Live synchronized forensic cluster connected to SpectraShield engine
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Engine Heartbeat:</span>
          <span className="font-mono text-emerald-400 flex items-center gap-1.5 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <span>ACTIVE 127.0.0.1:8000</span>
          </span>
        </div>
      </div>

      {/* 2.5D Radar / Field Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center mt-5 relative z-10">
        {/* Left Side: 2 Satellite Nodes */}
        <div className="lg:col-span-4 space-y-3.5 order-2 lg:order-1">
          {nodes.slice(0, 2).map((node) => {
            const Icon = node.icon;
            const isHovered = hoveredNode === node.id;

            return (
              <motion.div
                key={node.id}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={() => onNavigate(node.route)}
                whileHover={{ scale: 1.015, x: 2 }}
                transition={{ duration: 0.15 }}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer backdrop-blur-md relative overflow-hidden group ${
                  isHovered
                    ? `${node.borderColor} shadow-lg shadow-${node.color}-500/10 bg-[#121b33]/90`
                    : "border-white/10 bg-[#0d1426]/70 hover:border-white/20"
                }`}
              >
                {/* Node Top Glow */}
                <div
                  className="absolute top-0 left-0 right-0 h-[1px] opacity-40 group-hover:opacity-100 transition-opacity"
                  style={{ background: `linear-gradient(90deg, transparent, ${node.color}, transparent)` }}
                />

                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <div className={`p-2 rounded-lg ${node.bgColor} ${node.textColor} border ${node.borderColor} flex-shrink-0`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-slate-200 group-hover:text-white transition-colors">
                        {node.title}
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5">
                        {node.subtitle}
                      </div>
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <div className={`text-xl font-bold font-mono ${node.textColor}`}>
                      {node.count}
                    </div>
                  </div>
                </div>

                {/* Micro tracer footer */}
                <div className="mt-2.5 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-slate-400">
                  <span className="flex items-center gap-1 font-mono">
                    <span className={`w-1.5 h-1.5 rounded-full ${node.count > 0 ? "bg-" + node.color + "-400" : "bg-slate-500"}`} />
                    <span>{node.count > 0 ? "Active incidents" : "Clear"}</span>
                  </span>
                  <span className="flex items-center gap-0.5 text-cyan-400 group-hover:translate-x-0.5 transition-transform">
                    <span>Inspect</span>
                    <ArrowRight className="w-3 h-3" />
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Center: 2.5D Circular Security Core */}
        <div className="lg:col-span-4 flex flex-col items-center justify-center py-4 relative order-1 lg:order-2">
          {/* Concentric Rotating Rings */}
          <div className="relative w-48 h-48 sm:w-56 sm:h-56 flex items-center justify-center">
            {/* Outer Orbit Ring */}
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 40, ease: "linear" }}
              className="absolute inset-0 rounded-full border border-dashed border-cyan-500/20"
            />

            {/* Middle Orbit Ring */}
            <motion.div
              animate={{ rotate: -360 }}
              transition={{ repeat: Infinity, duration: 25, ease: "linear" }}
              className="absolute inset-4 rounded-full border border-cyan-400/25"
              style={{
                borderLeftColor: "transparent",
                borderRightColor: "transparent",
              }}
            />

            {/* Inner Glowing Ring */}
            <div className="absolute inset-10 rounded-full border border-cyan-400/30 bg-gradient-to-tr from-cyan-950/40 via-blue-950/50 to-slate-900/60 shadow-[0_0_30px_rgba(6,182,212,0.15)] flex flex-col items-center justify-center p-4 text-center backdrop-blur-md">
              {/* Pulsing Central Chip */}
              <div className="relative mb-1">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/30 to-blue-600/40 border border-cyan-400/50 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                  <Cpu className="w-5 h-5 text-cyan-300" />
                </div>
                <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
              </div>

              <div className="text-[11px] font-bold tracking-wider text-white uppercase">
                SpectraCore
              </div>
              <div className="text-[9px] font-mono text-cyan-300/80">
                {engineOnline ? "ONLINE 8000" : "RECONNECTING"}
              </div>

              <div className="mt-1 px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-[9px] font-mono text-slate-300">
                {totalCount} Total Cases
              </div>
            </div>

            {/* Orbiting Satellite Dots */}
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 12, ease: "linear" }}
              className="absolute inset-2 pointer-events-none"
            >
              <span className="absolute top-0 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,1)]" />
            </motion.div>

            <motion.div
              animate={{ rotate: -360 }}
              transition={{ repeat: Infinity, duration: 16, ease: "linear" }}
              className="absolute inset-6 pointer-events-none"
            >
              <span className="absolute bottom-0 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-blue-400 shadow-[0_0_8px_rgba(96,165,250,1)]" />
            </motion.div>
          </div>
        </div>

        {/* Right Side: 2 Satellite Nodes */}
        <div className="lg:col-span-4 space-y-3.5 order-3">
          {nodes.slice(2, 4).map((node) => {
            const Icon = node.icon;
            const isHovered = hoveredNode === node.id;

            return (
              <motion.div
                key={node.id}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={() => onNavigate(node.route)}
                whileHover={{ scale: 1.015, x: -2 }}
                transition={{ duration: 0.15 }}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer backdrop-blur-md relative overflow-hidden group ${
                  isHovered
                    ? `${node.borderColor} shadow-lg shadow-${node.color}-500/10 bg-[#121b33]/90`
                    : "border-white/10 bg-[#0d1426]/70 hover:border-white/20"
                }`}
              >
                {/* Node Top Glow */}
                <div
                  className="absolute top-0 left-0 right-0 h-[1px] opacity-40 group-hover:opacity-100 transition-opacity"
                  style={{ background: `linear-gradient(90deg, transparent, ${node.color}, transparent)` }}
                />

                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <div className={`p-2 rounded-lg ${node.bgColor} ${node.textColor} border ${node.borderColor} flex-shrink-0`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-slate-200 group-hover:text-white transition-colors">
                        {node.title}
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5">
                        {node.subtitle}
                      </div>
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <div className={`text-xl font-bold font-mono ${node.textColor}`}>
                      {node.count}
                    </div>
                  </div>
                </div>

                {/* Micro tracer footer */}
                <div className="mt-2.5 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-slate-400">
                  <span className="flex items-center gap-1 font-mono">
                    <span className={`w-1.5 h-1.5 rounded-full ${node.count > 0 ? "bg-" + node.color + "-400" : "bg-slate-500"}`} />
                    <span>{node.count > 0 ? "Telemetry verified" : "No records"}</span>
                  </span>
                  <span className="flex items-center gap-0.5 text-cyan-400 group-hover:translate-x-0.5 transition-transform">
                    <span>Explore</span>
                    <ArrowRight className="w-3 h-3" />
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
