import React, { useState, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  NodeProps,
  Handle,
  Position,
  BackgroundVariant,
  Node,
  Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Mail,
  User,
  Globe,
  Link2,
  Server,
  Shield,
  Radio,
  Users,
  X,
  Activity,
  Layers,
  Info,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  HelpCircle,
} from "lucide-react";
import { ThreatGraphData, ThreatGraphNode } from "../../../types/investigation";

interface Props {
  graphData: ThreatGraphData;
}

// Node state helper for styling: Trusted (emerald), Suspicious (amber), Malicious (red), Unknown (slate)
type NodeState = "Trusted" | "Suspicious" | "Malicious" | "Unknown";

const getNodeState = (node: ThreatGraphNode): { state: NodeState; color: string; bg: string; border: string } => {
  if (node.type === "email" && node.riskScore < 30) {
    return { state: "Trusted", color: "#10B981", bg: "rgba(16, 185, 129, 0.12)", border: "rgba(16, 185, 129, 0.4)" };
  }
  if (node.riskScore >= 70) {
    return { state: "Malicious", color: "#EF4444", bg: "rgba(239, 68, 68, 0.15)", border: "rgba(239, 68, 68, 0.5)" };
  }
  if (node.riskScore >= 30) {
    return { state: "Suspicious", color: "#F59E0B", bg: "rgba(245, 158, 11, 0.12)", border: "rgba(245, 158, 11, 0.4)" };
  }
  return { state: "Unknown", color: "#94A3B8", bg: "rgba(148, 163, 184, 0.1)", border: "rgba(148, 163, 184, 0.3)" };
};

const nodeTypeIcons: Record<string, React.FC<{ className?: string }>> = {
  email: Mail,
  sender: User,
  domain: Globe,
  url: Link2,
  ip: Server,
  asn: Shield,
  hosting: Radio,
  threat_actor: ShieldAlert,
};

const CustomGraphNode: React.FC<NodeProps> = ({ data, selected }) => {
  const d = data as unknown as ThreatGraphNode;
  const stateCfg = getNodeState(d);
  const IconComp = nodeTypeIcons[d.type] || Mail;

  return (
    <div
      className={`px-3.5 py-2.5 rounded-xl border transition-all cursor-pointer min-w-[170px] shadow-lg ${
        selected ? "ring-2 ring-cyan-400 shadow-cyan-500/20" : ""
      }`}
      style={{
        background: "rgba(10, 16, 32, 0.95)",
        borderColor: selected ? "#00E5FF" : stateCfg.border,
        backdropFilter: "blur(16px)",
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: stateCfg.color, width: 6, height: 6 }} />
      <div className="flex items-center gap-2 mb-1.5">
        <div className="w-5 h-5 rounded-md flex items-center justify-center" style={{ background: stateCfg.bg }}>
          <IconComp className="w-3 h-3" style={{ color: stateCfg.color } as any} />
        </div>
        <span className="text-[10px] font-mono uppercase tracking-wider font-bold" style={{ color: stateCfg.color }}>
          {d.type.replace("_", " ")}
        </span>
        <span
          className="ml-auto text-[9px] font-mono font-bold px-1.5 py-0.2 rounded"
          style={{ color: stateCfg.color, background: stateCfg.bg }}
        >
          {stateCfg.state}
        </span>
      </div>
      <div className="text-xs font-bold text-white truncate max-w-[180px]">
        {d.label}
      </div>
      <div className="text-[10px] font-mono text-slate-400 truncate max-w-[180px]">
        {d.sublabel}
      </div>
      <Handle type="source" position={Position.Right} style={{ background: stateCfg.color, width: 6, height: 6 }} />
    </div>
  );
};

export const ThreatGraphTab: React.FC<Props> = ({ graphData }) => {
  const [selectedNode, setSelectedNode] = useState<ThreatGraphNode | null>(null);

  const nodeTypes = useMemo(() => ({ customNode: CustomGraphNode }), []);

  // Hierarchical node layout:
  // [EMAIL] -> [SENDER DOMAIN] -> [SUSPICIOUS URL] -> [IP ADDRESS] -> [HOSTING ASN]
  const initialNodes: Node[] = useMemo(() => {
    const layoutPositions: Record<string, { x: number; y: number }> = {
      email_1: { x: 40, y: 150 },
      sender_1: { x: 270, y: 60 },
      domain_1: { x: 270, y: 240 },
      url_1: { x: 500, y: 150 },
      ip_1: { x: 730, y: 80 },
      asn_1: { x: 730, y: 240 },
      hosting_1: { x: 960, y: 150 },
      threat_intel_1: { x: 960, y: 280 },
    };

    return graphData.nodes.map((n, idx) => ({
      id: n.id,
      type: "customNode",
      position: layoutPositions[n.id] || { x: 60 + (idx % 4) * 230, y: 80 + Math.floor(idx / 4) * 140 },
      data: n as any,
    }));
  }, [graphData.nodes]);

  const initialEdges: Edge[] = useMemo(() => {
    return graphData.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: true,
      style: { stroke: "#00E5FF", strokeWidth: 1.5, opacity: 0.8 },
      labelStyle: { fill: "#38BDF8", fontSize: 9, fontFamily: "monospace", fontWeight: "bold" },
      labelBgStyle: { fill: "rgba(10, 16, 32, 0.95)", fillOpacity: 0.95 },
      labelBgPadding: [4, 2] as [number, number],
      labelBgBorderRadius: 4,
    }));
  }, [graphData.edges]);

  // ─── Empty State: No campaign graph available ─────────────────────────────
  if (!graphData.hasCampaignGraph || graphData.nodes.length === 0) {
    return (
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl border border-white/5 bg-white/2">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-slate-500" />
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              Threat Infrastructure Graph
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-600">
            Campaign: {graphData.campaignName || "UNATTRIBUTED"}
          </span>
        </div>
        <div className="w-full h-64 rounded-2xl border border-slate-700/40 bg-slate-900/40 flex flex-col items-center justify-center gap-4 text-center px-8">
          <HelpCircle className="w-10 h-10 text-slate-600" />
          <div className="space-y-1">
            <div className="text-sm font-mono font-bold text-slate-400">
              No Campaign Graph Available for This Investigation
            </div>
            <p className="text-xs text-slate-500 max-w-sm leading-relaxed">
              This investigation is not associated with a tracked threat campaign. No infrastructure
              graph has been constructed for this case.
            </p>
          </div>
          <span className="text-[10px] font-mono text-slate-700 px-3 py-1 rounded-full border border-slate-700/40 bg-slate-900/60">
            STATUS: NO_CAMPAIGN_CLUSTER
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Top Banner & Status Legend */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl border border-white/5 bg-white/2">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
            {graphData.campaignName?.toLowerCase().includes("campaign") ? "Campaign Threat Cluster" : "Investigation Infrastructure Graph"}
          </span>
          <span className="text-slate-600">·</span>
          <span className="text-xs font-mono text-cyan-300">
            {graphData.campaignName || "UNATTRIBUTED"}
          </span>
        </div>

        {/* Node States Legend */}
        <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 flex-wrap">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500" /> Malicious
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400" /> Suspicious
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400" /> Trusted
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-slate-400" /> Unknown
          </span>
        </div>
      </div>

      {/* Main Canvas & Detail Panel */}
      <div className="relative w-full h-[520px] rounded-2xl border border-cyan-500/20 overflow-hidden bg-[#070b14] shadow-2xl">
        <ReactFlow
          nodes={initialNodes}
          edges={initialEdges}
          nodeTypes={nodeTypes}
          onNodeClick={(_, node) => setSelectedNode(node.data as unknown as ThreatGraphNode)}
          fitView
          attributionPosition="bottom-left"
        >
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#1E293B" />
          <Controls className="!bg-[#0A1223] !border !border-cyan-500/20 !rounded-xl text-white" />
          <MiniMap
            nodeColor="#00E5FF"
            maskColor="rgba(5, 7, 13, 0.8)"
            className="!bg-[#0A1223] !border !border-cyan-500/20 !rounded-xl"
          />
        </ReactFlow>

        {/* Right-Side Node Intelligence Detail Panel */}
        {selectedNode && (
          <div
            className="absolute top-4 right-4 bottom-4 w-80 rounded-2xl border border-cyan-500/30 p-5 overflow-y-auto flex flex-col justify-between shadow-2xl z-30"
            style={{
              background: "rgba(10, 16, 32, 0.98)",
              backdropFilter: "blur(24px)",
            }}
          >
            <div>
              <div className="flex items-center justify-between gap-2 pb-3 mb-3 border-b border-white/8">
                <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" />
                  Node Intelligence
                </span>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="text-sm font-bold text-white mb-0.5">
                {selectedNode.label}
              </div>
              <div className="text-xs font-mono text-cyan-300/80 mb-3 break-all">
                {selectedNode.sublabel}
              </div>

              <div className="flex items-center gap-2 mb-4">
                <span className="text-xs font-mono text-slate-400">Node Risk Score:</span>
                <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-red-500/15 text-red-300 border border-red-500/30">
                  {selectedNode.riskScore} / 100
                </span>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
                  Entity Attributes:
                </div>
                {Object.entries(selectedNode.properties || {}).map(([k, v]) => (
                  <div key={k} className="p-2 rounded-lg bg-white/2 border border-white/5 flex justify-between gap-2">
                    <span className="text-slate-400">{k}:</span>
                    <span className="text-slate-200 font-semibold truncate">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-white/8 text-[11px] font-mono text-slate-500 text-center">
              Click another node or drag to inspect relationships
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
