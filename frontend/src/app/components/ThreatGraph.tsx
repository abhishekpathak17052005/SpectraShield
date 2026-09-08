import React, { useState, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  Handle,
  Position,
  NodeProps,
  BackgroundVariant,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Mail, Globe, Server, Users, Shield, ShieldAlert, Sparkles, RefreshCw, X } from "lucide-react";
import { getCampaignGraph, getSyndicateCommunities, type SyndicateCommunity } from "../api";

// ─── Node type definitions ─────────────────────────────────────────────────
type NodeKind = "email" | "ip" | "domain" | "asn" | "threat-actor" | "case" | "victim";

interface NodeData {
  label: string;
  kind: NodeKind;
  detail?: string;
  [key: string]: unknown;
}

const kindConfig: Record<NodeKind, { icon: React.FC<{ className?: string; style?: React.CSSProperties }>; borderColor: string; bgColor: string; textColor: string }> = {
  email: { icon: Mail, borderColor: "rgba(0,229,255,0.5)", bgColor: "rgba(0,229,255,0.08)", textColor: "#00e5ff" },
  ip: { icon: Server, borderColor: "rgba(245,158,11,0.5)", bgColor: "rgba(245,158,11,0.08)", textColor: "#f59e0b" },
  domain: { icon: Globe, borderColor: "rgba(239,68,68,0.5)", bgColor: "rgba(239,68,68,0.08)", textColor: "#ef4444" },
  asn: { icon: Shield, borderColor: "rgba(124,58,237,0.5)", bgColor: "rgba(124,58,237,0.08)", textColor: "#a78bfa" },
  "threat-actor": { icon: Users, borderColor: "rgba(239,68,68,0.7)", bgColor: "rgba(239,68,68,0.12)", textColor: "#f87171" },
  case: { icon: ShieldAlert, borderColor: "rgba(59,130,246,0.5)", bgColor: "rgba(59,130,246,0.08)", textColor: "#60a5fa" },
  victim: { icon: Users, borderColor: "rgba(16,185,129,0.5)", bgColor: "rgba(16,185,129,0.08)", textColor: "#34d399" },
};

// ─── Custom glass node ─────────────────────────────────────────────────────
const GlassNode: React.FC<NodeProps> = ({ data, selected }) => {
  const d = (data || {}) as NodeData;
  const rawKind = (d.kind || (d as any).type || "email") as NodeKind;
  const cfg = kindConfig[rawKind] ?? kindConfig.email;
  const IconComp = cfg.icon;
  const kindLabel = String(rawKind).replace("-", " ");

  return (
    <div
      className="relative rounded-xl px-4 py-3 min-w-36 cursor-pointer transition-all"
      style={{
        background: "rgba(10,18,35,0.94)",
        border: `1px solid ${selected ? cfg.textColor : cfg.borderColor}`,
        backdropFilter: "blur(16px)",
        boxShadow: selected ? `0 0 20px ${cfg.bgColor}, 0 0 40px ${cfg.bgColor}` : `0 0 8px ${cfg.bgColor}`,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: cfg.textColor, border: "none", width: 8, height: 8 }} />
      <div className="flex items-center gap-2 mb-1">
        <div className="w-6 h-6 rounded-md flex items-center justify-center"
          style={{ background: cfg.bgColor, border: `1px solid ${cfg.borderColor}` }}>
          <IconComp className="w-3.5 h-3.5" style={{ color: cfg.textColor }} />
        </div>
        <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: cfg.textColor }}>
          {kindLabel}
        </span>
      </div>
      <div className="text-xs font-semibold text-white truncate max-w-40">{d.label || "Entity"}</div>
      {d.detail && <div className="text-[10px] text-slate-500 mt-0.5 truncate max-w-40">{d.detail}</div>}
      <Handle type="source" position={Position.Right} style={{ background: cfg.textColor, border: "none", width: 8, height: 8 }} />
    </div>
  );
};

const nodeTypes = { glass: GlassNode };

// ─── Default seed graph ────────────────────────────────────────────────────
const defaultNodes = [
  { id: "ta1", type: "glass", position: { x: 0, y: 150 }, data: { label: "APT-FIN7 / Storm-0829", kind: "threat-actor", detail: "origin: RU · Active" } },
  { id: "d1", type: "glass", position: { x: 240, y: 50 }, data: { label: "microsoft-verify.tk", kind: "domain", detail: "Reg: 12 days ago" } },
  { id: "d2", type: "glass", position: { x: 240, y: 280 }, data: { label: "corpupdate-hr.net", kind: "domain", detail: "Reg: 3 days ago" } },
  { id: "ip1", type: "glass", position: { x: 500, y: 50 }, data: { label: "185.220.101.34", kind: "ip", detail: "Tor exit · RU" } },
  { id: "ip2", type: "glass", position: { x: 500, y: 280 }, data: { label: "45.77.220.195", kind: "ip", detail: "VPS · AWS US-EAST" } },
  { id: "asn1", type: "glass", position: { x: 750, y: 165 }, data: { label: "AS60694 MivoCloud", kind: "asn", detail: "Bulletproof host" } },
  { id: "e1", type: "glass", position: { x: 1000, y: 50 }, data: { label: "victim-corp.com", kind: "email", detail: "3 emails received" } },
  { id: "e2", type: "glass", position: { x: 1000, y: 280 }, data: { label: "finance@corp.com", kind: "email", detail: "BEC target" } },
];

const defaultEdges = [
  { id: "e1", source: "ta1", target: "d1", animated: true, style: { stroke: "#ef4444", strokeWidth: 1.5 }, label: "controls" },
  { id: "e2", source: "ta1", target: "d2", animated: true, style: { stroke: "#ef4444", strokeWidth: 1.5 }, label: "controls" },
  { id: "e3", source: "d1", target: "ip1", animated: true, style: { stroke: "#f59e0b", strokeWidth: 1.5 }, label: "resolves to" },
  { id: "e4", source: "d2", target: "ip2", animated: true, style: { stroke: "#f59e0b", strokeWidth: 1.5 }, label: "resolves to" },
  { id: "e5", source: "ip1", target: "asn1", style: { stroke: "#a78bfa", strokeWidth: 1 } },
  { id: "e6", source: "ip2", target: "asn1", style: { stroke: "#a78bfa", strokeWidth: 1 } },
  { id: "e7", source: "ip1", target: "e1", animated: true, style: { stroke: "#00e5ff", strokeWidth: 1.5 }, label: "sends to" },
  { id: "e8", source: "ip2", target: "e2", animated: true, style: { stroke: "#00e5ff", strokeWidth: 1.5 }, label: "sends to" },
];

const defaultCampaigns = [
  { id: "CAMP-0234", name: "Microsoft Wave Q3-26" },
  { id: "CAMP-0228", name: "HR Credential Harvest" },
  { id: "CAMP-0219", name: "Netflix Billing Sweep" },
];

// ─── Main ThreatGraph Component ─────────────────────────────────────────────
const ThreatGraph: React.FC = () => {
  const [nodes, setNodes, onNodesChange] = useNodesState(defaultNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(defaultEdges);
  const [activeItem, setActiveItem] = useState("CAMP-0234");
  const [syndicates, setSyndicates] = useState<SyndicateCommunity[]>([]);
  const [modularityScore, setModularityScore] = useState<number>(0.6033);
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [loading, setLoading] = useState(false);

  // Load Louvain Syndicates
  useEffect(() => {
    getSyndicateCommunities().then((res) => {
      if (res && res.syndicates && res.syndicates.length > 0) {
        setSyndicates(res.syndicates);
        if (res.modularity_score) {
          setModularityScore(res.modularity_score);
        }
      }
    }).catch(() => {});
  }, []);

  // Load Graph for active campaign / syndicate
  useEffect(() => {
    setLoading(true);
    getCampaignGraph(activeItem)
      .then((graph) => {
        if (!graph?.nodes?.length) return;
        setNodes(graph.nodes.map((node: any, idx: number) => ({
          ...node,
          type: "glass",
          position: {
            x: typeof node?.position?.x === "number" ? node.position.x : ((idx % 4) * 260 + 80),
            y: typeof node?.position?.y === "number" ? node.position.y : (Math.floor(idx / 4) * 160 + 80),
          },
          data: {
            ...node.data,
            kind: node.data?.kind ?? (node.data?.type === "ip" ? "ip" : node.data?.type === "domain" ? "domain" : node.data?.type === "campaign" ? "threat-actor" : "email"),
            label: node.data?.label || node.id || `Entity ${idx + 1}`,
          },
        })));
        setEdges(graph.edges ?? []);
      })
      .catch(() => {
        // Keep seed nodes on error
      })
      .finally(() => setLoading(false));
  }, [activeItem, setEdges, setNodes]);

  const onConnect = useCallback(
    (connection: Connection) => setEdges((eds) => addEdge(connection, eds)),
    [setEdges],
  );

  const onNodeClick = (_: React.MouseEvent, node: any) => {
    setSelectedNode(node.data as NodeData);
  };

  return (
    <div className="w-full min-h-screen flex flex-col relative"
      style={{ background: "linear-gradient(135deg, #05070d 0%, #0b0f1a 100%)" }}>

      {/* Header */}
      <div className="p-6 border-b border-white/5">
        <div className="max-w-7xl mx-auto flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center border border-red-500/30"
              style={{ background: "rgba(239,68,68,0.1)" }}>
              <ShieldAlert className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-white">Threat Campaign Graph</h1>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold text-violet-300 bg-violet-500/10 border border-violet-500/30 flex items-center gap-1">
                  <Sparkles className="w-3 h-3" />
                  Louvain Q = {modularityScore.toFixed(3)}
                </span>
              </div>
              <p className="text-xs text-slate-500">Cross-case entity co-occurrence &amp; attack syndicate community clustering</p>
            </div>
          </div>

          {/* Campaign & Syndicate Selectors */}
          <div className="flex gap-2 flex-wrap items-center">
            {/* Named Syndicates */}
            {syndicates.map((syn) => (
              <button
                key={syn.id}
                onClick={() => setActiveItem(syn.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all border ${
                  activeItem === syn.id
                    ? "border-violet-500/60 text-violet-200 bg-violet-500/20 shadow-lg shadow-violet-500/10"
                    : "border-white/5 text-slate-400 hover:text-slate-200 bg-white/2"
                }`}
              >
                <span>{syn.name}</span>
                <span className="ml-1.5 text-[10px] text-slate-500 font-mono">({syn.node_count} nodes)</span>
              </button>
            ))}

            {/* Individual Campaigns */}
            {defaultCampaigns.map((camp) => (
              <button
                key={camp.id}
                onClick={() => setActiveItem(camp.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all border ${
                  activeItem === camp.id
                    ? "border-red-500/50 text-red-200 bg-red-500/15"
                    : "border-white/5 text-slate-400 hover:text-slate-200 bg-white/2"
                }`}
              >
                <span className="font-mono">{camp.id}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Legend & Stats */}
      <div className="px-6 py-3 border-b border-white/5 flex items-center justify-between flex-wrap gap-4">
        <div className="max-w-7xl flex items-center gap-6 flex-wrap">
          <span className="text-xs text-slate-500 uppercase tracking-widest">Entity Types:</span>
          {(Object.entries(kindConfig) as Array<[NodeKind, typeof kindConfig[NodeKind]]>).map(([kind, cfg]) => {
            const IconComp = cfg.icon;
            return (
              <div key={kind} className="flex items-center gap-1.5 text-xs text-slate-400">
                <IconComp className="w-3.5 h-3.5" style={{ color: cfg.textColor }} />
                <span className="capitalize">{kind.replace("-", " ")}</span>
              </div>
            );
          })}
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-xs text-cyan-400 font-mono">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            <span>Resolving Graph Topology...</span>
          </div>
        )}
      </div>

      {/* Graph Canvas */}
      <div style={{ flex: 1, minHeight: "650px", position: "relative" }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onNodeClick={onNodeClick}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          style={{ background: "transparent" }}
          defaultEdgeOptions={{ type: "smoothstep" }}
        >
          <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="rgba(255,255,255,0.03)" />
          <Controls style={{ background: "rgba(10,18,35,0.85)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: "12px" }} />
          <MiniMap
            style={{ background: "rgba(10,18,35,0.85)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: "12px" }}
            maskColor="rgba(0,0,0,0.6)"
            nodeColor={(n) => kindConfig[(n.data as NodeData).kind]?.textColor ?? "#00e5ff"}
          />
        </ReactFlow>

        {/* Node Inspector Drawer */}
        <AnimatePresence>
          {selectedNode && (
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 50 }}
              className="absolute top-6 right-6 z-20 w-80 rounded-2xl border border-white/10 p-5 shadow-2xl space-y-4"
              style={{ background: "rgba(10,18,35,0.95)", backdropFilter: "blur(20px)" }}
            >
              <div className="flex items-center justify-between pb-3 border-b border-white/5">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Entity Details</span>
                </div>
                <button onClick={() => setSelectedNode(null)} className="text-slate-500 hover:text-white p-1">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div>
                <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Entity Name / Value</div>
                <div className="text-sm font-bold font-mono text-cyan-300 break-all">{selectedNode.label}</div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2.5 rounded-xl border border-white/5 bg-white/2">
                  <div className="text-[10px] text-slate-500 mb-0.5">Classification</div>
                  <div className="font-semibold text-slate-200 capitalize">{selectedNode.kind.replace("-", " ")}</div>
                </div>
                <div className="p-2.5 rounded-xl border border-white/5 bg-white/2">
                  <div className="text-[10px] text-slate-500 mb-0.5">Cluster Context</div>
                  <div className="font-semibold text-slate-200 truncate">{selectedNode.detail || "Correlated"}</div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default ThreatGraph;
