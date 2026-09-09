import React, { useState, useCallback, useEffect, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  BackgroundVariant,
  Node,
  Edge,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ShieldAlert,
  Sparkles,
  RefreshCw,
  Activity,
  X,
  Layers,
  Network,
} from "lucide-react";
import { getCampaignGraph, getSyndicateCommunities, type SyndicateCommunity } from "../api";
import { CyberThreatNode, CyberThreatNodeData } from "./investigation/CyberThreatNode";

const nodeTypes = {
  cyberThreat: CyberThreatNode,
  glass: CyberThreatNode,
  default: CyberThreatNode,
};

// ─── Default Screenshot High-Fidelity Cluster ────────────────────────────────
const DEFAULT_SCREENSHOT_NODES: Node[] = [
  {
    id: "node-domain",
    type: "cyberThreat",
    position: { x: 70, y: 140 },
    data: {
      id: "node-domain",
      category: "domain",
      badgeText: "SPOOFED SENDER DOMAIN",
      title: "micro-soft-billing.top",
      subtitle: "Age: 4 Days (Burner)",
      properties: {
        registrar: "NameCheap, Inc.",
        created: "4 days ago",
        entropy_score: "4.82 (High)",
        mx_records: "None (Burner/Send-Only)",
      },
    },
  },
  {
    id: "node-incident",
    type: "cyberThreat",
    position: { x: 80, y: 470 },
    data: {
      id: "node-incident",
      category: "incident",
      badgeText: "INGESTED INCIDENT",
      title: "CASE-2026-0891",
      subtitle: "Wire Instructions Phish",
      properties: {
        severity: "CRITICAL",
        target: "finance@enterprise.internal",
        dmarc_status: "Fail / Unaligned",
      },
    },
  },
  {
    id: "node-campaign",
    type: "cyberThreat",
    position: { x: 450, y: 310 },
    data: {
      id: "node-campaign",
      category: "campaign",
      badgeText: "THREAT CAMPAIGN CLUSTER",
      title: "European Wire Diversion",
      subtitle: "CAMP-2026-042 (FIN7 Emulation)",
      isFocal: true,
      properties: {
        actor: "FIN7 Emulation / Storm-0829",
        confidence: "94%",
        first_seen: "2026-09-02",
        ioc_count: 14,
      },
    },
  },
  {
    id: "node-ip",
    type: "cyberThreat",
    position: { x: 830, y: 130 },
    data: {
      id: "node-ip",
      category: "ip",
      badgeText: "ORIGINATING IP",
      title: "185[.]220[.]101[.]5",
      subtitle: "Tor Exit Node (Frankfurt, DE)",
      properties: {
        anonymizer: "TOR_EXIT_NODE",
        country: "Germany (DE)",
        city: "Frankfurt am Main",
        reverse_dns: "tor-exit-frankfurt.dfn.de",
      },
    },
  },
  {
    id: "node-asn",
    type: "cyberThreat",
    position: { x: 850, y: 490 },
    data: {
      id: "node-asn",
      category: "asn",
      badgeText: "AUTONOMOUS SYSTEM",
      title: "AS60729",
      subtitle: "Tor Exit Node Network",
      properties: {
        asn: "AS60729",
        organization: "Tor Relay Global Transit",
        threat_reputation: "BULLETPROOF_HOST",
      },
    },
  },
];

const DEFAULT_SCREENSHOT_EDGES: Edge[] = [
  {
    id: "e-domain-campaign",
    source: "node-domain",
    target: "node-campaign",
    sourceHandle: "b-src",
    targetHandle: "t",
    label: "PART_OF_CLUSTER",
    animated: true,
    className: "animated-threat-edge",
    style: { stroke: "#10b981", strokeWidth: 2 },
    labelStyle: { fill: "#000000", fontFamily: "ui-monospace, monospace", fontWeight: 800, fontSize: 9.5, letterSpacing: "0.06em" },
    labelBgStyle: { fill: "#ffffff", rx: 4, ry: 4 },
    labelBgPadding: [6, 2],
    markerEnd: { type: MarkerType.ArrowClosed, color: "#10b981", width: 14, height: 14 },
  },
  {
    id: "e-domain-ip",
    source: "node-domain",
    target: "node-ip",
    sourceHandle: "r-src",
    targetHandle: "t",
    label: "A_RECORD_RESOLVES",
    animated: true,
    className: "animated-threat-edge",
    style: { stroke: "#10b981", strokeWidth: 2 },
    labelStyle: { fill: "#000000", fontFamily: "ui-monospace, monospace", fontWeight: 800, fontSize: 9.5, letterSpacing: "0.06em" },
    labelBgStyle: { fill: "#ffffff", rx: 4, ry: 4 },
    labelBgPadding: [6, 2],
    markerEnd: { type: MarkerType.ArrowClosed, color: "#10b981", width: 14, height: 14 },
  },
  {
    id: "e-incident-campaign",
    source: "node-incident",
    target: "node-campaign",
    sourceHandle: "t-src",
    targetHandle: "l",
    label: "LINKED_TO",
    animated: true,
    className: "animated-threat-edge",
    style: { stroke: "#10b981", strokeWidth: 2 },
    labelStyle: { fill: "#000000", fontFamily: "ui-monospace, monospace", fontWeight: 800, fontSize: 9.5, letterSpacing: "0.06em" },
    labelBgStyle: { fill: "#ffffff", rx: 4, ry: 4 },
    labelBgPadding: [6, 2],
    markerEnd: { type: MarkerType.ArrowClosed, color: "#10b981", width: 14, height: 14 },
  },
  {
    id: "e-campaign-ip",
    source: "node-ip",
    target: "node-campaign",
    sourceHandle: "l-src",
    targetHandle: "r",
    animated: true,
    className: "animated-threat-edge",
    style: { stroke: "#10b981", strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#10b981", width: 14, height: 14 },
  },
  {
    id: "e-incident-ip",
    source: "node-incident",
    target: "node-campaign",
    sourceHandle: "r-src",
    targetHandle: "b",
    animated: true,
    className: "animated-threat-edge",
    style: { stroke: "#10b981", strokeWidth: 2 },
  },
  {
    id: "e-ip-asn",
    source: "node-ip",
    target: "node-asn",
    sourceHandle: "b-src",
    targetHandle: "t",
    label: "ANNOUNCED_BY",
    animated: false,
    style: { stroke: "#64748b", strokeWidth: 1.8 },
    labelStyle: { fill: "#000000", fontFamily: "ui-monospace, monospace", fontWeight: 800, fontSize: 9.5, letterSpacing: "0.06em" },
    labelBgStyle: { fill: "#ffffff", rx: 4, ry: 4 },
    labelBgPadding: [6, 2],
    markerEnd: { type: MarkerType.ArrowClosed, color: "#64748b", width: 14, height: 14 },
  },
];

const PRESET_CAMPAIGNS = [
  { id: "CAMP-2026-042", label: "European Wire Diversion", icon: Sparkles },
  { id: "CAMP-2026-M365", label: "M365 Harvest Spray", icon: ShieldAlert },
  { id: "all", label: "Global Neo4j Infrastructure", icon: Network },
];

const ThreatGraph: React.FC = () => {
  const [nodes, setNodes, onNodesChange] = useNodesState(DEFAULT_SCREENSHOT_NODES);
  const [edges, setEdges, onEdgesChange] = useEdgesState(DEFAULT_SCREENSHOT_EDGES);
  const [activeItem, setActiveItem] = useState("CAMP-2026-042");
  const [syndicates, setSyndicates] = useState<SyndicateCommunity[]>([]);
  const [modularityScore, setModularityScore] = useState<number>(0.6821);
  const [selectedNode, setSelectedNode] = useState<CyberThreatNodeData | null>(null);
  const [loading, setLoading] = useState(false);

  // Load Louvain Syndicates & Modularity
  useEffect(() => {
    getSyndicateCommunities()
      .then((res) => {
        if (res && res.syndicates && res.syndicates.length > 0) {
          setSyndicates(res.syndicates);
          if (res.modularity_score) {
            setModularityScore(res.modularity_score);
          }
        }
      })
      .catch(() => {});
  }, []);

  // Fetch live backend graph when selection changes
  useEffect(() => {
    if (activeItem === "CAMP-2026-042") {
      setNodes(DEFAULT_SCREENSHOT_NODES);
      setEdges(DEFAULT_SCREENSHOT_EDGES);
      return;
    }

    setLoading(true);
    getCampaignGraph(activeItem)
      .then((graph) => {
        if (!graph?.nodes?.length) return;

        // Position & map nodes into CyberThreatNode theme
        const mappedNodes: Node[] = graph.nodes.map((n: any, idx: number) => {
          const typeStr = (n.type || n.data?.type || n.data?.node_type || "").toLowerCase();
          const labelStr = n.data?.label || n.data?.name || n.id;
          let category: CyberThreatNodeData["category"] = "domain";
          let badge = "SPOOFED SENDER DOMAIN";

          if (typeStr.includes("campaign") || typeStr.includes("actor") || labelStr.toLowerCase().includes("campaign")) {
            category = "campaign";
            badge = "THREAT CAMPAIGN CLUSTER";
          } else if (typeStr.includes("ip") || labelStr.match(/^\d+\.\d+\.\d+\.\d+/)) {
            category = "ip";
            badge = "ORIGINATING IP";
          } else if (typeStr.includes("asn") || labelStr.toUpperCase().startsWith("AS")) {
            category = "asn";
            badge = "AUTONOMOUS SYSTEM";
          } else if (typeStr.includes("email") || typeStr.includes("incident") || typeStr.includes("case")) {
            category = "incident";
            badge = "INGESTED INCIDENT";
          }

          // Use circular / hierarchical positioning if not defined
          let x = n.position?.x;
          let y = n.position?.y;
          if (typeof x !== "number" || typeof y !== "number") {
            const angle = (2 * Math.PI * idx) / Math.max(graph.nodes.length, 1);
            const radius = category === "campaign" ? 0 : 320;
            x = Math.round(500 + radius * Math.cos(angle));
            y = Math.round(300 + radius * Math.sin(angle));
          }

          return {
            id: n.id,
            type: "cyberThreat",
            position: { x, y },
            data: {
              id: n.id,
              category,
              badgeText: badge,
              title: labelStr,
              subtitle: n.data?.detail || n.data?.country || n.data?.subject || "",
              isFocal: category === "campaign",
              properties: n.data || {},
            },
          };
        });

        const mappedEdges: Edge[] = (graph.edges || []).map((e: any) => {
          const isAsn = (e.label || "").toUpperCase().includes("ANNOUNCE") || (e.label || "").toUpperCase().includes("HOST");
          return {
            id: e.id,
            source: e.source,
            target: e.target,
            label: e.label ? e.label.toUpperCase().replace(/\s+/g, "_") : undefined,
            animated: !isAsn,
            className: !isAsn ? "animated-threat-edge" : undefined,
            style: {
              stroke: isAsn ? "#64748b" : "#10b981",
              strokeWidth: isAsn ? 1.8 : 2,
            },
            labelStyle: {
              fill: "#000000",
              fontFamily: "ui-monospace, monospace",
              fontWeight: 800,
              fontSize: 9.5,
              letterSpacing: "0.06em",
            },
            labelBgStyle: { fill: "#ffffff", rx: 4, ry: 4 },
            labelBgPadding: [6, 2],
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: isAsn ? "#64748b" : "#10b981",
              width: 14,
              height: 14,
            },
          };
        });

        setNodes(mappedNodes);
        setEdges(mappedEdges);
      })
      .catch((err) => {
        console.warn("Could not load backend campaign graph:", err);
      })
      .finally(() => setLoading(false));
  }, [activeItem, setEdges, setNodes]);

  const onConnect = useCallback(
    (connection: Connection) => setEdges((eds) => addEdge(connection, eds)),
    [setEdges],
  );

  const onNodeClick = (_: React.MouseEvent, node: any) => {
    setSelectedNode(node.data as CyberThreatNodeData);
  };

  return (
    <div className="w-full min-h-screen flex flex-col relative bg-[#050c09] text-white">
      {/* Top Header Bar */}
      <div className="p-4 sm:p-6 border-b border-emerald-950/60 bg-[#06140f]/80 backdrop-blur-md">
        <div className="max-w-7xl mx-auto flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center border border-emerald-500/30 bg-emerald-950/40 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]">
              <Network className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight">Threat Campaign Graph</h1>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold text-emerald-300 bg-emerald-950/60 border border-emerald-500/30 flex items-center gap-1 shadow-sm">
                  <Sparkles className="w-3 h-3 text-emerald-400" />
                  Louvain Q = {modularityScore.toFixed(4)}
                </span>
                {loading && (
                  <RefreshCw className="w-3.5 h-3.5 text-emerald-400 animate-spin" />
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Live Neo4j graph entity attribution &amp; Louvain modularity campaign clustering
              </p>
            </div>
          </div>

          {/* Cluster & Campaign Selector Buttons */}
          <div className="flex gap-2 flex-wrap items-center">
            {PRESET_CAMPAIGNS.map((camp) => (
              <button
                key={camp.id}
                onClick={() => setActiveItem(camp.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all border flex items-center gap-1.5 ${
                  activeItem === camp.id
                    ? "border-emerald-400 text-emerald-200 bg-emerald-950/60 shadow-[0_0_15px_rgba(16,185,129,0.25)]"
                    : "border-emerald-900/40 text-slate-400 hover:text-slate-200 hover:border-emerald-800 bg-[#071913]/60"
                }`}
              >
                <camp.icon className="w-3.5 h-3.5 text-emerald-400" />
                <span>{camp.label}</span>
              </button>
            ))}

            {/* Syndicates from Louvain Analysis */}
            {syndicates.map((syn) => (
              <button
                key={syn.id}
                onClick={() => setActiveItem(syn.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all border ${
                  activeItem === syn.id
                    ? "border-emerald-400 text-emerald-200 bg-emerald-950/60 shadow-[0_0_15px_rgba(16,185,129,0.25)]"
                    : "border-emerald-900/40 text-slate-400 hover:text-slate-200 hover:border-emerald-800 bg-[#071913]/60"
                }`}
              >
                <span>{syn.name}</span>
                <span className="ml-1 text-[10px] text-emerald-400 font-mono">({syn.node_count})</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Canvas Area */}
      <div className="relative w-full flex-1 min-h-[650px] overflow-hidden bg-[#050c09]">
        {/* Top-Left Floating Legend */}
        <div className="absolute top-5 left-5 z-20 flex items-center gap-5 px-4 py-2 rounded-full bg-[#081712]/90 border border-emerald-800/40 backdrop-blur-md shadow-2xl text-xs font-mono select-none">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399]" />
            <span className="text-emerald-300 font-medium">Threat Campaign</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-300 shadow-[0_0_8px_#6ee7b7]" />
            <span className="text-emerald-300 font-medium">Originating IP</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-teal-400 shadow-[0_0_8px_#2dd4bf]" />
            <span className="text-emerald-300 font-medium">Sender Domain</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-400" />
            <span className="text-slate-400 font-medium">ASN Infrastructure</span>
          </div>
        </div>

        {/* ReactFlow Component */}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onNodeClick={onNodeClick}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          attributionPosition="bottom-left"
          minZoom={0.4}
          maxZoom={1.8}
        >
          {/* Dark emerald matrix dot grid */}
          <Background variant={BackgroundVariant.Dots} gap={22} size={1.2} color="#0c3426" />
          
          <Controls className="!bg-[#071913] !border !border-emerald-800/40 !rounded-xl !text-emerald-400" />
          
          <MiniMap
            nodeColor={(n) => {
              const cat = (n.data?.category as string) || "";
              if (cat === "campaign") return "#10b981";
              if (cat === "ip") return "#34d399";
              if (cat === "domain") return "#2dd4bf";
              return "#ffffff";
            }}
            maskColor="rgba(5, 12, 9, 0.85)"
            className="!bg-[#071913] !border !border-emerald-800/50 !rounded-xl !bottom-5 !right-5 !w-36 !h-24 shadow-2xl"
          />
        </ReactFlow>

        {/* Node Detail Inspection Drawer */}
        {selectedNode && (
          <div
            className="absolute top-5 right-5 bottom-5 w-84 rounded-2xl border border-emerald-500/40 p-5 overflow-y-auto flex flex-col justify-between shadow-2xl z-30 animate-in fade-in slide-in-from-right-4 duration-200"
            style={{
              background: "rgba(6, 21, 16, 0.96)",
              backdropFilter: "blur(24px)",
            }}
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-emerald-800/40">
                <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 font-bold flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-emerald-400" />
                  Forensic Attribution
                </span>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white transition-colors p-1 rounded-md hover:bg-white/5"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-bold block mb-1">
                  {selectedNode.badgeText || selectedNode.category}
                </span>
                <div className="text-base font-bold text-white font-mono break-all">
                  {selectedNode.title}
                </div>
                {selectedNode.subtitle && (
                  <div className="text-xs font-mono text-slate-400 mt-0.5">
                    {selectedNode.subtitle}
                  </div>
                )}
              </div>

              <div className="space-y-2 pt-2">
                <div className="text-[10px] text-emerald-400 uppercase tracking-wider font-semibold">
                  Attribution Metadata:
                </div>
                {Object.entries(selectedNode.properties || {}).map(([k, v]) => (
                  <div key={k} className="p-2 rounded-lg bg-[#040f0b] border border-emerald-900/40 flex justify-between gap-2 text-xs font-mono">
                    <span className="text-slate-400 capitalize">{k.replace(/_/g, " ")}:</span>
                    <span className="text-emerald-300 font-semibold truncate">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-4 border-t border-emerald-900/40 text-[10px] font-mono text-slate-500 text-center">
              Click another node or drag to inspect relationships
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatGraph;
