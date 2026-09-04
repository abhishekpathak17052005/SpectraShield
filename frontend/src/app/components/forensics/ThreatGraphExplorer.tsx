import React, { useMemo } from "react";
import {
  ReactFlow,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { GitBranch, Shield, Globe, Server, Hash } from "lucide-react";

interface ThreatGraphExplorerProps {
  graphData?: {
    nodes?: any[];
    edges?: any[];
  };
  campaignName?: string;
  campaignId?: string;
}

export const ThreatGraphExplorer: React.FC<ThreatGraphExplorerProps> = ({
  graphData,
  campaignName = "European Executive Wire Diversion",
  campaignId = "CAMP-2026-M365",
}) => {
  // Default nodes and edges if not provided by backend
  const initialNodes: Node[] = useMemo(() => {
    if (graphData && graphData.nodes && graphData.nodes.length > 0) {
      return graphData.nodes.map((n) => ({
        id: n.id,
        position: n.position || { x: Math.random() * 400 + 50, y: Math.random() * 300 + 50 },
        data: { label: n.data?.label || n.id },
        style: {
          background: n.type === "campaign" ? "#7C3AED" : n.type === "ip" ? "#EF4444" : n.type === "domain" ? "#06B6D4" : "#1E293B",
          color: "#FFFFFF",
          border: "2px solid #334155",
          borderRadius: "8px",
          padding: "10px",
          fontFamily: "monospace",
          fontSize: "11px",
          width: 170,
          boxShadow: "0 4px 12px rgba(0,0,0,0.5)",
        },
      }));
    }

    return [
      {
        id: "c-1",
        position: { x: 260, y: 140 },
        data: { label: `🎯 ${campaignName}` },
        style: {
          background: "#7C3AED",
          color: "#FFFFFF",
          border: "2px solid #A78BFA",
          borderRadius: "10px",
          padding: "12px",
          fontFamily: "monospace",
          fontSize: "11px",
          fontWeight: "bold",
          width: 210,
          boxShadow: "0 0 20px rgba(124, 58, 237, 0.5)",
        },
      },
      {
        id: "d-1",
        position: { x: 60, y: 50 },
        data: { label: "🌐 micro-soft-billing.top" },
        style: {
          background: "#0F172A",
          color: "#38BDF8",
          border: "1.5px solid #0284C7",
          borderRadius: "8px",
          padding: "8px",
          fontFamily: "monospace",
          fontSize: "11px",
          width: 180,
        },
      },
      {
        id: "ip-1",
        position: { x: 500, y: 60 },
        data: { label: "🚨 185[.]220[.]101[.]5 (Tor Exit)" },
        style: {
          background: "#450A0A",
          color: "#FCA5A5",
          border: "1.5px solid #EF4444",
          borderRadius: "8px",
          padding: "8px",
          fontFamily: "monospace",
          fontSize: "11px",
          width: 190,
        },
      },
      {
        id: "asn-1",
        position: { x: 500, y: 250 },
        data: { label: "🏢 AS60729 (Tor Network)" },
        style: {
          background: "#0F172A",
          color: "#CBD5E1",
          border: "1.5px solid #475569",
          borderRadius: "8px",
          padding: "8px",
          fontFamily: "monospace",
          fontSize: "11px",
          width: 180,
        },
      },
      {
        id: "e-1",
        position: { x: 70, y: 240 },
        data: { label: "✉️ Invoice Wire Phish #402" },
        style: {
          background: "#1E1B4B",
          color: "#C7D2FE",
          border: "1.5px solid #6366F1",
          borderRadius: "8px",
          padding: "8px",
          fontFamily: "monospace",
          fontSize: "11px",
          width: 180,
        },
      },
    ];
  }, [graphData, campaignName]);

  const initialEdges: Edge[] = useMemo(() => {
    if (graphData && graphData.edges && graphData.edges.length > 0) {
      return graphData.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        animated: e.animated !== false,
        style: { stroke: "#06B6D4", strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#06B6D4" },
      }));
    }

    return [
      {
        id: "e1",
        source: "d-1",
        target: "c-1",
        label: "PART_OF",
        animated: true,
        style: { stroke: "#A78BFA", strokeWidth: 1.5 },
      },
      {
        id: "e2",
        source: "e-1",
        target: "c-1",
        label: "PART_OF",
        animated: true,
        style: { stroke: "#A78BFA", strokeWidth: 1.5 },
      },
      {
        id: "e3",
        source: "e-1",
        target: "ip-1",
        label: "ORIGINATED_FROM",
        animated: true,
        style: { stroke: "#EF4444", strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#EF4444" },
      },
      {
        id: "e4",
        source: "ip-1",
        target: "asn-1",
        label: "HOSTED_BY",
        style: { stroke: "#64748B", strokeWidth: 1.5 },
      },
    ];
  }, [graphData]);

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div className="rounded-xl border border-border bg-card/60 backdrop-blur-md overflow-hidden shadow-lg">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40">
        <div className="flex items-center gap-2">
          <GitBranch className="h-4 w-4 text-purple-400" />
          <span className="text-xs font-mono font-semibold tracking-wider text-foreground">
            THREAT ATTRIBUTION & INFRASTRUCTURE GRAPH (NEO4J / NETWORKX)
          </span>
        </div>
        <div className="text-xs font-mono text-purple-300">
          Campaign Cluster: <span className="font-bold">{campaignId}</span>
        </div>
      </div>

      <div className="h-[360px] w-full bg-slate-950">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
        >
          <Background color="#1E293B" gap={16} />
          <Controls />
        </ReactFlow>
      </div>

      <div className="p-3 bg-muted/20 border-t border-border flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-muted-foreground">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-purple-500" />
            Threat Campaign
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-red-500" />
            Originating IP
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            Sender Domain
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-slate-400" />
            ASN Infrastructure
          </span>
        </div>
        <div>Drag nodes to inspect entity relationships</div>
      </div>
    </div>
  );
};
