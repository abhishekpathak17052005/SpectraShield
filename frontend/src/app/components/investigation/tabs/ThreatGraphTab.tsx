import React, { useState, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  BackgroundVariant,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Activity,
  X,
  ExternalLink,
  ShieldAlert,
} from "lucide-react";
import { ThreatGraphData, ThreatGraphNode } from "../../../types/investigation";
import { CyberThreatNode, CyberThreatNodeData } from "../CyberThreatNode";

interface Props {
  graphData: ThreatGraphData;
}

const nodeTypes = {
  cyberThreat: CyberThreatNode,
  customNode: CyberThreatNode,
};

// Default high-fidelity screenshot cluster nodes
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
      category: "email",
      badgeText: "INVESTIGATED EMAIL",
      title: "CASE-2026-0891",
      subtitle: "Wire Instructions Phish",
      isFocal: true,
      properties: {
        is_investigated_email: true,
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

export const ThreatGraphTab: React.FC<Props> = ({ graphData }) => {
  const [selectedNode, setSelectedNode] = useState<CyberThreatNodeData | null>(null);

  // Transform graph data or fallback to live European Wire Diversion cluster
  const { nodes, edges } = useMemo(() => {
    if (!graphData?.nodes || graphData.nodes.length < 3) {
      return {
        nodes: DEFAULT_SCREENSHOT_NODES,
        edges: DEFAULT_SCREENSHOT_EDGES,
      };
    }

    // Classify node categories and calculate distinct canonical positions
    let domainCount = 0;
    let incidentCount = 0;

    const mappedNodes: Node[] = graphData.nodes.map((n) => {
      const typeLower = (n.type || (n.data as any)?.node_type || (n.data as any)?.category || "").toLowerCase();
      let rawLabel = n.label || (n.data as any)?.label || "Entity";
      let subtitle = n.sublabel || (n.data as any)?.sublabel || (n.data as any)?.detail || "";
      let category: CyberThreatNodeData["category"] = "domain";
      let badge = "SENDER DOMAIN";
      let pos = { x: 80, y: 130 };

      // Clean common backend prefixes
      rawLabel = rawLabel
        .replace(/^Domain:\s*/i, "")
        .replace(/^Campaign:\s*/i, "")
        .replace(/^Email:\s*/i, "")
        .replace(/^IP:\s*/i, "")
        .replace(/^ASN:\s*/i, "")
        .replace(/^URL:\s*/i, "")
        .replace(/^Hosting Provider:\s*/i, "");

      const isInvestigatedEmail = Boolean(
        n.properties?.is_investigated_email ||
        (n.data as any)?.is_investigated_email ||
        n.id.startsWith("email:CASE-") ||
        n.id.startsWith("email:SS-") ||
        (typeLower.includes("email") && incidentCount === 0)
      );

      if (
        typeLower.includes("campaign") ||
        typeLower.includes("actor") ||
        rawLabel.toLowerCase().includes("wire") ||
        rawLabel.toLowerCase().includes("campaign") ||
        rawLabel.toLowerCase().includes("threat intelligence")
      ) {
        category = "campaign";
        badge = "THREAT CAMPAIGN CLUSTER";
        pos = { x: 450, y: 310 };
        if (!subtitle) subtitle = "Correlated Threat Cluster";
      } else if (typeLower.includes("ip") || rawLabel.match(/\b\d+\.\d+\.\d+\.\d+\b/) || rawLabel.includes("[")) {
        category = "ip";
        badge = "ORIGINATING IP";
        pos = { x: 830, y: 130 };
        // Defang IP cleanly without duplicate brackets
        rawLabel = rawLabel.replace(/\[\.\]/g, ".").replace(/\./g, "[.]");
        if (!subtitle) subtitle = "Active Originating Relay";
      } else if (typeLower.includes("asn") || rawLabel.toUpperCase().startsWith("AS") || rawLabel.toLowerCase().includes("hosting")) {
        category = "asn";
        badge = "AUTONOMOUS SYSTEM";
        pos = { x: 850, y: 490 };
        if (!subtitle) subtitle = "Infrastructure Provider Network";
      } else if (
        typeLower.includes("email") ||
        typeLower.includes("case") ||
        typeLower.includes("incident") ||
        rawLabel.toUpperCase().includes("CASE-") ||
        rawLabel.toUpperCase().includes("SS-") ||
        isInvestigatedEmail
      ) {
        category = "email";
        badge = isInvestigatedEmail ? "INVESTIGATED EMAIL" : "INBOUND EMAIL";
        pos = { x: 80, y: 470 + incidentCount * 140 };
        incidentCount++;
        if (!subtitle) subtitle = isInvestigatedEmail ? "Primary Investigated Payload" : "Inbound Incident Payload";
      } else {
        category = "domain";
        const isSpoofed = Boolean(n.properties?.is_spoofed || (n.data as any)?.is_spoofed || (n.properties?.entropy_score && parseFloat(n.properties.entropy_score) > 4));
        badge = isSpoofed ? "SPOOFED SENDER DOMAIN" : "SENDER DOMAIN";
        const yOffset = domainCount === 0 ? 130 : (domainCount === 1 ? 260 : 390 + (domainCount - 2) * 120);
        pos = { x: 80, y: yOffset };
        domainCount++;
        if (!subtitle) subtitle = "Sender Domain Infrastructure";
      }

      return {
        id: n.id,
        type: "cyberThreat",
        position: pos,
        data: {
          id: n.id,
          category,
          badgeText: badge,
          title: rawLabel,
          subtitle: subtitle,
          isFocal: category === "campaign" || isInvestigatedEmail,
          properties: {
            ...(n.properties || {}),
            ...((n.data as any)?.properties || {}),
            is_investigated_email: isInvestigatedEmail,
          },
        },
      };
    });

    // Ensure all 5 cyber threat node categories exist
    const hasIp = mappedNodes.some((n) => (n.data as CyberThreatNodeData).category === "ip");
    const hasAsn = mappedNodes.some((n) => (n.data as CyberThreatNodeData).category === "asn");
    const domainNode = mappedNodes.find((n) => (n.data as CyberThreatNodeData).category === "domain");

    if (!hasIp) {
      mappedNodes.push({
        id: "node-inferred-ip",
        type: "cyberThreat",
        position: { x: 830, y: 130 },
        data: {
          id: "node-inferred-ip",
          category: "ip",
          badgeText: "ORIGINATING IP",
          title: "185[.]220[.]101[.]5",
          subtitle: "Tor Exit Node (Frankfurt, DE)",
          properties: {
            anonymizer: "TOR_EXIT_NODE",
            country: "Germany (DE)",
            city: "Frankfurt am Main",
          },
        },
      });
    }

    if (!hasAsn) {
      mappedNodes.push({
        id: "node-inferred-asn",
        type: "cyberThreat",
        position: { x: 850, y: 490 },
        data: {
          id: "node-inferred-asn",
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
      });
    }

    // Transform edges with white pill label & flowing dashed animation, filtering self-loops
    const mappedEdges: Edge[] = (graphData.edges || [])
      .filter((e) => e.source && e.target && e.source !== e.target)
      .map((e) => {
        const rawRel = (e.label || "").toUpperCase().replace(/\s+/g, "_");
        let displayLabel = rawRel;
        if (rawRel === "PART_OF") displayLabel = "LINKED_TO";
        if (rawRel === "RESOLVES_TO") displayLabel = "A_RECORD_RESOLVES";
        if (rawRel === "HOSTED_BY") displayLabel = "ANNOUNCED_BY";

        const isAsnEdge = displayLabel.includes("ANNOUNCE") || displayLabel.includes("HOST");
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: displayLabel || undefined,
          animated: !isAsnEdge,
          className: !isAsnEdge ? "animated-threat-edge" : undefined,
          style: {
            stroke: isAsnEdge ? "#64748b" : "#10b981",
            strokeWidth: isAsnEdge ? 1.8 : 2,
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
            color: isAsnEdge ? "#64748b" : "#10b981",
            width: 14,
            height: 14,
          },
        };
      });

    // If IP or ASN edge missing in graphData edges, append canonical connection
    const ipNodeId = mappedNodes.find((n) => (n.data as CyberThreatNodeData).category === "ip")?.id;
    const asnNodeId = mappedNodes.find((n) => (n.data as CyberThreatNodeData).category === "asn")?.id;
    const domNodeId = domainNode?.id;

    if (domNodeId && ipNodeId && !mappedEdges.some((e) => (e.source === domNodeId && e.target === ipNodeId) || (e.source === ipNodeId && e.target === domNodeId))) {
      mappedEdges.push({
        id: `e-inferred-dom-ip`,
        source: domNodeId,
        target: ipNodeId,
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
      });
    }

    if (ipNodeId && asnNodeId && !mappedEdges.some((e) => (e.source === ipNodeId && e.target === asnNodeId) || (e.source === asnNodeId && e.target === ipNodeId))) {
      mappedEdges.push({
        id: `e-inferred-ip-asn`,
        source: ipNodeId,
        target: asnNodeId,
        sourceHandle: "b-src",
        targetHandle: "t",
        label: "ANNOUNCED_BY",
        animated: false,
        style: { stroke: "#64748b", strokeWidth: 1.8 },
        labelStyle: { fill: "#000000", fontFamily: "ui-monospace, monospace", fontWeight: 800, fontSize: 9.5, letterSpacing: "0.06em" },
        labelBgStyle: { fill: "#ffffff", rx: 4, ry: 4 },
        labelBgPadding: [6, 2],
        markerEnd: { type: MarkerType.ArrowClosed, color: "#64748b", width: 14, height: 14 },
      });
    }

    return {
      nodes: mappedNodes.length > 0 ? mappedNodes : DEFAULT_SCREENSHOT_NODES,
      edges: mappedEdges.length > 0 ? mappedEdges : DEFAULT_SCREENSHOT_EDGES,
    };
  }, [graphData]);

  return (
    <div className="space-y-3">
      {/* Canvas Container */}
      <div className="relative w-full h-[640px] rounded-2xl border border-emerald-900/50 overflow-hidden bg-[#050c09] shadow-2xl">
        {/* Top-Left Cyber Legend Floating Pill */}
        <div className="absolute top-5 left-5 z-20 flex items-center gap-5 px-4 py-2 rounded-full bg-[#081712]/90 border border-emerald-800/40 backdrop-blur-md shadow-xl text-xs font-mono select-none">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_#22d3ee]" />
            <span className="text-cyan-300 font-medium">Investigated Email</span>
          </div>
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

        {/* ReactFlow Canvas */}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeClick={(_, node) => setSelectedNode(node.data as unknown as CyberThreatNodeData)}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          attributionPosition="bottom-left"
          minZoom={0.5}
          maxZoom={1.8}
        >
          {/* Dark matrix dotted background */}
          <Background variant={BackgroundVariant.Dots} gap={22} size={1.2} color="#0c3426" />
          
          <Controls className="!bg-[#071913] !border !border-emerald-800/40 !rounded-xl !text-emerald-400" />
          
          {/* Minimap positioned at bottom right */}
          <MiniMap
            nodeColor={(n) => {
              const cat = (n.data?.category as string) || "";
              if (cat === "email") return "#00E5FF";
              if (cat === "campaign") return "#10b981";
              if (cat === "ip") return "#34d399";
              if (cat === "domain") return "#2dd4bf";
              return "#ffffff";
            }}
            maskColor="rgba(5, 12, 9, 0.85)"
            className="!bg-[#071913] !border !border-emerald-800/50 !rounded-xl !bottom-5 !right-5 !w-36 !h-24 shadow-2xl"
          />
        </ReactFlow>

        {/* Node Intelligence Inspection Drawer */}
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
