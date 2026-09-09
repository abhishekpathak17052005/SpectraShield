import React, { useState, useMemo } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Globe,
  Server,
  Network,
  Mail,
  ShieldAlert,
  ShieldCheck,
  ChevronRight,
  ExternalLink,
  Layers,
  X,
  Share2,
} from "lucide-react";
import { ForensicCaseRecord } from "../../api";
import { defangText } from "../../services/investigationService";

interface InfrastructureGraphProps {
  cases: ForensicCaseRecord[];
  onNavigate: (route: string) => void;
}

interface GraphNode {
  id: string;
  label: string;
  type: "case" | "domain" | "ip" | "asn";
  risk?: number;
  caseId?: string;
  subtitle?: string;
  details?: Record<string, any>;
  x: number;
  y: number;
}

interface GraphEdge {
  from: string;
  to: string;
  label?: string;
}

export const InfrastructureGraph: React.FC<InfrastructureGraphProps> = ({ cases, onNavigate }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Build topological nodes & edges from live cases
  const { nodes, edges } = useMemo(() => {
    const nodeList: GraphNode[] = [];
    const edgeList: GraphEdge[] = [];
    const nodeMap = new Map<string, GraphNode>();

    const activeCases = cases.slice(0, 5);
    const width = 800;
    const height = 420;

    activeCases.forEach((c, idx) => {
      // 1. Case Node (Center column)
      const caseId = `case_${c.id}`;
      const caseY = 70 + idx * 70;
      const caseNode: GraphNode = {
        id: caseId,
        label: c.case_number || c.id.slice(0, 10),
        type: "case",
        risk: Math.round(c.final_risk ?? c.overall_risk_score ?? 0),
        caseId: c.id,
        subtitle: c.title || c.subject || "Security Case",
        details: {
          verdict: c.verdict || c.severity,
          created_at: c.created_at,
          analyst: c.assigned_analyst,
        },
        x: 400,
        y: caseY,
      };
      nodeList.push(caseNode);
      nodeMap.set(caseId, caseNode);

      // 2. Domain Node (Left column)
      let domain = "";
      if (c.sender && c.sender.includes("@")) {
        domain = c.sender.split("@")[1]?.replace(/[>]/g, "").trim().toLowerCase();
      }
      if (domain) {
        const domainId = `domain_${domain}`;
        if (!nodeMap.has(domainId)) {
          const domNode: GraphNode = {
            id: domainId,
            label: defangText(domain),
            type: "domain",
            subtitle: "Sender Domain",
            details: { sender: c.sender },
            x: 130,
            y: 70 + (nodeList.filter((n) => n.type === "domain").length) * 80,
          };
          nodeList.push(domNode);
          nodeMap.set(domainId, domNode);
        }
        edgeList.push({ from: domainId, to: caseId, label: "originates" });
      }

      // 3. IP Node (Right column)
      const ip = c.originating_node?.ip;
      if (ip) {
        const ipId = `ip_${ip}`;
        if (!nodeMap.has(ipId)) {
          const ipNode: GraphNode = {
            id: ipId,
            label: defangText(ip),
            type: "ip",
            subtitle: c.originating_node?.country ? `${c.originating_node.country}` : "Origin Node",
            details: {
              isp: c.originating_node?.isp,
              anonymized: c.originating_node?.is_anonymized,
            },
            x: 670,
            y: 80 + (nodeList.filter((n) => n.type === "ip").length) * 75,
          };
          nodeList.push(ipNode);
          nodeMap.set(ipId, ipNode);
        }
        edgeList.push({ from: caseId, to: ipId, label: "relayed_by" });

        // 4. ASN Node (Far right connection)
        const asn = c.originating_node?.asn;
        if (asn) {
          const asnId = `asn_${asn}`;
          if (!nodeMap.has(asnId)) {
            const asnNode: GraphNode = {
              id: asnId,
              label: asn,
              type: "asn",
              subtitle: c.originating_node?.isp || "Autonomous System",
              details: { provider: c.originating_node?.isp },
              x: 670,
              y: 280,
            };
            nodeList.push(asnNode);
            nodeMap.set(asnId, asnNode);
          }
          edgeList.push({ from: ipId, to: asnId, label: "announces" });
        }
      }
    });

    return { nodes: nodeList, edges: edgeList };
  }, [cases]);

  // Connected node IDs for active hover
  const connectedNodeIds = useMemo(() => {
    if (!hoveredNodeId) return null;
    const set = new Set<string>([hoveredNodeId]);
    edges.forEach((e) => {
      if (e.from === hoveredNodeId) set.add(e.to);
      if (e.to === hoveredNodeId) set.add(e.from);
    });
    return set;
  }, [hoveredNodeId, edges]);

  const getNodeColor = (type: GraphNode["type"], risk?: number) => {
    switch (type) {
      case "case":
        return (risk ?? 0) >= 70 ? "#ef4444" : (risk ?? 0) >= 30 ? "#f59e0b" : "#06b6d4";
      case "domain":
        return "#a855f7"; // Violet
      case "ip":
        return "#3b82f6"; // Blue
      case "asn":
        return "#f59e0b"; // Amber
      default:
        return "#06b6d4";
    }
  };

  const getNodeIcon = (type: GraphNode["type"]) => {
    switch (type) {
      case "case":
        return Mail;
      case "domain":
        return Globe;
      case "ip":
        return Server;
      case "asn":
        return Network;
    }
  };

  return (
    <div className="relative rounded-2xl border border-cyan-500/20 bg-gradient-to-b from-[#0c1224]/95 via-[#080d1a]/95 to-[#050914]/95 overflow-hidden shadow-2xl p-5 md:p-6 space-y-4">
      {/* Top Header & Legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-white/5 relative z-10">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Share2 className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide uppercase flex items-center gap-2">
              <span>Interactive Infrastructure Topology Graph</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-normal">
                2.5D INTERACTIVE
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">
              Correlating sender domains, case nodes, ingress IPs, and routing ASNs
            </p>
          </div>
        </div>

        {/* Entity Type Legend */}
        <div className="flex items-center gap-3 text-[11px] font-mono flex-wrap">
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <span>Case</span>
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400" />
            <span>Domain</span>
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-400" />
            <span>IP Node</span>
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
            <span>ASN</span>
          </span>
        </div>
      </div>

      {/* Main Graph Area */}
      <div className="relative w-full overflow-x-auto min-h-[420px] rounded-xl bg-[#060a14]/60 border border-white/5 flex items-center justify-center">
        {/* Ambient Grid overlay */}
        <div
          className="absolute inset-0 pointer-events-none opacity-20"
          style={{
            backgroundImage: "radial-gradient(circle, rgba(6, 182, 212, 0.15) 1px, transparent 1px)",
            backgroundSize: "24px 24px",
          }}
        />

        <svg width="800" height="420" className="relative z-10 select-none">
          {/* Edges */}
          {edges.map((e, idx) => {
            const fromNode = nodes.find((n) => n.id === e.from);
            const toNode = nodes.find((n) => n.id === e.to);
            if (!fromNode || !toNode) return null;

            const isHighlighted =
              hoveredNodeId === e.from ||
              hoveredNodeId === e.to ||
              selectedNode?.id === e.from ||
              selectedNode?.id === e.to;

            const strokeColor = isHighlighted ? "#06b6d4" : "rgba(255, 255, 255, 0.12)";
            const strokeWidth = isHighlighted ? 2 : 1;

            return (
              <g key={idx}>
                <line
                  x1={fromNode.x}
                  y1={fromNode.y}
                  x2={toNode.x}
                  y2={toNode.y}
                  stroke={strokeColor}
                  strokeWidth={strokeWidth}
                  strokeDasharray={isHighlighted ? "4 2" : undefined}
                  className="transition-all duration-300"
                />
                {isHighlighted && (
                  <circle
                    r="3"
                    fill="#06b6d4"
                    className="animate-ping"
                    cx={(fromNode.x + toNode.x) / 2}
                    cy={(fromNode.y + toNode.y) / 2}
                  />
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const isHovered = hoveredNodeId === node.id;
            const isSelected = selectedNode?.id === node.id;
            const isDimmed = connectedNodeIds && !connectedNodeIds.has(node.id);
            const color = getNodeColor(node.type, node.risk);

            return (
              <g
                key={node.id}
                className="cursor-pointer transition-transform duration-200"
                onMouseEnter={() => setHoveredNodeId(node.id)}
                onMouseLeave={() => setHoveredNodeId(null)}
                onClick={() => setSelectedNode(node)}
                style={{
                  opacity: isDimmed ? 0.3 : 1,
                  transformOrigin: `${node.x}px ${node.y}px`,
                }}
              >
                {/* Node Outer Halo on hover */}
                {(isHovered || isSelected) && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r="26"
                    fill={color}
                    opacity="0.25"
                    className="animate-pulse"
                  />
                )}

                {/* Node Circle */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r="18"
                  fill="#0b1120"
                  stroke={color}
                  strokeWidth={isSelected ? 3 : 2}
                  filter={`drop-shadow(0 0 6px ${color})`}
                />

                {/* Node Center Dot or Risk Number */}
                {node.type === "case" && typeof node.risk === "number" ? (
                  <text
                    x={node.x}
                    y={node.y + 4}
                    textAnchor="middle"
                    fill="#ffffff"
                    fontSize="10"
                    fontWeight="bold"
                    fontFamily="monospace"
                  >
                    {node.risk}
                  </text>
                ) : (
                  <circle cx={node.x} cy={node.y} r="5" fill={color} />
                )}

                {/* Node Label underneath */}
                <text
                  x={node.x}
                  y={node.y + 32}
                  textAnchor="middle"
                  fill={isSelected ? "#ffffff" : "#94a3b8"}
                  fontSize="11"
                  fontWeight="500"
                  fontFamily="monospace"
                >
                  {node.label.length > 16 ? node.label.slice(0, 14) + "..." : node.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Slide-out Node Inspector Panel */}
        <AnimatePresence>
          {selectedNode && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="absolute right-4 top-4 bottom-4 w-80 rounded-xl border border-cyan-500/30 bg-[#0d1527]/95 backdrop-blur-xl p-4 shadow-2xl z-20 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between pb-2 border-b border-white/5">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-semibold">
                    {selectedNode.type} Entity Inspector
                  </span>
                  <button
                    onClick={() => setSelectedNode(null)}
                    className="p-1 rounded text-slate-400 hover:text-white"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                <div className="mt-3 space-y-3">
                  <div>
                    <h4 className="text-sm font-bold text-white font-mono break-all">
                      {selectedNode.label}
                    </h4>
                    {selectedNode.subtitle && (
                      <p className="text-xs text-slate-400 mt-0.5">{selectedNode.subtitle}</p>
                    )}
                  </div>

                  {typeof selectedNode.risk === "number" && (
                    <div className="p-2.5 rounded-lg bg-black/30 border border-white/5 flex items-center justify-between">
                      <span className="text-xs text-slate-400">Assessed Threat Risk</span>
                      <span
                        className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                          selectedNode.risk >= 70
                            ? "bg-red-500/20 text-red-300"
                            : selectedNode.risk >= 30
                            ? "bg-amber-500/20 text-amber-300"
                            : "bg-emerald-500/20 text-emerald-300"
                        }`}
                      >
                        {selectedNode.risk} / 100
                      </span>
                    </div>
                  )}

                  {selectedNode.details && (
                    <div className="space-y-1 text-xs">
                      {Object.entries(selectedNode.details).map(([key, val]) => (
                        <div key={key} className="flex justify-between py-1 border-b border-white/5">
                          <span className="text-slate-400 capitalize">{key.replace(/_/g, " ")}</span>
                          <span className="text-slate-200 font-mono text-[11px] truncate max-w-[140px]">
                            {String(val || "None")}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {selectedNode.caseId ? (
                <button
                  onClick={() => onNavigate(`/investigations/${selectedNode.caseId}`)}
                  className="w-full py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
                >
                  <span>Open Full Investigation</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              ) : (
                <button
                  onClick={() => onNavigate("/investigations")}
                  className="w-full py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
                >
                  <span>Filter Investigations</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};
