import React, { useState, useMemo } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  GitBranch,
  Shield,
  Globe,
  Server,
  Hash,
  X,
  ExternalLink,
  Sparkles,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';
import { DefangedText } from '../common/DefangedText';
import { LiquidMorphButton } from '../liquid/LiquidMorphButton';

export const ThreatGraphView: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  const initialNodes: Node[] = useMemo(
    () => [
      {
        id: 'camp-1',
        type: 'default',
        position: { x: 420, y: 180 },
        data: {
          label: (
            <div className="p-3 text-left">
              <div className="flex items-center gap-1.5 text-purple-300 text-[10px] font-bold uppercase mb-1">
                <Sparkles className="w-3 h-3 text-purple-400" />
                THREAT CAMPAIGN CLUSTER
              </div>
              <div className="text-white font-bold text-xs">European Wire Diversion</div>
              <div className="text-slate-400 text-[10px] mt-0.5">CAMP-2026-042 (FIN7 Emulation)</div>
            </div>
          ),
          entityType: 'campaign',
          name: 'European Executive Wire Diversion',
          id: 'CAMP-2026-042',
          attribution: 'FIN7 / Carbanak Emulation Syndicate',
          confidence: '88%',
          firstSeen: '2026-08-12',
          linkedCount: 14,
        },
        style: {
          background: 'rgba(30, 27, 75, 0.85)',
          backdropFilter: 'blur(16px)',
          color: '#ffffff',
          border: '2px solid rgba(168, 85, 247, 0.6)',
          borderRadius: '20px',
          width: 250,
          boxShadow: '0 0 30px rgba(168, 85, 247, 0.35)',
        },
      },
      {
        id: 'ip-1',
        position: { x: 780, y: 70 },
        data: {
          label: (
            <div className="p-2.5 text-left">
              <div className="flex items-center gap-1.5 text-red-400 text-[10px] font-bold uppercase mb-0.5">
                <Server className="w-3 h-3" />
                ORIGINATING IP
              </div>
              <div className="text-red-200 font-bold text-xs">185[.]220[.]101[.]5</div>
              <div className="text-slate-400 text-[10px]">Tor Exit Node (Frankfurt, DE)</div>
            </div>
          ),
          entityType: 'ip',
          ip: '185.220.101.5',
          defanged: '185[.]220[.]101[.]5',
          location: 'Frankfurt, Germany',
          tor: true,
          risk: 95,
        },
        style: {
          background: 'rgba(69, 10, 10, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(239, 68, 68, 0.6)',
          borderRadius: '16px',
          width: 220,
          boxShadow: '0 0 20px rgba(239, 68, 68, 0.25)',
        },
      },
      {
        id: 'asn-1',
        position: { x: 800, y: 320 },
        data: {
          label: (
            <div className="p-2.5 text-left">
              <div className="flex items-center gap-1.5 text-slate-300 text-[10px] font-bold uppercase mb-0.5">
                <Globe className="w-3 h-3 text-cyan-400" />
                AUTONOMOUS SYSTEM
              </div>
              <div className="text-slate-100 font-bold text-xs">AS60729</div>
              <div className="text-slate-400 text-[10px]">Tor Exit Router Pool Network</div>
            </div>
          ),
          entityType: 'asn',
          asn: 'AS60729',
          name: 'Tor Transit Router Pool',
          peers: 42,
        },
        style: {
          background: 'rgba(15, 23, 42, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(148, 163, 184, 0.3)',
          borderRadius: '16px',
          width: 210,
        },
      },
      {
        id: 'domain-1',
        position: { x: 70, y: 80 },
        data: {
          label: (
            <div className="p-2.5 text-left">
              <div className="flex items-center gap-1.5 text-cyan-300 text-[10px] font-bold uppercase mb-0.5">
                <Globe className="w-3 h-3 text-cyan-400" />
                SPOOFED SENDER DOMAIN
              </div>
              <div className="text-cyan-200 font-bold text-xs">micro-soft-billing.top</div>
              <div className="text-slate-400 text-[10px]">Age: 4 Days (Burner)</div>
            </div>
          ),
          entityType: 'domain',
          domain: 'micro-soft-billing.top',
          age: '4 Days',
          nameservers: 'ns1.bulletproof-dns.is',
          targetedBrand: 'Microsoft 365',
        },
        style: {
          background: 'rgba(8, 51, 68, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(6, 182, 212, 0.5)',
          borderRadius: '16px',
          width: 220,
          boxShadow: '0 0 20px rgba(6, 182, 212, 0.2)',
        },
      },
      {
        id: 'email-1',
        position: { x: 80, y: 310 },
        data: {
          label: (
            <div className="p-2.5 text-left">
              <div className="flex items-center gap-1.5 text-indigo-300 text-[10px] font-bold uppercase mb-0.5">
                <Hash className="w-3 h-3 text-indigo-400" />
                INGESTED INCIDENT
              </div>
              <div className="text-indigo-100 font-bold text-xs">CASE-2026-0891</div>
              <div className="text-slate-400 text-[10px]">Wire Instructions Phish</div>
            </div>
          ),
          entityType: 'email',
          caseId: 'CASE-2026-0891',
          subject: 'URGENT: Acquisition Escrow Account Update',
          hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          risk: 94.5,
        },
        style: {
          background: 'rgba(30, 27, 75, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(99, 102, 241, 0.5)',
          borderRadius: '16px',
          width: 220,
        },
      },
    ],
    []
  );

  const initialEdges: Edge[] = useMemo(
    () => [
      {
        id: 'e1',
        source: 'domain-1',
        target: 'camp-1',
        label: 'PART_OF_CLUSTER',
        animated: true,
        style: { stroke: '#a855f7', strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      },
      {
        id: 'e2',
        source: 'email-1',
        target: 'camp-1',
        label: 'LINKED_TO',
        animated: true,
        style: { stroke: '#a855f7', strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      },
      {
        id: 'e3',
        source: 'email-1',
        target: 'ip-1',
        label: 'ORIGINATED_AT',
        animated: true,
        style: { stroke: '#ef4444', strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444' },
      },
      {
        id: 'e4',
        source: 'ip-1',
        target: 'asn-1',
        label: 'ANNOUNCED_BY',
        style: { stroke: '#64748b', strokeWidth: 1.5 },
      },
      {
        id: 'e5',
        source: 'domain-1',
        target: 'ip-1',
        label: 'A_RECORD_RESOLVES',
        animated: true,
        style: { stroke: '#06b6d4', strokeWidth: 1.5 },
      },
    ],
    []
  );

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  const handleNodeClick = (_: any, node: Node) => {
    setSelectedNode(node.data);
  };

  return (
    <div className="space-y-6 pb-16">
      {/* View Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
              Threat Campaign Attribution Graph
            </h1>
            <LiquidGlassBadge variant="campaign" label="NEO4J ENTITY CORRELATION" size="sm" />
          </div>
          <p className="text-xs md:text-sm text-slate-400 mt-1">
            Visual infrastructure graph linking rogue MTA IPs, sender burner domains, Autonomous Systems, and shared threat actor clusters.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
          <Info className="w-4 h-4 text-purple-400" />
          <span>Click any entity to inspect correlation telemetry</span>
        </div>
      </div>

      {/* Main Canvas + Correlation Drawer */}
      <div className="relative rounded-3xl border border-white/15 overflow-hidden bg-slate-950 shadow-2xl h-[620px] w-full">
        {/* Specular Rim Top Highlight */}
        <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-purple-400/80 to-transparent z-20" />

        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={handleNodeClick}
          fitView
          className="bg-slate-950"
        >
          <Background color="#1e293b" gap={20} size={1.5} />
          <Controls className="bg-slate-900 border border-white/10 fill-white text-white rounded-xl shadow-xl m-4" />
          <MiniMap
            nodeStrokeColor="#a855f7"
            nodeColor="#0f172a"
            maskColor="rgba(15, 23, 42, 0.85)"
            className="rounded-2xl border border-white/10 m-4 bg-slate-950 shadow-xl"
          />
        </ReactFlow>

        {/* Legend Overlay */}
        <div className="absolute top-4 left-4 z-10 flex flex-wrap items-center gap-3 p-3 rounded-2xl bg-slate-900/80 backdrop-blur-2xl border border-white/10 text-[11px] font-mono shadow-xl">
          <span className="flex items-center gap-1.5 text-purple-300">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500 shadow-[0_0_8px_rgba(168,85,247,0.8)]" />
            Threat Campaign
          </span>
          <span className="flex items-center gap-1.5 text-red-300">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
            Originating IP
          </span>
          <span className="flex items-center gap-1.5 text-cyan-300">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
            Sender Domain
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-400" />
            ASN Infrastructure
          </span>
        </div>

        {/* Sliding Right-Hand Entity Correlation Drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 bottom-4 w-80 sm:w-96 z-30 rounded-3xl border border-white/20 bg-slate-900/95 backdrop-blur-3xl p-5 shadow-2xl flex flex-col justify-between animate-liquid-pop">
            <div className="space-y-4 overflow-y-auto custom-scrollbar">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-purple-400" />
                  <span className="font-mono text-xs font-bold text-white uppercase tracking-wider">
                    Entity Telemetry Dissection
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedNode(null)}
                  className="p-1 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div>
                  <span className="text-slate-400 text-[10px] uppercase tracking-wider block mb-1">
                    Entity Type
                  </span>
                  <LiquidGlassBadge
                    variant="campaign"
                    label={(selectedNode.entityType || 'ENTITY').toUpperCase()}
                  />
                </div>

                {selectedNode.entityType === 'campaign' && (
                  <>
                    <div>
                      <span className="text-slate-400 text-[10px] uppercase tracking-wider block">
                        Campaign Designation
                      </span>
                      <span className="text-white font-bold text-sm">{selectedNode.name}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] uppercase tracking-wider block">
                        Attributed Threat Syndicate
                      </span>
                      <span className="text-purple-300 font-semibold">{selectedNode.attribution}</span>
                    </div>
                    <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950 border border-white/5">
                      <span className="text-slate-400">Confidence:</span>
                      <span className="text-emerald-400 font-bold">{selectedNode.confidence}</span>
                    </div>
                    <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950 border border-white/5">
                      <span className="text-slate-400">Correlated Cases:</span>
                      <span className="text-cyan-300 font-bold">{selectedNode.linkedCount} Incidents</span>
                    </div>
                  </>
                )}

                {selectedNode.entityType === 'ip' && (
                  <>
                    <div>
                      <span className="text-slate-400 text-[10px] uppercase tracking-wider block mb-1">
                        Defanged IP Address
                      </span>
                      <DefangedText value={selectedNode.defanged || selectedNode.ip} />
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] uppercase tracking-wider block">
                        Physical Geolocation
                      </span>
                      <span className="text-slate-200">{selectedNode.location}</span>
                    </div>
                    {selectedNode.tor && (
                      <div className="p-2 rounded-xl bg-red-950/40 border border-red-500/30 text-red-300 text-[11px] flex items-center gap-1.5 font-bold">
                        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                        <span>Verified Public Tor Exit Node</span>
                      </div>
                    )}
                  </>
                )}

                {selectedNode.entityType === 'domain' && (
                  <>
                    <div>
                      <span className="text-slate-400 text-[10px] uppercase tracking-wider block mb-1">
                        Domain Name
                      </span>
                      <DefangedText value={selectedNode.domain} />
                    </div>
                    <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950 border border-white/5">
                      <span className="text-slate-400">WHOIS Age:</span>
                      <span className="text-red-400 font-bold">{selectedNode.age}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] uppercase tracking-wider block">
                        Targeted Impersonation
                      </span>
                      <span className="text-cyan-300 font-bold">{selectedNode.targetedBrand}</span>
                    </div>
                  </>
                )}

                {selectedNode.entityType === 'email' && (
                  <>
                    <div>
                      <span className="text-slate-400 text-[10px] uppercase tracking-wider block">
                        Subject Line
                      </span>
                      <span className="text-white font-medium">{selectedNode.subject}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] uppercase tracking-wider block">
                        SHA-256 Checksum
                      </span>
                      <span className="text-cyan-300 text-[10px] truncate block select-all">
                        {selectedNode.hash}
                      </span>
                    </div>
                  </>
                )}
              </div>
            </div>

            <div className="pt-4 border-t border-white/10">
              <LiquidMorphButton
                mode="purple"
                className="w-full justify-center"
                icon={ExternalLink}
                onClick={() => alert(`Pivot investigation on ${selectedNode.name || selectedNode.id}`)}
              >
                Pivot Full Investigation
              </LiquidMorphButton>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
