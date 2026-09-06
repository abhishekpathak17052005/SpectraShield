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
  Network,
  Layers,
  Loader2,
} from 'lucide-react';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';
import { DefangedText } from '../common/DefangedText';
import { LiquidMorphButton } from '../liquid/LiquidMorphButton';
import { fetchCampaignCommunities } from '../../api';
import { LouvainCommunitiesResponse, ThreatCommunityCluster } from '../../types';

export const ThreatGraphView: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [showLouvain, setShowLouvain] = useState<boolean>(false);
  const [louvainData, setLouvainData] = useState<LouvainCommunitiesResponse | null>(null);
  const [loadingLouvain, setLoadingLouvain] = useState<boolean>(false);

  const handleToggleLouvain = async () => {
    if (!showLouvain && !louvainData) {
      setLoadingLouvain(true);
      try {
        const data = await fetchCampaignCommunities();
        setLouvainData(data);
      } catch (err) {
        console.error("Louvain communities error:", err);
      } finally {
        setLoadingLouvain(false);
      }
    }
    setShowLouvain(!showLouvain);
  };

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

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleToggleLouvain}
            className={`px-3.5 py-1.5 rounded-xl font-mono text-xs font-semibold transition-all flex items-center gap-2 border ${
              showLouvain
                ? 'bg-purple-500/30 text-purple-200 border-purple-500/60 shadow-[0_0_15px_rgba(168,85,247,0.35)]'
                : 'bg-white/5 text-slate-300 border-white/10 hover:bg-white/10 hover:text-white'
            }`}
          >
            {loadingLouvain ? (
              <Loader2 className="w-4 h-4 animate-spin text-purple-400" />
            ) : (
              <Network className="w-4 h-4 text-purple-400" />
            )}
            <span>Louvain Modularity (Q ≥ 0.65)</span>
            {louvainData && (
              <span className="px-1.5 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300">
                Q={louvainData.modularity.toFixed(3)}
              </span>
            )}
          </button>

          <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
            <Info className="w-4 h-4 text-purple-400" />
            <span>Click any entity to inspect correlation telemetry</span>
          </div>
        </div>
      </div>

      {/* Louvain Modularity Syndicate Detection Drawer/Panel */}
      {showLouvain && louvainData && (
        <LiquidGlassCard glowColor="purple" className="p-5 space-y-4 animate-fade-in border-purple-500/30">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-purple-500/20 text-purple-400 border border-purple-500/30">
                <Network className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold font-mono text-white">
                    NETWORKX LOUVAIN COMMUNITY MODULARITY PARTITIONING
                  </h3>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                    GRP-02-LOUVAIN
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Partitions multi-case threat graphs into discrete attack syndicates using Louvain heuristic optimization.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 font-mono text-xs">
              <div className="p-2 rounded-xl bg-slate-950/60 border border-white/10">
                <span className="text-slate-400">Modularity Score: </span>
                <span className="text-emerald-400 font-bold font-mono">
                  Q = {louvainData.modularity.toFixed(3)}
                </span>
                <span className="text-slate-500 text-[10px] ml-1">(Threshold ≥ 0.65)</span>
              </div>
              <div className="p-2 rounded-xl bg-slate-950/60 border border-white/10">
                <span className="text-slate-400">Identified Syndicates: </span>
                <span className="text-purple-300 font-bold">
                  {louvainData.syndicates_count}
                </span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {louvainData.communities.map((comm) => (
              <div
                key={comm.community_id}
                className="p-4 rounded-2xl bg-slate-950/60 border border-white/10 hover:border-purple-500/40 transition-all space-y-2.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Layers className="w-4 h-4 text-purple-400" />
                    <span className="text-xs font-bold font-mono text-white">
                      {comm.syndicate_name}
                    </span>
                  </div>
                  <LiquidGlassBadge
                    variant="campaign"
                    label={`${(comm.density * 100).toFixed(0)}% DENSITY`}
                    size="sm"
                  />
                </div>

                <div className="text-[11px] font-mono text-slate-400 space-y-1">
                  <div>
                    <span className="text-slate-500">Threat Actor: </span>
                    <span className="text-purple-300 font-semibold">{comm.dominant_threat_actor}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Threat Category: </span>
                    <span className="text-rose-300">{comm.dominant_category}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Associated Nodes ({comm.node_count}): </span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {comm.nodes.map((nodeId, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.5 rounded text-[10px] bg-white/5 text-slate-300 border border-white/10 font-mono"
                        >
                          {nodeId}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </LiquidGlassCard>
      )}

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
