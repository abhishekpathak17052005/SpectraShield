import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  FileText,
  Search,
  CheckCircle2,
  Lock,
  Copy,
  Check,
  AlertTriangle,
  ChevronDown,
  BrainCircuit,
  Fingerprint,
  Zap,
  FolderKanban,
  Globe,
  FileCode,
  Clock,
} from 'lucide-react';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidMorphButton } from '../liquid/LiquidMorphButton';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';
import { LiquidGlassAccordion } from '../liquid/LiquidGlassAccordion';
import { LiquidCausticProgress } from '../liquid/LiquidCausticProgress';
import { LiquidSegmentedControl, SegmentOption } from '../liquid/LiquidSegmentedControl';
import { DefangedText } from '../common/DefangedText';
import { HopMapVisualizer } from '../forensics/HopMapVisualizer';
import { RelayHopTimeline } from '../forensics/RelayHopTimeline';
import { AuthStatusMatrix } from '../forensics/AuthStatusMatrix';
import { AttachmentTriageCard } from '../forensics/AttachmentTriageCard';
import { CaseManagementView } from '../forensics/CaseManagementView';
import { StixExportModal } from '../forensics/StixExportModal';
import { analyzeForensicEmail, uploadEmlFile, MOCK_FORENSIC_ANALYSIS, ForensicAnalyzeResponse, getApiBase } from '../../api';

const SAMPLE_BEC_HEADERS = `Received: from relay.attacker-infra.net (relay.attacker-infra.net [185.220.101.5])
    by mx.victim-corp.com (Postfix) with ESMTPS id 4T0g1B0W9Kz
    for <cfo@victim-corp.com>; Wed, 04 Sep 2026 10:14:05 +0000 (UTC)
Received: from mta1.local-lan.com (unknown [10.0.0.15])
    by relay.attacker-infra.net with ESMTPS id 3R8k2L9P0X;
    Wed, 04 Sep 2026 10:14:02 +0000 (UTC)
From: "CEO Direct Directive" <ceo@micro-soft-billing.top>
To: <cfo@victim-corp.com>
Subject: URGENT: Acquisition Escrow Account Update - Wire Instructions Attached
Date: Wed, 04 Sep 2026 10:13:58 +0000
Message-ID: <20260904101358.89201@micro-soft-billing.top>
Authentication-Results: mx.victim-corp.com;
    dkim=fail (body hash did not verify) header.i=@micro-soft-billing.top;
    spf=fail (sender IP 185.220.101.5 not permitted) smtp.mailfrom=ceo@micro-soft-billing.top;
    dmarc=fail action=reject header.from=micro-soft-billing.top

Please find the revised escrow routing details for the ongoing European acquisition. Complete the wire transfer of $240,000 immediately before closing at 14:00 CET today. Do not discuss over voice due to NDA restrictions.`;

export const ForensicOpsView: React.FC<{ initialText?: string }> = ({ initialText }) => {
  const [inputText, setInputText] = useState(initialText || SAMPLE_BEC_HEADERS);
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<ForensicAnalyzeResponse>(MOCK_FORENSIC_ANALYSIS);
  const [copiedHash, setCopiedHash] = useState(false);
  const [xaiOpen, setXaiOpen] = useState(true);
  const [dragActive, setDragActive] = useState(false);
  const [activeTab, setActiveTab] = useState<string>('dissection');

  const handleRunAnalysis = async () => {
    setLoading(true);
    try {
      const res = await analyzeForensicEmail({
        email_text: inputText,
        sender_email: 'ceo@micro-soft-billing.top',
        subject: 'URGENT: Acquisition Escrow Account Update',
      });
      setAnalysis(res);
    } catch {
      // Offline fallback
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    try {
      const res = await uploadEmlFile(file);
      setAnalysis(res);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const copyHash = () => {
    navigator.clipboard.writeText(analysis.sha256_evidence_hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  return (
    <div className="space-y-8 pb-16">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
              Forensic Operations Center
            </h1>
            <LiquidGlassBadge variant="forensics" label="SPECTRA 2.0 FORENSIC ENGINE" size="sm" />
          </div>
          <p className="text-xs md:text-sm text-slate-400 mt-1">
            RFC 5322 header multi-hop routing traversal, Earliest Reliable Public Node (ERPN) isolation, and digital chain of custody.
          </p>
        </div>

        {/* Evidence Export Actions */}
        <StixExportModal
          caseId={analysis.case_id}
          caseNumber={analysis.case_number}
        />
      </div>

      {/* Sealed Evidence Vault Header Bar */}
      <LiquidGlassCard glowColor="crimson" className="p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 shadow-[0_0_20px_rgba(239,68,68,0.3)] shrink-0">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-bold text-white tracking-wide">
                  CASE VERIFICATION: {analysis.case_number}
                </span>
                <LiquidGlassBadge
                  variant={analysis.final_risk >= 70 ? 'critical' : 'warning'}
                  label={analysis.verdict}
                  size="sm"
                />
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Threat Classification: <span className="text-red-400 font-semibold">{analysis.threat_category}</span>
              </p>
            </div>
          </div>

          {/* Cryptographic SHA-256 Hash Seal */}
          <div className="flex flex-wrap items-center gap-3 bg-slate-950/70 border border-white/10 rounded-2xl p-3">
            <div className="flex items-center gap-1.5 text-xs font-mono text-emerald-400">
              <Lock className="w-3.5 h-3.5" />
              <span className="font-bold">SHA-256 EVIDENCE SEAL:</span>
            </div>
            <span className="font-mono text-xs text-cyan-300 select-all max-w-[200px] sm:max-w-xs truncate">
              {analysis.sha256_evidence_hash}
            </span>
            <button
              type="button"
              onClick={copyHash}
              className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
              title="Copy SHA-256 Evidence Hash"
            >
              {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
      </LiquidGlassCard>

      {/* Liquid Glass Sliding Segmented Navigation Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-2 border-b border-white/10">
        <LiquidSegmentedControl
          value={activeTab}
          onChange={setActiveTab}
          size="md"
          options={[
            { id: 'dissection', label: 'Forensic Dissection', icon: <BrainCircuit className="w-4 h-4" /> },
            { id: 'attachments', label: 'Static Attachments', icon: <FileCode className="w-4 h-4" />, badge: analysis.attachments?.length || 0 },
            { id: 'cases', label: 'SOC Case Board', icon: <FolderKanban className="w-4 h-4" /> },
            { id: 'map', label: 'Relay Cartography', icon: <Globe className="w-4 h-4" /> },
            { id: 'timeline', label: 'Hop Timeline', icon: <Clock className="w-4 h-4" /> },
          ]}
        />
        <div className="text-xs font-mono text-slate-400 hidden lg:flex items-center gap-2">
          <span>Active Scope:</span>
          <span className="text-cyan-400 font-bold uppercase">{activeTab}</span>
        </div>
      </div>

      {/* TAB 1: FULL DISSECTION VIEW */}
      {activeTab === 'dissection' && (
        <div className="space-y-8 animate-fade-in">
          {/* Raw Ingestion Studio & Upload Box */}
          <LiquidGlassCard glowColor="cyan" className="p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <BrainCircuit className="w-4 h-4 text-cyan-400" />
                <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                  RFC 5322 Ingestion Studio & .EML Drag-and-Drop
                </h3>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setInputText(SAMPLE_BEC_HEADERS)}
                  className="text-xs font-mono text-cyan-400 hover:text-cyan-300 underline underline-offset-4"
                >
                  Load Sample FIN7 BEC
                </button>
              </div>
            </div>

            {/* Drag and Drop Zone + Textarea */}
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={handleDrop}
              className={`relative rounded-2xl border-2 transition-all duration-300 overflow-hidden ${
                dragActive
                  ? 'border-cyan-400 bg-cyan-950/30'
                  : 'border-white/10 bg-slate-950/80'
              }`}
            >
              <textarea
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                rows={5}
                placeholder="Paste raw email headers or RFC 5322 MIME text (Received:, From:, To:, Subject:, Body)..."
                className="w-full p-4 font-mono text-xs text-slate-200 bg-transparent border-none resize-y focus:outline-none focus:ring-0 leading-relaxed placeholder:text-slate-600"
              />

              <div className="px-4 py-2.5 border-t border-white/5 bg-slate-900/60 flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono text-slate-400">
                <div className="flex items-center gap-2">
                  <UploadCloud className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Or drag & drop .eml / .msg file directly into this zone</span>
                </div>
                <label className="cursor-pointer text-cyan-300 hover:text-cyan-200 font-semibold underline">
                  Browse file
                  <input
                    type="file"
                    accept=".eml,.msg,.txt"
                    className="hidden"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        handleFileUpload(e.target.files[0]);
                      }
                    }}
                  />
                </label>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <LiquidMorphButton
                mode="cyan"
                onClick={handleRunAnalysis}
                icon={Zap}
                isLoading={loading}
              >
                Execute Deep Forensic Dissection
              </LiquidMorphButton>
            </div>
          </LiquidGlassCard>

          {/* Cryptographic DNS Authentication Status Matrix */}
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-purple-400" />
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                Cryptographic DNS Protocol Alignment Grid
              </h3>
            </div>
            <AuthStatusMatrix authentication={analysis.authentication} />
          </div>

          {/* Static Attachment Triage Stream (Phase 3) */}
          <div className="space-y-2">
            <AttachmentTriageCard attachments={analysis.attachments} />
          </div>

          {/* Cartographic Relay Hop Map & Origin Geolocation */}
          <div className="space-y-2">
            <HopMapVisualizer
              hops={analysis.relay_path}
              originNode={analysis.originating_node}
            />
          </div>

          {/* Chronological Relay Hop Timeline */}
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Search className="w-4 h-4 text-cyan-400" />
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                Chronological Relay Hop Path & Timestamp Inversion Audit
              </h3>
            </div>
            <RelayHopTimeline
              hops={analysis.relay_path}
              anomalies={analysis.anomalies}
            />
          </div>

          {/* Explainable AI (XAI) Reasonings & Cognitive Manipulation Accordion */}
          <LiquidGlassCard glowColor="purple" className="p-6">
            <button
              type="button"
              onClick={() => setXaiOpen(!xaiOpen)}
              className="w-full flex items-center justify-between text-left"
            >
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-purple-500/20 text-purple-400">
                  <BrainCircuit className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                    Explainable AI (XAI) Threat Dissection & MITRE ATT&CK Mapping
                  </h3>
                  <p className="text-xs text-slate-400">
                    Cognitive pressure cues, deceptive language vectors, and adversarial kill-chain alignment
                  </p>
                </div>
              </div>
              <ChevronDown
                className={`w-5 h-5 text-purple-400 transition-transform duration-300 ${
                  xaiOpen ? 'rotate-180' : ''
                }`}
              />
            </button>

            <LiquidGlassAccordion isOpen={xaiOpen}>
              <div className="space-y-6 pt-2">
                {/* Reasoning Summary Banner */}
                <div className="p-4 rounded-2xl bg-slate-950/80 border border-white/10 text-xs font-mono text-slate-300 leading-relaxed">
                  <span className="text-purple-400 font-bold">XAI SYNTHESIS:</span> {analysis.reasoning_summary}
                </div>

                {/* Cognitive Manipulation Progress Meters */}
                <div>
                  <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-3">
                    Psychological Manipulation Cues (NLP Vectors)
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <LiquidCausticProgress
                      label="Urgency Trigger"
                      progress={analysis.nlp_intelligence.urgency_score}
                      variant="crimson"
                    />
                    <LiquidCausticProgress
                      label="Authority Claim"
                      progress={analysis.nlp_intelligence.authority_score}
                      variant="purple"
                    />
                    <LiquidCausticProgress
                      label="Scarcity / Deadline"
                      progress={analysis.nlp_intelligence.scarcity_score}
                      variant="amber"
                    />
                    <LiquidCausticProgress
                      label="Fear Induction"
                      progress={analysis.nlp_intelligence.fear_score}
                      variant="cyan"
                    />
                  </div>
                </div>

                {/* MITRE ATT&CK Matrix & Threat Campaign Cluster */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div className="p-4 rounded-2xl bg-slate-950/60 border border-white/10 space-y-2">
                    <div className="text-xs font-mono font-bold text-red-400 uppercase tracking-wider">
                      Mapped MITRE ATT&CK Tactics
                    </div>
                    <div className="space-y-1.5 font-mono text-xs text-slate-300">
                      {analysis.mitre_tactics.map((tactic, i) => (
                        <div key={i} className="flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                          <span>{tactic}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-4 rounded-2xl bg-slate-950/60 border border-white/10 space-y-2">
                    <div className="text-xs font-mono font-bold text-purple-400 uppercase tracking-wider">
                      Attributed Threat Actor Cluster
                    </div>
                    <div className="font-mono text-xs space-y-1 text-slate-300">
                      <div>
                        <span className="text-slate-400">Campaign ID:</span>{' '}
                        <span className="text-purple-300 font-bold">{analysis.campaign.id}</span>
                      </div>
                      <div>
                        <span className="text-slate-400">Syndicate:</span>{' '}
                        <span className="text-white font-semibold">{analysis.campaign.threat_actor}</span>
                      </div>
                      <div>
                        <span className="text-slate-400">Attribution Confidence:</span>{' '}
                        <span className="text-emerald-400 font-bold">{analysis.campaign.attribution_confidence}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </LiquidGlassAccordion>
          </LiquidGlassCard>
        </div>
      )}

      {/* TAB 2: ATTACHMENT TRIAGE VIEW */}
      {activeTab === 'attachments' && (
        <div className="space-y-4 animate-fade-in">
          <AttachmentTriageCard attachments={analysis.attachments} />
        </div>
      )}

      {/* TAB 3: SOC CASE BOARD */}
      {activeTab === 'cases' && (
        <div className="space-y-4 animate-fade-in">
          <CaseManagementView
            apiBaseUrl={getApiBase()}
            onSelectCase={(caseId) => {
              setActiveTab('dissection');
            }}
          />
        </div>
      )}

      {/* TAB 4: RELAY CARTOGRAPHY */}
      {activeTab === 'map' && (
        <div className="space-y-4 animate-fade-in">
          <HopMapVisualizer
            hops={analysis.relay_path}
            originNode={analysis.originating_node}
          />
        </div>
      )}

      {/* TAB 5: HOP TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="space-y-4 animate-fade-in">
          <RelayHopTimeline
            hops={analysis.relay_path}
            anomalies={analysis.anomalies}
          />
        </div>
      )}
    </div>
  );
};
