import React, { useState } from 'react';
import {
  Mail,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Linkedin,
  Clock,
  Send,
  Archive,
  Trash2,
  Reply,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidMorphButton } from '../liquid/LiquidMorphButton';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';
import { DefangedText } from '../common/DefangedText';

interface EmailItem {
  id: string;
  senderName: string;
  senderEmail: string;
  subject: string;
  preview: string;
  date: string;
  riskScore: number;
  category: string;
  body: string;
  headers: string;
  urls: string[];
}

const SAMPLE_INBOX: EmailItem[] = [
  {
    id: 'msg-1',
    senderName: 'Microsoft 365 Security Support',
    senderEmail: 'security-noreply@micro-soft-billing.top',
    subject: 'URGENT: Verify your account now. Microsoft 365 suspended',
    preview: 'Your Microsoft corporate subscription has encountered an authentication billing failure...',
    date: '10:14 AM',
    riskScore: 94.5,
    category: 'Business Email Compromise (BEC)',
    body: `Dear Administrator,

We detected unauthorized access attempts from IP 185.220.101.5 (Frankfurt, Germany) to your Microsoft 365 Azure Tenant.
As a result, your organization's mailbox access will be permanently suspended within 24 hours unless you re-verify identity.

Click below to verify credential ownership:
https://secure-verify-account.tk/login/microsoft

Failure to complete verification will result in immediate tenant revocation.`,
    headers: `Received: from relay.attacker-infra.net (relay.attacker-infra.net [185.220.101.5])
    by mx.victim-corp.com with ESMTPS id 4T0g1B0W9Kz; Wed, 04 Sep 2026 10:14:05 +0000
From: "Microsoft 365 Security Support" <security-noreply@micro-soft-billing.top>
To: <admin@victim-corp.com>
Subject: URGENT: Verify your account now. Microsoft 365 suspended
DMARC: fail (action=reject)`,
    urls: ['https://secure-verify-account.tk/login/microsoft'],
  },
  {
    id: 'msg-2',
    senderName: 'PayPal Merchant Services',
    senderEmail: 'service@paypaI-security-auth.cc',
    subject: 'Unusual sign-in activity: Immediate verification needed',
    preview: 'We noticed a login from an unrecognized device in Moscow, Russia...',
    date: '08:42 AM',
    riskScore: 88.0,
    category: 'Credential Harvester',
    body: `Hello Customer,

A transaction of $490.00 USD was initiated from Moscow, Russia. If this was not you, confirm your account details immediately:
https://paypaI-security-auth.cc/confirm-identity

Regards,
PayPal Fraud Department`,
    headers: `Received: from mail.phish-pool.org [194.26.29.112]
From: service@paypaI-security-auth.cc
Subject: Unusual sign-in activity`,
    urls: ['https://paypaI-security-auth.cc/confirm-identity'],
  },
  {
    id: 'msg-3',
    senderName: 'GitHub Security Alerts',
    senderEmail: 'notifications@github.com',
    subject: '[GitHub] Dependabot alert for repository spectra-core',
    preview: 'We found a vulnerable dependency in your package.json file...',
    date: 'Yesterday',
    riskScore: 8.0,
    category: 'Legitimate Transactional',
    body: `Dependabot has discovered 1 moderate vulnerability in your dependencies:
axios < 1.7.4. Upgrade to version 1.7.4 or later.

View advisory: https://github.com/advisories/GHSA-8hc4-vh64-cxmj`,
    headers: `Received: from github.com [140.82.112.4]
From: notifications@github.com
DKIM: pass
SPF: pass`,
    urls: ['https://github.com/advisories/GHSA-8hc4-vh64-cxmj'],
  },
];

interface SentinelInboxesViewProps {
  onEscalateToSOC: (rawHeaders: string, emailBody: string) => void;
}

export const SentinelInboxesView: React.FC<SentinelInboxesViewProps> = ({ onEscalateToSOC }) => {
  const [platform, setPlatform] = useState<'gmail' | 'linkedin'>('gmail');
  const [selectedId, setSelectedId] = useState<string>(SAMPLE_INBOX[0].id);

  const activeEmail = SAMPLE_INBOX.find((e) => e.id === selectedId) || SAMPLE_INBOX[0];
  const isHighRisk = activeEmail.riskScore >= 70;

  return (
    <div className="space-y-8 pb-16">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
              Client Sentinel Inboxes
            </h1>
            <LiquidGlassBadge variant="safe" label="IN-CLIENT EXTENSION ACTIVE" size="sm" />
          </div>
          <p className="text-xs md:text-sm text-slate-400 mt-1">
            Simulated client inboxes demonstrating inline threat ribbons, real-time phishing badges, and 1-click SOC escalation.
          </p>
        </div>

        {/* Platform Switcher */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setPlatform('gmail')}
            className={`flex items-center gap-2 px-4 py-2 rounded-2xl text-xs font-mono font-bold transition-all ${
              platform === 'gmail'
                ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-lg shadow-red-950/40'
                : 'bg-slate-900/60 text-slate-400 border border-white/10 hover:text-white'
            }`}
          >
            <Mail className="w-4 h-4 text-red-400" />
            <span>Gmail Workplace</span>
          </button>
          <button
            type="button"
            onClick={() => setPlatform('linkedin')}
            className={`flex items-center gap-2 px-4 py-2 rounded-2xl text-xs font-mono font-bold transition-all ${
              platform === 'linkedin'
                ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40 shadow-lg shadow-blue-950/40'
                : 'bg-slate-900/60 text-slate-400 border border-white/10 hover:text-white'
            }`}
          >
            <Linkedin className="w-4 h-4 text-blue-400" />
            <span>LinkedIn InMail</span>
          </button>
        </div>
      </div>

      {/* Inbox Two-Pane Container */}
      <div className="rounded-3xl border border-white/15 bg-slate-950 shadow-2xl overflow-hidden grid grid-cols-1 lg:grid-cols-12 min-h-[620px]">
        {/* Left Col (4 Cols): Message List */}
        <div className="lg:col-span-5 border-b lg:border-b-0 lg:border-r border-white/10 bg-slate-900/70 backdrop-blur-2xl flex flex-col">
          <div className="p-4 border-b border-white/10 flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs font-bold text-white uppercase tracking-wider">
              {platform === 'gmail' ? <Mail className="w-4 h-4 text-red-400" /> : <Linkedin className="w-4 h-4 text-blue-400" />}
              <span>{platform === 'gmail' ? 'Primary Ingress (3)' : 'Recruiter Messages (1)'}</span>
            </div>
            <span className="text-[10px] font-mono text-cyan-400">Protected by SpectraShield</span>
          </div>

          <div className="divide-y divide-white/5 overflow-y-auto custom-scrollbar flex-1">
            {SAMPLE_INBOX.map((item) => {
              const isSelected = item.id === selectedId;
              const isThreat = item.riskScore >= 70;

              return (
                <div
                  key={item.id}
                  onClick={() => setSelectedId(item.id)}
                  className={`p-4 cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-cyan-950/40 border-l-4 border-cyan-400'
                      : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-semibold text-xs text-white truncate max-w-[180px]">
                      {item.senderName}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">{item.date}</span>
                  </div>

                  <div className="text-xs text-slate-200 font-medium truncate mb-1">
                    {item.subject}
                  </div>

                  <div className="text-[11px] text-slate-400 line-clamp-1 mb-2">
                    {item.preview}
                  </div>

                  {/* Inline SpectraShield Security Ribbon Pill */}
                  <div className="flex items-center justify-between">
                    <LiquidGlassBadge
                      variant={isThreat ? 'critical' : item.riskScore > 20 ? 'warning' : 'safe'}
                      label={`${item.category} (${Math.round(item.riskScore)}%)`}
                      size="sm"
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Col (7 Cols): Active Message Pane */}
        <div className="lg:col-span-7 flex flex-col justify-between bg-slate-950/90 backdrop-blur-3xl p-6 relative">
          {/* Animated Threat Warning Ribbon Banner */}
          {isHighRisk && (
            <div className="mb-6 p-4 rounded-2xl bg-gradient-to-r from-red-950/80 via-red-900/60 to-red-950/80 border border-red-500/50 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent skew-x-12 animate-liquid-sheen pointer-events-none" />
              <div className="flex items-center gap-3 relative z-10">
                <div className="p-2 rounded-xl bg-red-600 text-white animate-pulse">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-mono font-bold text-white tracking-wider">
                    CRITICAL PHISHING & CREDENTIAL HARVESTER ALERT
                  </div>
                  <div className="text-[11px] font-mono text-red-200 mt-0.5">
                    SpectraShield isolated fraudulent domain mimicking Microsoft corporate login.
                  </div>
                </div>
              </div>

              <LiquidMorphButton
                mode="crimson"
                className="relative z-10 text-xs py-2 px-3 whitespace-nowrap"
                onClick={() => onEscalateToSOC(activeEmail.headers, activeEmail.body)}
                icon={ExternalLink}
              >
                Escalate to SOC
              </LiquidMorphButton>
            </div>
          )}

          {/* Email Content */}
          <div className="space-y-4 flex-1">
            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-white/10 pb-4">
              <div>
                <h2 className="text-base md:text-lg font-bold text-white tracking-tight">
                  {activeEmail.subject}
                </h2>
                <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mt-1">
                  <span>From:</span>
                  <span className="text-cyan-300 font-medium">{activeEmail.senderName}</span>
                  <span>&lt;{activeEmail.senderEmail}&gt;</span>
                </div>
              </div>

              <div className="text-xs font-mono text-slate-400">{activeEmail.date}</div>
            </div>

            {/* Email Body */}
            <div className="font-sans text-sm text-slate-300 whitespace-pre-wrap leading-relaxed space-y-3">
              {activeEmail.body}
            </div>

            {/* Defanged Links List */}
            {activeEmail.urls.length > 0 && (
              <div className="p-4 rounded-2xl bg-slate-900 border border-white/10 space-y-2 mt-4">
                <div className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                  Defanged Hyperlinks Extracted from Message:
                </div>
                {activeEmail.urls.map((u, i) => (
                  <div key={i} className="flex items-center gap-2 font-mono text-xs">
                    <DefangedText value={u} />
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Bottom Action Toolbar */}
          <div className="pt-6 border-t border-white/10 flex flex-wrap items-center justify-between gap-3 mt-6">
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="p-2 rounded-xl bg-slate-900 border border-white/10 text-slate-400 hover:text-white transition-colors"
                title="Archive"
              >
                <Archive className="w-4 h-4" />
              </button>
              <button
                type="button"
                className="p-2 rounded-xl bg-slate-900 border border-white/10 text-slate-400 hover:text-white transition-colors"
                title="Delete"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center gap-2">
              <LiquidMorphButton
                mode="cyan"
                onClick={() => onEscalateToSOC(activeEmail.headers, activeEmail.body)}
                icon={ArrowRight}
              >
                1-Click Deep Forensic Dissection
              </LiquidMorphButton>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
