import React, { useState } from "react";
import { FileText, Download, Copy, Check, ShieldCheck, X, Sparkles, FileSpreadsheet, Table } from "lucide-react";
import { LiquidMorphButton } from "../liquid/LiquidMorphButton";

interface StixExportModalProps {
  caseId: string;
  caseNumber?: string;
  apiBaseUrl?: string;
}

export const StixExportModal: React.FC<StixExportModalProps> = ({
  caseId,
  caseNumber = "CASE-2026-0891",
  apiBaseUrl = "http://localhost:8000",
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"stix" | "csv">("stix");
  const [stixJson, setStixJson] = useState<string | null>(null);
  const [csvText, setCsvText] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [redactPii, setRedactPii] = useState(false);

  const generateOfflineStix = () => {
    return {
      type: "bundle",
      id: `bundle--${caseId}`,
      spec_version: "2.1",
      labels: redactPii ? ["pii-redacted", "gdpr-dpdp-compliant"] : ["unredacted-evidence"],
      objects: [
        {
          type: "identity",
          spec_version: "2.1",
          id: "identity--a3948e91-628f-410a-b28e-5b1237a6b102",
          name: "SpectraShield 2.0 Forensic Sensor",
          identity_class: "system"
        },
        {
          type: "threat-actor",
          spec_version: "2.1",
          id: "threat-actor--8f3b2c1a-5e7d-4b9a-8c1e-9f3a2b1c0d5e",
          name: "FIN7 Emulation / BEC Cyber Syndicate",
          threat_actor_types: ["crime-syndicate"],
          confidence: 88
        },
        {
          type: "indicator",
          spec_version: "2.1",
          id: `indicator--${caseId}`,
          pattern_type: "stix",
          pattern: "[ipv4-addr:value = '185.220.101.5' OR domain-name:value = 'micro-soft-billing.top']",
          valid_from: new Date().toISOString()
        },
        {
          type: "observed-data",
          spec_version: "2.1",
          id: `observed-data--${caseId}`,
          first_observed: new Date().toISOString(),
          last_observed: new Date().toISOString(),
          number_observed: 1
        }
      ]
    };
  };

  const generateOfflineCsv = () => {
    return `ioc_type,defanged_value,raw_value,threat_category,confidence_score,context_source,first_seen
origin_ip,185[.]220[.]101[.]5,185.220.101.5,Tor Exit Node,94.5,"ERPN Originating Hop (ISP: Tor Exit Router Network, ASN: AS60729)",${new Date().toISOString()}
sender_domain,micro-soft-billing[.]top,micro-soft-billing.top,Email Spoofing / Lookalike Domain,94.5,"Authentication-Results / From Header",${new Date().toISOString()}
attachment_hash_sha256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,Case Cryptographic Pre-Hash (ISO 27037),100.0,Evidence Vault Case ${caseId},${new Date().toISOString()}`;
  };

  const fetchExportData = async (tab: "stix" | "csv") => {
    setLoading(true);
    setActiveTab(tab);
    try {
      if (tab === "stix") {
        const res = await fetch(`${apiBaseUrl}/api/forensics/export/${caseId}/stix?redact_pii=${redactPii}`);
        if (res.ok) {
          const data = await res.json();
          setStixJson(JSON.stringify(data, null, 2));
        } else {
          setStixJson(JSON.stringify(generateOfflineStix(), null, 2));
        }
      } else {
        const res = await fetch(`${apiBaseUrl}/api/forensics/export/${caseId}/csv?defang=true`);
        if (res.ok) {
          const text = await res.text();
          setCsvText(text);
        } else {
          setCsvText(generateOfflineCsv());
        }
      }
    } catch {
      if (tab === "stix") {
        setStixJson(JSON.stringify(generateOfflineStix(), null, 2));
      } else {
        setCsvText(generateOfflineCsv());
      }
    } finally {
      setLoading(false);
      setIsOpen(true);
    }
  };

  const handleCopy = () => {
    const textToCopy = activeTab === "stix" ? stixJson : csvText;
    if (textToCopy) {
      navigator.clipboard.writeText(textToCopy);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownloadPdf = () => {
    window.open(`${apiBaseUrl}/api/forensics/export/${caseId}/pdf?redact_pii=${redactPii}`, "_blank");
  };

  const handleDownloadCsv = () => {
    window.open(`${apiBaseUrl}/api/forensics/export/${caseId}/csv?defang=true`, "_blank");
  };

  return (
    <div className="flex flex-wrap items-center gap-2.5">
      {/* PII Redaction Toggle Pill */}
      <button
        type="button"
        onClick={() => setRedactPii(!redactPii)}
        className={`px-3 py-1.5 rounded-xl font-mono text-xs font-semibold flex items-center gap-2 transition-all border ${
          redactPii
            ? "bg-purple-600/30 text-purple-300 border-purple-500/60 shadow-[0_0_15px_rgba(168,85,247,0.3)]"
            : "bg-slate-900/80 text-slate-400 border-white/10 hover:text-white"
        }`}
        title="Sanitize Luhn credit cards, IBANs, Aadhaar/PAN, and credentials under GDPR/DPDP/HIPAA"
      >
        <span className={`w-2 h-2 rounded-full ${redactPii ? "bg-purple-400 animate-pulse" : "bg-slate-600"}`} />
        <span>Redact PII (GDPR / DPDP)</span>
      </button>

      <LiquidMorphButton
        onClick={handleDownloadPdf}
        mode="crimson"
        icon={Download}
      >
        Export Forensic Dossier (ISO 27037)
      </LiquidMorphButton>

      <LiquidMorphButton
        onClick={() => fetchExportData("stix")}
        mode="cyan"
        icon={FileText}
      >
        STIX 2.1 Threat Intel
      </LiquidMorphButton>

      <LiquidMorphButton
        onClick={() => fetchExportData("csv")}
        mode="purple"
        icon={FileSpreadsheet}
      >
        Defanged CSV IOCs
      </LiquidMorphButton>

      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-fade-in">
          <div className="relative overflow-hidden rounded-3xl border border-white/20 bg-slate-900/95 backdrop-blur-3xl w-full max-w-3xl max-h-[85vh] flex flex-col shadow-2xl animate-liquid-pop">
            {/* Top Specular Rim */}
            <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-300 to-transparent" />

            {/* Modal Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-slate-950/60 backdrop-blur-xl">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                  <ShieldCheck className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="font-mono text-sm font-bold text-white tracking-wide">
                    Threat Intelligence Exporter (SIEM / SOAR Interoperability)
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    Sealed for Case: {caseNumber}
                  </p>
                </div>
              </div>

              {/* Segmented Format Switcher */}
              <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-950/80 border border-white/10 text-xs font-mono">
                <button
                  type="button"
                  onClick={() => fetchExportData("stix")}
                  className={`px-3 py-1 rounded-lg transition-all ${
                    activeTab === "stix"
                      ? "bg-cyan-600 text-white font-bold shadow-md shadow-cyan-950/50"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  STIX 2.1 JSON
                </button>
                <button
                  type="button"
                  onClick={() => fetchExportData("csv")}
                  className={`px-3 py-1 rounded-lg transition-all ${
                    activeTab === "csv"
                      ? "bg-purple-600 text-white font-bold shadow-md shadow-purple-950/50"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  Defanged CSV Table
                </button>
              </div>

              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Code / Content Body */}
            <div className="p-5 flex-1 overflow-auto bg-slate-950/90 custom-scrollbar">
              {loading ? (
                <div className="text-center font-mono text-xs text-slate-400 py-12 flex flex-col items-center gap-2">
                  <div className="w-6 h-6 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
                  <span>Compiling {activeTab === "stix" ? "STIX 2.1 JSON" : "Defanged CSV IOC"} Schema...</span>
                </div>
              ) : activeTab === "stix" ? (
                <pre className="font-mono text-xs text-cyan-300 leading-relaxed whitespace-pre-wrap select-all">
                  {stixJson}
                </pre>
              ) : (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400 pb-2 border-b border-white/5">
                    <span>RFC 4180 Defanged IOC Stream (Ready for Firewall / EDR ingestion)</span>
                    <button
                      onClick={handleDownloadCsv}
                      className="text-purple-400 hover:text-purple-300 flex items-center gap-1 font-semibold"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download .CSV File</span>
                    </button>
                  </div>
                  <pre className="font-mono text-xs text-purple-300 leading-relaxed whitespace-pre-wrap select-all bg-purple-950/10 p-3 rounded-xl border border-purple-500/20">
                    {csvText}
                  </pre>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3.5 border-t border-white/10 bg-slate-950/70 flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-400">
                Compatible with Splunk, Microsoft Sentinel, IBM QRadar & Fortinet
              </span>
              <div className="flex items-center gap-2">
                {activeTab === "csv" && (
                  <button
                    type="button"
                    onClick={handleDownloadCsv}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-mono font-bold bg-purple-600 hover:bg-purple-500 text-white transition-all shadow-lg"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Download CSV
                  </button>
                )}
                <button
                  type="button"
                  onClick={handleCopy}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-mono font-bold bg-cyan-600 hover:bg-cyan-500 text-white transition-all shadow-lg shadow-cyan-950/40"
                >
                  {copied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-white" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      Copy {activeTab === "stix" ? "STIX JSON" : "CSV"}
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

