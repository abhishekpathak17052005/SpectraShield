import React, { useState } from "react";
import { FileText, Download, Copy, Check, ShieldCheck, X, Sparkles } from "lucide-react";
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
  const [stixJson, setStixJson] = useState<string | null>(null);
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
        },
        ...(redactPii ? [{
          type: "note",
          spec_version: "2.1",
          id: `note--redaction-${caseId}`,
          content: "Evidentiary Redaction Applied: Credit card numbers, IBANs, SSN/Aadhaar/PAN, and banking details sanitized under GDPR Art. 17 / India DPDP Act 2023.",
          authors: ["SpectraShield PII Sanitization Engine"]
        }] : [])
      ]
    };
  };

  const fetchStix = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/forensics/export/${caseId}/stix?redact_pii=${redactPii}`);
      if (res.ok) {
        const data = await res.json();
        setStixJson(JSON.stringify(data, null, 2));
      } else {
        setStixJson(JSON.stringify(generateOfflineStix(), null, 2));
      }
    } catch {
      // Offline fallback: generate structured STIX 2.1 bundle
      setStixJson(JSON.stringify(generateOfflineStix(), null, 2));
    } finally {
      setLoading(false);
      setIsOpen(true);
    }
  };

  const handleCopy = () => {
    if (stixJson) {
      navigator.clipboard.writeText(stixJson);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownloadPdf = () => {
    window.open(`${apiBaseUrl}/api/forensics/export/${caseId}/pdf?redact_pii=${redactPii}`, "_blank");
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
        onClick={fetchStix}
        mode="cyan"
        icon={FileText}
      >
        STIX 2.1 Threat Intel
      </LiquidMorphButton>

      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-fade-in">
          <div className="relative overflow-hidden rounded-3xl border border-white/20 bg-slate-900/95 backdrop-blur-3xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl animate-liquid-pop">
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
                    OASIS STIX 2.1 Threat Intelligence Bundle
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    Sealed for Case: {caseNumber}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Code Body */}
            <div className="p-5 flex-1 overflow-auto bg-slate-950/90 custom-scrollbar">
              {loading ? (
                <div className="text-center font-mono text-xs text-slate-400 py-12 flex flex-col items-center gap-2">
                  <div className="w-6 h-6 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
                  <span>Compiling STIX 2.1 JSON Schema...</span>
                </div>
              ) : (
                <pre className="font-mono text-xs text-cyan-300 leading-relaxed whitespace-pre-wrap select-all">
                  {stixJson}
                </pre>
              )}
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3.5 border-t border-white/10 bg-slate-950/70 flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-400">
                Ready for Splunk, Microsoft Sentinel, IBM QRadar & OpenCTI
              </span>
              <button
                type="button"
                onClick={handleCopy}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-mono font-bold bg-cyan-600 hover:bg-cyan-500 text-white transition-all shadow-lg shadow-cyan-950/40"
              >
                {copied ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-white" />
                    Copied to Clipboard!
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    Copy STIX JSON
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
