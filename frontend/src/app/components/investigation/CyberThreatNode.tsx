import React, { memo } from "react";
import { Handle, Position, NodeProps } from "@xyflow/react";
import { Globe, Server, Sparkles, Hash, Shield, ShieldAlert, Radio, Mail } from "lucide-react";

export interface CyberThreatNodeData {
  id: string;
  category: "domain" | "ip" | "campaign" | "incident" | "asn" | "threat_actor" | "url" | "email";
  badgeText?: string;
  title: string;
  subtitle?: string;
  isFocal?: boolean;
  properties?: Record<string, any>;
}

export const CyberThreatNode: React.FC<NodeProps> = memo(({ data, selected }) => {
  const d = (data || {}) as CyberThreatNodeData;
  const category = (d.category || (d as any).type || "domain").toLowerCase();

  // Determine badge label & icon based on category
  const isInvestigatedEmail = Boolean(
    d.properties?.is_investigated_email ||
    d.badgeText === "INVESTIGATED EMAIL" ||
    (category === "email" && d.properties?.is_current_case) ||
    (category === "email" && d.id.startsWith("email:"))
  );
  let badgeText = d.badgeText;
  let IconComp = Globe;
  let isTitleEmerald = true;
  let isFocal = Boolean(d.isFocal || category === "campaign" || category === "threat_actor");

  if (category === "domain") {
    const isSpoofed = Boolean(d.properties?.is_spoofed || (d.badgeText && d.badgeText.includes("SPOOFED") && d.properties?.entropy_score));
    badgeText = isSpoofed ? "SPOOFED SENDER DOMAIN" : "SENDER DOMAIN";
    IconComp = Globe;
    isTitleEmerald = true;
  } else if (category === "ip") {
    badgeText = badgeText || "ORIGINATING IP";
    IconComp = Server;
    isTitleEmerald = true;
  } else if (category === "campaign" || category === "threat_actor") {
    badgeText = badgeText || "THREAT CAMPAIGN CLUSTER";
    IconComp = Sparkles;
    isTitleEmerald = false; // Bold white title
  } else if (category === "incident" || category === "case" || category === "email") {
    badgeText = isInvestigatedEmail ? "INVESTIGATED EMAIL" : (d.badgeText || "INBOUND EMAIL");
    IconComp = Mail;
    isTitleEmerald = false; // Bold white title
  } else if (category === "asn" || category === "hosting") {
    badgeText = badgeText || "AUTONOMOUS SYSTEM";
    IconComp = Globe;
    isTitleEmerald = false; // Bold white title
  }

  // Defang IP display if applicable (e.g. 185.220.101.5 -> 185[.]220[.]101[.]5)
  let displayTitle = d.title || (d as any).label || "Entity";
  if (category === "ip" && typeof displayTitle === "string" && displayTitle.includes(".") && !displayTitle.includes("[")) {
    displayTitle = displayTitle.replace(/\./g, "[.]");
  }

  return (
    <div
      className={`relative px-4 py-3 rounded-2xl transition-all duration-200 cursor-pointer select-none min-w-[210px] max-w-[280px] backdrop-blur-md ${
        selected ? "ring-2 ring-emerald-400" : ""
      }`}
      style={{
        background: isInvestigatedEmail ? "rgba(6, 28, 28, 0.96)" : "rgba(7, 25, 19, 0.94)",
        border: isInvestigatedEmail
          ? "1.5px solid #00E5FF"
          : isFocal || selected
          ? "1.5px solid #10b981"
          : "1px solid rgba(16, 185, 129, 0.38)",
        boxShadow: isInvestigatedEmail
          ? "0 0 35px rgba(0, 229, 255, 0.28), inset 0 0 15px rgba(0, 229, 255, 0.08)"
          : isFocal || selected
          ? "0 0 35px rgba(16, 185, 129, 0.32), inset 0 0 15px rgba(16, 185, 129, 0.08)"
          : "0 0 18px rgba(16, 185, 129, 0.12)",
      }}
    >
      {/* Multi-directional handles matching edge connections */}
      <Handle
        type="target"
        position={Position.Top}
        id="t"
        style={{ background: "#10b981", width: 7, height: 7, border: "2px solid #071913" }}
      />
      <Handle
        type="source"
        position={Position.Top}
        id="t-src"
        style={{ background: "#10b981", width: 7, height: 7, border: "2px solid #071913" }}
      />

      <Handle
        type="target"
        position={Position.Bottom}
        id="b"
        style={{ background: "#10b981", width: 7, height: 7, border: "2px solid #071913" }}
      />
      <Handle
        type="source"
        position={Position.Bottom}
        id="b-src"
        style={{ background: "#10b981", width: 7, height: 7, border: "2px solid #071913" }}
      />

      <Handle
        type="target"
        position={Position.Left}
        id="l"
        style={{ background: "#10b981", width: 7, height: 7, border: "2px solid #071913" }}
      />
      <Handle
        type="source"
        position={Position.Left}
        id="l-src"
        style={{ background: "#10b981", width: 7, height: 7, border: "2px solid #071913" }}
      />

      <Handle
        type="target"
        position={Position.Right}
        id="r"
        style={{ background: "#10b981", width: 7, height: 7, border: "2px solid #071913" }}
      />
      <Handle
        type="source"
        position={Position.Right}
        id="r-src"
        style={{ background: "#10b981", width: 7, height: 7, border: "2px solid #071913" }}
      />

      {/* Header category row */}
      <div className={`flex items-center gap-1.5 mb-1 ${isInvestigatedEmail ? "text-cyan-400" : "text-emerald-400"}`}>
        <IconComp className={`w-3.5 h-3.5 flex-shrink-0 ${isInvestigatedEmail ? "text-cyan-400" : "text-emerald-400"}`} />
        <span className="text-[9.5px] font-mono font-bold tracking-widest uppercase truncate">
          {badgeText}
        </span>
      </div>

      {/* Main Title */}
      <div className={`text-sm font-bold truncate leading-snug ${isTitleEmerald ? "text-emerald-400 font-mono" : "text-white font-sans"}`}>
        {displayTitle}
      </div>

      {/* Subtitle */}
      {d.subtitle && (
        <div className="text-[11px] font-mono text-slate-400/90 truncate mt-0.5">
          {d.subtitle}
        </div>
      )}
    </div>
  );
});
