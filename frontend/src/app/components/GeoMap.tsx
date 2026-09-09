import React, { useEffect, useState } from "react";
import { motion } from "motion/react";
import { MapContainer, TileLayer, CircleMarker, Tooltip, ZoomControl } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import { Globe, Shield, AlertTriangle, Activity, MapPin } from "lucide-react";
import { getForensicCases } from "../api";

// ─── Mock threat data ─────────────────────────────────────────────────────
interface ThreatPoint {
  id: string;
  lat: number;
  lng: number;
  country: string;
  city: string;
  riskScore: number;
  verdict: "malicious" | "suspicious" | "safe";
  isTor: boolean;
  isVPN: boolean;
  threatType: string;
  count: number;
}

const fallbackThreatPoints: ThreatPoint[] = [
  { id: "1", lat: 55.7558, lng: 37.6176, country: "RU", city: "Moscow", riskScore: 94, verdict: "malicious", isTor: false, isVPN: true, threatType: "Spearphishing", count: 12 },
  { id: "2", lat: 39.9042, lng: 116.4074, country: "CN", city: "Beijing", riskScore: 88, verdict: "malicious", isTor: false, isVPN: false, threatType: "BEC / Wire Fraud", count: 7 },
  { id: "3", lat: 6.5244, lng: 3.3792, country: "NG", city: "Lagos", riskScore: 91, verdict: "malicious", isTor: true, isVPN: false, threatType: "Advance Fee Fraud", count: 18 },
  { id: "4", lat: 37.7749, lng: -122.4194, country: "US", city: "San Francisco", riskScore: 45, verdict: "suspicious", isTor: false, isVPN: true, threatType: "Credential Phishing", count: 3 },
  { id: "5", lat: 51.5074, lng: -0.1278, country: "GB", city: "London", riskScore: 32, verdict: "suspicious", isTor: false, isVPN: false, threatType: "Brand Impersonation", count: 5 },
  { id: "6", lat: 35.6762, lng: 139.6503, country: "JP", city: "Tokyo", riskScore: 18, verdict: "safe", isTor: false, isVPN: false, threatType: "Legitimate", count: 1 },
  { id: "7", lat: 48.8566, lng: 2.3522, country: "FR", city: "Paris", riskScore: 72, verdict: "malicious", isTor: true, isVPN: false, threatType: "Malware Delivery", count: 4 },
  { id: "8", lat: 28.6139, lng: 77.2090, country: "IN", city: "New Delhi", riskScore: 61, verdict: "suspicious", isTor: false, isVPN: true, threatType: "Tech Support Scam", count: 8 },
  { id: "9", lat: -23.5505, lng: -46.6333, country: "BR", city: "São Paulo", riskScore: 79, verdict: "malicious", isTor: false, isVPN: false, threatType: "Banking Trojan", count: 6 },
  { id: "10", lat: 52.3676, lng: 4.9041, country: "NL", city: "Amsterdam", riskScore: 55, verdict: "suspicious", isTor: false, isVPN: true, threatType: "Proxy Relay", count: 9 },
  { id: "11", lat: 40.4168, lng: -3.7038, country: "ES", city: "Madrid", riskScore: 83, verdict: "malicious", isTor: false, isVPN: false, threatType: "QR Quishing", count: 2 },
  { id: "12", lat: -33.8688, lng: 151.2093, country: "AU", city: "Sydney", riskScore: 22, verdict: "safe", isTor: false, isVPN: false, threatType: "Legitimate", count: 1 },
];

// ─── Helpers ─────────────────────────────────────────────────────────────
const riskColor = (score: number, verdict: string) => {
  if (verdict === "malicious") return "#ef4444";
  if (verdict === "suspicious") return "#f59e0b";
  return "#10b981";
};

const riskRadius = (count: number) => Math.max(8, Math.min(22, count * 2));

// ─── Stats strip ─────────────────────────────────────────────────────────
const StatsStrip: React.FC = () => {
  const [points, setPoints] = useState<ThreatPoint[]>(fallbackThreatPoints);
  useEffect(() => {
    getForensicCases().then(({ cases }) => {
      const livePoints = cases.map((item: any, index) => {
        const origin = item.originating_node;
        return origin?.latitude != null && origin?.longitude != null ? {
          id: String(item.id ?? index), lat: origin.latitude, lng: origin.longitude,
          country: origin.country_code ?? origin.country ?? "--", city: origin.city ?? "Unknown",
          riskScore: Number(item.final_risk ?? 0),
          verdict: Number(item.final_risk ?? 0) >= 70 ? "malicious" : Number(item.final_risk ?? 0) >= 35 ? "suspicious" : "safe",
          isTor: origin.anonymization_type === "TOR", isVPN: Boolean(origin.is_anonymized && origin.anonymization_type !== "TOR"),
          threatType: item.threat_category ?? "Forensic incident", count: 1,
        } as ThreatPoint : null;
      }).filter(Boolean) as ThreatPoint[];
      if (livePoints.length) setPoints(livePoints);
    }).catch(() => {});
  }, []);
  const malicious = points.filter(t => t.verdict === "malicious").length;
  const suspicious = points.filter(t => t.verdict === "suspicious").length;
  const torNodes = points.filter(t => t.isTor).length;
  const vpnNodes = points.filter(t => t.isVPN).length;
  return (
    <div className="flex gap-3 flex-wrap">
      {[
        { label: "Malicious Origins", value: malicious, color: "#ef4444" },
        { label: "Suspicious", value: suspicious, color: "#f59e0b" },
        { label: "Tor Nodes", value: torNodes, color: "#a78bfa" },
        { label: "VPN Masked", value: vpnNodes, color: "#06b6d4" },
      ].map(s => (
        <div key={s.label} className="flex items-center gap-2 px-3 py-2 rounded-xl border border-white/5"
          style={{ background: "rgba(255,255,255,0.03)" }}>
          <span className="w-2 h-2 rounded-full" style={{ background: s.color }} />
          <span className="text-xs text-slate-400">{s.label}</span>
          <span className="text-xs font-bold text-white">{s.value}</span>
        </div>
      ))}
    </div>
  );
};

// ─── Main GeoMap ──────────────────────────────────────────────────────────
const GeoMap: React.FC = () => {
  const [mounted, setMounted] = useState(false);
  const [selected, setSelected] = useState<ThreatPoint | null>(null);
  const [points, setPoints] = useState<ThreatPoint[]>(fallbackThreatPoints);

  useEffect(() => { setMounted(true); }, []);
  useEffect(() => {
    getForensicCases().then(({ cases }) => {
      const livePoints = cases.map((item: any, index) => {
        const origin = item.originating_node;
        if (origin?.latitude == null || origin?.longitude == null) return null;
        const score = Number(item.final_risk ?? 0);
        return { id: String(item.id ?? index), lat: origin.latitude, lng: origin.longitude, country: origin.country_code ?? origin.country ?? "--", city: origin.city ?? "Unknown", riskScore: score, verdict: score >= 70 ? "malicious" : score >= 35 ? "suspicious" : "safe", isTor: origin.anonymization_type === "TOR", isVPN: Boolean(origin.is_anonymized && origin.anonymization_type !== "TOR"), threatType: item.threat_category ?? "Forensic incident", count: 1 } as ThreatPoint;
      }).filter(Boolean) as ThreatPoint[];
      if (livePoints.length) setPoints(livePoints);
    }).catch(() => {});
  }, []);

  return (
    <div className="w-full min-h-screen flex flex-col"
      style={{ background: "linear-gradient(135deg, #05070d 0%, #0b0f1a 100%)" }}>

      {/* Header */}
      <div className="p-6 border-b border-white/5">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between flex-wrap gap-4 mb-4">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center border border-cyan-500/30"
                style={{ background: "rgba(0,229,255,0.1)" }}>
                <Globe className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Geo Threat Map</h1>
                <p className="text-xs text-slate-500">Real-time global phishing origin visualization</p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs text-emerald-400 border border-emerald-500/20 px-3 py-2 rounded-xl"
              style={{ background: "rgba(16,185,129,0.06)" }}>
              <Activity className="w-3.5 h-3.5" />
              <span className="animate-pulse">Live</span>
              <span className="text-slate-400">{points.length} active threat origins</span>
            </div>
          </div>
          <StatsStrip />
        </div>
      </div>

      {/* Map + sidebar */}
      <div className="flex-1 flex gap-0 min-h-0" style={{ minHeight: 500 }}>
        {/* Leaflet map */}
        <div className="flex-1 relative">
          {mounted && (
            <MapContainer
              center={[20, 0]}
              zoom={2}
              style={{ height: "100%", minHeight: 500, background: "#060c14" }}
              zoomControl={false}
              scrollWheelZoom
            >
              <ZoomControl position="bottomright" />
              <TileLayer
                attribution='&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a>'
                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              />

              {points.map((point) => {
                const color = riskColor(point.riskScore, point.verdict);
                const r = riskRadius(point.count);

                return (
                  <React.Fragment key={point.id}>
                    {/* Outer pulse ring */}
                    <CircleMarker
                      center={[point.lat, point.lng]}
                      radius={r + 6}
                      pathOptions={{
                        color: color,
                        fillColor: color,
                        fillOpacity: 0.08,
                        weight: 1,
                        opacity: 0.4,
                      }}
                    />
                    {/* Main marker */}
                    <CircleMarker
                      center={[point.lat, point.lng]}
                      radius={r}
                      pathOptions={{
                        color: color,
                        fillColor: color,
                        fillOpacity: 0.7,
                        weight: point.isTor ? 3 : 1.5,
                        dashArray: point.isTor ? "4 4" : undefined,
                      }}
                      eventHandlers={{ click: () => setSelected(point) }}
                    >
                      <Tooltip direction="top" offset={[0, -r]} opacity={1}>
                        <div className="bg-slate-900 text-white text-xs p-2 rounded-lg border border-slate-700">
                          <div className="font-bold">{point.city}, {point.country}</div>
                          <div style={{ color }}>Risk: {point.riskScore} · {point.verdict}</div>
                          <div className="text-slate-400">{point.threatType}</div>
                          {point.isTor && <div className="text-purple-300 font-bold">⚡ Tor Exit Node</div>}
                          {point.isVPN && <div className="text-amber-300 font-bold">🔒 VPN Masked</div>}
                        </div>
                      </Tooltip>
                    </CircleMarker>
                  </React.Fragment>
                );
              })}
            </MapContainer>
          )}

          {/* Map legend */}
          <div className="absolute bottom-6 left-6 z-[1000] rounded-xl border border-white/10 p-4"
            style={{ background: "rgba(10,18,35,0.9)", backdropFilter: "blur(16px)" }}>
            <div className="text-xs text-slate-400 uppercase tracking-widest mb-3">Legend</div>
            <div className="space-y-2">
              {[
                { color: "#ef4444", label: "Malicious origin" },
                { color: "#f59e0b", label: "Suspicious origin" },
                { color: "#10b981", label: "Safe / benign" },
              ].map(l => (
                <div key={l.label} className="flex items-center gap-2 text-xs text-slate-300">
                  <div className="w-3 h-3 rounded-full" style={{ background: l.color }} />
                  {l.label}
                </div>
              ))}
              <div className="flex items-center gap-2 text-xs text-slate-300 mt-1">
                <div className="w-3 h-3 rounded-full border-2 border-dashed border-purple-400" />
                Tor exit node
              </div>
              <div className="text-[10px] text-slate-500 mt-1">Circle size = threat volume</div>
            </div>
          </div>
        </div>

        {/* Threat list sidebar */}
        <div className="w-80 flex-shrink-0 border-l border-white/5 overflow-y-auto"
          style={{ background: "rgba(5,7,13,0.9)", backdropFilter: "blur(20px)" }}>
          <div className="p-4 border-b border-white/5">
            <div className="text-xs text-slate-400 uppercase tracking-widest">Active Origins</div>
          </div>
          <div className="divide-y divide-white/3">
            {points.slice().sort((a, b) => b.riskScore - a.riskScore).map((point, i) => {
              const color = riskColor(point.riskScore, point.verdict);
              const isSelected = selected?.id === point.id;
              return (
                <motion.div
                  key={point.id}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03 }}
                  onClick={() => setSelected(isSelected ? null : point)}
                  className="p-4 cursor-pointer transition-all hover:bg-white/3"
                  style={{ background: isSelected ? "rgba(0,229,255,0.04)" : undefined }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
                      <span className="text-sm font-semibold text-white">{point.city}</span>
                      <span className="text-xs text-slate-500">{point.country}</span>
                    </div>
                    <div className="text-sm font-bold" style={{ color }}>{point.riskScore}</div>
                  </div>
                  <div className="text-xs text-slate-400 mb-1">{point.threatType}</div>
                  <div className="flex items-center gap-2 flex-wrap">
                    {point.isTor && (
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold text-purple-300 border border-purple-500/20 bg-purple-500/8">TOR</span>
                    )}
                    {point.isVPN && (
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold text-amber-300 border border-amber-500/20 bg-amber-500/8">VPN</span>
                    )}
                    <span className="text-[10px] text-slate-600">{point.count} email{point.count > 1 ? "s" : ""}</span>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default GeoMap;
