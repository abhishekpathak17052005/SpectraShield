import React, { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { Globe, ShieldAlert, Radio } from "lucide-react";
import { DefangedText } from "../common/DefangedText";

export interface RelayHopGeo {
  hop: number;
  received_from: string;
  by: string;
  ip?: string;
  defanged_ip?: string;
  is_private: boolean;
  is_origin: boolean;
  timestamp?: string;
  delay_seconds: number;
  geo?: {
    country?: string;
    country_code?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    asn?: string;
    isp?: string;
    is_anonymized?: boolean;
    anonymization_type?: string;
  } | null;
}

interface HopMapVisualizerProps {
  hops: RelayHopGeo[];
  originNode?: any;
}

export const HopMapVisualizer: React.FC<HopMapVisualizerProps> = ({ hops, originNode }) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);

  useEffect(() => {
    if (!mapContainerRef.current) return;

    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    const map = L.map(mapContainerRef.current, {
      zoomControl: true,
      attributionControl: false,
    }).setView([25.0, 10.0], 2);

    mapInstanceRef.current = map;

    // Dark vector carto tile map
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19,
      className: "dark-map-tiles",
    }).addTo(map);

    const validHops = hops.filter(
      (h) =>
        h.geo &&
        typeof h.geo.latitude === "number" &&
        typeof h.geo.longitude === "number" &&
        !isNaN(h.geo.latitude) &&
        !isNaN(h.geo.longitude)
    );

    const latLngs: L.LatLngExpression[] = [];

    validHops.forEach((hop) => {
      const lat = hop.geo!.latitude!;
      const lon = hop.geo!.longitude!;
      const isOrigin = hop.is_origin;
      const isTor = hop.geo?.is_anonymized;

      latLngs.push([lat, lon]);

      const markerColor = isOrigin ? "#ef4444" : isTor ? "#f59e0b" : "#06b6d4";
      const iconHtml = `
        <div style="
          position: relative;
          width: 26px;
          height: 26px;
          display: flex;
          align-items: center;
          justify-content: center;
        ">
          ${
            isOrigin
              ? `<div style="
                  position: absolute;
                  inset: -6px;
                  border-radius: 50%;
                  background: rgba(239, 68, 68, 0.4);
                  animation: beaconPulse 2.2s infinite;
                "></div>`
              : ""
          }
          <div style="
            position: relative;
            z-index: 2;
            width: 22px;
            height: 22px;
            background: ${markerColor};
            border: 2px solid #ffffff;
            border-radius: 50%;
            box-shadow: 0 0 14px ${markerColor};
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            font-family: monospace;
            font-size: 11px;
            font-weight: bold;
          ">
            ${hop.hop}
          </div>
        </div>
      `;

      const customIcon = L.divIcon({
        className: "custom-hop-marker",
        html: iconHtml,
        iconSize: [26, 26],
        iconAnchor: [13, 13],
      });

      const popupContent = `
        <div style="font-family: ui-monospace, monospace; font-size: 11px; color: #f8fafc; background: #0f172a; padding: 10px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.15); box-shadow: 0 10px 25px rgba(0,0,0,0.5); min-width: 200px;">
          <div style="font-weight: bold; margin-bottom: 6px; color: ${markerColor}; font-size: 12px;">
            ${isOrigin ? "🚨 EARLIEST RELIABLE ORIGIN" : `MTA HOP #${hop.hop}`}
          </div>
          <div style="margin-bottom: 2px;"><b>IP:</b> ${hop.defanged_ip || hop.ip || "N/A"}</div>
          <div style="margin-bottom: 2px;"><b>Location:</b> ${hop.geo?.city || "Unknown"}, ${hop.geo?.country || "Unknown"}</div>
          <div style="margin-bottom: 2px;"><b>ASN/ISP:</b> ${hop.geo?.asn || "N/A"} - ${hop.geo?.isp || "N/A"}</div>
          <div style="margin-bottom: 4px;"><b>Transit Delay:</b> +${hop.delay_seconds}s</div>
          ${isTor ? `<div style="color: #ef4444; font-weight: bold; margin-top: 4px;">⚠️ TOR EXIT ROUTER DETECTED</div>` : ""}
        </div>
      `;

      L.marker([lat, lon], { icon: customIcon }).addTo(map).bindPopup(popupContent);
    });

    // Geodesic path connecting hops
    if (latLngs.length > 1) {
      const polyline = L.polyline(latLngs, {
        color: "#06b6d4",
        weight: 3,
        opacity: 0.85,
        dashArray: "6, 8",
      }).addTo(map);

      map.fitBounds(polyline.getBounds(), { padding: [45, 45] });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 4);
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [hops]);

  return (
    <div className="relative overflow-hidden rounded-3xl border border-white/15 bg-slate-900/80 backdrop-blur-2xl shadow-2xl">
      {/* Specular Rim Top Highlight */}
      <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/80 to-transparent z-10" />

      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between px-5 py-3.5 border-b border-white/10 bg-slate-950/60 backdrop-blur-xl">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-cyan-400 animate-spin" style={{ animationDuration: '18s' }} />
          <span className="text-xs font-mono font-bold tracking-wider text-slate-200 uppercase">
            Cartographic MTA Flight Path & Physical Node Trace
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="h-2 w-2 rounded-full bg-red-500 animate-ping" />
            Origin (ERPN)
          </span>
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            Intermediate MTA
          </span>
        </div>
      </div>

      {/* Map Canvas */}
      <div className="relative h-[380px] w-full bg-slate-950">
        <div ref={mapContainerRef} className="h-full w-full" />

        {/* Origin Node HUD Overlay */}
        {originNode && (
          <div className="absolute bottom-4 left-4 z-[1000] rounded-2xl border border-white/15 bg-slate-900/90 backdrop-blur-3xl p-3.5 text-xs font-mono text-slate-200 shadow-2xl max-w-sm">
            <div className="flex items-center gap-1.5 text-red-400 font-bold mb-1.5">
              <ShieldAlert className="h-4 w-4 animate-pulse" />
              <span>EARLIEST RELIABLE PUBLIC NODE (ERPN)</span>
            </div>
            <div className="space-y-1 text-slate-300">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Defanged IP:</span>
                <DefangedText value={originNode.defanged_ip || originNode.ip} />
              </div>
              <div>
                <span className="text-slate-400">Location:</span> {originNode.city}, {originNode.country}
              </div>
              <div className="truncate">
                <span className="text-slate-400">Network:</span> {originNode.asn} ({originNode.isp})
              </div>
            </div>
            {originNode.is_anonymized && (
              <div className="mt-2 inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-500/20 text-red-300 text-[10px] font-bold border border-red-500/30">
                <Radio className="w-3 h-3 animate-ping" />
                <span>ANONYMIZED INFRASTRUCTURE: {originNode.anonymization_type || "TOR ROUTER"}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
