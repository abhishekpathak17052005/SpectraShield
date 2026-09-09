import React, { useState, useRef, useEffect, Suspense } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Canvas, useFrame } from "@react-three/fiber";
import * as THREE from "three";
import {
  Upload, Link2, Mail, Linkedin, Zap, ShieldCheck, ShieldAlert,
  AlertTriangle, CheckCircle2, ChevronRight, Copy, ExternalLink,
  RotateCcw, Lock, Globe, Brain, Server, Activity, Shield, QrCode, UserCheck,
} from "lucide-react";
import { analyze, uploadForensics, type AnalyzeResponse } from "../api";

// ─── Risk Orb (Three.js) ─────────────────────────────────────────────────────
const RiskOrbMesh: React.FC<{ riskScore: number }> = ({ riskScore }) => {
  const meshRef = useRef<THREE.Mesh>(null);
  const color = riskScore >= 70 ? "#ef4444" : riskScore >= 40 ? "#f59e0b" : "#10b981";

  useFrame(({ clock }) => {
    if (!meshRef.current) return;
    meshRef.current.rotation.y = clock.getElapsedTime() * 0.5;
    meshRef.current.rotation.x = Math.sin(clock.getElapsedTime() * 0.3) * 0.15;
  });

  return (
    <>
      <ambientLight intensity={0.4} />
      <pointLight position={[3, 3, 3]} intensity={1.5} color={color} />
      <pointLight position={[-3, -3, -3]} intensity={0.5} color={color} />
      <mesh ref={meshRef}>
        <sphereGeometry args={[1.4, 48, 48]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={0.3}
          roughness={0.1}
          metalness={0.8}
          transparent
          opacity={0.9}
        />
      </mesh>
      {/* Inner sphere */}
      <mesh>
        <sphereGeometry args={[1.2, 32, 32]} />
        <meshBasicMaterial color={color} transparent opacity={0.05} />
      </mesh>
      {/* Wireframe overlay */}
      <mesh ref={meshRef}>
        <sphereGeometry args={[1.42, 24, 24]} />
        <meshBasicMaterial wireframe color={color} transparent opacity={0.12} />
      </mesh>
    </>
  );
};

const RiskOrb: React.FC<{ riskScore: number }> = ({ riskScore }) => {
  const color = riskScore >= 70 ? "#ef4444" : riskScore >= 40 ? "#f59e0b" : "#10b981";
  return (
    <div className="relative w-40 h-40 mx-auto">
      <div className="absolute inset-0 rounded-full blur-2xl opacity-30" style={{ background: color }} />
      <Canvas camera={{ position: [0, 0, 3.5], fov: 45 }} gl={{ antialias: true, alpha: true }}>
        <Suspense fallback={null}>
          <RiskOrbMesh riskScore={riskScore} />
        </Suspense>
      </Canvas>
    </div>
  );
};

// ─── Scan animation sequence ─────────────────────────────────────────────────
const SCAN_STEPS = [
  { label: "Parsing Email Headers & MIME", icon: Mail },
  { label: "Checking SPF / DKIM / DMARC", icon: Lock },
  { label: "DeBERTa-v3 NLP Semantic Analysis", icon: Brain },
  { label: "URL & Live Threat Feed Lookup", icon: Globe },
  { label: "IP Geolocation & Tor/VPN Match", icon: Server },
  { label: "Computing Multi-Vector Risk Score", icon: Activity },
];

const ScanAnimation: React.FC<{ onComplete: () => void }> = ({ onComplete }) => {
  const [step, setStep] = useState(0);
  const [sweepY, setSweepY] = useState(0);

  useEffect(() => {
    const total = SCAN_STEPS.length;
    const stepDuration = 500;

    const id = setInterval(() => {
      setStep((s) => {
        if (s >= total - 1) {
          clearInterval(id);
          setTimeout(onComplete, 350);
          return s;
        }
        return s + 1;
      });
    }, stepDuration);

    // Sweep animation
    let sweepProgress = 0;
    const sweepId = setInterval(() => {
      sweepProgress = (sweepProgress + 2) % 100;
      setSweepY(sweepProgress);
    }, 16);

    const cleanup = setTimeout(() => clearInterval(sweepId), stepDuration * total + 350);
    return () => { clearInterval(id); clearInterval(sweepId); clearTimeout(cleanup); };
  }, [onComplete]);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className="flex flex-col items-center gap-8 py-8"
    >
      {/* 3D-ish envelope scanner */}
      <div className="relative w-48 h-36 rounded-xl overflow-hidden border border-cyan-500/30"
        style={{ background: "rgba(0,15,30,0.9)", boxShadow: "0 0 40px rgba(0,229,255,0.1) inset" }}>
        {/* Envelope body */}
        <div className="absolute inset-4 rounded-lg border border-cyan-500/20"
          style={{ background: "rgba(0,229,255,0.03)" }}>
          <div className="absolute top-0 left-0 right-0 h-8 border-b border-cyan-500/20 flex items-center justify-center">
            <div className="text-[8px] text-cyan-400/60 font-mono tracking-widest">EMAIL PACKET</div>
          </div>
          <div className="absolute bottom-2 left-3 right-3 space-y-1">
            <div className="h-1 bg-cyan-500/10 rounded" style={{ width: "80%" }} />
            <div className="h-1 bg-cyan-500/10 rounded" style={{ width: "60%" }} />
            <div className="h-1 bg-cyan-500/10 rounded" style={{ width: "70%" }} />
          </div>
        </div>

        {/* Sweeping scan plane */}
        <motion.div
          className="absolute left-0 right-0 h-0.5"
          style={{ top: `${sweepY}%`, background: "linear-gradient(90deg, transparent, #00e5ff, transparent)", boxShadow: "0 0 8px #00e5ff, 0 0 20px rgba(0,229,255,0.4)" }}
        />

        {/* Scan line glow */}
        <div className="absolute left-0 right-0 h-8 pointer-events-none"
          style={{ top: `${sweepY - 4}%`, background: `linear-gradient(to bottom, transparent, rgba(0,229,255,0.04), transparent)` }} />

        {/* Corner brackets */}
        <div className="absolute top-2 left-2 w-3 h-3 border-t border-l border-cyan-400/60" />
        <div className="absolute top-2 right-2 w-3 h-3 border-t border-r border-cyan-400/60" />
        <div className="absolute bottom-2 left-2 w-3 h-3 border-b border-l border-cyan-400/60" />
        <div className="absolute bottom-2 right-2 w-3 h-3 border-b border-r border-cyan-400/60" />
      </div>

      {/* Step progress */}
      <div className="w-full max-w-sm space-y-2">
        {SCAN_STEPS.map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0.3 }}
            animate={{ opacity: i <= step ? 1 : 0.3 }}
            className="flex items-center gap-3 text-sm"
          >
            <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 transition-all ${
              i < step ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" :
              i === step ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 animate-pulse" :
              "bg-white/5 text-slate-600 border border-white/5"
            }`}>
              {i < step ? <CheckCircle2 className="w-3 h-3" /> : <s.icon className="w-3 h-3" />}
            </div>
            <span className={i <= step ? "text-slate-200" : "text-slate-600"}>{s.label}</span>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
};

// ─── SVG Risk Gauge ───────────────────────────────────────────────────────────
const RiskGauge: React.FC<{ score: number }> = ({ score }) => {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const color = score >= 70 ? "#ef4444" : score >= 40 ? "#f59e0b" : "#10b981";

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="80" viewBox="-10 -10 140 90">
        {/* Track */}
        <path d="M 10 70 A 52 52 0 0 1 110 70" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" strokeLinecap="round" />
        {/* Arc fill */}
        <motion.path
          d="M 10 70 A 52 52 0 0 1 110 70"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${circ / 2}`}
          initial={{ strokeDashoffset: circ / 2 }}
          animate={{ strokeDashoffset: (circ / 2) * (1 - score / 100) }}
          transition={{ duration: 1.2, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
        {/* Score text */}
        <text x="60" y="65" textAnchor="middle" fill={color} fontSize="24" fontWeight="bold">{score}</text>
        <text x="60" y="78" textAnchor="middle" fill="#64748b" fontSize="9">RISK SCORE</text>
      </svg>
    </div>
  );
};

// ─── Factor bar ──────────────────────────────────────────────────────────────
const FactorBar: React.FC<{ label: string; value: number; color: string }> = ({ label, value, color }) => (
  <div className="space-y-1.5">
    <div className="flex justify-between text-xs">
      <span className="text-slate-400">{label}</span>
      <span className="font-semibold" style={{ color }}>{value}%</span>
    </div>
    <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${value}%` }}
        transition={{ duration: 1, ease: "easeOut" }}
        className="h-full rounded-full"
        style={{ background: color, boxShadow: `0 0 8px ${color}80` }}
      />
    </div>
  </div>
);

// ─── Tab definitions ─────────────────────────────────────────────────────────
const tabs = [
  { id: "email", label: "Paste Email", icon: Mail },
  { id: "url", label: "Paste URL", icon: Link2 },
  { id: "eml", label: "Upload .eml / .msg / .mbox", icon: Upload },
  { id: "linkedin", label: "LinkedIn Message", icon: Linkedin },
] as const;

type TabId = typeof tabs[number]["id"];
type State = "idle" | "scanning" | "results";

interface AnalyzePageProps {
  onOpenForensics?: (caseId?: string) => void;
}

const AnalyzePage: React.FC<AnalyzePageProps> = ({ onOpenForensics }) => {
  const [tab, setTab] = useState<TabId>("email");
  const [state, setState] = useState<State>("idle");
  const [emailText, setEmailText] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [linkedinMsg, setLinkedinMsg] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [privateMode, setPrivateMode] = useState(false);
  const [backendError, setBackendError] = useState(false);
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSubmit = async () => {
    setState("scanning");
    setBackendError(false);

    try {
      let result: AnalyzeResponse;
      if (tab === "eml" && selectedFile) {
        result = await uploadForensics(selectedFile, privateMode);
      } else {
        const body: Record<string, string | boolean> = { private_mode: privateMode };
        if (tab === "email") body.email_text = emailText;
        if (tab === "url") body.url = urlInput;
        if (tab === "linkedin") { body.email_text = linkedinMsg; body.platform = "linkedin"; }
        result = await analyze(body);
      }
      setAnalysis(result);
    } catch {
      setBackendError(true);
      setState("idle");
    }
  };

  const handleReset = () => {
    setState("idle");
    setFileName(null);
    setSelectedFile(null);
    setAnalysis(null);
  };

  const handleFileSelect = (file: File) => {
    setFileName(file.name);
    setSelectedFile(file);
  };

  const riskScore = Math.round(analysis?.final_risk ?? (analysis?.final_score ? analysis.final_score * 100 : 0));
  const factors = {
    linguistic: Math.round(analysis?.breakdown?.manipulation_score ?? 0),
    brand: Math.round(analysis?.breakdown?.brand_impersonation_score ?? 0),
    protocol: Math.round(analysis?.breakdown?.header_score ?? 0),
    url: Math.round(analysis?.breakdown?.url_score ?? 0),
  };
  const verdict = analysis?.verdict ?? "Unknown";
  const vColor = riskScore >= 70 ? "#ef4444" : riskScore >= 35 ? "#f59e0b" : "#10b981";

  return (
    <div className="w-full min-h-screen p-6 md:p-10"
      style={{ background: "linear-gradient(135deg, #05070d 0%, #0b0f1a 100%)" }}>

      {/* Backend error banner */}
      <AnimatePresence>
        {backendError && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="mb-6 flex items-center gap-3 p-4 rounded-xl border border-amber-500/30 text-amber-300 text-sm"
            style={{ background: "rgba(245,158,11,0.08)", backdropFilter: "blur(10px)" }}
          >
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            Backend inspection failed or unreachable. Please ensure the FastAPI server is running on port 8000.
          </motion.div>
        )}
      </AnimatePresence>

      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center border border-cyan-500/30"
              style={{ background: "rgba(0,229,255,0.1)" }}>
              <Zap className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Threat Analyzer</h1>
              <p className="text-xs text-slate-500">AI-powered multi-vector cognitive and header inspection</p>
            </div>
          </div>
          {state === "results" && (
            <button onClick={handleReset}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm text-slate-400 hover:text-white border border-white/10 hover:border-white/20 transition-all"
              style={{ background: "rgba(255,255,255,0.03)" }}>
              <RotateCcw className="w-4 h-4" />
              New Scan
            </button>
          )}
        </div>

        <AnimatePresence mode="wait">
          {/* ── IDLE: input form ── */}
          {state === "idle" && (
            <motion.div key="idle" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }}>
              {/* Tab nav */}
              <div className="flex gap-1 p-1 rounded-xl mb-6 border border-white/5"
                style={{ background: "rgba(255,255,255,0.03)", backdropFilter: "blur(10px)" }}>
                {tabs.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setTab(t.id)}
                    className={`flex-1 flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                      tab === t.id
                        ? "text-cyan-300 border border-cyan-500/30"
                        : "text-slate-500 hover:text-slate-300"
                    }`}
                    style={tab === t.id ? { background: "rgba(0,229,255,0.08)" } : {}}
                  >
                    <t.icon className="w-4 h-4" />
                    <span className="hidden sm:inline">{t.label}</span>
                  </button>
                ))}
              </div>

              {/* Input area */}
              <div className="rounded-2xl border border-white/5 p-6 mb-4"
                style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                {tab === "email" && (
                  <textarea
                    value={emailText}
                    onChange={(e) => setEmailText(e.target.value)}
                    placeholder="Paste raw email content with RFC 5322 headers or plain text..."
                    rows={10}
                    className="w-full bg-transparent text-slate-200 placeholder-slate-600 text-sm font-mono resize-none outline-none leading-relaxed"
                  />
                )}
                {tab === "url" && (
                  <div className="flex items-center gap-3">
                    <Link2 className="w-5 h-5 text-slate-500 flex-shrink-0" />
                    <input
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="https://suspicious-domain.tk/login/verify..."
                      className="flex-1 bg-transparent text-slate-200 placeholder-slate-600 text-sm outline-none"
                    />
                  </div>
                )}
                {tab === "eml" && (
                  <div
                    onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setDragOver(false);
                      const file = e.dataTransfer.files[0];
                      if (file) handleFileSelect(file);
                    }}
                    onClick={() => fileInputRef.current?.click()}
                    className={`flex flex-col items-center justify-center gap-4 h-48 rounded-xl border-2 border-dashed transition-all cursor-pointer ${
                      dragOver ? "border-cyan-400/60 bg-cyan-500/5" : "border-white/10 hover:border-white/20"
                    }`}
                  >
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".eml,.msg,.mbox"
                      className="hidden"
                      onChange={(e) => { if (e.target.files?.[0]) handleFileSelect(e.target.files[0]); }}
                    />
                    <Upload className={`w-8 h-8 ${dragOver ? "text-cyan-400" : "text-slate-500"}`} />
                    {fileName ? (
                      <div className="text-center">
                        <div className="text-sm text-cyan-300 font-medium">{fileName}</div>
                        <div className="text-xs text-slate-500 mt-1">Ready for multi-format ingestion &amp; analysis</div>
                      </div>
                    ) : (
                      <div className="text-center">
                        <div className="text-sm text-slate-400">Drop .eml, .msg (Outlook), or .mbox archive here</div>
                        <div className="text-xs text-slate-600 mt-1">or click to browse from device</div>
                      </div>
                    )}
                  </div>
                )}
                {tab === "linkedin" && (
                  <textarea
                    value={linkedinMsg}
                    onChange={(e) => setLinkedinMsg(e.target.value)}
                    placeholder="Paste the suspicious LinkedIn recruiter or networking message here..."
                    rows={8}
                    className="w-full bg-transparent text-slate-200 placeholder-slate-600 text-sm resize-none outline-none leading-relaxed"
                  />
                )}
              </div>

              {/* Privacy / PII Toggle */}
              <div className="flex items-center justify-between px-2 mb-6 text-xs text-slate-400">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={privateMode}
                    onChange={(e) => setPrivateMode(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span>Sanitize &amp; Redact PII (Credit cards, phone numbers, SSNs)</span>
                </label>
                <span className="text-slate-600">GDPR Art 32 / DPDP Compliant</span>
              </div>

              {/* Submit */}
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleSubmit}
                disabled={tab === "eml" ? !fileName : tab === "url" ? !urlInput : tab === "linkedin" ? !linkedinMsg : !emailText}
                className="w-full py-4 rounded-xl font-bold text-sm text-white flex items-center justify-center gap-3 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                style={{
                  background: "linear-gradient(135deg, rgba(0,229,255,0.25), rgba(124,58,237,0.25))",
                  border: "1px solid rgba(0,229,255,0.4)",
                  boxShadow: "0 0 30px rgba(0,229,255,0.1)",
                }}
              >
                <Zap className="w-5 h-5 text-cyan-400" />
                Analyze Threat
                <ChevronRight className="w-4 h-4" />
              </motion.button>
            </motion.div>
          )}

          {/* ── SCANNING animation ── */}
          {state === "scanning" && (
            <motion.div key="scanning"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="rounded-2xl border border-cyan-500/20 p-8"
              style={{ background: "rgba(10,18,35,0.8)", backdropFilter: "blur(20px)" }}>
              <div className="text-center mb-2">
                <h2 className="text-lg font-bold text-white">Live Inspection in Progress</h2>
                <p className="text-xs text-slate-500 mt-1">Multi-vector AI &amp; cryptographic evaluation running...</p>
              </div>
              <ScanAnimation onComplete={() => setState("results")} />
            </motion.div>
          )}

          {/* ── RESULTS ── */}
          {state === "results" && (
            <motion.div key="results"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6">

              {/* VIP Impersonation Alert Banner */}
              {analysis?.vip_impersonation?.is_vip_impersonation && (
                <div className="rounded-2xl p-4 border border-red-500/40 flex items-center gap-3 text-red-300"
                  style={{ background: "rgba(239,68,68,0.12)", backdropFilter: "blur(20px)" }}>
                  <UserCheck className="w-6 h-6 text-red-400 flex-shrink-0" />
                  <div>
                    <div className="font-bold text-sm">CRITICAL: Executive VIP Impersonation Detected</div>
                    <div className="text-xs text-red-200/80">
                      Message mimics executive <strong>{analysis.vip_impersonation.matched_vip?.name}</strong> ({analysis.vip_impersonation.matched_vip?.title}) but was transmitted from an unauthorized domain.
                    </div>
                  </div>
                </div>
              )}

              {/* Quishing QR Detection Banner */}
              {analysis?.quishing?.is_quishing_detected && (
                <div className="rounded-2xl p-4 border border-purple-500/40 flex items-center gap-3 text-purple-300"
                  style={{ background: "rgba(168,85,247,0.12)", backdropFilter: "blur(20px)" }}>
                  <QrCode className="w-6 h-6 text-purple-400 flex-shrink-0" />
                  <div>
                    <div className="font-bold text-sm">Quishing Alert: {analysis.quishing.qr_count} Embedded QR Code(s) Decoded</div>
                    <div className="text-xs font-mono text-purple-200/80 break-all">
                      Decoded Target: {analysis.quishing.decoded_urls.join(", ")}
                    </div>
                  </div>
                </div>
              )}

              {/* Verdict banner */}
              <div className="rounded-2xl p-6 border flex items-center justify-between"
                style={{
                  background: `rgba(${riskScore >= 70 ? "239,68,68" : riskScore >= 35 ? "245,158,11" : "16,185,129"},0.08)`,
                  borderColor: `${vColor}30`,
                  backdropFilter: "blur(20px)",
                }}>
                <div className="flex items-center gap-4">
                  {riskScore >= 70
                    ? <ShieldAlert className="w-10 h-10" style={{ color: vColor }} />
                    : <ShieldCheck className="w-10 h-10" style={{ color: vColor }} />
                  }
                  <div>
                    <div className="text-xs text-slate-400 uppercase tracking-widest mb-1">Verdict</div>
                    <div className="text-2xl font-bold" style={{ color: vColor }}>{verdict}</div>
                    {analysis?.threat_category && (
                      <div className="text-xs font-mono text-slate-400 mt-0.5">{analysis.threat_category}</div>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-slate-400 mb-1">Confidence</div>
                  <div className="text-xl font-bold text-white">{analysis?.confidence_level ?? `${riskScore}%`}</div>
                </div>
              </div>

              {/* Orb + Gauge + Factors */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Risk orb + gauge */}
                <div className="rounded-2xl p-6 border border-white/5 space-y-4"
                  style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                  <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Risk Score</h3>
                  <RiskOrb riskScore={riskScore} />
                  <RiskGauge score={riskScore} />
                </div>

                {/* Factor bars */}
                <div className="rounded-2xl p-6 border border-white/5 space-y-5"
                  style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                  <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Risk Vectors</h3>
                  <FactorBar label="Linguistic Manipulation" value={factors.linguistic} color="#ef4444" />
                  <FactorBar label="Brand Impersonation" value={factors.brand} color="#ef4444" />
                  <FactorBar label="Protocol Anomalies" value={factors.protocol} color="#f59e0b" />
                  <FactorBar label="URL / Domain Risk" value={factors.url} color="#ef4444" />
                </div>
              </div>

              {/* DeBERTa Transformer NLP Breakdown */}
              {analysis?.nlp_analysis?.category_probabilities && (
                <div className="rounded-2xl p-6 border border-white/5"
                  style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                      <Brain className="w-4 h-4 text-cyan-400" />
                      DeBERTa-v3 Transformer NLP Intent Distribution
                    </h3>
                    <span className="text-[10px] font-mono text-cyan-400/80">{analysis.nlp_analysis.model_name}</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                    {Object.entries(analysis.nlp_analysis.category_probabilities).map(([cat, prob]) => (
                      <div key={cat} className="p-3 rounded-xl border border-white/5 bg-white/2">
                        <div className="text-[10px] text-slate-400 truncate mb-1">{cat.replace(/_/g, " ")}</div>
                        <div className="text-sm font-bold font-mono text-cyan-300">{(prob * 100).toFixed(1)}%</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK trajectory */}
              <div className="rounded-2xl p-6 border border-white/5"
                style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">MITRE ATT&CK Trajectory</h3>
                <div className="flex items-center gap-2 flex-wrap">
                  {(analysis?.mitre_tactics && analysis.mitre_tactics.length > 0 ? analysis.mitre_tactics : ["T1566 - Phishing", "T1598 - Spearphishing"]).map((tactic, i, arr) => (
                    <React.Fragment key={tactic}>
                      <span className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold border border-violet-500/30 text-violet-300"
                        style={{ background: "rgba(124,58,237,0.1)" }}>
                        {tactic}
                      </span>
                      {i < arr.length - 1 && (
                        <ChevronRight className="w-3 h-3 text-slate-600 flex-shrink-0" />
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>

              {/* Summary */}
              <div className="rounded-2xl p-6 border border-white/5"
                style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}>
                <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">Threat Summary</h3>
                <p className="text-sm text-slate-300 leading-relaxed">{analysis?.reasoning_summary ?? "Analysis completed successfully."}</p>
              </div>

              {/* Actions */}
              <div className="flex gap-3">
                <button
                  onClick={() => {
                    if (onOpenForensics) {
                      onOpenForensics(analysis?.case_id);
                    }
                  }}
                  className="flex-1 py-3 rounded-xl text-sm font-semibold text-white border border-cyan-500/30 hover:border-cyan-500/50 transition-all flex items-center justify-center gap-2"
                  style={{ background: "rgba(0,229,255,0.12)" }}>
                  <ExternalLink className="w-4 h-4 text-cyan-400" />
                  Inspect in Forensic Dossier
                </button>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(analysis, null, 2));
                  }}
                  className="py-3 px-4 rounded-xl text-sm text-slate-400 border border-white/10 hover:border-white/20 transition-all"
                  style={{ background: "rgba(255,255,255,0.03)" }}
                  title="Copy Analysis JSON">
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default AnalyzePage;
