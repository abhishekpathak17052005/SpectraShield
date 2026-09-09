import React, { useRef, useState, useEffect, Suspense, useCallback } from "react";
import { motion, useMotionValue, useSpring, useInView } from "motion/react";
import {
  Shield, Zap, Globe, Lock, Brain, Search, FileText, Map,
  ArrowRight, ChevronDown, Mail, AlertTriangle, Eye, Database,
  Activity, ShieldCheck, GitBranch, QrCode, Users,
} from "lucide-react";
import { Canvas, useFrame } from "@react-three/fiber";
import * as THREE from "three";

// ─── Cursor glow blob ───────────────────────────────────────────────────────
const CursorGlow: React.FC = () => {
  const x = useMotionValue(200);
  const y = useMotionValue(200);
  const sx = useSpring(x, { stiffness: 80, damping: 25 });
  const sy = useSpring(y, { stiffness: 80, damping: 25 });

  useEffect(() => {
    const move = (e: MouseEvent) => { x.set(e.clientX); y.set(e.clientY); };
    window.addEventListener("mousemove", move);
    return () => window.removeEventListener("mousemove", move);
  }, [x, y]);

  return (
    <motion.div
      className="fixed top-0 left-0 w-64 h-64 pointer-events-none z-0 rounded-full"
      style={{
        x: sx, y: sy,
        translateX: "-50%", translateY: "-50%",
        background: "radial-gradient(circle, rgba(0,229,255,0.06) 0%, transparent 70%)",
        filter: "blur(20px)",
      }}
    />
  );
};

// ─── Three.js Globe Scene ────────────────────────────────────────────────────
function randomSpherePoint(r = 2): THREE.Vector3 {
  const theta = Math.random() * Math.PI * 2;
  const phi = Math.acos(2 * Math.random() - 1);
  return new THREE.Vector3(
    r * Math.sin(phi) * Math.cos(theta),
    r * Math.sin(phi) * Math.sin(theta),
    r * Math.cos(phi),
  );
}

const IP_POINTS = Array.from({ length: 30 }, () => randomSpherePoint(2.02));
const CYAN = new THREE.Color("#00e5ff");
const RED = new THREE.Color("#ef4444");

interface ArcDef {
  lineRef: React.MutableRefObject<THREE.Line | null>;
  points: THREE.Vector3[];
  progress: number;
  speed: number;
  done: boolean;
}

const GlobeScene: React.FC<{ mouseX: number; mouseY: number }> = ({ mouseX, mouseY }) => {
  const groupRef = useRef<THREE.Group>(null);
  const arcsGroupRef = useRef<THREE.Group>(null);
  const arcs = useRef<ArcDef[]>([]);
  const nextArcTimer = useRef(0);

  const spawnArc = useCallback(() => {
    const a = IP_POINTS[Math.floor(Math.random() * IP_POINTS.length)];
    const b = IP_POINTS[Math.floor(Math.random() * IP_POINTS.length)];
    if (a === b) return;

    const mid = new THREE.Vector3()
      .addVectors(a, b)
      .multiplyScalar(0.5)
      .normalize()
      .multiplyScalar(3.4);

    const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
    const pts = curve.getPoints(60);

    const geo = new THREE.BufferGeometry().setFromPoints(pts);
    geo.setDrawRange(0, 0);
    const mat = new THREE.LineBasicMaterial({ color: CYAN, opacity: 0.7, transparent: true });
    const line = new THREE.Line(geo, mat);
    arcsGroupRef.current?.add(line);

    const ref = { current: line } as React.MutableRefObject<THREE.Line | null>;
    arcs.current.push({ lineRef: ref, points: pts, progress: 0, speed: 0.018, done: false });
  }, []);

  useFrame(({ clock }) => {
    if (!groupRef.current) return;
    const t = clock.getElapsedTime();

    // Rotate globe
    groupRef.current.rotation.y = t * 0.06 + mouseX * 0.4;
    groupRef.current.rotation.x = mouseY * 0.2;

    // Update arc draw ranges
    arcs.current = arcs.current.filter((arc) => {
      if (arc.done) return false;
      arc.progress = Math.min(1, arc.progress + arc.speed);
      const visible = Math.floor(arc.progress * (arc.points.length + 1));
      const line = arc.lineRef.current;
      if (!line) return false;
      line.geometry.setDrawRange(0, visible);
      const material = line.material as THREE.LineBasicMaterial;
      if (material) {
        material.opacity = arc.progress > 0.8 ? 0.7 * (1 - (arc.progress - 0.8) / 0.2) : 0.7;
      }
      if (arc.progress >= 1) {
        setTimeout(() => {
          const finishedLine = arc.lineRef.current;
          if (!finishedLine) return;
          arcsGroupRef.current?.remove(finishedLine);
          finishedLine.geometry.dispose();
          finishedLine.material.dispose();
          arc.lineRef.current = null;
        }, 400);
        arc.done = true;
      }
      return !arc.done;
    });

    // Spawn new arcs periodically
    nextArcTimer.current -= 0.016;
    if (nextArcTimer.current <= 0) {
      spawnArc();
      nextArcTimer.current = 1.5 + Math.random() * 1.5;
    }
  });

  // IP point geometry
  const pointsGeo = React.useMemo(() => {
    const positions = new Float32Array(IP_POINTS.flatMap((p) => [p.x, p.y, p.z]));
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    return geo;
  }, []);

  return (
    <>
      <ambientLight intensity={0.3} />
      <pointLight position={[5, 5, 5]} intensity={0.8} color="#00e5ff" />
      <pointLight position={[-5, -5, -5]} intensity={0.3} color="#7c3aed" />

      <group ref={groupRef}>
        {/* Outer wireframe sphere */}
        <mesh>
          <sphereGeometry args={[2, 36, 36]} />
          <meshBasicMaterial wireframe color="#00e5ff" transparent opacity={0.12} />
        </mesh>
        {/* Inner glow sphere */}
        <mesh>
          <sphereGeometry args={[1.96, 24, 24]} />
          <meshStandardMaterial color="#000d1a" transparent opacity={0.6} />
        </mesh>
        {/* Latitude/longitude rings */}
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[2, 0.005, 8, 80]} />
          <meshBasicMaterial color="#00e5ff" transparent opacity={0.2} />
        </mesh>
        <mesh rotation={[0, 0, 0]}>
          <torusGeometry args={[2, 0.005, 8, 80]} />
          <meshBasicMaterial color="#00e5ff" transparent opacity={0.2} />
        </mesh>

        {/* IP points */}
        <points geometry={pointsGeo}>
          <pointsMaterial size={0.06} color="#00e5ff" sizeAttenuation />
        </points>

        {/* Red "threat" points (subset) */}
        {IP_POINTS.slice(0, 8).map((p, i) => (
          <mesh key={i} position={[p.x, p.y, p.z]}>
            <sphereGeometry args={[0.04, 6, 6]} />
            <meshBasicMaterial color="#ef4444" />
          </mesh>
        ))}

        {/* Arc container */}
        <group ref={arcsGroupRef} />
      </group>
    </>
  );
};

// ─── Globe Canvas with mouse tracking ───────────────────────────────────────
const GlobeCanvas: React.FC = () => {
  const [mouse, setMouse] = useState({ x: 0, y: 0 });

  return (
    <div
      className="w-full h-full"
      onMouseMove={(e) => {
        const rect = e.currentTarget.getBoundingClientRect();
        setMouse({
          x: ((e.clientX - rect.left) / rect.width - 0.5) * 2,
          y: ((e.clientY - rect.top) / rect.height - 0.5) * -2,
        });
      }}
    >
      <Canvas camera={{ position: [0, 0, 5.5], fov: 45 }} gl={{ antialias: true, alpha: true }}>
        <Suspense fallback={null}>
          <GlobeScene mouseX={mouse.x} mouseY={mouse.y} />
        </Suspense>
      </Canvas>
    </div>
  );
};

// ─── Count-up hook ───────────────────────────────────────────────────────────
function useCountUp(target: number, duration = 1800, active = false) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!active) return;
    let start = 0;
    const step = target / (duration / 16);
    const id = setInterval(() => {
      start = Math.min(start + step, target);
      setVal(Math.floor(start));
      if (start >= target) clearInterval(id);
    }, 16);
    return () => clearInterval(id);
  }, [target, duration, active]);
  return val;
}

// ─── Stat card ───────────────────────────────────────────────────────────────
const StatCard: React.FC<{ value: number; suffix?: string; label: string; icon: React.FC<{ className?: string }> }> = ({ value, suffix = "", label, icon: Icon }) => {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true });
  const count = useCountUp(value, 1800, inView);
  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.6 }}
      className="group relative rounded-2xl p-6 border border-cyan-500/10 hover:border-cyan-500/30 transition-all overflow-hidden"
      style={{ background: "rgba(10,20,40,0.6)", backdropFilter: "blur(20px)" }}
    >
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
        style={{ background: "radial-gradient(circle at top left, rgba(0,229,255,0.06), transparent 60%)" }} />
      <Icon className="w-6 h-6 mb-4 text-cyan-400" />
      <div className="text-4xl font-bold text-white mb-1">
        {count.toLocaleString()}{suffix}
      </div>
      <div className="text-sm text-slate-400">{label}</div>
    </motion.div>
  );
};

// ─── Feature cards ───────────────────────────────────────────────────────────
const features = [
  { icon: Shield, title: "Real-time Phishing Detection", desc: "Multi-layer NLP + header forensics analysis with sub-second verdict.", color: "cyan" },
  { icon: Eye, title: "Homoglyph & Zero-Width Unicode", desc: "Detect invisible characters and lookalike glyphs used to evade filters.", color: "violet" },
  { icon: Lock, title: "SPF / DKIM / DMARC Validation", desc: "Full email authentication protocol analysis with relay path tracing.", color: "cyan" },
  { icon: Map, title: "IP GeoLocation & Tor/VPN Detection", desc: "Trace sender origins; flag Tor exit nodes and known VPN infrastructure.", color: "emerald" },
  { icon: GitBranch, title: "Campaign Graph Attribution", desc: "Link related threats into campaigns via Neo4j graph clustering.", color: "violet" },
  { icon: FileText, title: "Tamper-Evident PDF / STIX Export", desc: "Forensic-grade report export with chain-of-custody hashing.", color: "amber" },
  { icon: QrCode, title: "QR Quishing Detection", desc: "Decode QR codes embedded in images and evaluate destination URLs.", color: "red" },
  { icon: Users, title: "PII Redaction & Privacy Mode", desc: "Auto-redact sensitive data before exporting or sharing reports.", color: "cyan" },
];

const colorMap: Record<string, string> = {
  cyan: "text-cyan-400 border-cyan-500/20 from-cyan-500/5",
  violet: "text-violet-400 border-violet-500/20 from-violet-500/5",
  emerald: "text-emerald-400 border-emerald-500/20 from-emerald-500/5",
  amber: "text-amber-400 border-amber-500/20 from-amber-500/5",
  red: "text-red-400 border-red-500/20 from-red-500/5",
};

// ─── How it works steps ──────────────────────────────────────────────────────
const steps = [
  { label: "Email Ingested", desc: "Raw email or .eml file accepted via browser extension or API" },
  { label: "NLP + Header Forensics", desc: "Linguistic manipulation scoring + header anomaly detection" },
  { label: "Geo-Trace & Attribution", desc: "IP geolocation, Tor/VPN flagging, ASN lookup" },
  { label: "Risk Score & Alert", desc: "Aggregated ML risk score 0-100 with MITRE tactic tagging" },
  { label: "Forensic Report / STIX", desc: "Tamper-evident PDF or STIX 2.1 bundle export" },
];

// ─── Animated world dots (simple SVG threat map teaser) ──────────────────────
const threatDots = [
  { cx: 22, cy: 38 }, { cx: 48, cy: 35 }, { cx: 52, cy: 42 }, { cx: 72, cy: 30 },
  { cx: 55, cy: 60 }, { cx: 30, cy: 55 }, { cx: 85, cy: 45 }, { cx: 15, cy: 45 },
  { cx: 62, cy: 50 }, { cx: 40, cy: 28 }, { cx: 78, cy: 55 }, { cx: 25, cy: 62 },
];

// ─── Tech stack pills ────────────────────────────────────────────────────────
const techStack = ["FastAPI", "PostgreSQL", "Neo4j", "React 18", "MITRE ATT&CK", "TypeScript", "TailwindCSS", "Three.js"];

// ─── Main LandingPage component ──────────────────────────────────────────────
const LandingPage: React.FC<{ onLaunchConsole: () => void }> = ({ onLaunchConsole }) => {
  const [webglFailed, setWebglFailed] = useState(false);

  useEffect(() => {
    try {
      const c = document.createElement("canvas");
      if (!c.getContext("webgl") && !c.getContext("experimental-webgl")) {
        setWebglFailed(true);
      }
    } catch {
      setWebglFailed(true);
    }
  }, []);

  return (
    <div className="relative w-full min-h-screen text-white overflow-x-hidden"
      style={{ background: "linear-gradient(135deg, #05070d 0%, #0b0f1a 50%, #05070d 100%)" }}>
      <CursorGlow />

      {/* ── HERO ── */}
      <section className="relative w-full h-screen flex items-center justify-center overflow-hidden">
        {/* 3D Globe or CSS fallback */}
        <div className="absolute inset-0 z-0">
          {!webglFailed ? (
            <GlobeCanvas />
          ) : (
            /* CSS fallback globe */
            <div className="w-full h-full flex items-center justify-center">
              <div className="w-96 h-96 rounded-full border border-cyan-500/20 animate-spin"
                style={{ animationDuration: "20s", boxShadow: "0 0 80px rgba(0,229,255,0.08) inset, 0 0 40px rgba(0,229,255,0.05)" }}>
                <div className="w-full h-full rounded-full border border-cyan-500/10 animate-spin"
                  style={{ animationDuration: "10s", animationDirection: "reverse" }} />
              </div>
            </div>
          )}
          {/* Radial gradient overlay */}
          <div className="absolute inset-0"
            style={{ background: "radial-gradient(ellipse 60% 60% at 50% 50%, transparent 30%, rgba(5,7,13,0.8) 70%)" }} />
        </div>

        {/* Hero card */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 1, ease: "easeOut" }}
          className="relative z-10 text-center max-w-4xl mx-auto px-6"
        >
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full mb-6 text-xs font-medium text-cyan-300 border border-cyan-500/30"
            style={{ background: "rgba(0,229,255,0.05)", backdropFilter: "blur(10px)" }}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            SIH 2026 · AICTE · Blockchain & Cybersecurity
          </motion.div>

          <h1 className="font-bold mb-6 text-white leading-none"
            style={{ fontSize: "clamp(2.8rem, 7vw, 6rem)", textShadow: "0 0 60px rgba(0,229,255,0.2)" }}>
            <span className="block">SpectraShield</span>
            <span className="block" style={{ background: "linear-gradient(90deg, #00e5ff, #7c3aed)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              AI
            </span>
          </h1>

          <p className="text-xl text-slate-400 mb-4 max-w-2xl mx-auto leading-relaxed">
            Trace Every Threat. Attribute Every Actor.
          </p>
          <p className="text-sm text-slate-500 mb-10 max-w-xl mx-auto">
            AI-Powered Email Threat Detection, GeoLocation &amp; Forensic Intelligence Platform
          </p>

          <div className="flex items-center justify-center gap-4 flex-wrap">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.97 }}
              onClick={onLaunchConsole}
              className="group flex items-center gap-2 px-8 py-3.5 rounded-xl font-semibold text-sm transition-all"
              style={{
                background: "linear-gradient(135deg, rgba(0,229,255,0.15), rgba(124,58,237,0.15))",
                border: "1px solid rgba(0,229,255,0.3)",
                backdropFilter: "blur(10px)",
                boxShadow: "0 0 30px rgba(0,229,255,0.1)",
              }}
            >
              <Zap className="w-4 h-4 text-cyan-400" />
              <span className="text-white">Launch Console</span>
              <ArrowRight className="w-4 h-4 text-cyan-400 group-hover:translate-x-1 transition-transform" />
            </motion.button>

            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              className="flex items-center gap-2 px-8 py-3.5 rounded-xl font-semibold text-sm text-slate-300 transition-all hover:text-white"
              style={{ border: "1px solid rgba(255,255,255,0.1)", backdropFilter: "blur(10px)", background: "rgba(255,255,255,0.03)" }}
            >
              <Eye className="w-4 h-4" />
              View Live Demo
            </motion.button>
          </div>
        </motion.div>

        {/* Scroll hint */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 2 }}
          className="absolute bottom-8 left-1/2 -translate-x-1/2 z-10 flex flex-col items-center gap-2 text-slate-500"
        >
          <span className="text-xs tracking-wider uppercase">Scroll to explore</span>
          <motion.div animate={{ y: [0, 6, 0] }} transition={{ repeat: Infinity, duration: 1.5 }}>
            <ChevronDown className="w-4 h-4" />
          </motion.div>
        </motion.div>
      </section>

      {/* ── STATS ── */}
      <section className="relative z-10 py-24 px-6 max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <p className="text-xs text-cyan-400 uppercase tracking-widest mb-3">The Email Threat Crisis</p>
          <h2 className="text-3xl md:text-4xl font-bold text-white">The numbers don't lie</h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <StatCard value={91} suffix="%" label="of cyberattacks start with email" icon={Mail} />
          <StatCard value={3400} suffix="+" label="phishing sites created daily" icon={AlertTriangle} />
          <StatCard value={4700000} suffix="" label="phishing emails blocked per day" icon={Shield} />
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section className="relative z-10 py-24 px-6 max-w-5xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <p className="text-xs text-violet-400 uppercase tracking-widest mb-3">Forensic Pipeline</p>
          <h2 className="text-3xl md:text-4xl font-bold text-white">How SpectraShield works</h2>
        </motion.div>

        <div className="relative">
          {/* Connecting line */}
          <div className="absolute left-5 top-5 bottom-5 w-px hidden md:block"
            style={{ background: "linear-gradient(to bottom, rgba(0,229,255,0.4), rgba(124,58,237,0.4), transparent)" }} />

          <div className="space-y-6">
            {steps.map((step, i) => (
              <motion.div
                key={step.label}
                initial={{ opacity: 0, x: -30 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.15 }}
                className="md:pl-12 flex items-start gap-4"
              >
                <div className="flex-shrink-0 w-10 h-10 rounded-xl flex items-center justify-center text-sm font-bold text-cyan-300 border border-cyan-500/30"
                  style={{ background: "rgba(0,229,255,0.08)", backdropFilter: "blur(10px)" }}>
                  {i + 1}
                </div>
                <div className="flex-1 rounded-2xl p-5 border border-white/5 hover:border-cyan-500/20 transition-all"
                  style={{ background: "rgba(10,20,40,0.5)", backdropFilter: "blur(16px)" }}>
                  <div className="text-sm font-semibold text-white mb-1">{step.label}</div>
                  <div className="text-sm text-slate-400">{step.desc}</div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── FEATURES BENTO GRID ── */}
      <section className="relative z-10 py-24 px-6 max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <p className="text-xs text-emerald-400 uppercase tracking-widest mb-3">Capabilities</p>
          <h2 className="text-3xl md:text-4xl font-bold text-white">Enterprise-grade protection</h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {features.map((feat, i) => {
            const cls = colorMap[feat.color] || colorMap.cyan;
            const [textCls, borderCls, gradientFrom] = cls.split(" ");
            return (
              <motion.div
                key={feat.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.07 }}
                className={`group relative rounded-2xl p-5 border ${borderCls} hover:border-opacity-60 transition-all overflow-hidden`}
                style={{ background: "rgba(10,18,35,0.65)", backdropFilter: "blur(20px)" }}
              >
                <div className={`absolute inset-0 bg-gradient-to-br ${gradientFrom} to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500`} />
                <div className="relative z-10">
                  <feat.icon className={`w-5 h-5 mb-3 ${textCls}`} />
                  <div className="text-sm font-semibold text-white mb-2">{feat.title}</div>
                  <div className="text-xs text-slate-400 leading-relaxed">{feat.desc}</div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </section>

      {/* ── LIVE THREAT MAP TEASER ── */}
      <section className="relative z-10 py-24 px-6 max-w-4xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="rounded-3xl overflow-hidden border border-cyan-500/10 p-8"
          style={{ background: "rgba(10,18,35,0.7)", backdropFilter: "blur(20px)" }}
        >
          <p className="text-xs text-cyan-400 uppercase tracking-widest mb-2">Live Threat Intelligence</p>
          <h3 className="text-2xl font-bold text-white mb-6">Global threat activity — right now</h3>

          <div className="relative rounded-xl overflow-hidden border border-white/5"
            style={{ height: 200, background: "rgba(0,5,15,0.8)" }}>
            <svg viewBox="0 0 100 60" className="w-full h-full opacity-20">
              <path fill="none" stroke="#00e5ff" strokeWidth="0.3"
                d="M10 30 Q20 10 30 28 Q40 45 50 30 Q60 15 70 32 Q80 48 90 30" />
              <path fill="none" stroke="#7c3aed" strokeWidth="0.3"
                d="M5 40 Q25 20 45 38 Q65 56 85 35 Q95 25 98 40" />
            </svg>
            {threatDots.map((dot, i) => (
              <motion.div
                key={i}
                className="absolute"
                style={{ left: `${dot.cx}%`, top: `${dot.cy}%` }}
              >
                <motion.div
                  animate={{ scale: [1, 2.5, 1], opacity: [0.8, 0, 0.8] }}
                  transition={{ duration: 2 + Math.random() * 2, repeat: Infinity, delay: Math.random() * 3 }}
                  className="w-2 h-2 -translate-x-1 -translate-y-1 rounded-full"
                  style={{ background: i % 4 === 0 ? "#ef4444" : i % 3 === 0 ? "#f59e0b" : "#00e5ff" }}
                />
              </motion.div>
            ))}
            <div className="absolute bottom-3 right-3 text-xs text-slate-500 flex items-center gap-1">
              <Activity className="w-3 h-3" />
              Live data · updating
            </div>
          </div>
        </motion.div>
      </section>

      {/* ── TECH STACK ── */}
      <section className="relative z-10 py-16 px-6 max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <p className="text-xs text-slate-500 uppercase tracking-widest">Built with</p>
        </div>
        <div className="flex flex-wrap justify-center gap-3">
          {techStack.map((tech, i) => (
            <motion.span
              key={tech}
              initial={{ opacity: 0, scale: 0.8 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.05 }}
              className="px-4 py-2 rounded-full text-sm text-slate-300 border border-white/10 hover:border-cyan-500/30 transition-all"
              style={{ background: "rgba(255,255,255,0.03)", backdropFilter: "blur(10px)" }}
            >
              {tech}
            </motion.span>
          ))}
        </div>
      </section>

      {/* ── CTA FOOTER ── */}
      <section className="relative z-10 py-24 px-6 max-w-3xl mx-auto text-center">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="rounded-3xl p-12 border border-cyan-500/20"
          style={{
            background: "rgba(10,18,35,0.8)",
            backdropFilter: "blur(30px)",
            boxShadow: "0 0 60px rgba(0,229,255,0.06) inset",
          }}
        >
          <ShieldCheck className="w-12 h-12 text-cyan-400 mx-auto mb-6" />
          <h2 className="text-3xl font-bold text-white mb-4">Ready to see it in action?</h2>
          <p className="text-slate-400 mb-8">Analyze your first email threat in under 30 seconds.</p>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.97 }}
            onClick={onLaunchConsole}
            className="inline-flex items-center gap-3 px-10 py-4 rounded-2xl font-bold text-sm text-white transition-all"
            style={{
              background: "linear-gradient(135deg, rgba(0,229,255,0.2), rgba(124,58,237,0.2))",
              border: "1px solid rgba(0,229,255,0.4)",
              boxShadow: "0 0 40px rgba(0,229,255,0.15)",
            }}
          >
            <Zap className="w-5 h-5 text-cyan-400" />
            Launch Console
            <ArrowRight className="w-5 h-5" />
          </motion.button>
        </motion.div>
      </section>

      {/* Bottom fade */}
      <div className="h-24 bg-gradient-to-t from-background to-transparent" />
    </div>
  );
};

export default LandingPage;
