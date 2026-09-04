import React, { useState } from 'react';
import {
  Sparkles,
  Layers,
  Zap,
  ShieldCheck,
  ShieldAlert,
  Sliders,
  ChevronDown,
  Info,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { LiquidGlassCard } from '../liquid/LiquidGlassCard';
import { LiquidMorphButton } from '../liquid/LiquidMorphButton';
import { LiquidSegmentedControl } from '../liquid/LiquidSegmentedControl';
import { LiquidGlassBadge } from '../liquid/LiquidGlassBadge';
import { LiquidCausticProgress } from '../liquid/LiquidCausticProgress';
import { LiquidGlassAccordion } from '../liquid/LiquidGlassAccordion';

export const StyleGuideView: React.FC = () => {
  const [segValue, setSegValue] = useState('forensics');
  const [progressVal, setProgressVal] = useState(78);
  const [accordionOpen, setAccordionOpen] = useState(true);

  return (
    <div className="space-y-10 pb-16">
      {/* Top Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
            Universal Liquid Glass Design System
          </h1>
          <LiquidGlassBadge variant="forensics" label="PHYSICS ENGINE v2.0" size="sm" />
        </div>
        <p className="text-xs md:text-sm text-slate-400 mt-1 max-w-2xl">
          Comprehensive specification and interactive component gallery simulating real-world optical physics:
          multi-tier refraction blurs, specular top rim edges, directional internal caustics, and zero-layout-shift morphing.
        </p>
      </div>

      {/* Physics Principles Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <LiquidGlassCard glowColor="cyan" className="p-5 space-y-2">
          <div className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
            1. Multi-Tier Refraction
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Light diffuses across tiered blurs (12px to 32px) coupled with <code className="text-cyan-300">backdrop-saturate-180</code> to maintain vibrant chromatic depth without washed-out grays.
          </p>
        </LiquidGlassCard>

        <LiquidGlassCard glowColor="purple" className="p-5 space-y-2">
          <div className="text-xs font-mono font-bold text-purple-400 uppercase tracking-wider">
            2. Specular Rim Edge
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Microscopic 1px top border gradient grazing the glass rim (<code className="text-purple-300">border-t border-white/80</code>) simulating high-angle specular reflection.
          </p>
        </LiquidGlassCard>

        <LiquidGlassCard glowColor="emerald" className="p-5 space-y-2">
          <div className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider">
            3. Viscous Surface Tension
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Transitions employ Apple-grade cubic beziers (<code className="text-emerald-300">cubic-bezier(0.16, 1, 0.3, 1)</code>) for elastic, zero-snap fluid movement.
          </p>
        </LiquidGlassCard>
      </div>

      {/* Interactive Primitives Gallery */}
      <div className="space-y-6">
        <h2 className="text-lg font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          <span>Interactive Component Primitives</span>
        </h2>

        {/* 1. Liquid Segmented Control */}
        <LiquidGlassCard glowColor="cyan" className="p-6 space-y-4">
          <div>
            <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
              Liquid Sliding Segmented Control
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Gliding liquid glass droplet indicator with elastic momentum and internal specular sheen.
            </p>
          </div>

          <div className="pt-2">
            <LiquidSegmentedControl
              options={[
                { id: 'dashboard', label: 'Executive SOC' },
                { id: 'forensics', label: 'Forensic Ops', badge: '2.0' },
                { id: 'graph', label: 'Threat Graph' },
                { id: 'sandbox', label: 'Link Sandbox' },
              ]}
              value={segValue}
              onChange={setSegValue}
              size="lg"
            />
          </div>
          <div className="text-xs font-mono text-cyan-300">
            Active Segment State: <span className="font-bold uppercase">{segValue}</span>
          </div>
        </LiquidGlassCard>

        {/* 2. Volumetric Morphing Action Buttons */}
        <LiquidGlassCard glowColor="crimson" className="p-6 space-y-4">
          <div>
            <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
              Volumetric Morphing Buttons
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Dual-gradient cyber buttons with dynamic diagonal specular refraction sheen waves.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-4 pt-2">
            <LiquidMorphButton mode="cyan" icon={Zap}>
              Cyan Forensics
            </LiquidMorphButton>
            <LiquidMorphButton mode="crimson" icon={ShieldAlert}>
              Crimson Malicious
            </LiquidMorphButton>
            <LiquidMorphButton mode="purple" icon={Sparkles}>
              Purple Attribution
            </LiquidMorphButton>
            <LiquidMorphButton mode="emerald" icon={ShieldCheck}>
              Emerald Verified
            </LiquidMorphButton>
            <LiquidMorphButton mode="amber" icon={AlertTriangle}>
              Amber Caution
            </LiquidMorphButton>
            <LiquidMorphButton mode="cyan" isLoading>
              Loading State
            </LiquidMorphButton>
          </div>
        </LiquidGlassCard>

        {/* 3. Glowing Status Droplets / Badges */}
        <LiquidGlassCard glowColor="purple" className="p-6 space-y-4">
          <div>
            <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
              Glowing Liquid Status Badges
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              High-contrast status pills featuring pulsing ambient occlusion core droplets.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <LiquidGlassBadge variant="safe" label="CLEAN VERIFIED (PASS)" icon={CheckCircle2} />
            <LiquidGlassBadge variant="warning" label="SUSPICIOUS DOMAIN AGE" icon={AlertTriangle} />
            <LiquidGlassBadge variant="critical" label="CRITICAL BEC EXPLOIT" icon={ShieldAlert} />
            <LiquidGlassBadge variant="forensics" label="RFC 5322 DISSECTION" icon={Zap} />
            <LiquidGlassBadge variant="campaign" label="FIN7 ATTRIBUTION CLUSTER" icon={Sparkles} />
          </div>
        </LiquidGlassCard>

        {/* 4. Caustic Progress Bars */}
        <LiquidGlassCard glowColor="amber" className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                Liquid Caustic Progress Bars
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Volumetric gradient fills with specular ray sheen sweeps and glowing leading head bead.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400">Interactive Test:</span>
              <input
                type="range"
                min="0"
                max="100"
                value={progressVal}
                onChange={(e) => setProgressVal(Number(e.target.value))}
                className="w-24 accent-cyan-400"
              />
            </div>
          </div>

          <div className="space-y-4 pt-2">
            <LiquidCausticProgress label="Composite Threat Severity" progress={progressVal} variant="crimson" />
            <LiquidCausticProgress label="Cognitive Urgency Pressure" progress={progressVal * 0.85} variant="amber" />
            <LiquidCausticProgress label="DNS Authentication Alignment" progress={progressVal * 0.65} variant="cyan" />
            <LiquidCausticProgress label="Campaign Attribution Confidence" progress={progressVal * 0.9} variant="purple" />
          </div>
        </LiquidGlassCard>

        {/* 5. Zero-Layout-Shift Accordion */}
        <LiquidGlassCard glowColor="emerald" className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                Zero-Layout-Shift Volumetric Accordion
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Employs CSS Grid fractional row animation (<code className="text-emerald-300">grid-template-rows: 0fr -&gt; 1fr</code>) for smooth fluid expansion.
              </p>
            </div>
            <LiquidMorphButton
              mode="emerald"
              onClick={() => setAccordionOpen(!accordionOpen)}
              icon={ChevronDown}
            >
              {accordionOpen ? 'Collapse' : 'Expand'}
            </LiquidMorphButton>
          </div>

          <LiquidGlassAccordion isOpen={accordionOpen}>
            <div className="space-y-2 text-xs font-mono text-slate-200">
              <div className="font-bold text-emerald-400">
                ✓ Butter-Smooth 60 FPS / 120 FPS Fractional Grid Animation
              </div>
              <p className="text-slate-400 leading-relaxed">
                By transitioning grid-template-rows from 0fr to 1fr instead of height auto, layout recalculation jitter is completely eliminated.
                Combined with a top specular glare line, expanding drawers feel like physical glass layers unfolding.
              </p>
            </div>
          </LiquidGlassAccordion>
        </LiquidGlassCard>
      </div>
    </div>
  );
};
