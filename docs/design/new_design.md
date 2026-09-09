# 🌊 SpectraShield 2.0 (Forensic Edition) — Master Frontend Architecture & Universal Liquid Glass Design Specification (`new_design.md`)

> **Document Type**: Master Specification, Design System, Component Library & Full-Stack Integration Contract  
> **Platform Name**: SpectraShield 2.0 (Forensic Edition)  
> **SIH Problem Statement ID**: 26106 (AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform)  
> **UI Architecture Style**: **Universal Liquid Glass Physics Engine** (Fluid Glassmorphism, Specular Caustics, Viscous Momentum & Zero-Layout-Shift Morphing)  
> **Regulatory Compliance**: ISO/IEC 27037 (Digital Evidence Chain of Custody) & Indian Bharatiya Nagarik Suraksha Sanhita (BNSS) Electronic Evidence Standards  
> **Target Framework & Libraries**: React 18/19, TypeScript, Vite, Tailwind CSS v3/v4, Lucide Icons, Leaflet / React-Leaflet, `@xyflow/react` (React Flow), Recharts, Framer Motion / Motion, Radix UI.

---

## 1. Executive Master Prompt for AI Web App Builders

*Copy and paste the prompt below directly into Lovable, v0, Bolt.new, Claude Artifacts, or Cursor:*

```text
You are building SpectraShield 2.0 (Forensic Edition), an enterprise-grade Email Threat Detection, Multi-Hop Relay Traceability, Origin Geolocation, and Digital Forensics Operations Center (SIH PS ID: 26106).

CRITICAL DESIGN REQUIREMENT:
Implement the interface strictly adhering to the "Universal Liquid Glass" design system. The UI must NOT look like flat, generic dashboards or basic glassmorphism. It must simulate real-world optical physics:
1. Multi-tier background refraction blurs (12px to 32px) boosted with backdrop-saturate-150 to backdrop-saturate-200.
2. Microscopic specular top rim highlights (1px border-t gradient from rgba(255,255,255,0.8) to transparent).
3. Directional ambient caustic radial glare pooling inside cards (radial-gradient flares matching threat severity).
4. Viscous surface tension and Apple-grade fluid cubic beziers: cubic-bezier(0.16, 1, 0.3, 1) and cubic-bezier(0.34, 1.56, 0.64, 1).
5. Continuous diagonal specular sheen sweeps (skew-x-12 animate-liquid-sheen) across active buttons and progress bars.
6. Zero-layout-shift volumetric accordions using CSS Grid fractional rows (grid-template-rows: 0fr -> 1fr).
7. Fluid sliding droplet segmented controls where the active navigation indicator glides with elastic momentum.

INTEGRATION CAPABILITIES:
The application must interface with two backend API tiers (with automatic fallback to realistic offline mock datasets):
1. SpectraShield 1.0 Heritage APIs: Quick Scan (/analyze), Scan History (/history), Top Targeted Brands (/dashboard/top-brands), and 7x24 Risk Heatmap (/dashboard/risk-heatmap).
2. SpectraShield 2.0 Forensic APIs: Raw RFC 5322 Ingestion (/api/forensics/analyze-email), .EML file upload (/api/forensics/upload-eml), Case Details (/api/forensics/cases/{id}), Interactive Neo4j Campaign Graph (/api/forensics/campaigns/{id}/graph), STIX 2.1 Threat Intel export, and Court-Admissible PDF Dossier streaming.

PROVIDE 6 DISTINCT LIQUID GLASS VIEWS ACCESSIBLE VIA A FIXED TOP LIQUID NAVBAR:
1. "Executive SOC Dashboard": Volumetric KPI cards, threat trends AreaChart, 7x24 risk heatmap, top impersonated brands bar chart, and real-time incident audit logs.
2. "Forensic Operations Center": Raw RFC 5322 header ingestion studio, Earliest Reliable Public Node (ERPN) isolation, Leaflet cartographic hop-by-hop relay world map with pulsing beacons, chronological hop timeline with latency calculations, and cryptographic SPF/DKIM/DMARC alignment matrix.
3. "Threat Attribution Graph": Full-screen interactive force-directed entity network (@xyflow/react) linking Emails, Origin IPs, Sender Domains, ASNs, and shared Threat Actor Campaigns.
4. "Sandboxed URL Previewer": Isolated link preview iframe, SSL certificate validation inspector, WHOIS domain age radar, and defanged link generator.
5. "Client Sentinel Inboxes": Interactive Gmail and LinkedIn desktop inbox replicas with liquid threat ribbons, inline badges, and a 1-click "Escalate to Forensic SOC" action.
6. "Extension Sentinel Popup": Compact 400x600px Chrome extension popup widget with animated circular risk gauge, threat breakdown bars, cognitive pressure cues, and remediation buttons.

Ensure full responsiveness (custom xs: 400px breakpoint, mobile floating liquid island drawer, tablet 2-column layout, desktop full grid).
```

---

## 2. Universal Liquid Glass Physics Model & Visual Foundations

Liquid Glass elevates standard glassmorphism into a dynamic, optically accurate digital material.

```
       ┌───────────────────────────────────────────────────────────────────┐
       │ 🌟 Specular Top Rim Highlight (border-t: rgba(255,255,255,0.75))   │
       │                                                                   │
       │   ☀️ Internal Caustic Radial Glare (radial-gradient flare)         │
       │                                                                   │
       │      [ Content / Dynamic Telemetry / Interactive Elements ]       │
       │                                                                   │
       │   🌊 Specular Beam Sheen Wave (skew-x-12 animate-liquid-sheen)    │
       │                                                                   │
       │ 🌑 Ambient Translucent Base (backdrop-blur-2xl + saturate-180)    │
       │ 💧 Soft Ambient Occlusion Glow (box-shadow: 0 24px 48px -12px...) │
       └───────────────────────────────────────────────────────────────────┘
```

### 2.1 Five Optical Physics Principles

1. **Refraction & Multi-Tier Blurring**: Background light diffuses across tiered blurs (`backdrop-blur-md` 12px for overlays, `backdrop-blur-2xl` 24px for cards, `backdrop-blur-3xl` 32px for modals and navbars) combined with `backdrop-saturate-150` to `backdrop-saturate-200` to maintain rich chrominance.
2. **Specular Rim Highlight**: Light rays grazing curved glass edges produce a 1px microscopic bright rim light (`border-t border-white/80` in dark mode: `border-t border-white/20`, fading downward to subtle occlusion `border-b border-black/40`).
3. **Internal Caustic Diffusion**: Reflected ambient light pools inside the surface using directional radial glows (`radial-gradient`), color-coded to threat severity (Cyan for Forensics, Crimson for Malicious/BEC, Amber for Caution, Emerald for Verified Safe, Purple for Attribution Graph).
4. **Viscous Surface Tension & Momentum**: Interactive elements expand, squash, stretch, and glide using fluid cubic beziers (`cubic-bezier(0.16, 1, 0.3, 1)` and `cubic-bezier(0.34, 1.56, 0.64, 1)`).
5. **Specular Caustic Sheen Wave**: High-velocity light rays sweep diagonally (`skew-x-12`) across active surfaces on hover or state change (`animate-liquid-sheen`).

---

## 3. Design Tokens & CSS Variables

Place these tokens in your root stylesheet (`src/styles/tokens.css` or `src/index.css`):

```css
:root {
  /* Surface Bases */
  --liquid-bg-base: rgba(255, 255, 255, 0.72);
  --liquid-bg-active: rgba(255, 255, 255, 0.92);
  --liquid-bg-elevated: rgba(255, 255, 255, 0.85);

  /* Specular Rim & Borders */
  --liquid-border-rim: rgba(255, 255, 255, 0.85);
  --liquid-border-subtle: rgba(226, 232, 240, 0.80);
  --liquid-border-dark: rgba(0, 0, 0, 0.06);

  /* Shadows & Ambient Occlusion */
  --liquid-shadow-sm: 0 4px 12px -2px rgba(15, 23, 42, 0.05), 0 2px 6px -1px rgba(15, 23, 42, 0.03);
  --liquid-shadow-md: 0 12px 28px -6px rgba(15, 23, 42, 0.08), 0 4px 12px -2px rgba(15, 23, 42, 0.04);
  --liquid-shadow-lg: 0 24px 48px -12px rgba(15, 23, 42, 0.12), 0 8px 24px -4px rgba(15, 23, 42, 0.06);
  --liquid-inner-glow: inset 0 1px 2px 0 rgba(255, 255, 255, 0.95), inset 0 -1px 2px 0 rgba(0, 0, 0, 0.04);

  /* Cyber Status Accents */
  --accent-forensics: #06b6d4;   /* Cyan */
  --accent-critical: #ef4444;    /* Crimson */
  --accent-warning: #f59e0b;     /* Amber */
  --accent-safe: #10b981;        /* Emerald */
  --accent-campaign: #a855f7;    /* Purple */

  /* Fluid Momentum Timing Curves */
  --liquid-ease-spring: cubic-bezier(0.34, 1.56, 0.64, 1);
  --liquid-ease-apple: cubic-bezier(0.16, 1, 0.3, 1);
  --liquid-ease-fluid: cubic-bezier(0.4, 0, 0.2, 1);
}

.dark {
  /* Dark Mode Surfaces (Obsidian & Tech Navy) */
  --liquid-bg-base: rgba(15, 23, 42, 0.65);
  --liquid-bg-active: rgba(30, 41, 59, 0.85);
  --liquid-bg-elevated: rgba(30, 41, 59, 0.75);

  /* Specular Rim & Borders */
  --liquid-border-rim: rgba(255, 255, 255, 0.18);
  --liquid-border-subtle: rgba(255, 255, 255, 0.08);
  --liquid-border-dark: rgba(0, 0, 0, 0.40);

  /* Deep Occlusion Shadows */
  --liquid-shadow-sm: 0 4px 14px -2px rgba(0, 0, 0, 0.35), 0 2px 6px -1px rgba(0, 0, 0, 0.25);
  --liquid-shadow-md: 0 16px 32px -8px rgba(0, 0, 0, 0.50), 0 6px 16px -4px rgba(0, 0, 0, 0.35);
  --liquid-shadow-lg: 0 30px 60px -15px rgba(0, 0, 0, 0.70), 0 10px 30px -5px rgba(0, 0, 0, 0.45);
  --liquid-inner-glow: inset 0 1px 1px 0 rgba(255, 255, 255, 0.16), inset 0 -1px 1px 0 rgba(0, 0, 0, 0.50);
}
```

---

## 4. Master Keyframe Animations & Tailwind Configuration

Extend `tailwind.config.js` with the custom breakpoint, keyframes, and animations:

```javascript
/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  theme: {
    screens: {
      'xs': '400px',   // Small mobile phones
      'sm': '640px',   // Phablets
      'md': '768px',   // Tablets
      'lg': '1024px',  // Laptops / Workstations
      'xl': '1280px',  // Large Desktops
      '2xl': '1536px',
    },
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      animation: {
        'liquid-sheen':   'liquidSheen 2.8s cubic-bezier(0.4, 0, 0.2, 1) infinite',
        'liquid-pop':     'liquidDropletPop 0.38s cubic-bezier(0.34, 1.56, 0.64, 1) both',
        'liquid-dismiss': 'liquidDropletDismiss 0.28s cubic-bezier(0.4, 0, 1, 1) both',
        'liquid-caustic': 'liquidCausticPulse 6s ease infinite',
        'beacon-pulse':   'beaconPulse 2.4s cubic-bezier(0, 0, 0.2, 1) infinite',
        'fade-in':        'fadeIn 0.22s cubic-bezier(0.25, 1, 0.5, 1) both',
        'fade-out':       'fadeOut 0.22s cubic-bezier(0.25, 1, 0.5, 1) both',
      },
      keyframes: {
        liquidSheen: {
          '0%':   { transform: 'translateX(-150%) skewX(-18deg)', opacity: '0' },
          '25%':  { opacity: '0.85' },
          '75%':  { opacity: '0.85' },
          '100%': { transform: 'translateX(250%) skewX(-18deg)', opacity: '0' },
        },
        liquidDropletPop: {
          '0%':   { opacity: '0', transform: 'scale(0.92) translateY(-8px)', filter: 'blur(4px)' },
          '60%':  { opacity: '1', transform: 'scale(1.025) translateY(1px)', filter: 'blur(0)' },
          '100%': { opacity: '1', transform: 'scale(1) translateY(0)', filter: 'blur(0)' },
        },
        liquidDropletDismiss: {
          '0%':   { opacity: '1', transform: 'scale(1) translateY(0)', filter: 'blur(0)' },
          '40%':  { opacity: '0.6', transform: 'scale(0.97) translateY(-4px)', filter: 'blur(1px)' },
          '100%': { opacity: '0', transform: 'scale(0.9) translateY(-12px)', filter: 'blur(6px)' },
        },
        liquidCausticPulse: {
          '0%, 100%': { backgroundPosition: '0% 50%', filter: 'hue-rotate(0deg) brightness(1)' },
          '50%':      { backgroundPosition: '100% 50%', filter: 'hue-rotate(15deg) brightness(1.08)' },
        },
        beaconPulse: {
          '0%':   { transform: 'scale(1)', opacity: '0.8' },
          '50%':  { transform: 'scale(1.6)', opacity: '0.2' },
          '100%': { transform: 'scale(2.2)', opacity: '0' },
        },
        fadeIn:  { '0%': { opacity: '0', transform: 'translateY(3px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        fadeOut: { '0%': { opacity: '1' }, '100%': { opacity: '0' } },
      },
      transitionTimingFunction: {
        'liquid-spring': 'cubic-bezier(0.34, 1.56, 0.64, 1)',
        'liquid-apple':  'cubic-bezier(0.16, 1, 0.3, 1)',
      },
    },
  },
  plugins: [],
};
```

---

## 5. Reusable Liquid Glass Cyber Components (React + TSX)

### 5.1 Liquid Sliding Segmented Control (Top Nav Switcher)
**File**: `src/app/components/liquid/LiquidSegmentedControl.tsx`  
*Provides the master navigation pill bar where a glowing liquid glass droplet glides between active tabs with viscous momentum.*

```tsx
import React, { useRef, useState, useEffect } from 'react';

export interface SegmentOption {
  id: string;
  label: string;
  icon?: React.ReactNode;
  badge?: string | number;
}

interface LiquidSegmentedControlProps {
  options: SegmentOption[];
  value: string;
  onChange: (id: string) => void;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const LiquidSegmentedControl: React.FC<LiquidSegmentedControlProps> = ({
  options,
  value,
  onChange,
  className = '',
  size = 'md',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [indicatorStyle, setIndicatorStyle] = useState({ left: 0, width: 0, opacity: 0 });

  const sizeClasses = {
    sm: 'p-0.5 text-xs gap-0.5',
    md: 'p-1 text-xs md:text-sm gap-1',
    lg: 'p-1.5 text-sm md:text-base gap-1.5',
  };

  useEffect(() => {
    if (!containerRef.current || !value) return;
    const activeEl = containerRef.current.querySelector<HTMLElement>(`[data-liquid-value="${value}"]`);
    if (activeEl) {
      setIndicatorStyle({
        left: activeEl.offsetLeft,
        width: activeEl.offsetWidth,
        opacity: 1,
      });
    }
  }, [value, options]);

  return (
    <div
      ref={containerRef}
      className={`relative inline-flex items-center rounded-2xl backdrop-blur-2xl bg-slate-900/50 border border-white/10 shadow-inner ${sizeClasses[size]} ${className}`}
    >
      {/* Sliding Liquid Glass Droplet Indicator */}
      <div
        className="absolute top-1 bottom-1 rounded-xl transition-all duration-500 ease-liquid-apple pointer-events-none overflow-hidden"
        style={{
          left: `${indicatorStyle.left}px`,
          width: `${indicatorStyle.width}px`,
          opacity: indicatorStyle.opacity,
        }}
      >
        {/* Specular Droplet Rim & Caustic Backdrop */}
        <div className="absolute inset-0 bg-white/15 backdrop-blur-3xl rounded-xl border border-white/25 shadow-lg shadow-cyan-950/40" />
        
        {/* Specular Top Glare */}
        <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-300/80 to-transparent" />
        
        {/* Diagonal Specular Sheen Wave */}
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -skew-x-12 animate-liquid-sheen opacity-40" />
      </div>

      {/* Segment Option Buttons */}
      {options.map((opt) => {
        const isSelected = opt.id === value;
        return (
          <button
            key={opt.id}
            type="button"
            data-liquid-value={opt.id}
            onClick={() => onChange(opt.id)}
            className={`relative z-10 px-3.5 py-1.5 rounded-xl font-medium transition-colors duration-300 select-none flex items-center gap-2 ${
              isSelected
                ? 'text-cyan-300 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {opt.icon && <span className="transition-transform duration-300">{opt.icon}</span>}
            <span>{opt.label}</span>
            {opt.badge !== undefined && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                {opt.badge}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
};
```

---

### 5.2 Volumetric Morphing Action Button
**File**: `src/app/components/liquid/LiquidMorphButton.tsx`  
*Dual-gradient cyber button with crossfading state layers, specular wave sheen sweep, and elastic squash-and-stretch on click.*

```tsx
import React from 'react';
import { LucideIcon } from 'lucide-react';

interface LiquidMorphButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  mode?: 'cyan' | 'crimson' | 'purple' | 'emerald';
  isLoading?: boolean;
  disabled?: boolean;
  icon?: LucideIcon;
  className?: string;
  type?: 'button' | 'submit';
}

export const LiquidMorphButton: React.FC<LiquidMorphButtonProps> = ({
  children,
  onClick,
  mode = 'cyan',
  isLoading = false,
  disabled = false,
  icon: Icon,
  className = '',
  type = 'button',
}) => {
  const gradientStyles = {
    cyan: 'from-cyan-600 via-sky-500 to-blue-600 shadow-cyan-950/50',
    crimson: 'from-red-600 via-rose-500 to-red-700 shadow-red-950/50',
    purple: 'from-purple-600 via-violet-500 to-indigo-600 shadow-purple-950/50',
    emerald: 'from-emerald-600 via-teal-500 to-green-600 shadow-emerald-950/50',
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || isLoading}
      className={`group relative overflow-hidden rounded-2xl px-5 py-2.5 font-sans text-xs md:text-sm font-semibold text-white shadow-xl transition-all duration-500 ease-liquid-apple active:scale-[0.97] hover:shadow-2xl disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
    >
      {/* Fluid Gradient Base */}
      <div className={`absolute inset-0 bg-gradient-to-r ${gradientStyles[mode]} transition-all duration-500`} />

      {/* Internal Glass Reflection Matrix */}
      <div className="absolute inset-0 backdrop-blur-md bg-black/10" />

      {/* Specular Rim Edge Highlights */}
      <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-white/80 to-transparent" />
      <div className="absolute bottom-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-black/40 to-transparent" />

      {/* Continuous Dynamic Specular Refraction Wave */}
      <div className="absolute -inset-full bg-gradient-to-r from-transparent via-white/30 to-transparent skew-x-12 -translate-x-full group-hover:animate-liquid-sheen pointer-events-none" />

      {/* Button Content */}
      <div className="relative z-10 flex items-center justify-center gap-2">
        {isLoading ? (
          <div className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
        ) : (
          Icon && <Icon className="w-4 h-4 transition-transform duration-300 group-hover:scale-110" />
        )}
        <span className="tracking-wide">{children}</span>
      </div>
    </button>
  );
};
```

---

### 5.3 Volumetric Expanding Accordion (Zero-Layout-Shift)
**File**: `src/app/components/liquid/LiquidGlassAccordion.tsx`  
*Employs CSS Grid fractional row animation (`grid-template-rows: 0fr -> 1fr`) to provide butter-smooth fluid expansion for Explainable AI (XAI) reasonings, RFC 5322 header traces, and MITRE ATT&CK mappings.*

```tsx
import React from 'react';

interface LiquidGlassAccordionProps {
  isOpen: boolean;
  children: React.ReactNode;
  className?: string;
}

export const LiquidGlassAccordion: React.FC<LiquidGlassAccordionProps> = ({
  isOpen,
  children,
  className = '',
}) => {
  return (
    <div
      className={`grid transition-[grid-template-rows,opacity] duration-700 ease-liquid-apple ${
        isOpen ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0 pointer-events-none'
      } ${className}`}
    >
      <div className="overflow-hidden">
        <div className="rounded-2xl border border-white/10 bg-slate-900/60 backdrop-blur-2xl p-5 shadow-xl relative mt-2">
          {/* Top Specular Rim */}
          <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent" />
          {children}
        </div>
      </div>
    </div>
  );
};
```

---

### 5.4 Liquid Glass Container / Modal / Card
**File**: `src/app/components/liquid/LiquidGlassCard.tsx`  
*The ultimate volumetric card featuring multi-tier blur, internal caustic radial glow, specular rim edges, and subtle hover elevation.*

```tsx
import React from 'react';

interface LiquidGlassCardProps {
  children: React.ReactNode;
  glowColor?: 'cyan' | 'crimson' | 'purple' | 'amber' | 'emerald';
  className?: string;
  onClick?: () => void;
}

export const LiquidGlassCard: React.FC<LiquidGlassCardProps> = ({
  children,
  glowColor = 'cyan',
  className = '',
  onClick,
}) => {
  const glowGradients = {
    cyan: 'from-cyan-500/15 via-sky-500/5 to-transparent',
    crimson: 'from-red-500/15 via-rose-500/5 to-transparent',
    purple: 'from-purple-500/15 via-violet-500/5 to-transparent',
    amber: 'from-amber-500/15 via-yellow-500/5 to-transparent',
    emerald: 'from-emerald-500/15 via-teal-500/5 to-transparent',
  };

  return (
    <div
      onClick={onClick}
      className={`relative overflow-hidden rounded-3xl border border-white/10 bg-slate-900/70 backdrop-blur-3xl backdrop-saturate-180 shadow-2xl p-5 md:p-6 transition-all duration-500 hover:border-white/20 hover:shadow-cyan-950/20 ${className}`}
    >
      {/* Ambient Internal Caustic Flare */}
      <div
        className={`absolute -top-24 -left-24 w-72 h-72 rounded-full bg-gradient-to-br ${glowGradients[glowColor]} blur-3xl pointer-events-none`}
      />

      {/* Top Specular Rim */}
      <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-white/25 to-transparent" />

      {/* Bottom Subtle Occlusion */}
      <div className="absolute bottom-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-black/40 to-transparent" />

      {/* Content */}
      <div className="relative z-10">{children}</div>
    </div>
  );
};
```

---

### 5.5 Liquid Caustic Progress Bar
**File**: `src/app/components/liquid/LiquidCausticProgress.tsx`  
*Used for composite threat scores, BEC confidence gauges, and granular sub-vector breakdowns (Headers, Geolocation, NLP, URLs).*

```tsx
import React from 'react';

interface LiquidCausticProgressProps {
  progress: number; // 0 to 100
  label: string;
  valueSuffix?: string;
  variant?: 'cyan' | 'crimson' | 'amber' | 'emerald' | 'purple';
  className?: string;
}

export const LiquidCausticProgress: React.FC<LiquidCausticProgressProps> = ({
  progress,
  label,
  valueSuffix = '%',
  variant = 'cyan',
  className = '',
}) => {
  const clamped = Math.min(100, Math.max(0, progress));

  const variantGradients = {
    cyan: 'from-cyan-500 to-blue-600',
    crimson: 'from-red-500 to-rose-600',
    amber: 'from-amber-500 to-yellow-600',
    emerald: 'from-emerald-500 to-teal-600',
    purple: 'from-purple-500 to-indigo-600',
  };

  const textColors = {
    cyan: 'text-cyan-400',
    crimson: 'text-red-400',
    amber: 'text-amber-400',
    emerald: 'text-emerald-400',
    purple: 'text-purple-400',
  };

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div className="flex items-center justify-between text-xs font-mono">
        <span className="text-slate-300">{label}</span>
        <span className={`font-bold ${textColors[variant]}`}>
          {clamped.toFixed(1)}{valueSuffix}
        </span>
      </div>

      <div className="relative h-2.5 w-full overflow-hidden rounded-full border border-white/10 bg-slate-900/80 backdrop-blur-md p-0.5 shadow-inner">
        <div
          className={`relative h-full rounded-full bg-gradient-to-r ${variantGradients[variant]} transition-all duration-700 ease-liquid-apple`}
          style={{ width: `${clamped}%` }}
        >
          {/* Specular Ray Sheen */}
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/35 to-transparent skew-x-12 animate-liquid-sheen" />

          {/* Glowing Leading Head Droplet */}
          <div className="absolute right-0 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-white shadow-[0_0_8px_2px_rgba(255,255,255,0.8)]" />
        </div>
      </div>
    </div>
  );
};
```

---

### 5.6 Glowing Liquid Status Droplet / Badge
**File**: `src/app/components/liquid/LiquidGlassBadge.tsx`  
*Status tags with glowing pulsing droplets, glass backgrounds, and high-legibility text.*

```tsx
import React from 'react';
import { LucideIcon } from 'lucide-react';

interface LiquidGlassBadgeProps {
  label: string;
  variant?: 'safe' | 'warning' | 'critical' | 'forensics' | 'campaign';
  icon?: LucideIcon;
  className?: string;
}

export const LiquidGlassBadge: React.FC<LiquidGlassBadgeProps> = ({
  label,
  variant = 'forensics',
  icon: Icon,
  className = '',
}) => {
  const styles = {
    safe: {
      bg: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
      dot: 'bg-emerald-400 shadow-[0_0_10px_2px_rgba(16,185,129,0.6)]',
    },
    warning: {
      bg: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
      dot: 'bg-amber-400 shadow-[0_0_10px_2px_rgba(245,158,11,0.6)]',
    },
    critical: {
      bg: 'bg-red-500/10 text-red-300 border-red-500/30',
      dot: 'bg-red-400 shadow-[0_0_10px_2px_rgba(239,68,68,0.6)]',
    },
    forensics: {
      bg: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
      dot: 'bg-cyan-400 shadow-[0_0_10px_2px_rgba(6,182,212,0.6)]',
    },
    campaign: {
      bg: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
      dot: 'bg-purple-400 shadow-[0_0_10px_2px_rgba(168,85,247,0.6)]',
    },
  };

  const current = styles[variant];

  return (
    <div
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border backdrop-blur-xl font-mono text-xs shadow-sm select-none ${current.bg} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full animate-pulse ${current.dot}`} />
      {Icon && <Icon className="w-3.5 h-3.5" />}
      <span>{label}</span>
    </div>
  );
};
```

---

### 5.7 Responsive Fixed Liquid Glass Navbar & Mobile Floating Island Drawer
**File**: `src/app/components/common/CyberNavbar.tsx`  
*Fixed `top-0 h-16` bar with scroll-reactive glass blur, live UTC clock, backend health indicator, and mobile island drawer with animated dismissal.*

```tsx
import React, { useState, useEffect } from 'react';
import { ShieldAlert, Activity, Menu, X, Clock, ExternalLink } from 'lucide-react';
import { LiquidSegmentedControl, SegmentOption } from '../liquid/LiquidSegmentedControl';

interface CyberNavbarProps {
  activeView: string;
  onViewChange: (view: string) => void;
  caseCount?: number;
  isBackendConnected?: boolean;
}

export const CyberNavbar: React.FC<CyberNavbarProps> = ({
  activeView,
  onViewChange,
  caseCount = 142,
  isBackendConnected = true,
}) => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isClosing, setIsClosing] = useState(false);
  const [currentTime, setCurrentTime] = useState('');

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().split(' ')[4] + ' UTC');
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);
    return () => clearInterval(timer);
  }, []);

  const navOptions: SegmentOption[] = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'forensics', label: 'Forensic Ops', badge: '2.0' },
    { id: 'graph', label: 'Threat Graph' },
    { id: 'linkpreview', label: 'Link Sandbox' },
    { id: 'sentinel', label: 'Inboxes' },
    { id: 'popup', label: 'Extension' },
  ];

  const closeMobileMenu = () => {
    setIsClosing(true);
    setTimeout(() => {
      setMobileOpen(false);
      setIsClosing(false);
    }, 260);
  };

  return (
    <>
      <header
        className={`fixed top-0 left-0 right-0 z-50 w-full h-16 transition-all duration-500 ease-liquid-apple ${
          isScrolled
            ? 'bg-slate-950/85 backdrop-blur-3xl border-b border-white/10 shadow-2xl'
            : 'bg-slate-950/40 backdrop-blur-xl border-b border-white/5'
        }`}
      >
        <div className="max-w-7xl mx-auto h-full px-4 flex items-center justify-between gap-4">
          {/* Logo & Platform Title */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-2xl bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.3)]">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-bold tracking-tight text-white text-base md:text-lg">
                  SpectraShield
                </span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                  2.0
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400 hidden sm:block">
                SIH PS: 26106 | Forensic Edition
              </p>
            </div>
          </div>

          {/* Desktop / Tablet Liquid Segmented Control */}
          <div className="hidden md:block">
            <LiquidSegmentedControl
              options={navOptions}
              value={activeView}
              onChange={onViewChange}
              size="md"
            />
          </div>

          {/* Right Status Pills & Mobile Hamburger */}
          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900/60 border border-white/10 text-xs font-mono text-slate-300">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>{currentTime}</span>
            </div>

            <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900/60 border border-white/10 text-xs font-mono">
              <span
                className={`w-2 h-2 rounded-full ${
                  isBackendConnected
                    ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]'
                    : 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.8)]'
                }`}
              />
              <span className="hidden sm:inline text-slate-300">
                {isBackendConnected ? 'Backend Live' : 'Offline Mode'}
              </span>
            </div>

            {/* Mobile Hamburger Button */}
            <button
              type="button"
              onClick={() => (mobileOpen ? closeMobileMenu() : setMobileOpen(true))}
              className="p-2 rounded-xl bg-slate-900/80 border border-white/10 text-slate-300 hover:text-white md:hidden"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Floating Liquid Glass Island Drawer */}
      {mobileOpen && (
        <>
          <div
            onClick={closeMobileMenu}
            className={`fixed top-16 inset-0 z-40 bg-black/60 backdrop-blur-sm md:hidden ${
              isClosing ? 'animate-fade-out' : 'animate-fade-in'
            }`}
          />
          <div
            className={`fixed top-20 inset-x-4 max-w-md mx-auto z-50 md:hidden rounded-3xl border border-white/15 bg-slate-900/90 backdrop-blur-3xl p-5 shadow-2xl space-y-2 ${
              isClosing ? 'animate-liquid-dismiss' : 'animate-liquid-pop'
            }`}
          >
            <div className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider mb-2">
              Select Operations Module
            </div>
            {navOptions.map((opt) => (
              <button
                key={opt.id}
                onClick={() => {
                  onViewChange(opt.id);
                  closeMobileMenu();
                }}
                className={`w-full flex items-center justify-between px-4 py-3 rounded-2xl text-sm font-medium transition-all ${
                  activeView === opt.id
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                    : 'text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <span>{opt.label}</span>
                {opt.badge && (
                  <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-cyan-500/30 text-cyan-300">
                    {opt.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
        </>
      )}
    </>
  );
};
```

---

## 6. Detailed View Specifications with Liquid Glass Enhancements

### 6.1 View 1: Executive SOC Dashboard (`DashboardView.tsx`)
- **Structure**:
  1. **Top Metric Cards Row (`LiquidGlassCard` grid)**:
     - Total Ingested Scans (Volume metric with mini Sparkline).
     - Blocked High-Risk Threats (Crimson caustic glow with count & delta).
     - Business Email Compromise Alerts (Amber caustic glow with active campaign count).
     - System Integrity & Vault Status (Emerald glow: `ISO/IEC 27037 Compliant`).
  2. **Threat Trends Timeline (`ThreatTimelineChart.tsx`)**:
     - Embedded in a `LiquidGlassCard` with time-range filter (`LiquidSegmentedControl`: `7d`, `30d`, `90d`).
     - Recharts `AreaChart` with cyan/crimson linear gradients showing daily clean vs malicious volume.
  3. **7x24 Risk Density Heatmap (`RiskHeatmapMatrix.tsx`)**:
     - Matrix of Day of Week (Sun-Sat) vs Hour of Day (00-23).
     - Each cell is a rounded glass droplet with variable background opacity based on threat count. Hovering triggers a `LiquidGlassCard` tooltip showing exact incident counts and top flagged brand.
  4. **Top Impersonated Brands (`TopBrandsChart.tsx`)**:
     - Horizontal bar chart with animated specular sweeps on each bar.
     - Brand identity cards (Microsoft, PayPal, Amazon, Google) with brand color accents.
  5. **Live Incident Audit Table**:
     - Glass table container with sticky header.
     - Rows highlight on hover with defanged IP copy buttons and instant case inspection triggers.

---

### 6.2 View 2: Deep Forensic Operations Center (`ForensicOpsView.tsx`)
- **Structure**:
  1. **Raw Ingestion Studio**:
     - Text area for pasting raw RFC 5322 headers, drag-and-drop file target for `.eml`/`.msg` files, and "Load Sample BEC Phish" demo button.
     - Action button: `LiquidMorphButton` (`Execute Deep Forensic Scan`).
  2. **Case Verification Banner**:
     - When an email is analyzed, renders Case Number, SHA-256 evidence hash (with a green `Vault Sealed` padlock icon), and overall Risk Meter.
  3. **Cryptographic DNS Alignment Grid (`AuthStatusMatrix.tsx`)**:
     - 3-card grid for SPF, DKIM, and DMARC with status badges (`LiquidGlassBadge`).
  4. **Cartographic Relay World Map (`HopMapVisualizer.tsx`)**:
     - Built with Leaflet using dark vector tiles (`https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png`).
     - Earliest Reliable Public Node (ERPN) is rendered with a pulsing cyan beacon (`animate-beacon`).
     - Animated dashed geodesic flight paths connect the MTAs.
     - Dark glass popups display transit delay, defanged IP, and Tor/VPN flags.
  5. **Chronological Relay Hop Timeline (`RelayHopTimeline.tsx`)**:
     - Vertical circuit line connecting hop cards.
     - Automatically flags internal RFC 1918 bogons as `[FILTERED BOGON]`.
     - Flags timestamp inversions ($\Delta t < 0$) with a pulsing red warning.
  6. **Explainable AI (XAI) Reasoning Accordion (`LiquidGlassAccordion`)**:
     - Expands smoothly with zero layout shift to show cognitive manipulation triggers (Urgency, Fear, Authority) and MITRE ATT&CK codes.
  7. **Evidentiary Export Suite (`StixExportModal.tsx`)**:
     - Downloads court-admissible PDF dossiers or copies STIX 2.1 JSON bundles.

---

### 6.3 View 3: Threat Attribution Graph (`ThreatGraphView.tsx`)
- **Technology**: Full-screen `@xyflow/react` (React Flow) canvas.
- **Node Designs (Styled as Liquid Glass Islands)**:
  - `EmailNode`: Dark navy glass with envelope icon, SHA-256 hash, and risk score.
  - `IpNode`: Cyan border, server icon, defanged IP, and Tor exit badge.
  - `DomainNode`: Violet border, globe icon, and domain age counter.
  - `AsnNode`: Blue border, network icon, and ISP organization name.
  - `CampaignNode`: Glowing purple border with `animate-beacon` pulse and attribution confidence badge.
- **Interactivity**:
  - Dragging, zooming, and clicking nodes triggers a right-hand sliding glass drawer with full historical incident correlation.

---

### 6.4 View 4: Sandboxed URL Previewer (`LinkPreviewView.tsx`)
- **Structure**:
  - URL input box with instant `Analyze Link` trigger.
  - Sandboxed iframe emulation pane with safe preview mode.
  - **SSL Security Radar**: Displays Certificate Authority, Subject Alternative Names, and EV/DV validation badge.
  - **WHOIS Domain Age Gauge**: Circular radar displaying registration date, registrar name, and "Burner Domain" risk warnings.
  - **One-Click Defanged Copy**: Copies `hxxps[://]...` to prevent accidental execution.

---

### 6.5 View 5: Client Sentinel Inboxes (`SentinelDemoView.tsx`)
- **Structure**:
  - Full desktop client simulations for **Gmail** and **LinkedIn Messaging**.
  - In-row risk badges next to email subjects (`LiquidGlassBadge`).
  - High-risk emails feature an animated red liquid warning ribbon across the message pane.
  - Adds an in-inbox **"Escalate to Forensic SOC"** button that extracts raw RFC 5322 headers and sends them to the Forensic Operations Center.

---

### 6.6 View 6: Standalone Client Extension Widget (`ExtensionPopupView.tsx`)
- **Structure**:
  - 400x600px liquid glass card simulating the Chromium Manifest V3 extension popup.
  - **Volumetric Circular Risk Meter**: SVG-based animated arc with needle glow and risk percentage.
  - **Granular Risk Breakdown**: Manipulation, URL reputation, AI patterns, Brand mismatch.
  - Remediation buttons (`Mark Safe`, `Quarantine`, `Escalate to SOC`).

---

## 7. Complete Backend API Integration Contracts

The frontend interacts with the FastAPI backend running on port `8000` (configurable via `VITE_API_URL`):

### 7.1 Upgraded Forensic Endpoints (SpectraShield 2.0)

| Endpoint | Method | Purpose | Request / Response Schema |
| :--- | :--- | :--- | :--- |
| `/api/forensics/analyze-email` | `POST` | Deep RFC 5322 parsing, ERPN isolation, BEC NLP, Campaign graph, SHA-256 sealing | `ForensicAnalyzeRequest` $\rightarrow$ `ForensicAnalyzeResponse` |
| `/api/forensics/upload-eml` | `POST` | Multipart upload for `.eml` and `.msg` files | `multipart/form-data` (file) $\rightarrow$ `ForensicAnalyzeResponse` |
| `/api/forensics/cases` | `GET` | Lists all evidence vault records | `?limit=50` $\rightarrow$ `{ total: number, cases: CaseRecord[] }` |
| `/api/forensics/cases/{id}` | `GET` | Case details, full dissection, and cryptographic audit trail | `{ case, analysis, audit_trail: AuditLog[] }` |
| `/api/forensics/campaigns/{id}/graph` | `GET` | Nodes and edges formatted for `@xyflow/react` | `{ nodes: FlowNode[], edges: FlowEdge[] }` |
| `/api/forensics/export/{id}/pdf` | `GET` | Court-admissible ISO/IEC 27037 PDF dossier | Binary stream (`application/pdf`) |
| `/api/forensics/export/{id}/stix` | `GET` | OASIS STIX 2.1 Threat Intel bundle | JSON stream (`application/json`) |

### 7.2 Heritage Endpoints (SpectraShield 1.0)

| Endpoint | Method | Purpose | Request / Response Schema |
| :--- | :--- | :--- | :--- |
| `/analyze` | `POST` | Quick scan combining heuristic manipulation & URL threat intel | `EmailRequest` $\rightarrow$ `AnalyzeResponse` |
| `/dashboard/top-brands` | `GET` | Top impersonated brands distribution | `?days=7&risk=all&limit=6` $\rightarrow$ `TopBrandsResponse` |
| `/dashboard/risk-heatmap` | `GET` | 7x24 hour incident density matrix | `?days=7&risk=all` $\rightarrow$ `RiskHeatmapResponse` |
| `/history` | `GET` | Historical scan records | `HistoryRecord[]` |
| `/history/{id}` | `DELETE` | Delete single scan record | `{ message: string }` |
| `/history` | `DELETE` | Purge entire scan history | `{ message: string }` |

---

## 8. Offline Mock Fallback System & Datasets

To ensure the AI-generated frontend works flawlessly in preview environments (Lovable, v0, Bolt, offline demos), the API client (`src/app/api.ts`) must wrap all calls with automatic mock fallbacks:

```typescript
// Pattern in src/app/api.ts
export async function analyzeForensicEmail(payload: ForensicAnalyzeRequest): Promise<ForensicAnalyzeResponse> {
  const base = getApiBase();
  try {
    const res = await fetch(`${base}/api/forensics/analyze-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (res.ok) return await res.json();
  } catch (error) {
    console.warn("Backend offline. Using Liquid Glass Forensic Mock.", error);
  }
  return MOCK_FORENSIC_ANALYSIS;
}
```

### 8.1 High-Fidelity Mock Forensic Dataset (`MOCK_FORENSIC_ANALYSIS`)
```json
{
  "case_id": "8f3b2c1a-5e7d-4b9a-8c1e-9f3a2b1c0d5e",
  "case_number": "CASE-2026-0891",
  "sha256_evidence_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "final_risk": 94.5,
  "verdict": "High Risk / Malicious",
  "threat_category": "Business Email Compromise (BEC)",
  "reasoning_summary": "Flagged as High Risk: Cryptographic DMARC alignment failed, origin IP traced to verified Tor exit node in Frankfurt, Germany, and executive financial diversion cues detected.",
  "authentication": {
    "spf": {
      "status": "Fail",
      "domain": "micro-soft-billing.top",
      "sender_ip": "185.220.101.5",
      "reason": "Sending IP not authorized in SPF DNS record"
    },
    "dkim": {
      "status": "Fail",
      "selector": "default",
      "domain": "micro-soft-billing.top",
      "valid": false,
      "reason": "Cryptographic body hash mismatch"
    },
    "dmarc": {
      "status": "Fail",
      "domain": "micro-soft-billing.top",
      "policy": "reject",
      "aligned": false,
      "alignment_type": "strict"
    }
  },
  "originating_node": {
    "ip": "185.220.101.5",
    "defanged_ip": "185[.]220[.]101[.]5",
    "country": "Germany",
    "country_code": "DE",
    "city": "Frankfurt",
    "latitude": 50.1109,
    "longitude": 8.6821,
    "asn": "AS60729",
    "isp": "Tor Exit Router Network",
    "is_anonymized": true,
    "anonymization_type": "TOR",
    "risk_rating": 95.0
  },
  "relay_path": [
    {
      "hop": 1,
      "received_from": "client-node.internal (10.0.0.15)",
      "by": "mta1.local-lan.com",
      "protocol": "ESMTP",
      "ip": "10.0.0.15",
      "defanged_ip": "10[.]0[.]0[.]15",
      "is_private": true,
      "is_origin": false,
      "timestamp": "2026-09-02T10:14:00Z",
      "delay_seconds": 0,
      "geo": null
    },
    {
      "hop": 2,
      "received_from": "mta1.local-lan.com",
      "by": "relay.attacker-infra.net",
      "protocol": "ESMTPS",
      "ip": "185.220.101.5",
      "defanged_ip": "185[.]220[.]101[.]5",
      "is_private": false,
      "is_origin": true,
      "timestamp": "2026-09-02T10:14:02Z",
      "delay_seconds": 2,
      "geo": {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821
      }
    },
    {
      "hop": 3,
      "received_from": "relay.attacker-infra.net",
      "by": "mx.victim-corp.com",
      "protocol": "ESMTPS",
      "ip": "172.217.194.27",
      "defanged_ip": "172[.]217[.]194[.]27",
      "is_private": false,
      "is_origin": false,
      "timestamp": "2026-09-02T10:14:05Z",
      "delay_seconds": 3,
      "geo": {
        "country": "United States",
        "country_code": "US",
        "city": "Mountain View",
        "lat": 37.422,
        "lon": -122.084
      }
    }
  ],
  "campaign": {
    "id": "CAMP-2026-042",
    "name": "Targeted European Wire Diversion",
    "attribution_confidence": 88.0,
    "threat_actor": "FIN7 / Carbanak Emulation",
    "linked_incidents_count": 8
  },
  "nlp_intelligence": {
    "financial_intent": true,
    "executive_impersonation": true,
    "urgency_score": 85.0,
    "fear_score": 10.0,
    "authority_score": 90.0,
    "scarcity_score": 40.0,
    "homoglyph_detected": true
  },
  "breakdown": {
    "header_score": 92.0,
    "origin_score": 95.0,
    "nlp_score": 88.0,
    "url_score": 75.0,
    "killchain_severity": 85.0
  },
  "mitre_tactics": [
    "T1566.002 - Spearphishing Link",
    "T1598.003 - Spearphishing for Information",
    "T1090.003 - Proxy: Multi-hop Proxy"
  ],
  "anomalies": [
    "Bogon IP 10.0.0.15 discarded from physical geolocation resolution.",
    "Earliest Reliable Public Node (ERPN) isolated at Hop #2 (185.220.101.5).",
    "Sender envelope return-path mismatch with visible RFC 5322 From: address."
  ],
  "created_at": "2026-09-04T12:00:00Z"
}
```

---

## 9. GPU Hardware Acceleration, Performance & Accessibility (a11y)

1. **GPU Offloading**:
   - Always declare `will-change: transform, opacity` and `transform: translateZ(0)` on sliding indicators, sheen sweeps, and modals to maintain 60 FPS / 120 FPS.
   - Always declare `-webkit-backdrop-filter: blur(...)` alongside `backdrop-filter: blur(...)` for iOS Safari compatibility.
2. **Reduced Motion Compliance**:
   ```css
   @media (prefers-reduced-motion: reduce) {
     *, ::before, ::after {
       animation-duration: 0.01ms !important;
       animation-iteration-count: 1 !important;
       transition-duration: 0.01ms !important;
     }
     .animate-liquid-sheen,
     .animate-liquid-pop,
     .animate-liquid-dismiss,
     .animate-liquid-caustic,
     .animate-beacon-pulse {
       animation: none !important;
     }
   }
   ```
3. **Contrast Compliance (WCAG AA)**:
   - All body text against dark liquid glass is styled with `text-slate-100` or `text-white` ($> 7:1$ contrast ratio). Secondary labels use `text-slate-300` ($> 4.5:1$).
4. **Court-Admissible Evidence Formatting**:
   - Every IOC (IP, domain, URL) is defanged by default (e.g., `185[.]220[.]101[.]5`) to eliminate accidental live clicks.

---

## 10. Sequential Generation Roadmap for External AI Builders

1. **Step 1: Setup Tokens & Tailwind**:
   - Copy Section 3 CSS variables into `src/index.css`.
   - Update `tailwind.config.js` with Section 4 keyframes and easing curves.
2. **Step 2: Component Primitives**:
   - Create `src/app/components/liquid/` containing `LiquidSegmentedControl`, `LiquidMorphButton`, `LiquidGlassAccordion`, `LiquidGlassCard`, `LiquidCausticProgress`, and `LiquidGlassBadge`.
3. **Step 3: Navigation Shell**:
   - Create `CyberNavbar.tsx` with fixed `top-0 h-16` height, live UTC clock, backend status, and mobile island drawer. Add `pt-16` to the page container in `App.tsx`.
4. **Step 4: Deep Forensic Operations View**:
   - Assemble `ForensicOpsView.tsx` with the raw ingestion text area, Leaflet `HopMapVisualizer.tsx` with pulsing beacon, `RelayHopTimeline.tsx`, and `AuthStatusMatrix.tsx`.
5. **Step 5: Executive Dashboard & Threat Graph**:
   - Assemble `DashboardView.tsx` with Recharts and 7x24 heatmap, and `ThreatGraphView.tsx` using `@xyflow/react`.
6. **Step 6: Inboxes & Extension Popup**:
   - Assemble `SentinelDemoView.tsx` with Gmail/LinkedIn threat ribbons and `ExtensionPopupView.tsx` with the SVG circular gauge.
7. **Step 7: Verification**:
   - Test seamless tab navigation, verify fluid sliding droplet animations, test mobile menu open/dismiss, and confirm offline mock data fallback.

---
*Master Specification sealed with Universal Liquid Glass Physics Engine.*
