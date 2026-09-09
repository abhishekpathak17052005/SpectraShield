import React, { useEffect, useState } from "react";
import { motion } from "motion/react";
import { ShieldAlert, ShieldCheck, AlertTriangle } from "lucide-react";

interface AnimatedRiskGaugeProps {
  score: number;
  confidence?: number;
  verdict?: string;
  size?: number;
  strokeWidth?: number;
}

export const AnimatedRiskGauge: React.FC<AnimatedRiskGaugeProps> = ({
  score,
  confidence = 90,
  verdict,
  size = 150,
  strokeWidth = 11,
}) => {
  const [animatedScore, setAnimatedScore] = useState<number>(0);

  useEffect(() => {
    // Smooth number interpolation up to score
    let start = 0;
    const duration = 900; // ms
    const startTime = performance.now();

    const animateNumber = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(Math.round(score * easeProgress));

      if (progress < 1) {
        requestAnimationFrame(animateNumber);
      }
    };

    requestAnimationFrame(animateNumber);
  }, [score]);

  const roundedScore = Math.round(score);
  const isHigh = roundedScore >= 70;
  const isMed = roundedScore >= 30 && roundedScore < 70;

  const color = isHigh ? "#ef4444" : isMed ? "#f59e0b" : "#10b981";
  const glowColor = isHigh
    ? "rgba(239, 68, 68, 0.35)"
    : isMed
    ? "rgba(245, 158, 11, 0.3)"
    : "rgba(16, 185, 129, 0.25)";

  const center = size / 2;
  const radius = center - strokeWidth - 4;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center relative p-3">
      {/* Halo glow behind circular gauge */}
      <div
        className="absolute w-32 h-32 rounded-full blur-2xl pointer-events-none transition-all duration-700 opacity-60"
        style={{ background: glowColor }}
      />

      <div className="relative flex items-center justify-center">
        <svg width={size} height={size} className="transform -rotate-90">
          {/* Track Background */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            stroke="rgba(255, 255, 255, 0.07)"
            strokeWidth={strokeWidth}
            fill="transparent"
          />

          {/* Animated Gauge Arc */}
          <motion.circle
            cx={center}
            cy={center}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.1, ease: "easeOut" }}
            style={{
              filter: `drop-shadow(0 0 6px ${color})`,
            }}
          />
        </svg>

        {/* Center Score & Scale */}
        <div className="absolute flex flex-col items-center justify-center text-center select-none">
          <span className="text-3xl sm:text-4xl font-extrabold font-mono tracking-tight text-white">
            {animatedScore}
          </span>
          <span className="text-[10px] text-slate-400 uppercase font-mono tracking-wider">
            / 100 RISK
          </span>
        </div>
      </div>

      {/* Verdict and Confidence below gauge */}
      <div className="mt-3 flex flex-col items-center gap-1.5 text-center">
        <div className="flex items-center gap-2">
          <span
            className={`text-xs font-bold font-mono px-2.5 py-0.5 rounded tracking-wide border uppercase flex items-center gap-1.5 ${
              isHigh
                ? "bg-red-500/15 text-red-300 border-red-500/30"
                : isMed
                ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
                : "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
            }`}
          >
            {isHigh ? (
              <ShieldAlert className="w-3.5 h-3.5" />
            ) : isMed ? (
              <AlertTriangle className="w-3.5 h-3.5" />
            ) : (
              <ShieldCheck className="w-3.5 h-3.5" />
            )}
            <span>{verdict || (isHigh ? "PHISHING" : isMed ? "SUSPICIOUS" : "SAFE")}</span>
          </span>
        </div>

        <span className="text-[11px] text-slate-400">
          Confidence Level: <b className="text-slate-200 font-medium font-mono">{confidence}%</b>
        </span>
      </div>
    </div>
  );
};
