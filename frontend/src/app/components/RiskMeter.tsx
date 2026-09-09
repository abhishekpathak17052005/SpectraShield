import React, { useEffect, useState } from "react";
import { motion, useSpring, useTransform, useMotionValue } from "motion/react";
import { useTheme } from "next-themes";

interface RiskMeterProps {
  score: number;
  loading: boolean;
}

const RiskMeter: React.FC<RiskMeterProps> = ({ score, loading }) => {
  const { resolvedTheme } = useTheme();
  const radius = 60;
  const strokeWidth = 8;
  const circumference = 2 * Math.PI * radius;
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Theme colors
  const themeColors = {
    light: {
      safe: "#16A34A",
      warning: "#F59E0B",
      danger: "#DC2626",
      track: "#E2E8F0"
    },
    dark: {
      safe: "#00FFAA",
      warning: "#FFA500",
      danger: "#FF3B3B",
      track: "#1E293B"
    }
  };

  const currentColors = mounted && resolvedTheme === "light" ? themeColors.light : themeColors.dark;

  // Create a motion value for the raw score
  const scoreMV = useMotionValue(0);
  
  // Create a spring that follows the scoreMV
  const springScore = useSpring(scoreMV, { stiffness: 60, damping: 20 });
  
  useEffect(() => {
    if (!loading) {
      scoreMV.set(score);
    } else {
      scoreMV.set(0);
    }
  }, [score, loading, scoreMV]);

  const strokeDashoffset = useTransform(springScore, (value) => {
    const progress = Math.min(Math.max(value, 0), 100);
    return circumference - (progress / 100) * circumference;
  });

  const color = useTransform(
    springScore,
    [0, 30, 70, 100],
    [currentColors.safe, currentColors.safe, currentColors.warning, currentColors.danger]
  );

  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    const unsubscribe = springScore.on("change", (latest) => {
      setDisplayScore(Math.round(latest));
    });
    return () => unsubscribe();
  }, [springScore]);

  // Re-render transforms when theme changes to update colors
  // This is a bit tricky with useTransform. We might need to recreate the transform or update it.
  // Actually, since currentColors changes, the arrays passed to useTransform change. 
  // But useTransform with arrays creates a new transformer. React will re-run this component function, 
  // so `color` will be a new MotionValue linked to the new colors.
  
  return (
    <div className="relative flex items-center justify-center w-48 h-48 py-4">
      {/* Outer Glow Ring */}
      <motion.div 
        className="absolute w-full h-full rounded-full opacity-20 blur-xl"
        style={{ backgroundColor: color }}
      />

      <svg width="160" height="160" viewBox="0 0 160 160" className="-rotate-90 relative z-10">
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2.5" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>
        
        {/* Track Circle */}
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke={currentColors.track}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          className="opacity-50 transition-colors duration-300"
        />
        
        {/* Progress Circle */}
        <motion.circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          style={{ strokeDashoffset }}
          className="drop-shadow-[0_0_8px_rgba(255,255,255,0.3)] transition-colors duration-300"
          filter="url(#glow)"
        />
      </svg>

      {/* Center Content */}
      <div className="absolute flex flex-col items-center justify-center z-20">
        <motion.div 
          className="text-5xl font-bold tracking-tighter tabular-nums text-foreground transition-colors duration-300"
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
        >
          {displayScore}
        </motion.div>
        <span className="text-[10px] text-muted-foreground uppercase tracking-widest mt-1 font-semibold">Risk Score</span>
      </div>
    </div>
  );
};

export default RiskMeter;
