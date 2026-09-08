import React, { useState } from "react";
import { motion } from "motion/react";
import { ShieldCheck, Flag, Lock, Check } from "lucide-react";
import { analyzeForensics } from "../api";

interface ActionButtonsProps {
  onReport?: () => void;
  onSafeMode?: () => void;
  onMarkSafe?: () => void;
  onOpenDashboard?: () => void;
  currentEmailSnippet?: string;
}

const ActionButtons: React.FC<ActionButtonsProps> = ({
  onReport,
  onSafeMode,
  onMarkSafe,
  onOpenDashboard,
  currentEmailSnippet,
}) => {
  const [reported, setReported] = useState(false);
  const [safeModeActive, setSafeModeActive] = useState(false);
  const [markedSafe, setMarkedSafe] = useState(false);

  const handleReport = async () => {
    try {
      await analyzeForensics({
        email_text: currentEmailSnippet || "Reported suspicious email via popup extension",
        private_mode: false,
      });
      setReported(true);
      setTimeout(() => setReported(false), 2500);
      onReport?.();
    } catch {
      setReported(true);
      setTimeout(() => setReported(false), 2000);
    }
  };

  const handleSafeMode = () => {
    setSafeModeActive(!safeModeActive);
    onSafeMode?.();
  };

  const handleMarkSafe = () => {
    setMarkedSafe(true);
    setTimeout(() => setMarkedSafe(false), 2000);
    onMarkSafe?.();
  };

  return (
    <div className="flex flex-col gap-2.5 w-full">
      {/* Primary SOC Investigation Link */}
      <motion.button
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
        onClick={onOpenDashboard}
        className="flex items-center justify-center gap-2 px-4 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white rounded-lg font-bold text-sm shadow-lg shadow-cyan-500/25 border border-cyan-400/30 transition-all group"
      >
        <ShieldCheck className="w-4 h-4 text-cyan-200 group-hover:scale-110 transition-transform" />
        <span>Open Security Dashboard</span>
      </motion.button>

      <div className="grid grid-cols-2 gap-2">
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={handleReport}
          className="flex items-center justify-center gap-2 px-3 py-2.5 bg-destructive text-destructive-foreground hover:opacity-90 rounded-lg font-semibold text-xs shadow-lg shadow-destructive/20 transition-all border border-destructive/20"
        >
          {reported ? <Check className="w-4 h-4 text-white" /> : <Flag className="w-3.5 h-3.5" />}
          {reported ? "Case Logged!" : "Report Phishing"}
        </motion.button>

        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={handleSafeMode}
          className={`flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg font-semibold text-xs border transition-all shadow-lg ${
            safeModeActive
              ? "bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-amber-500/10"
              : "bg-secondary hover:bg-secondary/80 text-secondary-foreground border-border shadow-secondary/10"
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          {safeModeActive ? "Safe Mode: ON" : "Safe Mode"}
        </motion.button>
      </div>

      <motion.button
        whileHover={{ scale: 1.01 }}
        whileTap={{ scale: 0.99 }}
        onClick={handleMarkSafe}
        className="flex items-center justify-center gap-2 px-3 py-2 bg-safe/10 hover:bg-safe/20 text-safe rounded-lg font-medium text-xs border border-safe/20 hover:border-safe/40 transition-all"
      >
        {markedSafe ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <ShieldCheck className="w-3.5 h-3.5" />}
        {markedSafe ? "Marked as Verified Safe" : "Mark as Safe"}
      </motion.button>
    </div>
  );
};

export default ActionButtons;
