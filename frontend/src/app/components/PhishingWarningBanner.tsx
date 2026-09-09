import React from "react";
import { motion, AnimatePresence } from "motion/react";
import { ChevronRight, ShieldAlert } from "lucide-react";

interface PhishingWarningBannerProps {
  isVisible: boolean;
  onDismiss: () => void;
  riskScore?: number;
}

const PhishingWarningBanner: React.FC<PhishingWarningBannerProps> = ({ 
  isVisible, 
  onDismiss,
  riskScore = 82 
}) => {
  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ y: -100, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -100, opacity: 0 }}
          transition={{ type: "spring", stiffness: 300, damping: 30 }}
          className="relative w-full z-50 rounded-xl overflow-hidden shadow-2xl shadow-destructive/40 border border-destructive/30 backdrop-blur-md"
        >
          {/* Background */}
          <div className="absolute inset-0 bg-destructive/95 z-0"></div>
          
          {/* Subtle animated overlay pattern */}
          <div className="absolute inset-0 opacity-20 z-0 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:16px_16px]"></div>
          
          <div className="relative z-10 flex flex-col items-start justify-between p-3 gap-3">
            
            {/* Left Side: Icon & Text */}
            <div className="flex items-center gap-3">
              <div className="relative flex-shrink-0">
                <div className="absolute inset-0 bg-white rounded-full animate-ping opacity-20"></div>
                <div className="relative bg-white/20 p-2 rounded-full shadow-lg border border-white/30">
                  <ShieldAlert className="w-4 h-4 text-white" />
                </div>
              </div>
              
              <div className="flex flex-col">
                <h3 className="text-white font-bold text-sm tracking-tight flex items-center gap-2">
                  High Phishing Risk Detected
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-extrabold bg-white/20 border border-white/30 text-white">
                    {riskScore}%
                  </span>
                </h3>
                <p className="text-white/80 text-[11px] font-medium leading-tight max-w-[280px]">
                  This site exhibits malicious behavior patterns.
                </p>
              </div>
            </div>

            {/* Right Side: Actions */}
            <div className="flex items-center justify-end gap-2 w-full mt-1">
              <button 
                onClick={onDismiss}
                className="text-[11px] font-semibold text-white/60 hover:text-white px-2 py-1.5 rounded-lg hover:bg-white/10 transition-colors whitespace-nowrap"
              >
                Proceed Anyway
              </button>
              
              <button className="flex items-center justify-center gap-1.5 px-3 py-1.5 bg-white text-destructive text-[11px] font-bold rounded-lg shadow-lg shadow-black/20 hover:bg-white/90 hover:scale-105 transition-all transform active:scale-95 group border border-white/50">
                View Details
                <ChevronRight className="w-3 h-3 text-destructive group-hover:translate-x-0.5 transition-transform" />
              </button>
            </div>
          </div>
          
          {/* Bottom Progress/Timer Bar (Optional visual flair) */}
          <div className="absolute bottom-0 left-0 h-[2px] bg-white w-full opacity-30"></div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default PhishingWarningBanner;
