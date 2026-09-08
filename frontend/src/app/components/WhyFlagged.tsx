import React, { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { ChevronDown, AlertCircle, Info } from "lucide-react";

interface WhyFlaggedProps {
  loading: boolean;
}

const WhyFlagged: React.FC<WhyFlaggedProps> = ({ loading }) => {
  const [isOpen, setIsOpen] = useState(false);

  if (loading) return null;

  return (
    <div className="w-full">
      <motion.button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-3 rounded-lg bg-card hover:bg-card/80 border border-border transition-all group shadow-sm"
        whileHover={{ scale: 1.01 }}
        whileTap={{ scale: 0.99 }}
      >
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-primary" />
          <span className="text-sm font-semibold text-foreground">Why was this flagged?</span>
        </div>
        <motion.div
          animate={{ rotate: isOpen ? 180 : 0 }}
          transition={{ duration: 0.2 }}
        >
          <ChevronDown className="w-4 h-4 text-muted-foreground group-hover:text-foreground transition-colors" />
        </motion.div>
      </motion.button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            <div className="p-4 mt-2 bg-muted/30 rounded-lg border border-border text-sm text-muted-foreground leading-relaxed space-y-3">
              <p>
                <strong className="text-destructive block mb-1">High Risk Detected</strong>
                This URL exhibits patterns commonly associated with phishing attacks. The domain was registered less than 24 hours ago and attempts to mimic a known banking institution.
              </p>
              <div className="flex flex-col gap-2 mt-2">
                <div className="flex items-start gap-2 text-xs">
                  <div className="min-w-1.5 min-h-1.5 w-1.5 h-1.5 rounded-full bg-destructive mt-1.5"></div>
                  <span>Look-alike domain detected (example-bank-login.com vs examplebank.com)</span>
                </div>
                <div className="flex items-start gap-2 text-xs">
                  <div className="min-w-1.5 min-h-1.5 w-1.5 h-1.5 rounded-full bg-warning mt-1.5"></div>
                  <span>No SSL certificate history found</span>
                </div>
                <div className="flex items-start gap-2 text-xs">
                  <div className="min-w-1.5 min-h-1.5 w-1.5 h-1.5 rounded-full bg-destructive mt-1.5"></div>
                  <span>Suspicious JavaScript redirection detected</span>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default WhyFlagged;
