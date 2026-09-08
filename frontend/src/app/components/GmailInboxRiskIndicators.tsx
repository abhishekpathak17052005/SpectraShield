import React, { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Star, Square, AlertTriangle, ShieldAlert, CheckCircle2 } from "lucide-react";

type RiskLevel = "safe" | "suspicious" | "high";

interface EmailItem {
  id: string;
  sender: string;
  subject: string;
  snippet: string;
  date: string;
  riskLevel: RiskLevel;
  riskScore: number;
}

const mockEmails: EmailItem[] = [
  {
    id: "1",
    sender: "HR Department",
    subject: "ACTION REQUIRED: Payroll Update",
    snippet: "Please verify your direct deposit details immediately to avoid...",
    date: "10:42 AM",
    riskLevel: "high",
    riskScore: 89,
  },
  {
    id: "2",
    sender: "Amazon.com",
    subject: "Your package has been delivered",
    snippet: "Order #402-99201 delivered to Front Porch...",
    date: "9:15 AM",
    riskLevel: "suspicious",
    riskScore: 62,
  },
  {
    id: "3",
    sender: "Google Security",
    subject: "New sign-in on Windows",
    snippet: "We noticed a new sign-in to your Google Account...",
    date: "Yesterday",
    riskLevel: "safe",
    riskScore: 12,
  },
];

const RiskBadge: React.FC<{ level: RiskLevel; score: number }> = ({ level, score }) => {
  const [isHovered, setIsHovered] = useState(false);

  const config = {
    safe: { icon: CheckCircle2, color: "text-safe", bg: "bg-safe/10", tooltipIndicator: "bg-safe" },
    suspicious: { icon: AlertTriangle, color: "text-warning", bg: "bg-warning/10", tooltipIndicator: "bg-warning" },
    high: { icon: ShieldAlert, color: "text-destructive", bg: "bg-destructive/10", tooltipIndicator: "bg-destructive" },
  };

  const { icon: Icon, color, bg, tooltipIndicator } = config[level];

  return (
    <div 
      className="relative inline-flex items-center ml-2"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <motion.div 
        whileHover={{ scale: 1.1 }}
        className={`p-1 rounded-md ${bg} ${color} cursor-help`}
      >
        <Icon className="w-4 h-4" />
      </motion.div>

      <AnimatePresence>
        {isHovered && (
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.15 }}
            className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 w-max max-w-[200px] z-50 pointer-events-none"
          >
            <div className="bg-popover border border-border text-popover-foreground text-xs py-1.5 px-3 rounded-lg shadow-xl flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${tooltipIndicator}`} />
              <span className="font-medium">Phishing probability: {score}%</span>
              
              {/* Little arrow pointing down */}
              <div className="absolute bottom-[-4px] left-1/2 -translate-x-1/2 w-2 h-2 bg-popover border-r border-b border-border rotate-45 transform"></div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const GmailInboxRiskIndicators: React.FC = () => {
  return (
    <div className="w-full bg-card rounded-xl overflow-hidden border border-border shadow-lg">
      {/* Fake Gmail Header for Context */}
      <div className="px-4 py-3 bg-muted/50 border-b border-border flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Inbox Simulation</span>
        <div className="flex gap-2">
          <div className="w-2 h-2 rounded-full bg-muted-foreground/30"></div>
          <div className="w-2 h-2 rounded-full bg-muted-foreground/30"></div>
        </div>
      </div>

      <div className="flex flex-col divide-y divide-border">
        {mockEmails.map((email) => (
          <div 
            key={email.id} 
            className="group relative flex items-start gap-3 p-3 hover:bg-muted/50 transition-colors cursor-pointer"
          >
            {/* Left Controls */}
            <div className="flex flex-col items-center gap-3 pt-1 text-muted-foreground">
              <Square className="w-4 h-4 hover:text-foreground transition-colors" />
              <Star className="w-4 h-4 hover:text-yellow-400 transition-colors" />
            </div>

            {/* Email Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-baseline justify-between mb-0.5">
                <span className={`text-sm font-bold truncate ${email.riskLevel === 'high' ? 'text-foreground' : 'text-foreground/80'}`}>
                  {email.sender}
                </span>
                <span className="text-[10px] text-muted-foreground whitespace-nowrap ml-2">
                  {email.date}
                </span>
              </div>
              
              <div className="flex items-center mb-0.5">
                <span className="text-sm font-medium text-foreground truncate max-w-[180px]">
                  {email.subject}
                </span>
                <RiskBadge level={email.riskLevel} score={email.riskScore} />
              </div>

              <p className="text-xs text-muted-foreground truncate pr-4">
                {email.snippet}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default GmailInboxRiskIndicators;
