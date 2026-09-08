import React from "react";
import { motion } from "motion/react";
import { TrendingUp, Globe, Building2, Paperclip, AlertTriangle } from "lucide-react";

interface RiskBreakdownProps {
  loading: boolean;
}

const metrics = [
  { 
    label: "Manipulation Score", 
    icon: TrendingUp, 
    value: 78, 
    colors: {
      bar: "bg-destructive",
      text: "text-destructive",
      bg: "bg-destructive",
      border: "border-destructive"
    },
    detail: "High" 
  },
  { 
    label: "URL Risk", 
    icon: Globe, 
    value: 65, 
    colors: {
      bar: "bg-warning",
      text: "text-warning",
      bg: "bg-warning",
      border: "border-warning"
    },
    detail: "Suspicious" 
  },
  { 
    label: "Brand Impersonation", 
    icon: Building2, 
    value: 92, 
    colors: {
      bar: "bg-destructive",
      text: "text-destructive",
      bg: "bg-destructive",
      border: "border-destructive"
    },
    detail: "Critical" 
  },
  { 
    label: "Attachment Risk", 
    icon: Paperclip, 
    value: 12, 
    colors: {
      bar: "bg-safe",
      text: "text-safe",
      bg: "bg-safe",
      border: "border-safe"
    },
    detail: "Low" 
  },
];

const RiskBreakdown: React.FC<RiskBreakdownProps> = ({ loading }) => {
  if (loading) {
    return (
      <div className="w-full space-y-4 animate-pulse">
        <div className="h-4 w-32 bg-muted rounded"></div>
        <div className="space-y-3">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-16 bg-muted/50 rounded-lg border border-border"></div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="w-full space-y-4">
      <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-widest mb-2 flex items-center gap-2 pl-1">
        <AlertTriangle className="w-3 h-3 text-muted-foreground" />
        Analysis Breakdown
      </h3>

      <div className="grid grid-cols-1 gap-3">
        {metrics.map((metric, index) => (
          <motion.div
            key={metric.label}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 + index * 0.1 }}
            className="group relative bg-card/40 hover:bg-card/60 p-3 rounded-lg border border-border hover:border-foreground/20 transition-all cursor-default backdrop-blur-sm"
          >
            {/* Background Glow on Hover */}
            <div className={`absolute inset-0 opacity-0 group-hover:opacity-5 transition-opacity duration-500 ${metric.colors.bg}`}></div>

            <div className="flex items-center justify-between mb-2 relative z-10">
              <div className="flex items-center gap-2.5">
                <div className={`p-1.5 rounded-md bg-muted border border-border group-hover:border-foreground/20 transition-colors`}>
                  <metric.icon className="w-3.5 h-3.5 text-muted-foreground group-hover:text-foreground transition-colors" />
                </div>
                <span className="text-sm font-medium text-foreground/80 group-hover:text-foreground transition-colors">{metric.label}</span>
              </div>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${metric.colors.text} ${metric.colors.border}/30 bg-card/50`}>
                {metric.detail}
              </span>
            </div>

            {/* Progress Bar */}
            <div className="relative w-full h-1.5 bg-muted rounded-full overflow-hidden">
              <motion.div
                className={`absolute left-0 top-0 h-full rounded-full ${metric.colors.bar} shadow-[0_0_8px_currentColor]`}
                initial={{ width: 0 }}
                animate={{ width: `${metric.value}%` }}
                transition={{ duration: 1, delay: 0.5 + index * 0.1, ease: "easeOut" }}
              />
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
};

export default RiskBreakdown;