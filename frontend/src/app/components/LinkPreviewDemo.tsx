import React, { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Mail, ExternalLink, ShieldAlert, X } from "lucide-react";
import LinkPreview from "./LinkPreview";

interface SuspiciousLink {
  url: string;
  riskScore: number;
  context: string;
}

const LinkPreviewDemo: React.FC = () => {
  const [selectedLink, setSelectedLink] = useState<SuspiciousLink | null>(null);

  const suspiciousLinks: SuspiciousLink[] = [
    {
      url: "https://secure-verify-account.tk/login/microsoft/verify",
      riskScore: 87,
      context: "Click here to verify your Microsoft account before it gets suspended.",
    },
    {
      url: "http://paypal-security-update.xyz/confirm-payment",
      riskScore: 94,
      context: "Your PayPal account requires immediate attention. Update your payment method now.",
    },
    {
      url: "https://amazon-delivery-tracking.ru/package/track?id=12345",
      riskScore: 76,
      context: "Track your Amazon package delivery status here.",
    },
    {
      url: "https://banking-alert.net/chase/login/verify-identity",
      riskScore: 91,
      context: "Urgent: Verify your Chase bank account to prevent restrictions.",
    },
  ];

  const getRiskColor = (score: number) => {
    if (score >= 70) return "text-destructive border-destructive/30 bg-destructive/5";
    if (score >= 40) return "text-warning border-warning/30 bg-warning/5";
    return "text-safe border-safe/30 bg-safe/5";
  };

  return (
    <div className="w-full min-h-screen bg-background p-8 transition-colors duration-300">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-3 mb-4">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/30 blur-xl rounded-full" />
              <ShieldAlert className="w-12 h-12 text-primary relative z-10" />
            </div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-foreground via-primary to-muted-foreground bg-clip-text text-transparent">
              SpectraShield AI Link Preview
            </h1>
          </div>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
            Click any suspicious link below to see the secure preview interface with real-time threat analysis
          </p>
        </div>

        {/* Simulated Email with Suspicious Links */}
        {!selectedLink && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-card rounded-2xl border border-border overflow-hidden shadow-2xl mb-8"
          >
            {/* Email Header */}
            <div className="bg-muted/50 border-b border-border px-6 py-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-10 h-10 bg-destructive/20 rounded-full flex items-center justify-center">
                  <Mail className="w-5 h-5 text-destructive" />
                </div>
                <div>
                  <div className="text-foreground font-semibold">IT Security Department</div>
                  <div className="text-xs text-muted-foreground">security@company-verify.tk</div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-destructive" />
                <span className="text-sm font-semibold text-destructive">Phishing Warning Active</span>
              </div>
            </div>

            {/* Email Content */}
            <div className="p-6">
              <h3 className="text-xl font-bold text-foreground mb-4">
                Urgent: Account Security Update Required
              </h3>
              <div className="space-y-6 text-foreground/80">
                <p>Dear User,</p>
                <p>
                  We have detected suspicious activity on your account. To ensure your security, please
                  verify your credentials immediately.
                </p>

                {/* Suspicious Links List */}
                <div className="bg-muted/30 border border-border rounded-xl p-4 space-y-3">
                  <div className="text-sm font-semibold text-muted-foreground mb-3">
                    Select a link to preview (SpectraShield protection enabled):
                  </div>
                  {suspiciousLinks.map((link, index) => (
                    <motion.button
                      key={index}
                      onClick={() => setSelectedLink(link)}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className={`w-full text-left p-4 rounded-lg border transition-all hover:scale-[1.02] ${getRiskColor(
                        link.riskScore
                      )}`}
                    >
                      <div className="flex items-start gap-3">
                        <ExternalLink
                          className={`w-5 h-5 flex-shrink-0 mt-0.5 ${
                            link.riskScore >= 70
                              ? "text-destructive"
                              : link.riskScore >= 40
                              ? "text-warning"
                              : "text-safe"
                          }`}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm text-foreground mb-1">{link.context}</div>
                          <div className="text-xs font-mono text-muted-foreground truncate">{link.url}</div>
                          <div className="flex items-center gap-2 mt-2">
                            <span
                              className={`text-xs font-semibold ${
                                link.riskScore >= 70
                                  ? "text-destructive"
                                  : link.riskScore >= 40
                                  ? "text-warning"
                                  : "text-safe"
                              }`}
                            >
                              Risk: {link.riskScore}%
                            </span>
                            <span className="text-xs text-muted-foreground">•</span>
                            <span className="text-xs text-muted-foreground">Click to analyze safely</span>
                          </div>
                        </div>
                      </div>
                    </motion.button>
                  ))}
                </div>

                <p className="text-sm text-muted-foreground italic">
                  SpectraShield AI will analyze any link before opening, protecting you from phishing attacks.
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {/* Link Preview Modal */}
        <AnimatePresence>
          {selectedLink && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
              onClick={() => setSelectedLink(null)}
            >
              <motion.div
                initial={{ scale: 0.9, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.9, opacity: 0 }}
                transition={{ type: "spring", duration: 0.5 }}
                onClick={(e) => e.stopPropagation()}
                className="relative max-w-5xl w-full max-h-[90vh] overflow-y-auto"
              >
                {/* Close Button */}
                <button
                  onClick={() => setSelectedLink(null)}
                  className="absolute top-2 right-2 z-10 w-10 h-10 bg-card hover:bg-muted border border-border rounded-full flex items-center justify-center transition-colors"
                >
                  <X className="w-5 h-5 text-muted-foreground" />
                </button>

                {/* Link Preview Component */}
                <LinkPreview url={selectedLink.url} riskScore={selectedLink.riskScore} />
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Info Cards */}
        {!selectedLink && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className="bg-card border border-border rounded-xl p-6"
            >
              <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4">
                <ShieldAlert className="w-6 h-6 text-primary" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">Real-time Analysis</h3>
              <p className="text-sm text-muted-foreground">
                Every link is analyzed in real-time before you visit, checking domain reputation, SSL
                certificates, and known phishing indicators.
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.6 }}
              className="bg-card border border-border rounded-xl p-6"
            >
              <div className="w-12 h-12 bg-safe/10 rounded-lg flex items-center justify-center mb-4">
                <Mail className="w-6 h-6 text-safe" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">Sandboxed Preview</h3>
              <p className="text-sm text-muted-foreground">
                View a safe, isolated preview of the destination page without executing any malicious
                scripts or tracking pixels.
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7 }}
              className="bg-card border border-border rounded-xl p-6"
            >
              <div className="w-12 h-12 bg-destructive/10 rounded-lg flex items-center justify-center mb-4">
                <ExternalLink className="w-6 h-6 text-destructive" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">Informed Decisions</h3>
              <p className="text-sm text-muted-foreground">
                Make informed choices with detailed threat indicators, domain age, SSL status, and security
                recommendations.
              </p>
            </motion.div>
          </div>
        )}
      </div>
    </div>
  );
};

export default LinkPreviewDemo;