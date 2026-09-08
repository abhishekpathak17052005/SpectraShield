import React from "react";
import { createRoot } from "react-dom/client";
import { motion, AnimatePresence } from "motion/react";
import { AlertTriangle, ShieldAlert, CheckCircle2 } from "lucide-react";

type RiskLevel = "safe" | "suspicious" | "high";

interface EmailRiskData {
  riskLevel: RiskLevel;
  riskScore: number;
}

// Risk Badge Component (Standalone for Gmail injection)
const RiskBadge: React.FC<EmailRiskData & { hoverable?: boolean }> = ({ riskLevel, riskScore, hoverable = true }) => {
  const [isHovered, setIsHovered] = React.useState(false);

  const config = {
    safe: { icon: CheckCircle2, color: "#10b981", bg: "rgba(16, 185, 129, 0.1)", label: "Safe" },
    suspicious: { icon: AlertTriangle, color: "#fbbf24", bg: "rgba(251, 191, 36, 0.1)", label: "Suspicious" },
    high: { icon: ShieldAlert, color: "#ef4444", bg: "rgba(239, 68, 68, 0.1)", label: "High Risk" },
  };

  const { icon: Icon, color, bg, label } = config[riskLevel];

  return (
    <div
      className="spectrashield-risk-badge"
      style={{
        position: "relative",
        display: "inline-flex",
        alignItems: "center",
        marginLeft: "8px",
        zIndex: 10,
      }}
      onMouseEnter={() => hoverable && setIsHovered(true)}
      onMouseLeave={() => hoverable && setIsHovered(false)}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        whileHover={hoverable ? { scale: 1.1 } : {}}
        transition={{ duration: 0.2 }}
        style={{
          padding: "4px",
          borderRadius: "6px",
          backgroundColor: bg,
          color: color,
          cursor: hoverable ? "help" : "default",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Icon size={16} strokeWidth={2.5} />
      </motion.div>

      <AnimatePresence>
        {isHovered && hoverable && (
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.15 }}
            style={{
              position: "absolute",
              left: "50%",
              transform: "translateX(-50%)",
              bottom: "calc(100% + 8px)",
              zIndex: 99999,
              pointerEvents: "none",
              whiteSpace: "nowrap",
            }}
          >
            <div
              style={{
                backgroundColor: "#1e293b",
                border: "1px solid #475569",
                color: "#e2e8f0",
                fontSize: "12px",
                padding: "6px 12px",
                borderRadius: "8px",
                boxShadow: "0 10px 25px rgba(0, 0, 0, 0.4)",
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <span
                style={{
                  width: "8px",
                  height: "8px",
                  borderRadius: "50%",
                  backgroundColor: color,
                }}
              />
              <span style={{ fontWeight: 600 }}>
                {label}: {riskScore}% risk
              </span>

              {/* Tooltip Arrow */}
              <div
                style={{
                  position: "absolute",
                  bottom: "-4px",
                  left: "50%",
                  transform: "translateX(-50%) rotate(45deg)",
                  width: "8px",
                  height: "8px",
                  backgroundColor: "#1e293b",
                  border: "1px solid #475569",
                  borderTop: "none",
                  borderLeft: "none",
                }}
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// Gmail Email Risk Analyzer (simulated - replace with real API)
class SpectraShieldAnalyzer {
  // Simulated risk analysis based on email content
  analyzeEmail(emailSubject: string, emailSender: string): EmailRiskData {
    const subject = emailSubject.toLowerCase();
    const sender = emailSender.toLowerCase();

    // High-risk keywords
    if (
      subject.includes("urgent") ||
      subject.includes("action required") ||
      subject.includes("verify") ||
      subject.includes("suspended") ||
      subject.includes("confirm your") ||
      sender.includes("noreply") ||
      subject.includes("payroll")
    ) {
      return {
        riskLevel: "high",
        riskScore: Math.floor(Math.random() * 20) + 75, // 75-95
      };
    }

    // Suspicious keywords
    if (
      subject.includes("click here") ||
      subject.includes("limited time") ||
      subject.includes("congratulations") ||
      sender.includes("delivery") ||
      sender.includes("support")
    ) {
      return {
        riskLevel: "suspicious",
        riskScore: Math.floor(Math.random() * 30) + 40, // 40-70
      };
    }

    // Safe
    return {
      riskLevel: "safe",
      riskScore: Math.floor(Math.random() * 25) + 5, // 5-30
    };
  }
}

// Gmail Content Script Injector
class GmailRiskInjector {
  private analyzer: SpectraShieldAnalyzer;
  private processedEmails: Set<string>;
  private observer: MutationObserver | null;

  constructor() {
    this.analyzer = new SpectraShieldAnalyzer();
    this.processedEmails = new Set();
    this.observer = null;
  }

  // Get all email rows from Gmail's inbox
  getEmailRows(): NodeListOf<Element> {
    // Gmail email row selectors (these may vary based on Gmail's DOM structure)
    // Common selectors for Gmail inbox rows:
    return document.querySelectorAll('tr.zA, tr[role="row"]');
  }

  // Extract email subject from a row
  getEmailSubject(row: Element): string | null {
    // Try multiple selectors for subject
    const subjectSelectors = [
      'span.bog',    // Classic subject span
      'span[data-thread-id]', // Thread subject
      '.y6 span',    // Another subject variant
      '[role="link"] > span:nth-child(2)', // Link-based subject
    ];

    for (const selector of subjectSelectors) {
      const element = row.querySelector(selector);
      if (element?.textContent) {
        return element.textContent.trim();
      }
    }

    return null;
  }

  // Extract email sender from a row
  getEmailSender(row: Element): string | null {
    // Try multiple selectors for sender
    const senderSelectors = [
      'span.yW span[email]',
      'span[email]',
      '.yX.xY span',
      'td.yX span',
    ];

    for (const selector of senderSelectors) {
      const element = row.querySelector(selector);
      if (element?.textContent) {
        return element.textContent.trim();
      }
    }

    return null;
  }

  // Find the best position to inject the badge
  findBadgeInjectionPoint(row: Element): Element | null {
    // Look for the subject container
    const subjectContainers = [
      row.querySelector('span.bog'),
      row.querySelector('.y6'),
      row.querySelector('[role="link"]'),
    ];

    for (const container of subjectContainers) {
      if (container) {
        return container.parentElement || container;
      }
    }

    return null;
  }

  // Inject risk badge into an email row
  injectBadge(row: Element) {
    const rowId = (row as HTMLElement).dataset.threadId || row.querySelector('[data-legacy-thread-id]')?.getAttribute('data-legacy-thread-id');
    
    // Skip if already processed
    if (!rowId || this.processedEmails.has(rowId)) {
      return;
    }

    const subject = this.getEmailSubject(row);
    const sender = this.getEmailSender(row);

    if (!subject && !sender) {
      return; // Not enough data
    }

    const injectionPoint = this.findBadgeInjectionPoint(row);
    if (!injectionPoint) {
      return;
    }

    // Analyze email
    const riskData = this.analyzer.analyzeEmail(subject || "", sender || "");

    // Create container for the badge
    const badgeContainer = document.createElement('span');
    badgeContainer.className = 'spectrashield-badge-container';
    badgeContainer.style.display = 'inline-flex';
    badgeContainer.style.alignItems = 'center';
    badgeContainer.style.marginLeft = '6px';
    badgeContainer.style.verticalAlign = 'middle';

    // Inject badge using React
    const root = createRoot(badgeContainer);
    root.render(<RiskBadge {...riskData} />);

    // Append to the injection point
    injectionPoint.appendChild(badgeContainer);

    // Mark as processed
    this.processedEmails.add(rowId);
  }

  // Process all visible emails
  processEmails() {
    const emailRows = this.getEmailRows();
    emailRows.forEach((row) => this.injectBadge(row));
  }

  // Start observing Gmail for new emails
  startObserving() {
    // Process existing emails
    this.processEmails();

    // Watch for new emails being loaded
    this.observer = new MutationObserver((mutations) => {
      let shouldProcess = false;

      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
          shouldProcess = true;
        }
      });

      if (shouldProcess) {
        // Debounce the processing
        setTimeout(() => this.processEmails(), 300);
      }
    });

    // Observe the inbox container
    const inboxContainer = document.querySelector('[role="main"]') || document.body;
    this.observer.observe(inboxContainer, {
      childList: true,
      subtree: true,
    });
  }

  // Stop observing
  stopObserving() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
  }
}

// Initialize the injector when Gmail is ready
function initGmailIntegration() {
  // Wait for Gmail to be fully loaded
  const waitForGmail = setInterval(() => {
    const inboxCheck = document.querySelector('[role="main"]') || document.querySelector('tr.zA');
    
    if (inboxCheck) {
      clearInterval(waitForGmail);
      console.log('[SpectraShield AI] Gmail detected, initializing risk indicators...');

      const injector = new GmailRiskInjector();
      injector.startObserving();

      // Re-process when navigating between folders
      window.addEventListener('hashchange', () => {
        setTimeout(() => injector.processEmails(), 500);
      });
    }
  }, 500);

  // Timeout after 30 seconds
  setTimeout(() => clearInterval(waitForGmail), 30000);
}

// Auto-initialize if we're on Gmail
if (window.location.hostname.includes('mail.google.com')) {
  initGmailIntegration();
}

export { RiskBadge, GmailRiskInjector, initGmailIntegration };