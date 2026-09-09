import React, { useState, useEffect } from "react";
import { motion } from "motion/react";
import { 
  Star, 
  Square, 
  Archive, 
  Trash2, 
  Mail, 
  RefreshCw, 
  Search,
  Menu,
  ChevronDown,
  MoreVertical,
  AlertTriangle,
  ShieldAlert,
  CheckCircle2
} from "lucide-react";
import { analyze } from "../api";

type RiskLevel = "safe" | "suspicious" | "high";

interface EmailItem {
  id: string;
  sender: string;
  senderEmail: string;
  subject: string;
  snippet: string;
  time: string;
  starred: boolean;
  selected: boolean;
  unread: boolean;
  riskLevel: RiskLevel;
  riskScore: number;
  investigationId?: string;
}

const mockGmailEmails: EmailItem[] = [
  {
    id: "ss-00421",
    sender: "PayPal Security Support",
    senderEmail: "security-update@paypa1-support.com",
    subject: "Your account requires immediate verification",
    snippet: "Immediate action required: Suspicious unauthorized login attempt detected from 185.220.101.5. Click here to verify your identity before account suspension...",
    time: "10:42 AM",
    starred: true,
    selected: false,
    unread: true,
    riskLevel: "high",
    riskScore: 87,
    investigationId: "SS-2026-0912-00421",
  },
  {
    id: "1",
    sender: "HR Department",
    senderEmail: "hr-payroll@corpupdate.tk",
    subject: "URGENT: Payroll System Update Required",
    snippet: "Your payroll account requires immediate verification. Click here to update your banking details before Friday or...",
    time: "11:23 AM",
    starred: false,
    selected: false,
    unread: true,
    riskLevel: "high",
    riskScore: 92,
    investigationId: "INV-2026-9041",
  },
  {
    id: "2",
    sender: "Amazon Services",
    senderEmail: "no-reply@amazon-delivery.net",
    subject: "Your package delivery attempt failed",
    snippet: "We attempted to deliver your package but no one was home. Please confirm your address to reschedule delivery...",
    time: "10:15 AM",
    starred: false,
    selected: false,
    unread: true,
    riskLevel: "suspicious",
    riskScore: 68,
  },
  {
    id: "3",
    sender: "Microsoft Security",
    senderEmail: "security-noreply@accountverify.com",
    subject: "Your account has been suspended",
    snippet: "Unusual activity detected on your Microsoft account. Verify your identity within 24 hours to restore access...",
    time: "9:47 AM",
    starred: false,
    selected: false,
    unread: true,
    riskLevel: "high",
    riskScore: 88,
  },
  {
    id: "4",
    sender: "Netflix",
    senderEmail: "support@netflix-billing.info",
    subject: "Payment Declined - Update Required",
    snippet: "Your payment method was declined. Please update your billing information to continue enjoying Netflix...",
    time: "Yesterday",
    starred: false,
    selected: false,
    unread: false,
    riskLevel: "suspicious",
    riskScore: 71,
  },
  {
    id: "5",
    sender: "Google Calendar",
    senderEmail: "calendar-notification@google.com",
    subject: "Event reminder: Team Standup at 2 PM",
    snippet: "This is a reminder that you have \"Team Standup\" scheduled for today at 2:00 PM PST...",
    time: "Yesterday",
    starred: true,
    selected: false,
    unread: false,
    riskLevel: "safe",
    riskScore: 8,
  },
  {
    id: "6",
    sender: "LinkedIn",
    senderEmail: "notifications@linkedin.com",
    subject: "You have 3 new connection requests",
    snippet: "Sarah Chen, Michael Rodriguez, and 1 other person want to connect with you on LinkedIn...",
    time: "2 days ago",
    starred: false,
    selected: false,
    unread: false,
    riskLevel: "safe",
    riskScore: 15,
  },
  {
    id: "7",
    sender: "IT Support Team",
    senderEmail: "it.support@company-helpdesk.com",
    subject: "Mandatory Security Training - Complete Now",
    snippet: "All employees must complete the security awareness training by end of day. Click the link below to start...",
    time: "2 days ago",
    starred: false,
    selected: false,
    unread: false,
    riskLevel: "suspicious",
    riskScore: 54,
  },
];

// Inline Risk Badge Component
const RiskBadge: React.FC<{ level: RiskLevel; score: number }> = ({ level, score }) => {
  const [isHovered, setIsHovered] = useState(false);

  const config = {
    safe: { icon: CheckCircle2, color: "text-emerald-500", bg: "bg-emerald-500/10", dotColor: "bg-emerald-500" },
    suspicious: { icon: AlertTriangle, color: "text-amber-400", bg: "bg-amber-400/10", dotColor: "bg-amber-400" },
    high: { icon: ShieldAlert, color: "text-rose-500", bg: "bg-rose-500/10", dotColor: "bg-rose-500" },
  };

  const { icon: Icon, color, bg, dotColor } = config[level];

  return (
    <div
      className="relative inline-flex items-center ml-2 z-10"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        whileHover={{ scale: 1.1 }}
        transition={{ duration: 0.2 }}
        className={`p-1 rounded-md ${bg} ${color} cursor-help`}
      >
        <Icon className="w-4 h-4" strokeWidth={2.5} />
      </motion.div>

      {isHovered && (
        <motion.div
          initial={{ opacity: 0, y: 10, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          transition={{ duration: 0.15 }}
          className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 w-max max-w-[220px] z-50 pointer-events-none"
        >
          <div className="bg-slate-900 border border-slate-700 text-slate-200 text-xs py-1.5 px-3 rounded-lg shadow-2xl flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${dotColor}`} />
            <span className="font-semibold">
              {level === "high" ? "High Risk" : level === "suspicious" ? "Suspicious" : "Safe"}: {score}% risk
            </span>

            {/* Tooltip Arrow */}
            <div className="absolute bottom-[-4px] left-1/2 -translate-x-1/2 w-2 h-2 bg-slate-900 border-r border-b border-slate-700 rotate-45 transform"></div>
          </div>
        </motion.div>
      )}
    </div>
  );
};

interface GmailDemoProps {
  onOpenInvestigation?: (caseId?: string) => void;
}

const GmailDemo: React.FC<GmailDemoProps> = ({ onOpenInvestigation }) => {
  const [emails, setEmails] = useState<EmailItem[]>(mockGmailEmails);
  const [selectAll, setSelectAll] = useState(false);

  useEffect(() => {
    let cancelled = false;
    Promise.all(mockGmailEmails.map(async (email) => {
      try {
        const result = await analyze({
          email_text: `${email.subject}\n\n${email.snippet}`,
          sender_email: email.senderEmail,
          private_mode: true,
        });
        const score = Math.round(result.final_risk ?? 0);
        return { ...email, riskScore: score, riskLevel: score >= 70 ? "high" : score >= 35 ? "suspicious" : "safe" } as EmailItem;
      } catch {
        return email;
      }
    })).then((liveEmails) => {
      if (!cancelled) setEmails(liveEmails);
    });
    return () => { cancelled = true; };
  }, []);

  const toggleStar = (id: string) => {
    setEmails(emails.map(email => 
      email.id === id ? { ...email, starred: !email.starred } : email
    ));
  };

  const toggleSelect = (id: string) => {
    setEmails(emails.map(email => 
      email.id === id ? { ...email, selected: !email.selected } : email
    ));
  };

  const toggleSelectAll = () => {
    setSelectAll(!selectAll);
    setEmails(emails.map(email => ({ ...email, selected: !selectAll })));
  };

  return (
    <div className="w-full h-full min-h-screen bg-[#f6f8fc] flex flex-col">
      {/* Gmail Header */}
      <header className="bg-white border-b border-gray-200 px-4 py-2 flex items-center gap-4 sticky top-0 z-20">
        <button className="p-2 hover:bg-gray-100 rounded-full transition-colors">
          <Menu className="w-5 h-5 text-gray-600" />
        </button>
        
        <div className="flex items-center gap-2">
          <Mail className="w-6 h-6 text-red-500" />
          <span className="text-xl text-gray-700 font-normal">Gmail</span>
        </div>

        <div className="flex-1 max-w-2xl mx-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search mail"
              className="w-full pl-11 pr-4 py-2.5 bg-[#eaf1fb] hover:bg-white hover:shadow-md focus:bg-white focus:shadow-md rounded-full outline-none transition-all text-sm"
            />
          </div>
        </div>

        <div className="flex items-center gap-1">
          <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center text-sm font-medium">
            U
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar (minimal) */}
        <aside className="w-16 bg-white border-r border-gray-200 flex flex-col items-center py-4 gap-2">
          <button className="w-10 h-10 flex items-center justify-center rounded-full hover:bg-gray-100 transition-colors">
            <Mail className="w-5 h-5 text-gray-600" />
          </button>
        </aside>

        {/* Main Content */}
        <main className="flex-1 flex flex-col overflow-hidden bg-white">
          {/* Toolbar */}
          <div className="px-4 py-2 border-b border-gray-200 flex items-center gap-4">
            <div className="flex items-center gap-2">
              <button 
                onClick={toggleSelectAll}
                className="p-2 hover:bg-gray-100 rounded transition-colors"
              >
                <Square className={`w-5 h-5 ${selectAll ? 'fill-blue-600 text-blue-600' : 'text-gray-600'}`} />
              </button>
              <button className="p-2 hover:bg-gray-100 rounded transition-colors">
                <Archive className="w-5 h-5 text-gray-600" />
              </button>
              <button className="p-2 hover:bg-gray-100 rounded transition-colors">
                <Trash2 className="w-5 h-5 text-gray-600" />
              </button>
              <button className="p-2 hover:bg-gray-100 rounded transition-colors">
                <RefreshCw className="w-5 h-5 text-gray-600" />
              </button>
            </div>

            <div className="ml-auto flex items-center gap-2 text-sm text-gray-600">
              <span>1-{emails.length} of {emails.length}</span>
            </div>
          </div>

          {/* Email List */}
          <div className="flex-1 overflow-y-auto">
            {/* Category Tabs */}
            <div className="flex items-center gap-6 px-4 pt-3 pb-2 border-b border-gray-200 bg-white sticky top-0 z-10">
              <button className="flex items-center gap-2 pb-2 border-b-2 border-blue-600 text-blue-600 text-sm font-medium">
                <Mail className="w-4 h-4" />
                Primary
              </button>
              <button className="flex items-center gap-2 pb-2 text-gray-600 text-sm hover:text-gray-900">
                Social
              </button>
              <button className="flex items-center gap-2 pb-2 text-gray-600 text-sm hover:text-gray-900">
                Promotions
              </button>
            </div>

            {/* Email Rows */}
            <div className="divide-y divide-gray-200">
              {emails.map((email, index) => (
                <motion.div
                  key={email.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  onClick={() => {
                    if (onOpenInvestigation) {
                      onOpenInvestigation(email.investigationId || (email.id === "1" ? "INV-2026-9041" : email.id === "2" ? "INV-2026-8812" : "SS-2026-0912-00421"));
                    }
                  }}
                  className={`group flex items-center gap-2 px-4 py-2 hover:shadow-[inset_1px_0_0_#dadce0,inset_-1px_0_0_#dadce0,0_1px_2px_0_rgba(60,64,67,0.3),0_1px_3px_1px_rgba(60,64,67,0.15)] cursor-pointer transition-all ${
                    email.selected ? 'bg-blue-50' : 'bg-white'
                  } ${email.unread ? 'font-medium' : 'font-normal'}`}
                >
                  {/* Checkbox */}
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleSelect(email.id);
                    }}
                    className="flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
                  >
                    <Square className={`w-5 h-5 ${email.selected ? 'fill-blue-600 text-blue-600' : 'text-gray-400'}`} />
                  </button>

                  {/* Star */}
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleStar(email.id);
                    }}
                    className="flex-shrink-0"
                  >
                    <Star className={`w-5 h-5 transition-colors ${
                      email.starred 
                        ? 'fill-yellow-400 text-yellow-400' 
                        : 'text-gray-400 hover:text-gray-600'
                    }`} />
                  </button>

                  {/* Sender */}
                  <div className="w-48 flex-shrink-0 truncate">
                    <span className={`text-sm ${email.unread ? 'text-gray-900' : 'text-gray-600'}`}>
                      {email.sender}
                    </span>
                  </div>

                  {/* Subject + Risk Badge */}
                  <div className="flex-1 min-w-0 flex items-center">
                    <span className={`text-sm truncate ${email.unread ? 'text-gray-900' : 'text-gray-600'}`}>
                      {email.subject}
                    </span>
                    <RiskBadge level={email.riskLevel} score={email.riskScore} />
                    <span className="mx-2 text-gray-400">—</span>
                    <span className="text-sm text-gray-500 truncate flex-1">
                      {email.snippet}
                    </span>
                  </div>

                  {/* Time & Quick Investigate Action */}
                  <div className="flex-shrink-0 text-right flex items-center justify-end gap-2 min-w-[110px]">
                    {onOpenInvestigation && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onOpenInvestigation(email.investigationId || (email.id === "1" ? "INV-2026-9041" : email.id === "2" ? "INV-2026-8812" : "SS-2026-0912-00421"));
                        }}
                        className="hidden group-hover:inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-cyan-700 text-white hover:bg-cyan-800 shadow-sm"
                        title="Analyze email in SpectraShield Security Investigation"
                      >
                        <ShieldAlert className="w-3 h-3" />
                        <span>Investigate</span>
                      </button>
                    )}
                    <span className="text-xs text-gray-500 group-hover:hidden">
                      {email.time}
                    </span>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </main>
      </div>

      {/* SpectraShield Branding Footer */}
      <div className="bg-gradient-to-r from-[#0B1120] to-[#1a1f35] px-6 py-3 border-t border-indigo-900/30 flex items-center justify-between">
        <div className="flex items-center gap-2 text-emerald-400">
          <ShieldAlert className="w-4 h-4" />
          <span className="text-sm font-semibold">SpectraShield AI Active</span>
        </div>
        <span className="text-xs text-slate-400">
          Protecting {emails.length} emails • {emails.filter(e => e.riskLevel === 'high').length} high risk detected
        </span>
      </div>
    </div>
  );
};

export default GmailDemo;