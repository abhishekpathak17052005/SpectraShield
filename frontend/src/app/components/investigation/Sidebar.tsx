import React from "react";
import { motion } from "motion/react";
import { useTheme } from "next-themes";
import {
  ShieldCheck,
  LayoutDashboard,
  Crosshair,
  Radio,
  Layers,
  Shield,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Moon,
  Sun,
  MailCheck,
  Puzzle,
} from "lucide-react";

export type NavItemKey =
  | "overview"
  | "investigations"
  | "email_intelligence"
  | "mail_intelligence"
  | "threat_intelligence"
  | "forensics"
  | "evidence"
  | "reports"
  | "settings"
  | "extension";

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
  activeItem?: NavItemKey;
  onSelectItem?: (item: NavItemKey) => void;
}

interface NavSection {
  title?: string;
  items: Array<{
    key: NavItemKey;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string;
  }>;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed,
  onToggleCollapse,
  activeItem = "investigations",
  onSelectItem,
}) => {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = React.useState(false);
  const [selectedNav, setSelectedNav] = React.useState<NavItemKey>(activeItem);

  React.useEffect(() => {
    setSelectedNav(activeItem);
  }, [activeItem]);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  const navSections: NavSection[] = [
    {
      title: "Command Center",
      items: [
        { key: "overview", label: "Overview", icon: LayoutDashboard },
        { key: "investigations", label: "Investigations", icon: Crosshair },
      ],
    },
    {
      title: "Email Security",
      items: [
        { key: "email_intelligence", label: "Email Intelligence", icon: MailCheck },
      ],
    },
    {
      title: "Threat Analysis",
      items: [
        { key: "threat_intelligence", label: "Threat Intelligence", icon: Radio },
        { key: "forensics", label: "Forensic Intelligence", icon: Layers },
        { key: "evidence", label: "Evidence", icon: Shield },
      ],
    },
    {
      title: "System",
      items: [
        { key: "reports", label: "Reports", icon: FileText },
        { key: "settings", label: "Settings", icon: Settings },
      ],
    },
    {
      title: "Deployment",
      items: [
        { key: "extension", label: "Browser Extension", icon: Puzzle, badge: "GET" },
      ],
    },
  ];

  return (
    <motion.aside
      animate={{ width: collapsed ? 72 : 248 }}
      transition={{ duration: 0.25, ease: "easeInOut" }}
      className="h-screen sticky top-0 left-0 self-start flex flex-col justify-between border-r z-30 select-none flex-shrink-0 bg-sidebar-background border-sidebar-border"
    >
      {/* Top Section: Logo & Toggle */}
      <div>
        <div className="h-16 flex items-center justify-between px-4 border-b border-sidebar-border">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="relative flex-shrink-0 w-9 h-9 rounded-xl bg-accent/20 border border-accent/40 flex items-center justify-center shadow-lg shadow-accent/10">
              <ShieldCheck className="w-5 h-5 text-accent" />
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-success animate-ping opacity-75" />
            </div>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }}
                className="leading-tight truncate"
              >
                <div className="text-xs font-bold tracking-wider text-sidebar-foreground uppercase flex items-center gap-1">
                  <span>Spectra</span>
                  <span className="text-accent">Shield</span>
                </div>
                <div className="text-[10px] text-text-muted tracking-wider uppercase font-medium">
                  SOC Security Platform
                </div>
              </motion.div>
            )}
          </div>

          <button
            onClick={onToggleCollapse}
            className="p-1.5 rounded-lg text-text-muted hover:text-accent hover:bg-accent/10 border border-transparent hover:border-accent/20 transition-colors"
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Sections */}
        <nav className="p-2 space-y-3 mt-1 overflow-y-auto max-h-[calc(100vh-170px)] custom-scrollbar">
          {navSections.map((section, sIdx) => (
            <div key={section.title || sIdx} className="space-y-1">
              {/* Section Header */}
              {!collapsed ? (
                <div className="px-2.5 pt-1.5 pb-1 text-[10px] font-semibold tracking-wider text-text-muted uppercase">
                  <span>{section.title}</span>
                </div>
              ) : (
                sIdx > 0 && <div className="my-1.5 mx-2 border-t border-sidebar-border" />
              )}

              {/* Section Items */}
              {section.items.map((item) => {
                const Icon = item.icon;
                const effectiveActive = selectedNav || activeItem;
                const isActive =
                  effectiveActive === item.key ||
                  ((item.key === "email_intelligence" || item.key === "mail_intelligence") &&
                    (effectiveActive === "email_intelligence" || effectiveActive === "mail_intelligence"));

                return (
                  <button
                    key={item.key}
                    onClick={() => {
                      setSelectedNav(item.key);
                      onSelectItem?.(item.key);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all relative group overflow-hidden border ${
                      isActive
                        ? "text-sidebar-active-foreground border-accent/30 shadow-[0_0_16px_rgba(6,182,212,0.08)]"
                        : "text-text-muted hover:text-text-secondary hover:bg-sidebar-hover border-transparent"
                    }`}
                    title={collapsed ? item.label : undefined}
                  >
                    {/* Animated Active Background & Left Indicator */}
                    {isActive && (
                      <motion.div
                        layoutId="active-nav-indicator"
                        transition={{ type: "spring", stiffness: 450, damping: 35 }}
                        className="absolute inset-0 bg-sidebar-active pointer-events-none rounded-lg"
                      >
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 rounded-r bg-accent shadow-[0_0_8px_rgba(6,182,212,0.9)]" />
                      </motion.div>
                    )}
                    <Icon
                      className={`w-4 h-4 flex-shrink-0 transition-transform duration-150 group-hover:scale-110 relative z-10 ${
                        isActive ? "text-accent" : "text-text-muted group-hover:text-accent"
                      }`}
                    />
                    {!collapsed && (
                      <div className="flex-1 flex items-center justify-between truncate relative z-10 group-hover:translate-x-0.5 transition-transform duration-150">
                        <span className="truncate">{item.label}</span>
                        {item.badge && (
                          <span
                            className={`text-[9px] font-mono px-1.5 py-0.5 rounded tracking-widest font-bold ${
                              item.badge === "ACTIVE"
                                ? "bg-accent/20 text-accent border border-accent/40"
                                : item.badge === "LIVE"
                                ? "bg-success/20 text-success border border-success/40"
                                : "bg-info/20 text-info border border-info/40"
                            }`}
                          >
                            {item.badge}
                          </span>
                        )}
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </div>

      {/* Bottom Section: Theme Toggle & User Profile */}
      <div className="p-3 border-t border-sidebar-border space-y-3">
        {/* Theme Toggle */}
        {mounted && (
          <div
            className={`flex items-center gap-2 p-2 rounded-xl border border-sidebar-border transition-all bg-surface-muted/30 ${
              collapsed ? "justify-center" : ""
            }`}
          >
            {!collapsed && (
              <span className="text-[10px] text-text-muted font-semibold uppercase tracking-wider flex-1">
                Theme
              </span>
            )}
            <div className="flex items-center gap-1 p-1 rounded-lg bg-surface-elevated border border-border">
              <button
                onClick={() => setTheme("light")}
                className={`p-1.5 rounded-md transition-all ${
                  theme === "light"
                    ? "bg-accent/20 text-accent border border-accent/40"
                    : "text-text-muted hover:text-accent hover:bg-surface-hover"
                }`}
                title="Light mode"
                aria-label="Light mode"
              >
                <Sun className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setTheme("dark")}
                className={`p-1.5 rounded-md transition-all ${
                  theme === "dark"
                    ? "bg-accent/20 text-accent border border-accent/40"
                    : "text-text-muted hover:text-accent hover:bg-surface-hover"
                }`}
                title="Dark mode"
                aria-label="Dark mode"
              >
                <Moon className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* User Profile */}
        <div
          className={`flex items-center gap-2.5 p-2 rounded-xl border border-sidebar-border transition-all bg-surface-muted/30 ${
            collapsed ? "justify-center" : ""
          }`}
        >
          <div className="relative w-8 h-8 rounded-lg bg-gradient-to-tr from-accent to-info flex items-center justify-center font-bold text-xs text-accent-foreground shadow">
            AM
            <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-success border-2 border-background" />
          </div>
          {!collapsed && (
            <div className="truncate leading-tight flex-1">
              <div className="text-xs font-semibold text-text-primary truncate">Alex Mercer</div>
              <div className="text-[10px] text-text-secondary font-mono truncate">
                Senior SOC Analyst
              </div>
            </div>
          )}
        </div>
      </div>
    </motion.aside>
  );
};
