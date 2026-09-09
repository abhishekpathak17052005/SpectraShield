import React, { useState } from "react";
import { motion } from "motion/react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Bell,
  Mail,
  Lock,
  Eye,
  Settings,
} from "lucide-react";

const StyleGuide: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"colors" | "typography" | "buttons" | "cards" | "alerts" | "icons">("colors");

  return (
    <div className="w-full min-h-screen bg-background text-foreground p-8 transition-colors duration-300">
      {/* Header */}
      <div className="max-w-7xl mx-auto mb-12">
        <div className="flex items-center gap-4 mb-6">
          <div className="relative">
            <div className="absolute inset-0 bg-safe/30 blur-xl rounded-full" />
            <Shield className="w-12 h-12 text-safe relative z-10" />
          </div>
          <div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-foreground via-primary to-muted-foreground bg-clip-text text-transparent">
              SpectraShield AI Style Guide
            </h1>
            <p className="text-muted-foreground mt-1">Design system for high-tech security interfaces</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex gap-2 bg-muted/50 border border-border rounded-xl p-1 backdrop-blur-sm">
          {(["colors", "typography", "buttons", "cards", "alerts", "icons"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all capitalize ${
                activeTab === tab
                  ? "bg-primary/10 text-primary border border-primary/20"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      <div className="max-w-7xl mx-auto">
        {/* Colors Section */}
        {activeTab === "colors" && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8"
          >
            <div>
              <h2 className="text-2xl font-bold mb-6 text-foreground">Color Palette</h2>

              {/* Semantic Colors */}
              <div className="mb-8">
                <h3 className="text-lg font-semibold text-foreground/80 mb-4">Semantic Colors</h3>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-card border border-border rounded-xl p-6 backdrop-blur-sm">
                    <div className="w-full h-24 rounded-lg bg-background border border-border mb-4"></div>
                    <div className="text-sm font-mono text-muted-foreground">--background</div>
                    <div className="text-xs text-muted-foreground mt-1">App Background</div>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-6 backdrop-blur-sm">
                    <div className="w-full h-24 rounded-lg bg-card border border-border mb-4"></div>
                    <div className="text-sm font-mono text-muted-foreground">--card</div>
                    <div className="text-xs text-muted-foreground mt-1">Card Background</div>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-6 backdrop-blur-sm">
                    <div className="w-full h-24 rounded-lg bg-primary border border-border mb-4"></div>
                    <div className="text-sm font-mono text-muted-foreground">--primary</div>
                    <div className="text-xs text-muted-foreground mt-1">Primary Brand</div>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-6 backdrop-blur-sm">
                    <div className="w-full h-24 rounded-lg bg-secondary border border-border mb-4"></div>
                    <div className="text-sm font-mono text-muted-foreground">--secondary</div>
                    <div className="text-xs text-muted-foreground mt-1">Secondary Brand</div>
                  </div>
                </div>
              </div>

              {/* Status Colors */}
              <div className="mb-8">
                <h3 className="text-lg font-semibold text-foreground/80 mb-4">Status Colors</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-card border border-border rounded-xl p-6 backdrop-blur-sm">
                    <div className="w-full h-24 rounded-lg bg-safe mb-4 flex items-center justify-center">
                      <CheckCircle className="w-12 h-12 text-background" />
                    </div>
                    <div className="text-sm font-mono text-safe">--safe</div>
                    <div className="text-xs text-muted-foreground mt-1">Safe State</div>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-6 backdrop-blur-sm">
                    <div className="w-full h-24 rounded-lg bg-warning mb-4 flex items-center justify-center">
                      <AlertTriangle className="w-12 h-12 text-background" />
                    </div>
                    <div className="text-sm font-mono text-warning">--warning</div>
                    <div className="text-xs text-muted-foreground mt-1">Warning State</div>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-6 backdrop-blur-sm">
                    <div className="w-full h-24 rounded-lg bg-destructive mb-4 flex items-center justify-center">
                      <XCircle className="w-12 h-12 text-destructive-foreground" />
                    </div>
                    <div className="text-sm font-mono text-destructive">--destructive</div>
                    <div className="text-xs text-muted-foreground mt-1">Danger State</div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Typography Section */}
        {activeTab === "typography" && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8"
          >
            <div>
              <h2 className="text-2xl font-bold mb-6 text-foreground">Typography</h2>
              
              <div className="space-y-6 bg-card border border-border rounded-xl p-6 backdrop-blur-sm">
                <div>
                  <h1 className="text-4xl font-bold text-foreground mb-2">H1 Heading</h1>
                  <div className="text-xs text-muted-foreground font-mono">text-4xl · font-bold</div>
                </div>
                <div>
                  <h2 className="text-3xl font-bold text-foreground mb-2">H2 Heading</h2>
                  <div className="text-xs text-muted-foreground font-mono">text-3xl · font-bold</div>
                </div>
                <div>
                  <h3 className="text-2xl font-semibold text-foreground mb-2">H3 Heading</h3>
                  <div className="text-xs text-muted-foreground font-mono">text-2xl · font-semibold</div>
                </div>
                <div>
                  <p className="text-base text-foreground mb-1">Body Text (Foreground)</p>
                  <div className="text-xs text-muted-foreground font-mono">text-base</div>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Muted Text</p>
                  <div className="text-xs text-muted-foreground font-mono">text-sm · text-muted-foreground</div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Buttons Section */}
        {activeTab === "buttons" && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8"
          >
            <div>
              <h2 className="text-2xl font-bold mb-6 text-foreground">Button Styles</h2>

              {/* Primary Buttons */}
              <div className="mb-8">
                <h3 className="text-lg font-semibold text-foreground/80 mb-4">Solid Buttons</h3>
                <div className="bg-card border border-border rounded-xl p-6 backdrop-blur-sm space-y-4">
                  <div className="flex flex-wrap gap-4 items-center">
                    <button className="px-6 py-3 bg-safe text-safe-foreground font-semibold rounded-xl transition-all hover:opacity-90 flex items-center gap-2">
                      <CheckCircle className="w-5 h-5" />
                      Safe Action
                    </button>
                    <button className="px-6 py-3 bg-warning text-warning-foreground font-semibold rounded-xl transition-all hover:opacity-90 flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5" />
                      Warning Action
                    </button>
                    <button className="px-6 py-3 bg-destructive text-destructive-foreground font-semibold rounded-xl transition-all hover:opacity-90 flex items-center gap-2">
                      <XCircle className="w-5 h-5" />
                      Danger Action
                    </button>
                  </div>
                </div>
              </div>

              {/* Secondary Buttons */}
              <div className="mb-8">
                <h3 className="text-lg font-semibold text-foreground/80 mb-4">Outline/Secondary Buttons</h3>
                <div className="bg-card border border-border rounded-xl p-6 backdrop-blur-sm space-y-4">
                  <div className="flex flex-wrap gap-4 items-center">
                    <button className="px-6 py-3 bg-safe/10 border-2 border-safe/30 text-safe font-semibold rounded-xl transition-all hover:bg-safe/20">
                      Safe Secondary
                    </button>
                    <button className="px-6 py-3 bg-warning/10 border-2 border-warning/30 text-warning font-semibold rounded-xl transition-all hover:bg-warning/20">
                      Warning Secondary
                    </button>
                    <button className="px-6 py-3 bg-destructive/10 border-2 border-destructive/30 text-destructive font-semibold rounded-xl transition-all hover:bg-destructive/20">
                      Danger Secondary
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Cards Section */}
        {activeTab === "cards" && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8"
          >
            <div>
              <h2 className="text-2xl font-bold mb-6 text-foreground">Cards</h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="relative bg-card border border-safe/30 rounded-xl p-6 backdrop-blur-sm overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-safe/5 to-transparent" />
                  <div className="relative z-10">
                    <CheckCircle className="w-8 h-8 text-safe mb-3" />
                    <h4 className="text-lg font-semibold text-foreground mb-2">Safe Status</h4>
                    <p className="text-sm text-muted-foreground">No threats detected</p>
                  </div>
                </div>

                <div className="relative bg-card border border-warning/30 rounded-xl p-6 backdrop-blur-sm overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-warning/5 to-transparent" />
                  <div className="relative z-10">
                    <AlertTriangle className="w-8 h-8 text-warning mb-3" />
                    <h4 className="text-lg font-semibold text-foreground mb-2">Warning Status</h4>
                    <p className="text-sm text-muted-foreground">Requires attention</p>
                  </div>
                </div>

                <div className="relative bg-card border border-destructive/30 rounded-xl p-6 backdrop-blur-sm overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-destructive/5 to-transparent" />
                  <div className="relative z-10">
                    <XCircle className="w-8 h-8 text-destructive mb-3" />
                    <h4 className="text-lg font-semibold text-foreground mb-2">Danger Status</h4>
                    <p className="text-sm text-muted-foreground">Critical threat</p>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default StyleGuide;