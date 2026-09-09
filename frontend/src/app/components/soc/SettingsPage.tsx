import React, { useEffect, useState } from "react";
import { SocLayout } from "./SocLayout";
import {
  RefreshCw,
  Server,
  Radio,
  User,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  Zap,
  Database,
  Key,
  CheckCircle2,
  AlertCircle,
  Eye,
  EyeOff,
  X,
  Globe,
  Lock,
} from "lucide-react";
import {
  getApiBase,
  getMe,
  UserProfile,
  getSystemIntegrations,
  testIntegration,
  syncOpenPhishFeed,
  updateIntegrationKey,
  SystemIntegrationsResponse,
} from "../../api";
import { Button, Badge } from "../ui";

interface Props {
  onNavigate: (route: string) => void;
}

interface TestState {
  loading: boolean;
  success?: boolean;
  latency_ms?: number;
  message?: string;
}

export const SettingsPage: React.FC<Props> = ({ onNavigate }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [health, setHealth] = useState<{
    status: string;
    service?: string;
    version?: string;
  } | null>(null);
  const [integrations, setIntegrations] = useState<SystemIntegrationsResponse | null>(null);
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);

  // Per-service test state
  const [testStates, setTestStates] = useState<Record<string, TestState>>({});

  // OpenPhish feed sync state
  const [syncingFeed, setSyncingFeed] = useState<boolean>(false);
  const [syncFeedMessage, setSyncFeedMessage] = useState<string | null>(null);

  // Modal for key editing
  const [keyModal, setKeyModal] = useState<{
    open: boolean;
    service: string;
    name: string;
    currentKeyMasked?: string | null;
  } | null>(null);
  const [inputKey, setInputKey] = useState<string>("");
  const [showKeyText, setShowKeyText] = useState<boolean>(false);
  const [savingKey, setSavingKey] = useState<boolean>(false);
  const [keyModalError, setKeyModalError] = useState<string | null>(null);
  const [keyModalSuccess, setKeyModalSuccess] = useState<string | null>(null);

  const checkStatus = async () => {
    setLoading(true);
    try {
      const [hRes, uRes, intRes] = await Promise.allSettled([
        fetch(`${getApiBase()}/health`).then((r) => (r.ok ? r.json() : null)),
        getMe(),
        getSystemIntegrations(),
      ]);

      if (hRes.status === "fulfilled") setHealth(hRes.value);
      if (uRes.status === "fulfilled") setUserProfile(uRes.value);
      if (intRes.status === "fulfilled") setIntegrations(intRes.value);
    } catch (err) {
      console.error("Settings status check error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkStatus();
  }, []);

  const handleTestService = async (serviceId: string) => {
    setTestStates((prev) => ({
      ...prev,
      [serviceId]: { loading: true },
    }));

    try {
      const result = await testIntegration(serviceId);
      setTestStates((prev) => ({
        ...prev,
        [serviceId]: {
          loading: false,
          success: result.success,
          latency_ms: result.latency_ms,
          message: result.message,
        },
      }));
      // Auto-clear message after 8 seconds
      setTimeout(() => {
        setTestStates((prev) => {
          if (!prev[serviceId]) return prev;
          const updated = { ...prev };
          delete updated[serviceId];
          return updated;
        });
      }, 8000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Connection test failed";
      setTestStates((prev) => ({
        ...prev,
        [serviceId]: {
          loading: false,
          success: false,
          message: msg,
        },
      }));
    }
  };

  const handleSyncOpenPhish = async () => {
    setSyncingFeed(true);
    setSyncFeedMessage(null);
    try {
      const res = await syncOpenPhishFeed();
      setSyncFeedMessage(res.message);
      // Refresh integration metrics
      const fresh = await getSystemIntegrations().catch(() => null);
      if (fresh) setIntegrations(fresh);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Feed synchronization failed";
      setSyncFeedMessage(msg);
    } finally {
      setSyncingFeed(false);
      setTimeout(() => setSyncFeedMessage(null), 8000);
    }
  };

  const handleOpenKeyModal = (service: string, name: string, currentMasked?: string | null) => {
    setKeyModal({
      open: true,
      service,
      name,
      currentKeyMasked,
    });
    setInputKey("");
    setShowKeyText(false);
    setKeyModalError(null);
    setKeyModalSuccess(null);
  };

  const handleSaveKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyModal || !inputKey.trim()) return;

    setSavingKey(true);
    setKeyModalError(null);
    setKeyModalSuccess(null);

    try {
      const res = await updateIntegrationKey(keyModal.service, inputKey.trim());
      setKeyModalSuccess(res.message);
      // Refresh integrations data immediately
      const fresh = await getSystemIntegrations().catch(() => null);
      if (fresh) setIntegrations(fresh);

      // Automatically test connection with the new key!
      handleTestService(keyModal.service);

      setTimeout(() => {
        setKeyModal(null);
      }, 1500);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to update API key";
      setKeyModalError(msg);
    } finally {
      setSavingKey(false);
    }
  };

  const isHealthy = health?.status === "healthy";
  const dbConfig = integrations?.database;
  const isDbConnected = dbConfig?.is_connected ?? isHealthy;

  return (
    <SocLayout
      activeNav="settings"
      onNavigate={onNavigate}
      title="Settings & Integrations"
      subtitle="Operational health, live telemetry feeds, and threat intelligence configuration"
      actions={
        <Button
          onClick={checkStatus}
          disabled={loading}
          variant="ghost"
          size="sm"
          className="flex items-center gap-1.5"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-accent" : ""}`} />
          <span>Refresh Feeds</span>
        </Button>
      }
    >
      <div className="space-y-6">
        {/* ─── 1. CORE SYSTEM SERVICES ────────────────────────────────────────── */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-accent" />
              <h2 className="text-sm font-semibold text-foreground tracking-tight">
                Core System Services
              </h2>
            </div>
            <span className="text-[11px] text-text-muted font-mono">
              Engine: {health?.version || "2.0.0-phase3"}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {/* Backend API */}
            <div className="p-4 rounded-xl border border-border bg-surface-elevated space-y-2 hover:border-border transition-colors">
              <div className="flex items-center justify-between">
                <span className="text-xs text-text-secondary font-medium">FastAPI Gateway</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface text-text-secondary font-mono">HTTP/200</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  {isHealthy && (
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
                  )}
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${isHealthy ? "bg-success" : "bg-danger"}`} />
                </span>
                <span className="text-sm font-medium text-foreground">
                  {isHealthy ? "Connected" : "Unavailable"}
                </span>
              </div>
              <div className="text-[11px] text-text-muted flex items-center justify-between pt-1 border-t border-border">
                <span>Port 8000</span>
                <span className="text-success font-mono">Live</span>
              </div>
            </div>

            {/* Detection Engine */}
            <div className="p-4 rounded-xl border border-border bg-surface-elevated space-y-2 hover:border-border transition-colors">
              <div className="flex items-center justify-between">
                <span className="text-xs text-text-secondary font-medium">Consensus Pipeline</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent font-mono">5 Engines</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-accent" />
                </span>
                <span className="text-sm font-medium text-foreground">
                  Consensus Active
                </span>
              </div>
              <div className="text-[11px] text-text-muted flex items-center justify-between pt-1 border-t border-border">
                <span>NLP + CTI + Brand</span>
                <span className="text-accent font-mono">Online</span>
              </div>
            </div>

            {/* Database */}
            <div className="p-4 rounded-xl border border-border bg-surface-elevated space-y-2 hover:border-border transition-colors">
              <div className="flex items-center justify-between">
                <span className="text-xs text-text-secondary font-medium">Database Vault</span>
                <button
                  onClick={() => handleTestService("database")}
                  disabled={testStates["database"]?.loading}
                  className="text-[10px] px-1.5 py-0.5 rounded bg-surface hover:bg-surface-elevated text-text-secondary hover:text-foreground transition-colors flex items-center gap-1"
                >
                  <RefreshCw className={`w-2.5 h-2.5 ${testStates["database"]?.loading ? "animate-spin text-accent" : ""}`} />
                  <span>Ping</span>
                </button>
              </div>
              <div className="flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  {isDbConnected && (
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
                  )}
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${isDbConnected ? "bg-success" : "bg-warning"}`} />
                </span>
                <span className="text-sm font-medium text-foreground truncate">
                  {dbConfig?.provider || (isDbConnected ? "Supabase (PostgreSQL)" : "In-Memory Vault")}
                </span>
              </div>
              <div className="text-[11px] text-text-muted flex items-center justify-between pt-1 border-t border-border">
                <span>{dbConfig?.records_count !== undefined ? `${dbConfig.records_count} Incident Scans` : "Incident datastore"}</span>
                {testStates["database"]?.latency_ms !== undefined ? (
                  <span className="text-success font-mono">{testStates["database"].latency_ms}ms</span>
                ) : (
                  <span className="text-success font-mono">Connected</span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* ─── 2. THREAT INTELLIGENCE FEEDS ───────────────────────────────────── */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-success" />
              <h2 className="text-sm font-semibold text-foreground tracking-tight">
                Threat Intelligence Integrations
              </h2>
            </div>
            {syncFeedMessage && (
              <span className="text-xs text-success bg-success/10 border border-success/30 px-2.5 py-0.5 rounded-full animate-fade-in">
                {syncFeedMessage}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* 1. VirusTotal */}
            {(() => {
              const vt = integrations?.virustotal;
              const isConfigured = vt ? vt.configured : false;
              const testState = testStates["virustotal"];
              return (
                <div className="p-4 rounded-xl border border-border bg-surface-elevated flex flex-col justify-between space-y-3 hover:border-border transition-all shadow-sm">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs text-text-secondary font-medium">VirusTotal</span>
                      <Badge variant="accent" className="text-[10px]">
                        Multi-AV
                      </Badge>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="relative flex h-2 w-2">
                        {isConfigured && (
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
                        )}
                        <span className={`relative inline-flex rounded-full h-2 w-2 ${isConfigured ? "bg-success" : "bg-text-muted"}`} />
                      </span>
                      <span className={`text-sm font-medium ${isConfigured ? "text-foreground" : "text-text-secondary"}`}>
                        {isConfigured ? "Connected" : "Not Configured"}
                      </span>
                    </div>

                    <p className="text-[11px] text-text-muted mt-1 line-clamp-1">
                      {vt?.description || "Antivirus heuristics & URL telemetry"}
                    </p>

                    <div className="mt-2.5 space-y-1 text-[11px] font-mono bg-surface p-2 rounded-lg border border-border">
                      <div className="flex justify-between text-text-secondary">
                        <span>Cached URLs:</span>
                        <span className="text-foreground font-semibold">{vt?.cache_entries ?? "—"}</span>
                      </div>
                      <div className="flex justify-between text-text-secondary">
                        <span>Key:</span>
                        <span className="text-accent truncate max-w-[110px]" title={vt?.key_masked || undefined}>
                          {vt?.key_masked ? vt.key_masked.slice(0, 12) + "…" : "None"}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="pt-2 border-t border-border space-y-2">
                    {testState && (
                      <div className={`text-[10px] px-2 py-1 rounded flex items-center gap-1.5 ${
                        testState.loading
                          ? "bg-surface text-text-secondary"
                          : testState.success
                          ? "bg-success/10 text-success border border-success/30"
                          : "bg-danger/10 text-danger border border-danger/30"
                      }`}>
                        {testState.loading ? (
                          <RefreshCw className="w-3 h-3 animate-spin text-accent" />
                        ) : testState.success ? (
                          <CheckCircle2 className="w-3 h-3 text-success shrink-0" />
                        ) : (
                          <AlertCircle className="w-3 h-3 text-danger shrink-0" />
                        )}
                        <span className="truncate">
                          {testState.loading ? "Testing..." : testState.success ? `Operational (${testState.latency_ms}ms)` : testState.message}
                        </span>
                      </div>
                    )}

                    <div className="flex items-center gap-1.5">
                      <Button
                        onClick={() => handleTestService("virustotal")}
                        disabled={testState?.loading}
                        variant="secondary"
                        size="sm"
                        className="flex-1 flex items-center justify-center gap-1 text-[11px]"
                      >
                        <Zap className="w-3 h-3" />
                        <span>Test Ping</span>
                      </Button>
                      <Button
                        onClick={() => handleOpenKeyModal("virustotal", "VirusTotal", vt?.key_masked)}
                        variant="ghost"
                        size="sm"
                        className="px-2 text-[11px]"
                        title="Configure API Key"
                      >
                        <Key className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* 2. OpenPhish */}
            {(() => {
              const op = integrations?.openphish;
              const isConfigured = op ? op.configured : true;
              const testState = testStates["openphish"];
              return (
                <div className="p-4 rounded-xl border border-border bg-surface-elevated flex flex-col justify-between space-y-3 hover:border-border transition-all shadow-sm">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs text-text-secondary font-medium">OpenPhish</span>
                      <Badge variant="success" className="text-[10px]">
                        Zero-Day Feed
                      </Badge>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="relative flex h-2 w-2">
                        {isConfigured && (
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
                        )}
                        <span className={`relative inline-flex rounded-full h-2 w-2 ${isConfigured ? "bg-success" : "bg-text-muted"}`} />
                      </span>
                      <span className={`text-sm font-medium ${isConfigured ? "text-foreground" : "text-text-secondary"}`}>
                        {isConfigured ? "Connected" : "Not Configured"}
                      </span>
                    </div>

                    <p className="text-[11px] text-text-muted mt-1 line-clamp-1">
                      {op?.description || "Live zero-day targeted phishing URL telemetry"}
                    </p>

                    <div className="mt-2.5 space-y-1 text-[11px] font-mono bg-surface p-2 rounded-lg border border-border">
                      <div className="flex justify-between text-text-secondary">
                        <span>Active Indicators:</span>
                        <span className="text-success font-semibold">{op?.indicators_count?.toLocaleString() ?? "—"}</span>
                      </div>
                      <div className="flex justify-between text-text-secondary">
                        <span>Feed Sync:</span>
                        <span className="text-foreground truncate max-w-[110px]">24h Automated</span>
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="pt-2 border-t border-border space-y-2">
                    {testState && (
                      <div className={`text-[10px] px-2 py-1 rounded flex items-center gap-1.5 ${
                        testState.loading
                          ? "bg-surface text-text-secondary"
                          : testState.success
                          ? "bg-success/10 text-success border border-success/30"
                          : "bg-danger/10 text-danger border border-danger/30"
                      }`}>
                        {testState.loading ? (
                          <RefreshCw className="w-3 h-3 animate-spin text-accent" />
                        ) : testState.success ? (
                          <CheckCircle2 className="w-3 h-3 text-success shrink-0" />
                        ) : (
                          <AlertCircle className="w-3 h-3 text-danger shrink-0" />
                        )}
                        <span className="truncate">
                          {testState.loading ? "Testing..." : testState.success ? `Feed Active (${testState.latency_ms}ms)` : testState.message}
                        </span>
                      </div>
                    )}

                    <div className="flex items-center gap-1.5">
                      <Button
                        onClick={() => handleTestService("openphish")}
                        disabled={testState?.loading}
                        variant="secondary"
                        size="sm"
                        className="flex-1 flex items-center justify-center gap-1 text-[11px]"
                      >
                        <Zap className="w-3 h-3" />
                        <span>Test Feed</span>
                      </Button>
                      <Button
                        onClick={handleSyncOpenPhish}
                        disabled={syncingFeed}
                        variant="success"
                        size="sm"
                        className="flex items-center gap-1 text-[11px]"
                        title="Force sync now"
                      >
                        <RefreshCw className={`w-3 h-3 ${syncingFeed ? "animate-spin" : ""}`} />
                        <span>Sync</span>
                      </Button>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* 3. Google Safe Browsing */}
            {(() => {
              const gsb = integrations?.google_safe_browsing;
              const isConfigured = gsb ? gsb.configured : false;
              const testState = testStates["google_safe_browsing"];
              return (
                <div className="p-4 rounded-xl border border-border bg-surface-elevated flex flex-col justify-between space-y-3 hover:border-border transition-all shadow-sm">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs text-text-secondary font-medium">Safe Browsing</span>
                      <Badge variant="warning" className="text-[10px]">
                        Google v4
                      </Badge>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="relative flex h-2 w-2">
                        {isConfigured && (
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
                        )}
                        <span className={`relative inline-flex rounded-full h-2 w-2 ${isConfigured ? "bg-success" : "bg-text-muted"}`} />
                      </span>
                      <span className={`text-sm font-medium ${isConfigured ? "text-foreground" : "text-text-secondary"}`}>
                        {isConfigured ? "Connected" : "Not Configured"}
                      </span>
                    </div>

                    <p className="text-[11px] text-text-muted mt-1 line-clamp-1">
                      {gsb?.description || "Google web reputation & phishing classifier"}
                    </p>

                    <div className="mt-2.5 space-y-1 text-[11px] font-mono bg-surface p-2 rounded-lg border border-border">
                      <div className="flex justify-between text-text-secondary">
                        <span>API Quota:</span>
                        <span className="text-foreground font-semibold">10,000 / day</span>
                      </div>
                      <div className="flex justify-between text-text-secondary">
                        <span>Key:</span>
                        <span className="text-accent truncate max-w-[110px]" title={gsb?.key_masked || undefined}>
                          {gsb?.key_masked ? gsb.key_masked.slice(0, 12) + "…" : "None"}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="pt-2 border-t border-border space-y-2">
                    {testState && (
                      <div className={`text-[10px] px-2 py-1 rounded flex items-center gap-1.5 ${
                        testState.loading
                          ? "bg-surface text-text-secondary"
                          : testState.success
                          ? "bg-success/10 text-success border border-success/30"
                          : "bg-danger/10 text-danger border border-danger/30"
                      }`}>
                        {testState.loading ? (
                          <RefreshCw className="w-3 h-3 animate-spin text-accent" />
                        ) : testState.success ? (
                          <CheckCircle2 className="w-3 h-3 text-success shrink-0" />
                        ) : (
                          <AlertCircle className="w-3 h-3 text-danger shrink-0" />
                        )}
                        <span className="truncate">
                          {testState.loading ? "Testing..." : testState.success ? `Operational (${testState.latency_ms}ms)` : testState.message}
                        </span>
                      </div>
                    )}

                    <div className="flex items-center gap-1.5">
                      <Button
                        onClick={() => handleTestService("google_safe_browsing")}
                        disabled={testState?.loading}
                        variant="secondary"
                        size="sm"
                        className="flex-1 flex items-center justify-center gap-1 text-[11px]"
                      >
                        <Zap className="w-3 h-3" />
                        <span>Test Ping</span>
                      </Button>
                      <Button
                        onClick={() => handleOpenKeyModal("google_safe_browsing", "Google Safe Browsing", gsb?.key_masked)}
                        variant="ghost"
                        size="sm"
                        className="px-2 text-[11px]"
                        title="Configure API Key"
                      >
                        <Key className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* 4. AbuseIPDB */}
            {(() => {
              const abuse = integrations?.abuseipdb;
              const isConfigured = abuse ? abuse.configured : true;
              const testState = testStates["abuseipdb"];
              return (
                <div className="p-4 rounded-xl border border-border bg-surface-elevated flex flex-col justify-between space-y-3 hover:border-border transition-all shadow-sm">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs text-text-secondary font-medium">AbuseIPDB</span>
                      <Badge variant="accent" className="text-[10px]">
                        IP Intel
                      </Badge>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="relative flex h-2 w-2">
                        {isConfigured && (
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
                        )}
                        <span className={`relative inline-flex rounded-full h-2 w-2 ${isConfigured ? "bg-success" : "bg-text-muted"}`} />
                      </span>
                      <span className={`text-sm font-medium ${isConfigured ? "text-foreground" : "text-text-secondary"}`}>
                        {isConfigured ? "Connected" : "Not Configured"}
                      </span>
                    </div>

                    <p className="text-[11px] text-text-muted mt-1 line-clamp-1">
                      {abuse?.description || "IP reputation & brute-force telemetry database"}
                    </p>

                    <div className="mt-2.5 space-y-1 text-[11px] font-mono bg-surface p-2 rounded-lg border border-border">
                      <div className="flex justify-between text-text-secondary">
                        <span>Daily Quota:</span>
                        <span className="text-foreground font-semibold">1,000 / day</span>
                      </div>
                      <div className="flex justify-between text-text-secondary">
                        <span>Key:</span>
                        <span className="text-accent truncate max-w-[110px]" title={abuse?.key_masked || undefined}>
                          {abuse?.key_masked ? abuse.key_masked.slice(0, 12) + "…" : "None"}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="pt-2 border-t border-border space-y-2">
                    {testState && (
                      <div className={`text-[10px] px-2 py-1 rounded flex items-center gap-1.5 ${
                        testState.loading
                          ? "bg-surface text-text-secondary"
                          : testState.success
                          ? "bg-success/10 text-success border border-success/30"
                          : "bg-danger/10 text-danger border border-danger/30"
                      }`}>
                        {testState.loading ? (
                          <RefreshCw className="w-3 h-3 animate-spin text-accent" />
                        ) : testState.success ? (
                          <CheckCircle2 className="w-3 h-3 text-success shrink-0" />
                        ) : (
                          <AlertCircle className="w-3 h-3 text-danger shrink-0" />
                        )}
                        <span className="truncate">
                          {testState.loading ? "Testing..." : testState.success ? `Operational (${testState.latency_ms}ms)` : testState.message}
                        </span>
                      </div>
                    )}

                    <div className="flex items-center gap-1.5">
                      <Button
                        onClick={() => handleTestService("abuseipdb")}
                        disabled={testState?.loading}
                        variant="secondary"
                        size="sm"
                        className="flex-1 flex items-center justify-center gap-1 text-[11px]"
                      >
                        <Zap className="w-3 h-3" />
                        <span>Test Ping</span>
                      </Button>
                      <Button
                        onClick={() => handleOpenKeyModal("abuseipdb", "AbuseIPDB", abuse?.key_masked)}
                        variant="ghost"
                        size="sm"
                        className="px-2 text-[11px]"
                        title="Configure API Key"
                      >
                        <Key className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                </div>
              );
            })()}
          </div>
        </div>

        {/* ─── 3. USER PROFILE ────────────────────────────────────────────────── */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <User className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold text-foreground tracking-tight">
              Authenticated Security Operator
            </h2>
          </div>

          <div className="p-4 rounded-xl border border-border bg-surface-elevated grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
            <div>
              <span className="text-text-secondary">Analyst</span>
              <div className="text-sm font-medium text-foreground mt-0.5">
                {userProfile?.name || "Alex Mercer"}
              </div>
            </div>
            <div>
              <span className="text-text-secondary">Email & Access</span>
              <div className="text-sm font-medium text-text-secondary mt-0.5">
                {userProfile?.email || "alex.mercer@spectrashield.internal"}
              </div>
            </div>
            <div>
              <span className="text-text-secondary">SOC Role</span>
              <div className="text-sm font-medium text-accent mt-0.5 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-accent" />
                <span>{userProfile?.role || "Lead Security Analyst"}</span>
              </div>
            </div>
          </div>
        </div>

        {/* ─── 4. ADVANCED / DEVELOPER DIAGNOSTICS (COLLAPSIBLE) ──────────────── */}
        <div className="border-t border-border pt-4">
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-xs text-text-secondary hover:text-foreground transition-colors"
          >
            <span>Advanced / Developer Diagnostics</span>
            {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {showAdvanced && (
            <div className="mt-3 p-4 rounded-xl border border-border bg-surface text-xs font-mono space-y-2 text-text-secondary">
              <div className="flex justify-between py-1 border-b border-border">
                <span>FastAPI Gateway Endpoint</span>
                <span className="text-foreground">{getApiBase()}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border">
                <span>Backend Build Version</span>
                <span className="text-foreground">{health?.version || "2.0.0-phase3"}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border">
                <span>Database Connection</span>
                <span className="text-success">{dbConfig?.provider || "Supabase (PostgreSQL)"}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border">
                <span>OpenPhish Indicators In Memory / DB</span>
                <span className="text-success">{integrations?.openphish?.indicators_count ?? 0}</span>
              </div>
              <div className="flex justify-between py-1">
                <span>Frontend Client Build</span>
                <span className="text-foreground">v2.4.1 (Forensic SOC Edition)</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ─── CONFIGURE KEY MODAL ──────────────────────────────────────────────── */}
      {keyModal?.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md rounded-2xl border border-border bg-surface-elevated shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-lg bg-accent/10 border border-accent/20 text-accent">
                  <Key className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-foreground">
                    Configure {keyModal.name} API Key
                  </h3>
                  <p className="text-xs text-text-secondary">
                    Keys are securely stored in the backend environment
                  </p>
                </div>
              </div>
              <button
                onClick={() => setKeyModal(null)}
                className="p-1 rounded-lg hover:bg-surface text-text-secondary hover:text-foreground transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {keyModal.currentKeyMasked && (
              <div className="p-3 rounded-lg bg-surface border border-border text-xs font-mono">
                <span className="text-text-secondary block text-[11px] mb-1">Current Active Key:</span>
                <span className="text-accent break-all">{keyModal.currentKeyMasked}</span>
              </div>
            )}

            <form onSubmit={handleSaveKey} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">
                  New API Key / Token
                </label>
                <div className="relative">
                  <input
                    type={showKeyText ? "text" : "password"}
                    value={inputKey}
                    onChange={(e) => setInputKey(e.target.value)}
                    placeholder="Paste your API key here..."
                    className="w-full px-3 py-2 pr-10 rounded-lg bg-surface border border-border text-foreground text-xs font-mono placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowKeyText(!showKeyText)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-secondary hover:text-foreground transition-colors"
                  >
                    {showKeyText ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {keyModalError && (
                <div className="p-2.5 rounded-lg bg-danger/10 border border-danger/30 text-danger text-xs flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{keyModalError}</span>
                </div>
              )}

              {keyModalSuccess && (
                <div className="p-2.5 rounded-lg bg-success/10 border border-success/30 text-success text-xs flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>{keyModalSuccess}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2">
                <Button
                  type="button"
                  onClick={() => setKeyModal(null)}
                  disabled={savingKey}
                  variant="secondary"
                  size="sm"
                  className="text-xs"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={savingKey || !inputKey.trim()}
                  variant="accent"
                  size="sm"
                  className="text-xs flex items-center gap-1.5"
                >
                  {savingKey ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Saving...</span>
                    </>
                  ) : (
                    <>
                      <Lock className="w-3.5 h-3.5" />
                      <span>Save & Authenticate</span>
                    </>
                  )}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </SocLayout>
  );
};
