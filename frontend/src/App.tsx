import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Activity, BookOpen, Building2, FileSearch, Globe, Grid, LayoutDashboard, Lock, LogOut, Network, Radar, Search, Shield, ShieldAlert, ShieldBan, Unlock, Wifi, WifiOff, Wrench } from "lucide-react";
import { api, setSessionToken } from "./api";
import { CommandPalette } from "./components/CommandPalette";
import { Device360Modal } from "./components/Device360Modal";
import { useLiveSocket } from "./hooks/useLiveSocket";
import { EASY_NAV_LABELS, NAV_LABELS, type Lang } from "./i18n";
import { EnterprisePage } from "./pages/EnterprisePage";
import { FirewallPage } from "./pages/FirewallPage";
import { ForensicsPage } from "./pages/ForensicsPage";
import { IdsPage } from "./pages/IdsPage";
import { IpamPage } from "./pages/IpamPage";
import { LearningLabPage } from "./pages/LearningLabPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ScannerPage } from "./pages/ScannerPage";
import { SnmpPage } from "./pages/SnmpPage";
import { ToolsPage } from "./pages/ToolsPage";
import { TopologyPage } from "./pages/TopologyPage";
import type { AlertRecord, DeviceRecord, PacketSummary, ScanSchedule, SnmpMetric, SystemStatus, TabId } from "./types";

const PRO_NAV_ITEMS: Array<{ id: TabId; label: string; icon: typeof LayoutDashboard }> = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "scanner", label: "IP Scanner", icon: Radar },
  { id: "topology", label: "Topology Map", icon: Network },
  { id: "ipam", label: "IPAM & NetFlow", icon: Grid },
  { id: "ids", label: "IDS & Snort", icon: ShieldAlert },
  { id: "forensics", label: "Forensics & Reports", icon: FileSearch },
  { id: "tools", label: "Tools & Monitors", icon: Wrench },
  { id: "snmp", label: "SNMP & Traffic", icon: Activity },
  { id: "firewall", label: "Firewall & Policy", icon: ShieldBan },
  { id: "enterprise", label: "Enterprise & Hospital", icon: Building2 },
  { id: "lab", label: "Blue Team Lab", icon: BookOpen },
];

const EASY_NAV_ITEMS: Array<{ id: TabId; label: string; icon: typeof LayoutDashboard }> = [
  { id: "overview", label: "Home (1-Click Check)", icon: LayoutDashboard },
  { id: "scanner", label: "Wi-Fi Devices", icon: Radar },
  { id: "firewall", label: "Alerts & Block", icon: ShieldBan },
];

export function App() {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [easyMode, setEasyMode] = useState<boolean>(() => {
    try {
      return localStorage.getItem("netsentinel_easy_mode") === "true";
    } catch {
      return false;
    }
  });
  const [wsConnected, setWsConnected] = useState(false);

  // Optional Passcode Lock State
  const [lockEnabled, setLockEnabled] = useState(false);
  const [authenticated, setAuthenticated] = useState(true);
  const [passcodeInput, setPasscodeInput] = useState("");
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [scanSchedule, setScanSchedule] = useState<ScanSchedule | null>(null);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [metrics, setMetrics] = useState<SnmpMetric[]>([]);
  const [blockedActiveCount, setBlockedActiveCount] = useState(0);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lang, setLang] = useState<Lang>(() => {
    try {
      return localStorage.getItem("netsentinel_lang") === "en" ? "en" : "th";
    } catch {
      return "th";
    }
  });
  const [cmdOpen, setCmdOpen] = useState(false);
  const [inspectIp, setInspectIp] = useState<string | null>(null);

  const toggleLang = () => {
    const next: Lang = lang === "th" ? "en" : "th";
    setLang(next);
    try {
      localStorage.setItem("netsentinel_lang", next);
    } catch {
      // Ignore storage error
    }
  };

  const toggleEasyMode = () => {
    const next = !easyMode;
    setEasyMode(next);
    try {
      localStorage.setItem("netsentinel_easy_mode", String(next));
    } catch {
      // Ignore storage error
    }
    if (next && !EASY_NAV_ITEMS.some((i) => i.id === activeTab)) {
      setActiveTab("overview");
    }
  };

  const refreshAll = useCallback(async (signal?: AbortSignal) => {
    setError(null);
    try {
      const auth = await api.getAuthStatus(signal);
      setLockEnabled(auth.lock_enabled);
      setAuthenticated(auth.authenticated);
      if (auth.lock_enabled && !auth.authenticated) {
        setLoading(false);
        return;
      }

      const [sysRes, devRes, alertRes, pktRes, metricRes, fwRes] = await Promise.all([
        api.getSystemStatus(signal),
        api.listDevices(signal),
        api.listAlerts("all", 100, signal),
        api.getPackets(60, signal),
        api.getSnmpMetrics(60, signal),
        api.getFirewallStatus(signal),
      ]);
      setStatus(sysRes);
      setDevices(devRes.devices);
      setScanSchedule(devRes.schedule);
      setAlerts(alertRes.alerts);
      setPackets(pktRes.packets);
      setMetrics(metricRes.metrics);
      setBlockedActiveCount(fwRes.active_count);
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError(err instanceof Error ? err.message : "Unable to reach NetSentinel backend");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    refreshAll(ctrl.signal);
    return () => ctrl.abort();
  }, [refreshAll]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useLiveSocket({
    onConnectionChange: setWsConnected,
    onAlert: (alert) => {
      setAlerts((prev) => [alert, ...prev.filter((a) => a.id !== alert.id)].slice(0, 150));
      refreshAll();
    },
    onPacket: (pkt) => {
      setPackets((prev) => [pkt, ...prev].slice(0, 100));
    },
    onSnmpMetric: (metric) => {
      setMetrics((prev) => [...prev.slice(-59), metric]);
    },
    onAnyEvent: (type) => {
      if (
        type === "scan_completed" ||
        type === "device_updated" ||
        type === "firewall_updated" ||
        type === "policy_updated" ||
        type === "alerts_cleared"
      ) {
        refreshAll();
      }
    },
  });

  const handleUnlock = async (e: FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    try {
      const res = await api.loginPasscode(passcodeInput);
      setSessionToken(res.token);
      setPasscodeInput("");
      setAuthenticated(true);
      await refreshAll();
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "Passcode ไม่ถูกต้อง");
    }
  };

  const handleToggleLockSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    try {
      if (lockEnabled) {
        await api.disablePasscode(passcodeInput);
        setSessionToken("");
        setLockEnabled(false);
        setAuthenticated(true);
      } else {
        const res = await api.setupPasscode(passcodeInput);
        setSessionToken(res.token);
        setLockEnabled(true);
        setAuthenticated(true);
      }
      setPasscodeInput("");
      setAuthModalOpen(false);
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "Failed to update passcode");
    }
  };

  const handleLogout = async () => {
    try {
      await api.logoutPasscode();
    } finally {
      setSessionToken("");
      setAuthenticated(false);
    }
  };

  if (lockEnabled && !authenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 p-4 text-slate-100">
        <form
          onSubmit={handleUnlock}
          className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl"
        >
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-cyan-500/15 p-2 text-cyan-400">
              <Lock className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-base font-bold">NetSentinel Locked</h1>
              <p className="text-xs text-slate-400">กรอก Passcode เพื่อเข้าสู่ Dashboard</p>
            </div>
          </div>
          {authError && (
            <p className="mt-3 rounded bg-rose-500/15 px-3 py-2 text-xs text-rose-300">
              {authError}
            </p>
          )}
          <input
            type="password"
            value={passcodeInput}
            onChange={(e) => setPasscodeInput(e.target.value)}
            placeholder="Passcode (อย่างน้อย 6 ตัวอักษร)"
            className="mt-4 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          />
          <button
            type="submit"
            className="mt-4 w-full rounded-lg bg-cyan-600 py-2 text-sm font-semibold text-white hover:bg-cyan-500"
          >
            ปลดล็อก
          </button>
        </form>
      </div>
    );
  }

  const navItems = (easyMode ? EASY_NAV_ITEMS : PRO_NAV_ITEMS).map((item) => ({
    ...item,
    label: easyMode
      ? (EASY_NAV_LABELS[lang][item.id] ?? item.label)
      : (NAV_LABELS[lang][item.id] ?? item.label),
  }));
  const onlineDevicesCount = devices.filter((d) => d.status === "online").length;

  useEffect(() => {
    const active = navItems.find((i) => i.id === activeTab);
    document.title = active ? `NetSentinel — ${active.label}` : "NetSentinel";
  }, [activeTab, navItems]);

  useEffect(() => {
    if (!authModalOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setAuthModalOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [authModalOpen]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-cyan-600 focus:px-3 focus:py-2 focus:text-xs focus:font-semibold focus:text-white"
      >
        ข้ามไปยังเนื้อหาหลัก
      </a>
      {/* Top Navbar */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-slate-950/95 print:hidden">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/15 text-cyan-400 ring-1 ring-cyan-500/30">
              <Shield className="h-5 w-5" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-slate-100" translate="no">
                NetSentinel
              </h1>
              <p className="text-[11px] text-slate-400">
                {easyMode ? "Easy Mode (สำหรับผู้ใช้ทั่วไป)" : "Pro SOC / NOC Mode"}
              </p>
            </div>
          </div>

          <nav className="flex flex-wrap items-center gap-1" aria-label="Primary navigation">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  aria-current={active ? "page" : undefined}
                  onClick={() => setActiveTab(item.id)}
                  className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors duration-150 ${
                    active
                      ? "bg-cyan-600 text-white"
                      : "text-slate-300 hover:bg-slate-800 hover:text-white"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                  {item.label}
                </button>
              );
            })}
          </nav>

          <div className="flex items-center gap-2 text-xs">
            <button
              type="button"
              onClick={() => setCmdOpen(true)}
              aria-label="เปิด Command Palette ค้นหาด่วน (Ctrl+K)"
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] font-medium text-slate-300 hover:bg-slate-800"
            >
              <Search className="h-3 w-3" aria-hidden="true" />
              <span translate="no" className="hidden sm:inline">Ctrl+K</span>
            </button>

            <button
              type="button"
              onClick={toggleLang}
              aria-label="สลับภาษาไทย/อังกฤษ"
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-800"
            >
              <Globe className="h-3 w-3 text-cyan-400" aria-hidden="true" />
              <span translate="no">{lang.toUpperCase()}</span>
            </button>

            <button
              type="button"
              onClick={toggleEasyMode}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-800"
            >
              {easyMode ? "สลับเป็น Pro SOC" : "สลับเป็น Easy Mode"}
            </button>

            <button
              type="button"
              onClick={() => {
                setAuthError(null);
                setPasscodeInput("");
                setAuthModalOpen(true);
              }}
              aria-label="ตั้งค่าล็อกหน้าเว็บด้วยรหัสผ่าน"
              className={`rounded-lg border p-1.5 ${
                lockEnabled
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                  : "border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800"
              }`}
            >
              {lockEnabled ? <Lock className="h-3.5 w-3.5" /> : <Unlock className="h-3.5 w-3.5" />}
            </button>

            {lockEnabled && (
              <button
                type="button"
                onClick={handleLogout}
                aria-label="ออกจากระบบ"
                className="rounded-lg border border-slate-700 bg-slate-900 p-1.5 text-slate-300 hover:bg-slate-800"
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            )}

            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${
                wsConnected
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                  : "border-rose-500/30 bg-rose-500/10 text-rose-300"
              }`}
            >
              {wsConnected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
              {wsConnected ? "Live WS" : "Disconnected"}
            </span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main id="main-content" className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
        {activeTab === "overview" && (
          <OverviewPage
            status={status}
            statusError={error}
            alerts={alerts}
            metrics={metrics}
            onlineDevicesCount={onlineDevicesCount}
            blockedActiveCount={blockedActiveCount}
            onRetry={() => refreshAll()}
            onNavigate={setActiveTab}
          />
        )}

        {activeTab === "scanner" && (
          <ScannerPage
            devices={devices}
            defaultSubnet={status?.capabilities.default_subnet ?? "192.168.1.0/24"}
            schedule={scanSchedule}
            loading={loading}
            error={error}
            onRefresh={() => refreshAll()}
            onInspectIp={setInspectIp}
          />
        )}

        {activeTab === "topology" && (
          <TopologyPage
            devices={devices}
            gatewayIp={status?.capabilities.gateway_ip ?? null}
            loading={loading}
            error={error}
            onRefresh={() => refreshAll()}
          />
        )}

        {activeTab === "ipam" && (
          <IpamPage defaultSubnet={status?.capabilities.default_subnet ?? "192.168.1.0/24"} />
        )}

        {activeTab === "ids" && (
          <IdsPage
            alerts={alerts}
            packets={packets}
            sniffer={status?.sniffer ?? null}
            loading={loading}
            error={error}
            onRefresh={() => refreshAll()}
          />
        )}

        {activeTab === "forensics" && <ForensicsPage />}

        {activeTab === "tools" && <ToolsPage />}

        {activeTab === "snmp" && (
          <SnmpPage metrics={metrics} onMetricsUpdated={() => refreshAll()} />
        )}

        {activeTab === "firewall" && (
          <FirewallPage onPolicyChanged={() => refreshAll()} />
        )}

        {activeTab === "enterprise" && (
          <EnterprisePage onUpdated={() => refreshAll()} />
        )}

        {activeTab === "lab" && (
          <LearningLabPage
            defaultSubnet={status?.capabilities.default_subnet ?? "192.168.1.0/24"}
            onRefresh={() => refreshAll()}
            onNavigate={setActiveTab}
          />
        )}
      </main>

      <CommandPalette
        open={cmdOpen}
        onClose={() => setCmdOpen(false)}
        navItems={navItems}
        devices={devices}
        alerts={alerts}
        onSelectTab={setActiveTab}
        onInspectDevice={setInspectIp}
      />

      <Device360Modal ip={inspectIp} onClose={() => setInspectIp(null)} />

      {/* Passcode Lock Configuration Modal */}
      {authModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4"
          role="dialog"
          aria-modal="true"
        >
          <form
            onSubmit={handleToggleLockSubmit}
            className="w-full max-w-sm rounded-xl border border-slate-700 bg-slate-900 p-5"
          >
            <h3 className="text-sm font-bold text-slate-100">
              {lockEnabled ? "ปิด Passcode Lock" : "ตั้ง Passcode ล็อกหน้า Dashboard"}
            </h3>
            <p className="mt-1 text-xs text-slate-400">
              {lockEnabled
                ? "กรอกรหัสผ่านปัจจุบันเพื่อปิดระบบล็อก"
                : "ตั้งรหัสอย่างน้อย 6 ตัวอักษร (เก็บรหัสแบบ Salted PBKDF2-SHA256)"}
            </p>
            {authError && (
              <p className="mt-2 text-xs text-rose-300">{authError}</p>
            )}
            <input
              type="password"
              value={passcodeInput}
              onChange={(e) => setPasscodeInput(e.target.value)}
              placeholder="Passcode (min 6 chars)"
              className="mt-3 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100"
            />
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setAuthModalOpen(false)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-200"
              >
                ยกเลิก
              </button>
              <button
                type="submit"
                className="rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500"
              >
                {lockEnabled ? "ปิดระบบล็อก" : "เปิดใช้ Passcode"}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

export default App;
