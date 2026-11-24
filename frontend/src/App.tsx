import { useCallback, useEffect, useState } from "react";
import { Activity, LayoutDashboard, Radar, Shield, ShieldAlert, ShieldBan, Wifi, WifiOff } from "lucide-react";
import { api } from "./api";
import { useLiveSocket } from "./hooks/useLiveSocket";
import { FirewallPage } from "./pages/FirewallPage";
import { IdsPage } from "./pages/IdsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ScannerPage } from "./pages/ScannerPage";
import { SnmpPage } from "./pages/SnmpPage";
import type { AlertRecord, DeviceRecord, PacketSummary, SnmpMetric, SystemStatus, TabId } from "./types";

const NAV_ITEMS: Array<{ id: TabId; label: string; icon: typeof LayoutDashboard }> = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "scanner", label: "IP Scanner", icon: Radar },
  { id: "ids", label: "IDS & Snort", icon: ShieldAlert },
  { id: "snmp", label: "SNMP & Traffic", icon: Activity },
  { id: "firewall", label: "Firewall & Policy", icon: ShieldBan },
];

export function App() {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [wsConnected, setWsConnected] = useState(false);

  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [metrics, setMetrics] = useState<SnmpMetric[]>([]);
  const [blockedActiveCount, setBlockedActiveCount] = useState(0);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshAll = useCallback(async (signal?: AbortSignal) => {
    setError(null);
    try {
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
      if (type === "scan_completed" || type === "firewall_updated" || type === "policy_updated" || type === "alerts_cleared") {
        refreshAll();
      }
    },
  });

  const onlineDevicesCount = devices.filter((d) => d.status === "online").length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Top Navbar */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/15 text-cyan-400 ring-1 ring-cyan-500/30">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-slate-100">
                NetSentinel
              </h1>
              <p className="text-[11px] text-slate-400">
                SolarWinds + Snort Hybrid NOC/SOC Platform
              </p>
            </div>
          </div>

          <nav className="flex flex-wrap items-center gap-1" aria-label="Primary navigation">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                    active
                      ? "bg-cyan-600 text-white shadow-sm"
                      : "text-slate-300 hover:bg-slate-800 hover:text-white"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {item.label}
                </button>
              );
            })}
          </nav>

          <div className="flex items-center gap-2 text-xs">
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
      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
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
            loading={loading}
            error={error}
            onRefresh={() => refreshAll()}
          />
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

        {activeTab === "snmp" && (
          <SnmpPage metrics={metrics} onMetricsUpdated={() => refreshAll()} />
        )}

        {activeTab === "firewall" && (
          <FirewallPage onPolicyChanged={() => refreshAll()} />
        )}
      </main>
    </div>
  );
}

export default App;
