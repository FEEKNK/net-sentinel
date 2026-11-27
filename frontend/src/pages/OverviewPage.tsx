import { useEffect, useState } from "react";
import { Activity, Globe, Loader2, Monitor, Radar, ShieldAlert, ShieldBan, ShieldCheck } from "lucide-react";
import { api } from "../api";
import type { AlertRecord, SnmpMetric, SystemStatus, WatchdogPing } from "../types";
import { BandwidthChart, formatBps } from "../components/BandwidthChart";
import { EmptyState, ErrorState, LearnBanner, LoadingState, SeverityBadge } from "../components/StateViews";

interface OverviewPageProps {
  status: SystemStatus | null;
  statusError: string | null;
  alerts: AlertRecord[];
  metrics: SnmpMetric[];
  onlineDevicesCount: number;
  blockedActiveCount: number;
  onRetry: () => void;
  onNavigate: (tab: "scanner" | "ids" | "snmp" | "firewall") => void;
}

export function OverviewPage({
  status,
  statusError,
  alerts,
  metrics,
  onlineDevicesCount,
  blockedActiveCount,
  onRetry,
  onNavigate,
}: OverviewPageProps) {
  const [checking, setChecking] = useState(false);
  const [quickSummary, setQuickSummary] = useState<string | null>(null);
  const [quickError, setQuickError] = useState<string | null>(null);
  const [watchdogEnabled, setWatchdogEnabled] = useState(false);
  const [watchdogTarget, setWatchdogTarget] = useState("1.1.1.1");
  const [latestPing, setLatestPing] = useState<WatchdogPing | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    api
      .getWatchdog(ctrl.signal)
      .then((wd) => {
        setWatchdogEnabled(wd.enabled);
        setWatchdogTarget(wd.target_ip);
        if (wd.pings.length > 0) setLatestPing(wd.pings[wd.pings.length - 1]);
      })
      .catch(() => {});
    return () => ctrl.abort();
  }, []);

  if (statusError) {
    return <ErrorState message={statusError} onRetry={onRetry} />;
  }
  if (!status) {
    return <LoadingState message="กำลังเชื่อมต่อศูนย์ควบคุม NOC/SOC..." />;
  }

  const latestMetric = metrics[metrics.length - 1];

  const handleQuickCheck = async () => {
    setChecking(true);
    setQuickError(null);
    setQuickSummary(null);
    try {
      const res = await api.quickHealthCheck();
      setLatestPing(res.watchdog);
      const netStatus = res.watchdog.online
        ? `อินเทอร์เน็ตปกติ (${res.watchdog.latency_ms ?? "-"} ms)`
        : "อินเทอร์เน็ตขาดการเชื่อมต่อ!";
      setQuickSummary(
        `ตรวจวง ${res.scan.cidr} เสร็จใน ${res.scan.duration_ms} ms — พบออนไลน์ ${res.scan.online_count} เครื่อง · ${netStatus}`
      );
      onRetry();
    } catch (err) {
      setQuickError(err instanceof Error ? err.message : "Quick check failed");
    } finally {
      setChecking(false);
    }
  };

  const toggleWatchdog = async () => {
    try {
      const res = await api.updateWatchdog({ enabled: !watchdogEnabled });
      setWatchdogEnabled(res.enabled);
    } catch (err) {
      setQuickError(err instanceof Error ? err.message : "Watchdog update failed");
    }
  };

  return (
    <div className="space-y-6">
      {/* 1-Click Guided Health Check Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-700 bg-slate-900 p-5">
        <div>
          <h2 className="text-base font-bold text-slate-100">
            ตรวจสุขภาพวง Wi-Fi และความปลอดภัยในคลิกเดียว
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-slate-300">
            สแกนเครื่องทั้งหมดในวง <span translate="no">{status.capabilities.default_subnet}</span> + เช็กสถานะเน็ตออกโลก (<span translate="no">{watchdogTarget}</span>) + วัดความเร็ว Bandwidth ล่าสุด
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={toggleWatchdog}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition-colors duration-150 ${
              watchdogEnabled
                ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                : "border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            <Globe className="h-3.5 w-3.5" aria-hidden="true" />
            Internet Watchdog: {watchdogEnabled ? "ON" : "OFF"}
            {latestPing && (
              <span className="ml-1 font-mono text-[11px] tabular-nums" translate="no">
                ({latestPing.online ? `${latestPing.latency_ms ?? "-"} ms` : "DOWN"})
              </span>
            )}
          </button>

          <button
            type="button"
            disabled={checking}
            onClick={handleQuickCheck}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white transition-colors duration-150 hover:bg-cyan-500 disabled:opacity-60"
          >
            {checking ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <Radar className="h-4 w-4" aria-hidden="true" />
            )}
            {checking ? "กำลังตรวจเช็กทั้งวง…" : "1-Click Health Check"}
          </button>
        </div>
      </div>

      {quickSummary && (
        <div className="rounded-xl border border-emerald-500/40 bg-emerald-950/30 px-4 py-3 text-xs font-medium text-emerald-200">
          {quickSummary}
        </div>
      )}
      {quickError && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-xs text-rose-200">
          {quickError}
        </div>
      )}

      <LearnBanner
        title="ศูนย์ควบคุมรวม (NOC + SOC)"
        summary="หน้านี้รวมภาพรวมสุขภาพเครือข่ายแบบ SolarWinds (จำนวนเครื่องออนไลน์ + ความเร็ว Bandwidth) เข้ากับระบบแจ้งเตือนการบุกรุกแบบ Snort (Alerts + Active Response) โดยดึงข้อมูลจริงจาก SQLite และ WebSocket"
      />

      {/* Privilege & Safe Mode Strip */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/70 px-4 py-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          <span className="rounded-md bg-slate-800 px-2.5 py-1 font-medium text-slate-200">
            OS: {status.capabilities.os_name}
          </span>
          <span
            className={`rounded-md px-2.5 py-1 font-medium ${
              status.capabilities.is_admin
                ? "bg-emerald-500/15 text-emerald-300"
                : "bg-amber-500/15 text-amber-300"
            }`}
          >
            Privilege: {status.capabilities.is_admin ? "Admin / Root (Full Capture)" : "Standard User (Safe Mode)"}
          </span>
          <span className="rounded-md bg-slate-800 px-2.5 py-1 text-slate-300">
            Subnet: {status.capabilities.default_subnet} | Gateway: {status.capabilities.gateway_ip ?? "N/A"}
          </span>
        </div>

        <span
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-semibold ${
            status.policy.dry_run
              ? "bg-cyan-500/15 text-cyan-300"
              : "bg-rose-500/20 text-rose-300"
          }`}
        >
          <ShieldCheck className="h-3.5 w-3.5" />
          {status.policy.dry_run ? "Firewall: DRY-RUN SAFE MODE" : "Firewall: LIVE ENFORCE"}
        </span>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <button
          type="button"
          onClick={() => onNavigate("scanner")}
          className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left transition-colors duration-150 hover:border-cyan-500/50"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">อุปกรณ์ออนไลน์ (Devices)</span>
            <Monitor className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums text-slate-100">{onlineDevicesCount}</p>
          <p className="mt-1 text-xs text-slate-400" translate="no">วง {status.capabilities.default_subnet}</p>
        </button>

        <button
          type="button"
          onClick={() => onNavigate("ids")}
          className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left transition-colors duration-150 hover:border-amber-500/50"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">การแจ้งเตือนทั้งหมด (IDS Alerts)</span>
            <ShieldAlert className="h-4 w-4 text-amber-400" aria-hidden="true" />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums text-slate-100">{status.alert_counts.total}</p>
          <p className="mt-1 text-xs tabular-nums text-rose-300">
            Critical: {status.alert_counts.critical} | High: {status.alert_counts.high}
          </p>
        </button>

        <button
          type="button"
          onClick={() => onNavigate("snmp")}
          className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left transition-colors duration-150 hover:border-emerald-500/50"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Bandwidth ล่าสุด (NIC/SNMP)</span>
            <Activity className="h-4 w-4 text-emerald-400" aria-hidden="true" />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums text-slate-100">
            {latestMetric ? formatBps(latestMetric.in_bps + latestMetric.out_bps) : "0 bps"}
          </p>
          <p className="mt-1 text-xs tabular-nums text-slate-400">
            CPU: {latestMetric?.cpu_pct ?? "-"}% | RAM: {latestMetric?.mem_pct ?? "-"}%
          </p>
        </button>

        <button
          type="button"
          onClick={() => onNavigate("firewall")}
          className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left transition-colors duration-150 hover:border-rose-500/50"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">IP ที่ถูกบล็อก (Blocked)</span>
            <ShieldBan className="h-4 w-4 text-rose-400" aria-hidden="true" />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums text-slate-100">{blockedActiveCount}</p>
          <p className="mt-1 text-xs tabular-nums text-slate-400">
            Snort Rules: {status.rules_loaded} กฎ
          </p>
        </button>
      </div>

      {/* Charts & Recent Alerts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 lg:col-span-2">
          <h3 className="mb-3 text-sm font-semibold text-slate-100">
            Real-time Network Throughput
          </h3>
          <BandwidthChart metrics={metrics} />
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100">Recent IDS Alerts</h3>
            <button
              type="button"
              onClick={() => onNavigate("ids")}
              className="text-xs font-medium text-cyan-400 hover:underline"
            >
              ดูทั้งหมด
            </button>
          </div>

          {alerts.length === 0 ? (
            <EmptyState
              title="ยังไม่พบการแจ้งเตือน"
              description="เปิด Live Sniffer หรือไปที่หน้า IDS เพื่อลองกด Attack Simulator ทดสอบระบบ"
              actionLabel="ไปหน้า IDS & Simulator"
              onAction={() => onNavigate("ids")}
            />
          ) : (
            <ul className="divide-y divide-slate-800/80">
              {alerts.slice(0, 6).map((alert) => (
                <li key={alert.id} className="py-2.5 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <SeverityBadge severity={alert.severity} />
                    <span className="font-mono text-[11px] tabular-nums text-slate-400" translate="no">
                      {alert.source_ip}
                    </span>
                  </div>
                  <p className="mt-1.5 font-medium leading-normal text-slate-200">{alert.title}</p>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
