import { Activity, Monitor, ShieldAlert, ShieldBan, ShieldCheck } from "lucide-react";
import type { AlertRecord, SnmpMetric, SystemStatus } from "../types";
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
  if (statusError) {
    return <ErrorState message={statusError} onRetry={onRetry} />;
  }
  if (!status) {
    return <LoadingState message="กำลังเชื่อมต่อศูนย์ควบคุม NOC/SOC..." />;
  }

  const latestMetric = metrics[metrics.length - 1];

  return (
    <div className="space-y-6">
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
          className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left transition hover:border-cyan-500/40"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">อุปกรณ์ออนไลน์ (Devices)</span>
            <Monitor className="h-4 w-4 text-cyan-400" />
          </div>
          <p className="mt-2 text-2xl font-bold text-slate-100">{onlineDevicesCount}</p>
          <p className="mt-1 text-xs text-slate-400">วง {status.capabilities.default_subnet}</p>
        </button>

        <button
          type="button"
          onClick={() => onNavigate("ids")}
          className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left transition hover:border-amber-500/40"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">การแจ้งเตือนทั้งหมด (IDS Alerts)</span>
            <ShieldAlert className="h-4 w-4 text-amber-400" />
          </div>
          <p className="mt-2 text-2xl font-bold text-slate-100">{status.alert_counts.total}</p>
          <p className="mt-1 text-xs text-rose-300">
            Critical: {status.alert_counts.critical} | High: {status.alert_counts.high}
          </p>
        </button>

        <button
          type="button"
          onClick={() => onNavigate("snmp")}
          className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left transition hover:border-emerald-500/40"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Bandwidth ล่าสุด (NIC/SNMP)</span>
            <Activity className="h-4 w-4 text-emerald-400" />
          </div>
          <p className="mt-2 text-2xl font-bold text-slate-100">
            {latestMetric ? formatBps(latestMetric.in_bps + latestMetric.out_bps) : "0 bps"}
          </p>
          <p className="mt-1 text-xs text-slate-400">
            CPU: {latestMetric?.cpu_pct ?? "-"}% | RAM: {latestMetric?.mem_pct ?? "-"}%
          </p>
        </button>

        <button
          type="button"
          onClick={() => onNavigate("firewall")}
          className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left transition hover:border-rose-500/40"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">IP ที่ถูกบล็อก (Blocked)</span>
            <ShieldBan className="h-4 w-4 text-rose-400" />
          </div>
          <p className="mt-2 text-2xl font-bold text-slate-100">{blockedActiveCount}</p>
          <p className="mt-1 text-xs text-slate-400">
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
            />
          ) : (
            <ul className="space-y-2.5">
              {alerts.slice(0, 6).map((alert) => (
                <li
                  key={alert.id}
                  className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-xs"
                >
                  <div className="flex items-center justify-between gap-2">
                    <SeverityBadge severity={alert.severity} />
                    <span className="font-mono text-[11px] text-slate-400">
                      {alert.source_ip}
                    </span>
                  </div>
                  <p className="mt-1.5 font-medium text-slate-200">{alert.title}</p>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
