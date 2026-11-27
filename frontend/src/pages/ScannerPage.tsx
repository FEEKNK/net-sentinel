import { useEffect, useState, type FormEvent } from "react";
import { Clock, Loader2, Power, Radar, ShieldAlert, ShieldBan, ShieldCheck } from "lucide-react";
import { api } from "../api";
import type { DeviceRecord, ScanSchedule } from "../types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState, ErrorState, LearnBanner, LoadingState } from "../components/StateViews";

interface ScannerPageProps {
  devices: DeviceRecord[];
  defaultSubnet: string;
  schedule: ScanSchedule | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onInspectIp?: (ip: string) => void;
}

export function ScannerPage({
  devices,
  defaultSubnet,
  schedule,
  loading,
  error,
  onRefresh,
  onInspectIp,
}: ScannerPageProps) {
  const [cidr, setCidr] = useState(defaultSubnet || "192.168.1.0/24");
  const [cidrDirty, setCidrDirty] = useState(false);
  const [scanPorts, setScanPorts] = useState(true);
  const [portProfile, setPortProfile] = useState("default");
  const [customPortSpec, setCustomPortSpec] = useState("21,22,80,443,3389,8080");
  const [scanUdp, setScanUdp] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const [pendingConfirm, setPendingConfirm] = useState<
    { kind: "block" | "wol"; ip: string; mac?: string } | null
  >(null);
  const [busyAction, setBusyAction] = useState(false);

  useEffect(() => {
    if (!cidrDirty && defaultSubnet) {
      setCidr(defaultSubnet);
    }
  }, [defaultSubnet, cidrDirty]);

  const handleScan = async (e: FormEvent) => {
    e.preventDefault();
    setScanError(null);
    setScanMessage(null);
    if (!cidr.trim()) {
      setScanError("กรุณาระบุวง Subnet (เช่น 192.168.1.0/24)");
      return;
    }
    setScanning(true);
    try {
      const spec =
        portProfile === "custom"
          ? customPortSpec.trim()
          : portProfile === "web_db"
            ? "80,443,3000,3306,5432,8000,8080,8443"
            : undefined;
      const res = await api.scanSubnet(cidr.trim(), scanPorts, spec, scanUdp);
      setScanMessage(
        `สแกน ${res.cidr} เสร็จสิ้น (${res.scanned_hosts} IPs) — พบออนไลน์ ${res.online_count} เครื่อง ใช้เวลา ${res.duration_ms} ms`
      );
      onRefresh();
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const handleToggleTrust = async (dev: DeviceRecord) => {
    setScanError(null);
    try {
      await api.updateDevice(dev.ip, { trusted: !dev.trusted });
      onRefresh();
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Update failed");
    }
  };

  const handleScheduleChange = async (patch: {
    enabled?: boolean;
    interval_seconds?: number;
  }) => {
    setScanError(null);
    try {
      await api.updateScanSchedule({ ...patch, cidr: cidr.trim() || defaultSubnet });
      onRefresh();
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Failed to update schedule");
    }
  };

  const executeConfirm = async () => {
    if (!pendingConfirm) return;
    setBusyAction(true);
    setScanError(null);
    try {
      if (pendingConfirm.kind === "block") {
        const res = await api.blockIp(
          pendingConfirm.ip,
          "Blocked manually from IP Scanner device table",
          true
        );
        setScanMessage(res.message);
      } else {
        const res = await api.sendWakeOnLan(pendingConfirm.ip, true);
        setScanMessage(`ส่ง Wake-on-LAN ไปยัง ${res.mac} (${res.broadcast}) แล้ว`);
      }
      setPendingConfirm(null);
      onRefresh();
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Action failed");
      setPendingConfirm(null);
    } finally {
      setBusyAction(false);
    }
  };

  return (
    <div className="space-y-5">
      <LearnBanner
        title="IP & Subnet Scanner + Known Devices + Auto-Scan"
        summary="สแกนทุกบ้านเลขที่ในวง Wi-Fi/LAN พร้อมดึงชื่อเครื่อง (rDNS, NetBIOS, mDNS) และตรวจจับ Randomized MAC ของมือถือ คุณสามารถกด 'Trust' เพื่อจำอุปกรณ์ที่รู้จัก หากมีเครื่องแปลกหน้าเข้ามาใหม่ระบบจะตี Alert เตือนทันที"
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <form
          onSubmit={handleScan}
          className="flex flex-wrap items-end gap-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4 lg:col-span-2"
        >
          <div className="min-w-[200px] flex-1">
            <label htmlFor="subnet-input" className="block text-xs font-medium text-slate-300">
              Target Subnet (CIDR, ใหญ่สุด /20)
            </label>
            <input
              id="subnet-input"
              type="text"
              value={cidr}
              onChange={(e) => {
                setCidrDirty(true);
                setCidr(e.target.value);
              }}
              placeholder="192.168.1.0/24"
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3 pb-1 text-xs text-slate-300">
            <label className="inline-flex cursor-pointer items-center gap-1.5">
              <input
                type="checkbox"
                checked={scanPorts}
                onChange={(e) => setScanPorts(e.target.checked)}
                className="h-4 w-4 rounded border-slate-700 bg-slate-950 text-cyan-500"
              />
              TCP Ports
            </label>
            {scanPorts && (
              <select
                aria-label="Port scan profile"
                value={portProfile}
                onChange={(e) => setPortProfile(e.target.value)}
                className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-slate-200"
              >
                <option value="default">Quick 16 Ports</option>
                <option value="web_db">Web &amp; DB Ports</option>
                <option value="custom">Custom Range</option>
              </select>
            )}
            {scanPorts && portProfile === "custom" && (
              <input
                type="text"
                aria-label="Custom port specification"
                value={customPortSpec}
                onChange={(e) => setCustomPortSpec(e.target.value)}
                placeholder="22,80,8000-8010"
                className="w-36 rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-xs text-slate-100"
              />
            )}
            <label className="inline-flex cursor-pointer items-center gap-1.5">
              <input
                type="checkbox"
                checked={scanUdp}
                onChange={(e) => setScanUdp(e.target.checked)}
                className="h-4 w-4 rounded border-slate-700 bg-slate-950 text-cyan-500"
              />
              UDP (NTP)
            </label>
          </div>

          <button
            type="submit"
            disabled={scanning}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
            {scanning ? "กำลังสแกน..." : "Scan Now"}
          </button>
        </form>

        {/* Scheduled Auto-Scan Control */}
        <div className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <div className="flex items-center justify-between">
            <span className="inline-flex items-center gap-1.5 font-semibold text-slate-200">
              <Clock className="h-4 w-4 text-cyan-400" />
              Scheduled Auto-Scan
            </span>
            <button
              type="button"
              onClick={() => handleScheduleChange({ enabled: !(schedule?.enabled ?? false) })}
              className={`rounded-lg px-2.5 py-1 font-semibold text-white ${
                schedule?.enabled ? "bg-emerald-600 hover:bg-emerald-500" : "bg-slate-700 hover:bg-slate-600"
              }`}
            >
              {schedule?.enabled ? "ON" : "OFF"}
            </button>
          </div>
          <div className="mt-3 flex items-center justify-between gap-2 text-slate-400">
            <span>ความถี่ในการเช็ก:</span>
            <select
              aria-label="Auto scan interval"
              value={schedule?.interval_seconds ?? 120}
              onChange={(e) =>
                handleScheduleChange({ interval_seconds: Number(e.target.value) })
              }
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200"
            >
              <option value={60}>ทุก 1 นาที</option>
              <option value={120}>ทุก 2 นาที</option>
              <option value={300}>ทุก 5 นาที</option>
              <option value={900}>ทุก 15 นาที</option>
            </select>
          </div>
        </div>
      </div>

      {scanMessage && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 px-4 py-2.5 text-xs text-emerald-200">
          {scanMessage}
        </div>
      )}
      {scanError && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-2.5 text-xs text-rose-200">
          {scanError}
        </div>
      )}

      {error ? (
        <ErrorState message={error} onRetry={onRefresh} />
      ) : loading ? (
        <LoadingState />
      ) : devices.length === 0 ? (
        <EmptyState
          title="ยังไม่มีข้อมูลอุปกรณ์ในฐานข้อมูล"
          description="กรอกวง Subnet ด้านบน (หรือลอง 127.0.0.1/32 เพื่อทดสอบเครื่องตัวเอง) แล้วกด Scan Now"
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/70">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950/60 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Risk</th>
                <th className="px-4 py-3 font-medium">Trust</th>
                <th className="px-4 py-3 font-medium">IP Address</th>
                <th className="px-4 py-3 font-medium">Name / Hostname</th>
                <th className="px-4 py-3 font-medium">MAC / Vendor</th>
                <th className="px-4 py-3 font-medium">Latency / Uptime</th>
                <th className="px-4 py-3 font-medium">Open Ports</th>
                <th className="px-4 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {devices.map((dev) => (
                <tr key={dev.ip} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ${
                        dev.status === "online"
                          ? "bg-emerald-500/15 text-emerald-300"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          dev.status === "online" ? "bg-emerald-400" : "bg-slate-500"
                        }`}
                      />
                      {dev.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      title={(dev.risk_reasons ?? []).join("\n") || "Low risk"}
                      className={`inline-flex items-center rounded px-2 py-0.5 font-mono text-[11px] font-bold ${
                        dev.risk_grade === "A"
                          ? "bg-emerald-500/15 text-emerald-300"
                          : dev.risk_grade === "B"
                            ? "bg-cyan-500/15 text-cyan-300"
                            : dev.risk_grade === "C"
                              ? "bg-amber-500/15 text-amber-300"
                              : "bg-rose-500/20 text-rose-300"
                      }`}
                    >
                      {dev.risk_grade ?? "A"} ({dev.risk_score ?? 0})
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      type="button"
                      onClick={() => handleToggleTrust(dev)}
                      aria-label={`สลับสถานะ Trusted สำหรับ ${dev.ip}`}
                      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium ${
                        dev.trusted
                          ? "bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25"
                          : "bg-amber-500/15 text-amber-300 hover:bg-amber-500/25"
                      }`}
                    >
                      {dev.trusted ? (
                        <>
                          <ShieldCheck className="h-3 w-3" /> Known
                        </>
                      ) : (
                        <>
                          <ShieldAlert className="h-3 w-3" /> New
                        </>
                      )}
                    </button>
                  </td>
                  <td className="px-4 py-3 font-mono font-semibold text-cyan-300">{dev.ip}</td>
                  <td className="max-w-[180px] truncate px-4 py-3 text-slate-200">
                    <div className="font-medium">{dev.custom_name || dev.hostname || "-"}</div>
                    {dev.custom_name && dev.hostname && (
                      <div className="text-[11px] text-slate-500">{dev.hostname}</div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-mono text-slate-300">{dev.mac || "-"}</div>
                    <div className="text-[11px] text-slate-500">
                      {dev.vendor} {dev.os_guess && dev.os_guess !== "Unknown" ? `· ${dev.os_guess}` : ""}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-300">
                    <div>{dev.latency_ms !== null ? `${dev.latency_ms} ms` : "-"}</div>
                    <div className="text-[11px] text-emerald-400">{dev.uptime_pct ?? 100}% up</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {dev.open_ports.length === 0 ? (
                        <span className="text-slate-500">None</span>
                      ) : (
                        dev.open_ports.map((p) => (
                          <span
                            key={`${dev.ip}-${p.port}`}
                            title={p.banner || p.service}
                            className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] text-amber-300"
                          >
                            {p.port}/{p.service}
                            {p.banner ? ` · ${p.banner.slice(0, 18)}` : ""}
                          </span>
                        ))
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="inline-flex gap-1.5">
                      {onInspectIp && (
                        <button
                          type="button"
                          onClick={() => onInspectIp(dev.ip)}
                          aria-label={`เปิด Device 360 Timeline สำหรับ ${dev.ip}`}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-700"
                        >
                          <Clock className="h-3 w-3" />
                          360°
                        </button>
                      )}
                      <button
                        type="button"
                        disabled={!dev.mac}
                        onClick={() => setPendingConfirm({ kind: "wol", ip: dev.ip, mac: dev.mac })}
                        aria-label={`ปลุกเครื่อง ${dev.ip} ด้วย Wake-on-LAN`}
                        className="inline-flex items-center gap-1 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-2 py-1 text-[11px] font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-40"
                      >
                        <Power className="h-3 w-3" />
                        WoL
                      </button>
                      <button
                        type="button"
                        onClick={() => setPendingConfirm({ kind: "block", ip: dev.ip })}
                        aria-label={`บล็อก IP ${dev.ip}`}
                        className="inline-flex items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-[11px] font-medium text-rose-300 hover:bg-rose-500/20"
                      >
                        <ShieldBan className="h-3 w-3" />
                        Block
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={pendingConfirm !== null}
        title={
          pendingConfirm?.kind === "wol"
            ? `ส่ง Wake-on-LAN ไปยัง ${pendingConfirm.ip}?`
            : `ยืนยันการบล็อก IP ${pendingConfirm?.ip ?? ""}`
        }
        description={
          pendingConfirm?.kind === "wol"
            ? `ระบบจะส่ง Magic Packet ไปยัง MAC ${pendingConfirm.mac ?? ""} เพื่อเปิดเครื่องผ่านสาย LAN`
            : "หากระบบอยู่ในโหมด Dry-Run จะบันทึกการทดสอบลงฐานข้อมูลโดยไม่ตัดการเชื่อมต่อจริง แต่หากเปิด Live Enforce จะสั่งบล็อกผ่าน Firewall ทันที"
        }
        confirmLabel={pendingConfirm?.kind === "wol" ? "ส่ง Magic Packet" : "ยืนยัน Block IP"}
        danger={pendingConfirm?.kind === "block"}
        busy={busyAction}
        onConfirm={executeConfirm}
        onCancel={() => setPendingConfirm(null)}
      />
    </div>
  );
}
