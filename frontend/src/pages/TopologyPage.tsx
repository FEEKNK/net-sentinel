import { useEffect, useState } from "react";
import { Power, ShieldAlert, ShieldBan, ShieldCheck } from "lucide-react";
import { api } from "../api";
import type { DeviceHistoryPoint, DeviceRecord } from "../types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState, ErrorState, LearnBanner, LoadingState } from "../components/StateViews";

interface TopologyPageProps {
  devices: DeviceRecord[];
  gatewayIp: string | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export function TopologyPage({
  devices,
  gatewayIp,
  loading,
  error,
  onRefresh,
}: TopologyPageProps) {
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [history, setHistory] = useState<DeviceHistoryPoint[]>([]);
  const [customName, setCustomName] = useState("");
  const [feedback, setFeedback] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<"wol" | "block" | null>(null);
  const [busy, setBusy] = useState(false);

  const selectedDevice = devices.find((d) => d.ip === selectedIp) ?? devices[0] ?? null;

  useEffect(() => {
    if (!selectedDevice) return;
    setCustomName(selectedDevice.custom_name || "");
    const ctrl = new AbortController();
    api
      .getDeviceHistory(selectedDevice.ip, 30, ctrl.signal)
      .then((res) => setHistory(res.history))
      .catch(() => setHistory([]));
    return () => ctrl.abort();
  }, [selectedDevice?.ip]);

  if (error) return <ErrorState message={error} onRetry={onRefresh} />;
  if (loading) return <LoadingState />;
  if (devices.length === 0) {
    return (
      <EmptyState
        title="ยังไม่มีอุปกรณ์สำหรับวาดแผนผังเครือข่าย"
        description="ไปที่หน้า IP Scanner เพื่อกดสแกนวง LAN ของคุณก่อน แล้วกลับมาดูแผนผังที่นี่"
      />
    );
  }

  const width = 620;
  const height = 440;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(165, Math.max(120, 100 + devices.length * 4));

  const saveMetadata = async (trustedOverride?: boolean) => {
    if (!selectedDevice) return;
    setBusy(true);
    setActionError(null);
    setFeedback(null);
    try {
      await api.updateDevice(selectedDevice.ip, {
        custom_name: customName,
        trusted: trustedOverride ?? selectedDevice.trusted,
      });
      setFeedback(`อัปเดตข้อมูล ${selectedDevice.ip} เรียบร้อย`);
      onRefresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setBusy(false);
    }
  };

  const executeConfirmed = async () => {
    if (!selectedDevice || !confirmAction) return;
    setBusy(true);
    setActionError(null);
    setFeedback(null);
    try {
      if (confirmAction === "wol") {
        const res = await api.sendWakeOnLan(selectedDevice.ip, true);
        setFeedback(`ส่ง Magic Packet (Wake-on-LAN) ไปยัง ${res.mac} ผ่าน ${res.broadcast} แล้ว`);
      } else {
        const res = await api.blockIp(selectedDevice.ip, "Blocked from Topology Map", true);
        setFeedback(res.message);
      }
      setConfirmAction(null);
      onRefresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Action failed");
      setConfirmAction(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <LearnBanner
        title="Interactive Network Topology Map (แผนผังวง LAN)"
        summary="แสดง Router (Gateway) อยู่ตรงกลาง โยงเส้นไปหาทุกอุปกรณ์ในวง: สีเขียว = Trusted และออนไลน์, สีส้ม = อุปกรณ์ใหม่ที่ยังไม่ยืนยัน Trusted, สีเทา = ออฟไลน์ กดคลิกที่จุดวงกลมเพื่อดู Latency ย้อนหลัง ตั้งชื่อ หรือสั่ง Wake-on-LAN"
      />

      {feedback && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 px-4 py-2 text-xs text-emerald-200">
          {feedback}
        </div>
      )}
      {actionError && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-2 text-xs text-rose-200">
          {actionError}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* SVG Map */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 lg:col-span-2">
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="h-[420px] w-full rounded-lg bg-slate-950/80"
            role="img"
            aria-label="LAN Network Topology Map"
          >
            {/* Spoke lines */}
            {devices.slice(0, 28).map((dev, idx, arr) => {
              const angle = (2 * Math.PI * idx) / arr.length - Math.PI / 2;
              const x = cx + radius * Math.cos(angle);
              const y = cy + radius * Math.sin(angle);
              const online = dev.status === "online";
              return (
                <line
                  key={`line-${dev.ip}`}
                  x1={cx}
                  y1={cy}
                  x2={x}
                  y2={y}
                  stroke={online ? (dev.trusted ? "#10b981" : "#f59e0b") : "#334155"}
                  strokeWidth={selectedDevice?.ip === dev.ip ? 2.5 : 1.4}
                  strokeDasharray={online ? undefined : "4 4"}
                  opacity={0.75}
                />
              );
            })}

            {/* Center Gateway Node */}
            <g>
              <circle cx={cx} cy={cy} r={30} fill="#0f172a" stroke="#22d3ee" strokeWidth={2.5} />
              <text x={cx} y={cy - 3} textAnchor="middle" fill="#67e8f9" fontSize="10" fontWeight="bold">
                GATEWAY
              </text>
              <text x={cx} y={cy + 11} textAnchor="middle" fill="#cbd5e1" fontSize="9">
                {gatewayIp ?? "LAN Hub"}
              </text>
            </g>

            {/* Device Nodes */}
            {devices.slice(0, 28).map((dev, idx, arr) => {
              const angle = (2 * Math.PI * idx) / arr.length - Math.PI / 2;
              const x = cx + radius * Math.cos(angle);
              const y = cy + radius * Math.sin(angle);
              const isSelected = selectedDevice?.ip === dev.ip;
              const fill =
                dev.status !== "online"
                  ? "#1e293b"
                  : dev.trusted
                    ? "#064e3b"
                    : "#451a03";
              const stroke =
                dev.status !== "online"
                  ? "#64748b"
                  : dev.trusted
                    ? "#34d399"
                    : "#fbbf24";
              const label = dev.custom_name || dev.hostname || dev.ip;

              return (
                <g
                  key={`node-${dev.ip}`}
                  className="cursor-pointer"
                  onClick={() => setSelectedIp(dev.ip)}
                >
                  <circle
                    cx={x}
                    cy={y}
                    r={isSelected ? 21 : 17}
                    fill={fill}
                    stroke={isSelected ? "#22d3ee" : stroke}
                    strokeWidth={isSelected ? 3 : 2}
                  />
                  <text x={x} y={y + 3} textAnchor="middle" fill="#f8fafc" fontSize="8.5" fontWeight="bold">
                    .{dev.ip.split(".").pop()}
                  </text>
                  <text x={x} y={y + 30} textAnchor="middle" fill="#cbd5e1" fontSize="9">
                    {label.length > 14 ? `${label.slice(0, 13)}…` : label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Node Inspector */}
        {selectedDevice && (
          <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-mono text-base font-bold text-cyan-300">{selectedDevice.ip}</h3>
                <p className="text-slate-400">{selectedDevice.vendor}</p>
              </div>
              <button
                type="button"
                disabled={busy}
                onClick={() => saveMetadata(!selectedDevice.trusted)}
                className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 font-semibold ${
                  selectedDevice.trusted
                    ? "bg-emerald-500/15 text-emerald-300"
                    : "bg-amber-500/15 text-amber-300"
                }`}
              >
                {selectedDevice.trusted ? (
                  <>
                    <ShieldCheck className="h-3.5 w-3.5" /> Trusted
                  </>
                ) : (
                  <>
                    <ShieldAlert className="h-3.5 w-3.5" /> Untrusted
                  </>
                )}
              </button>
            </div>

            <div className="space-y-1 rounded-lg bg-slate-950/70 p-3 font-mono text-[11px] text-slate-300">
              <div>MAC: {selectedDevice.mac || "-"}</div>
              <div>Hostname: {selectedDevice.hostname || "-"}</div>
              <div>Uptime: {selectedDevice.uptime_pct ?? 100}%</div>
              <div>
                Latency: {selectedDevice.latency_ms !== null ? `${selectedDevice.latency_ms} ms` : "-"}
              </div>
            </div>

            <div className="space-y-2">
              <label htmlFor="topo-custom-name" className="block font-medium text-slate-300">
                ชื่อเล่นอุปกรณ์ (Custom Name)
              </label>
              <div className="flex gap-2">
                <input
                  id="topo-custom-name"
                  type="text"
                  value={customName}
                  onChange={(e) => setCustomName(e.target.value)}
                  placeholder="เช่น iPhone ของฉัน / Router"
                  className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => saveMetadata()}
                  className="rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
                >
                  บันทึก
                </button>
              </div>
            </div>

            {/* Latency History mini bar */}
            <div>
              <p className="mb-1.5 font-medium text-slate-300">
                ประวัติ Latency ล่าสุด ({history.length} จุด)
              </p>
              {history.length === 0 ? (
                <p className="text-slate-500">ยังไม่มีประวัติการสแกนย้อนหลัง</p>
              ) : (
                <div className="flex h-14 items-end gap-1 rounded bg-slate-950 p-2">
                  {history.slice(-20).map((pt) => {
                    const online = pt.status === "online";
                    const pct = pt.latency_ms
                      ? Math.min(100, Math.max(15, (pt.latency_ms / 100) * 100))
                      : 20;
                    return (
                      <div
                        key={pt.id}
                        title={`${pt.status} ${pt.latency_ms ?? "-"} ms`}
                        style={{ height: `${online ? pct : 100}%` }}
                        className={`flex-1 rounded-xs ${
                          online ? "bg-cyan-400/80" : "bg-rose-500/50"
                        }`}
                      />
                    );
                  })}
                </div>
              )}
            </div>

            <div className="flex gap-2 pt-2">
              <button
                type="button"
                disabled={!selectedDevice.mac}
                onClick={() => setConfirmAction("wol")}
                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 py-2 font-semibold text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-40"
              >
                <Power className="h-3.5 w-3.5" />
                Wake-on-LAN
              </button>
              <button
                type="button"
                onClick={() => setConfirmAction("block")}
                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 py-2 font-semibold text-rose-300 hover:bg-rose-500/20"
              >
                <ShieldBan className="h-3.5 w-3.5" />
                Block IP
              </button>
            </div>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmAction !== null}
        title={
          confirmAction === "wol"
            ? `ส่ง Wake-on-LAN ไปยัง ${selectedDevice?.ip ?? ""}?`
            : `ยืนยันการบล็อก IP ${selectedDevice?.ip ?? ""}?`
        }
        description={
          confirmAction === "wol"
            ? `ระบบจะส่ง Magic Packet (UDP Port 9) ไปยัง MAC ${selectedDevice?.mac ?? ""} เพื่อปลุกเครื่องในวง LAN`
            : "ระบบจะใช้การบล็อกตามนโยบาย Firewall ปัจจุบัน (Dry-Run หรือ Live Enforce)"
        }
        danger={confirmAction === "block"}
        busy={busy}
        onConfirm={executeConfirmed}
        onCancel={() => setConfirmAction(null)}
      />
    </div>
  );
}
