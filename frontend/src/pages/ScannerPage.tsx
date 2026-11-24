import { useEffect, useState, type FormEvent } from "react";
import { Loader2, Radar, ShieldBan } from "lucide-react";
import { api } from "../api";
import type { DeviceRecord } from "../types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState, ErrorState, LearnBanner, LoadingState } from "../components/StateViews";

interface ScannerPageProps {
  devices: DeviceRecord[];
  defaultSubnet: string;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export function ScannerPage({
  devices,
  defaultSubnet,
  loading,
  error,
  onRefresh,
}: ScannerPageProps) {
  const [cidr, setCidr] = useState(defaultSubnet || "192.168.1.0/24");
  const [cidrDirty, setCidrDirty] = useState(false);

  useEffect(() => {
    if (!cidrDirty && defaultSubnet) {
      setCidr(defaultSubnet);
    }
  }, [defaultSubnet, cidrDirty]);
  const [scanPorts, setScanPorts] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [blockTarget, setBlockTarget] = useState<string | null>(null);
  const [blocking, setBlocking] = useState(false);

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
      const res = await api.scanSubnet(cidr.trim(), scanPorts);
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

  const confirmBlock = async () => {
    if (!blockTarget) return;
    setBlocking(true);
    setScanError(null);
    try {
      const res = await api.blockIp(
        blockTarget,
        "Blocked manually from IP Scanner device table",
        true
      );
      setScanMessage(res.message);
      setBlockTarget(null);
      onRefresh();
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Block failed");
      setBlockTarget(null);
    } finally {
      setBlocking(false);
    }
  };

  return (
    <div className="space-y-5">
      <LearnBanner
        title="IP & Subnet Scanner (สมุดเช็กชื่อคนในซอย)"
        summary="ส่ง ARP/Ping ออกไปถามทุกบ้านเลขที่ในวง Subnet เพื่อดูว่าเครื่องไหนเปิดใช้งานอยู่ ได้เลข MAC Address (เลขประจำตัวการ์ดแลน), ยี่ห้ออุปกรณ์ (OUI Vendor), Latency (ความไวในการตอบกลับ) และพอร์ตที่เปิดประตูทิ้งไว้"
      />

      <form
        onSubmit={handleScan}
        className="flex flex-wrap items-end gap-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4"
      >
        <div className="min-w-[220px] flex-1">
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

        <label className="inline-flex cursor-pointer items-center gap-2 pb-2 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={scanPorts}
            onChange={(e) => setScanPorts(e.target.checked)}
            className="h-4 w-4 rounded border-slate-700 bg-slate-950 text-cyan-500"
          />
          สแกน Common TCP Ports ด้วย (22, 80, 443, 445, 3389...)
        </label>

        <button
          type="submit"
          disabled={scanning}
          className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
          {scanning ? "กำลังสแกนทั้งวง..." : "Scan Now"}
        </button>
      </form>

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
                <th className="px-4 py-3 font-medium">IP Address</th>
                <th className="px-4 py-3 font-medium">Hostname</th>
                <th className="px-4 py-3 font-medium">MAC / Vendor</th>
                <th className="px-4 py-3 font-medium">Latency</th>
                <th className="px-4 py-3 font-medium">Open Ports</th>
                <th className="px-4 py-3 text-right font-medium">Action</th>
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
                  <td className="px-4 py-3 font-mono font-semibold text-cyan-300">{dev.ip}</td>
                  <td className="max-w-[180px] truncate px-4 py-3 text-slate-200">
                    {dev.hostname || "-"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-mono text-slate-300">{dev.mac || "-"}</div>
                    <div className="text-[11px] text-slate-500">{dev.vendor}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-300">
                    {dev.latency_ms !== null ? `${dev.latency_ms} ms` : "-"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {dev.open_ports.length === 0 ? (
                        <span className="text-slate-500">None</span>
                      ) : (
                        dev.open_ports.map((p) => (
                          <span
                            key={`${dev.ip}-${p.port}`}
                            className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] text-amber-300"
                          >
                            {p.port}/{p.service}
                          </span>
                        ))
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => setBlockTarget(dev.ip)}
                      aria-label={`บล็อก IP ${dev.ip}`}
                      className="inline-flex items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 text-[11px] font-medium text-rose-300 hover:bg-rose-500/20"
                    >
                      <ShieldBan className="h-3 w-3" />
                      Block
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={blockTarget !== null}
        title={`ยืนยันการบล็อก IP ${blockTarget ?? ""}`}
        description="หากระบบอยู่ในโหมด Dry-Run จะบันทึกการทดสอบลงฐานข้อมูลโดยไม่ตัดการเชื่อมต่อจริง แต่หากเปิด Live Enforce จะสั่งบล็อกผ่าน Firewall ทันที (IP เครื่องตัวเองและ Gateway จะถูกป้องกันโดย Whitelist เสมอ)"
        confirmLabel="ยืนยัน Block IP"
        busy={blocking}
        onConfirm={confirmBlock}
        onCancel={() => setBlockTarget(null)}
      />
    </div>
  );
}
