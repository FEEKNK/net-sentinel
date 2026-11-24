import { useEffect, useState, type FormEvent } from "react";
import { Plus, RefreshCw, Trash2 } from "lucide-react";
import { api } from "../api";
import type { SnmpMetric, SnmpTarget } from "../types";
import { BandwidthChart, formatBps } from "../components/BandwidthChart";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState, ErrorState, LearnBanner, LoadingState } from "../components/StateViews";

interface SnmpPageProps {
  metrics: SnmpMetric[];
  onMetricsUpdated: () => void;
}

export function SnmpPage({ metrics, onMetricsUpdated }: SnmpPageProps) {
  const [targets, setTargets] = useState<SnmpTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [community, setCommunity] = useState("public");
  const [port, setPort] = useState("161");
  const [submitting, setSubmitting] = useState(false);
  const [polling, setPolling] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SnmpTarget | null>(null);

  const loadTargets = async (signal?: AbortSignal) => {
    setError(null);
    try {
      const data = await api.listSnmpTargets(signal);
      setTargets(data.targets);
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError(err instanceof Error ? err.message : "Failed to load SNMP targets");
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const ctrl = new AbortController();
    loadTargets(ctrl.signal);
    return () => ctrl.abort();
  }, []);

  const handleAddTarget = async (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !host.trim()) {
      setError("กรุณากรอกชื่ออุปกรณ์และ Host IP");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await api.createSnmpTarget({
        name: name.trim(),
        host: host.trim(),
        community: community.trim() || "public",
        port: Number(port) || 161,
      });
      setName("");
      setHost("");
      await loadTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add SNMP target");
    } finally {
      setSubmitting(false);
    }
  };

  const handlePollNow = async () => {
    setPolling(true);
    setError(null);
    try {
      await api.pollSnmpNow();
      onMetricsUpdated();
      await loadTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Poll failed");
    } finally {
      setPolling(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setSubmitting(true);
    try {
      await api.deleteSnmpTarget(deleteTarget.id, true);
      setDeleteTarget(null);
      await loadTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
      setDeleteTarget(null);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <LearnBanner
        title="SNMP & Bandwidth Monitoring (มิเตอร์วัดความเร็ว Router/Switch)"
        summary="โปรโตคอล SNMP ช่วยให้เราส่งคำถามไปขอดูค่า Bandwidth (ifInOctets/ifOutOctets) ของ Router/Switch ในองค์กรได้ ส่วนเครื่องที่ไม่ได้ต่อ Router SNMP ระบบจะวัดความเร็วการ์ดแลน (NIC) พร้อม CPU/RAM ของเครื่องนี้ให้ดูแบบ Real-time"
      />

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-100">
            Bandwidth History (Local NIC & SNMP Targets)
          </h3>
          <button
            type="button"
            disabled={polling}
            onClick={handlePollNow}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${polling ? "animate-spin" : ""}`} />
            Poll Now
          </button>
        </div>
        <BandwidthChart metrics={metrics} />
      </div>

      {/* Add SNMP Target */}
      <form
        onSubmit={handleAddTarget}
        className="grid grid-cols-1 gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4 sm:grid-cols-5"
      >
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="ชื่ออุปกรณ์ (เช่น Core-Router)"
          aria-label="SNMP target name"
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100"
        />
        <input
          type="text"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="Host IP (เช่น 192.168.1.1)"
          aria-label="SNMP target host"
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-100"
        />
        <input
          type="text"
          value={community}
          onChange={(e) => setCommunity(e.target.value)}
          placeholder="Community (public)"
          aria-label="SNMP community"
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-100"
        />
        <input
          type="number"
          value={port}
          onChange={(e) => setPort(e.target.value)}
          placeholder="Port (161)"
          aria-label="SNMP port"
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-100"
        />
        <button
          type="submit"
          disabled={submitting}
          className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-2 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
        >
          <Plus className="h-4 w-4" />
          เพิ่ม SNMP Target
        </button>
      </form>

      {error && <ErrorState message={error} onRetry={() => loadTargets()} />}

      {loading ? (
        <LoadingState />
      ) : targets.length === 0 ? (
        <EmptyState
          title="ยังไม่มี SNMP Target ภายนอก"
          description="ตอนนี้ระบบกำลังวัดค่า Local Host NIC ให้ดูอัตโนมัติ หรือเพิ่ม Router/Switch ที่เปิด SNMPv2c ด้านบนได้"
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/70">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">Name</th>
                <th className="px-4 py-3 font-medium">Host:Port</th>
                <th className="px-4 py-3 font-medium">Runtime Status</th>
                <th className="px-4 py-3 text-right font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {targets.map((t) => (
                <tr key={t.id}>
                  <td className="px-4 py-3 font-medium text-slate-100">{t.name}</td>
                  <td className="px-4 py-3 font-mono text-slate-300">
                    {t.host}:{t.port}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded px-2 py-0.5 text-[11px] font-medium ${
                        t.runtime?.status === "online"
                          ? "bg-emerald-500/15 text-emerald-300"
                          : t.runtime?.status === "error"
                            ? "bg-rose-500/15 text-rose-300"
                            : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {t.runtime?.status ?? "idle"}
                      {t.runtime?.message ? ` (${t.runtime.message})` : ""}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => setDeleteTarget(t)}
                      aria-label={`ลบ SNMP target ${t.name}`}
                      className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 text-[11px] text-rose-300 hover:bg-rose-500/20"
                    >
                      <Trash2 className="h-3 w-3" />
                      ลบ
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Latest Metric Samples */}
      {metrics.length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h4 className="mb-2 text-xs font-semibold text-slate-300">ค่าล่าสุดในฐานข้อมูล (5 รายการ)</h4>
          <div className="space-y-1.5 text-xs">
            {metrics
              .slice(-5)
              .reverse()
              .map((m) => (
                <div
                  key={m.id}
                  className="flex flex-wrap items-center justify-between rounded bg-slate-950/60 px-3 py-1.5 font-mono text-[11px]"
                >
                  <span className="text-slate-200">{m.target_name} ({m.source_type})</span>
                  <span className="text-cyan-300">
                    In: {formatBps(m.in_bps)} | Out: {formatBps(m.out_bps)}
                  </span>
                </div>
              ))}
          </div>
        </div>
      )}

      <ConfirmDialog
        open={deleteTarget !== null}
        title={`ยืนยันการลบ ${deleteTarget?.name ?? ""}`}
        description={`ต้องการลบ SNMP Target (${deleteTarget?.host ?? ""}) ออกจากระบบหรือไม่?`}
        confirmLabel="ลบ Target"
        busy={submitting}
        onConfirm={confirmDelete}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}
