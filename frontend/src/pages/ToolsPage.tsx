import { useEffect, useState, type FormEvent } from "react";
import { Cpu, Gauge, Globe, Loader2, Plus, RefreshCw, Route, Trash2, Wifi } from "lucide-react";
import { api } from "../api";
import type { HttpMonitor, ProcessConnection, TracerouteHop, WifiAnalysis } from "../types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState, ErrorState, LearnBanner, LoadingState } from "../components/StateViews";

export function ToolsPage() {
  // Process Connections
  const [connections, setConnections] = useState<ProcessConnection[]>([]);
  const [procSummary, setProcSummary] = useState<Array<{ process: string; count: number }>>([]);
  const [procError, setProcError] = useState<string | null>(null);

  // Wi-Fi Analyzer
  const [wifi, setWifi] = useState<WifiAnalysis | null>(null);

  // Traceroute & Speedtest
  const [traceTarget, setTraceTarget] = useState("1.1.1.1");
  const [tracing, setTracing] = useState(false);
  const [hops, setHops] = useState<TracerouteHop[]>([]);
  const [traceError, setTraceError] = useState<string | null>(null);

  const [testingSpeed, setTestingSpeed] = useState(false);
  const [speedResult, setSpeedResult] = useState<{
    latency_ms?: number;
    download_mbps?: number;
    duration_seconds?: number;
  } | null>(null);
  const [speedError, setSpeedError] = useState<string | null>(null);

  // HTTP / SSL Monitors
  const [monitors, setMonitors] = useState<HttpMonitor[]>([]);
  const [monName, setMonName] = useState("");
  const [monUrl, setMonUrl] = useState("");
  const [monError, setMonError] = useState<string | null>(null);
  const [checkingId, setCheckingId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<HttpMonitor | null>(null);

  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const loadAll = async (signal?: AbortSignal) => {
    setLoadError(null);
    try {
      const [procRes, wifiRes, monRes] = await Promise.all([
        api.getProcessConnections(120, signal),
        api.getWifiAnalysis(signal),
        api.listHttpMonitors(signal),
      ]);
      setConnections(procRes.connections);
      setProcSummary(procRes.process_summary);
      setProcError(procRes.error);
      setWifi(wifiRes);
      setMonitors(monRes.monitors);
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setLoadError(err instanceof Error ? err.message : "Failed to load diagnostic tools");
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const ctrl = new AbortController();
    loadAll(ctrl.signal);
    return () => ctrl.abort();
  }, []);

  const handleSpeedTest = async () => {
    setTestingSpeed(true);
    setSpeedError(null);
    try {
      const res = await api.runSpeedTest();
      if (!res.success) {
        setSpeedError(res.error ?? "Speed test failed");
      } else {
        setSpeedResult(res);
      }
    } catch (err) {
      setSpeedError(err instanceof Error ? err.message : "Speed test failed");
    } finally {
      setTestingSpeed(false);
    }
  };

  const handleTraceroute = async (e: FormEvent) => {
    e.preventDefault();
    if (!traceTarget.trim()) return;
    setTracing(true);
    setTraceError(null);
    try {
      const res = await api.runTraceroute(traceTarget.trim(), 15);
      setHops(res.hops);
      if (res.error) setTraceError(res.error);
    } catch (err) {
      setTraceError(err instanceof Error ? err.message : "Traceroute failed");
    } finally {
      setTracing(false);
    }
  };

  const handleAddMonitor = async (e: FormEvent) => {
    e.preventDefault();
    setMonError(null);
    if (!monName.trim() || !monUrl.trim()) {
      setMonError("กรุณาระบุชื่อและ URL (ขึ้นต้นด้วย http:// หรือ https://)");
      return;
    }
    try {
      await api.createHttpMonitor(monName.trim(), monUrl.trim());
      setMonName("");
      setMonUrl("");
      const res = await api.listHttpMonitors();
      setMonitors(res.monitors);
    } catch (err) {
      setMonError(err instanceof Error ? err.message : "Failed to add monitor");
    }
  };

  const handleCheckMonitor = async (id: number) => {
    setCheckingId(id);
    setMonError(null);
    try {
      await api.checkHttpMonitor(id);
      const res = await api.listHttpMonitors();
      setMonitors(res.monitors);
    } catch (err) {
      setMonError(err instanceof Error ? err.message : "Check failed");
    } finally {
      setCheckingId(null);
    }
  };

  const confirmDeleteMonitor = async () => {
    if (!deleteTarget) return;
    try {
      await api.deleteHttpMonitor(deleteTarget.id, true);
      setDeleteTarget(null);
      const res = await api.listHttpMonitors();
      setMonitors(res.monitors);
    } catch (err) {
      setMonError(err instanceof Error ? err.message : "Delete failed");
      setDeleteTarget(null);
    }
  };

  if (loading) return <LoadingState message="กำลังโหลดเครื่องมือตรวจเช็กระบบและเครือข่าย…" />;
  if (loadError) return <ErrorState message={loadError} onRetry={() => loadAll()} />;

  return (
    <div className="space-y-6">
      <LearnBanner
        title="Tools & Service Monitors (เครื่องมือตรวจเช็กเชิงลึก)"
        summary="ดูว่าโปรแกรมไหนในเครื่องกำลังต่อเน็ต (Process Sockets), วิเคราะห์สัญญาณและ Channel Wi-Fi รอบบ้าน, ทดสอบความเร็วเน็ต + Traceroute ทีละ Hop, และเช็กสถานะเว็บพร้อมวันหมดอายุใบรับรอง SSL"
      />

      {/* Row 1: Speedtest & Traceroute + Wi-Fi Analyzer */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Speedtest & Traceroute */}
        <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Gauge className="h-4 w-4 text-cyan-400" aria-hidden="true" />
              Internet Speed &amp; Traceroute Lab
            </h3>
            <button
              type="button"
              disabled={testingSpeed}
              onClick={handleSpeedTest}
              className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white transition-colors duration-150 hover:bg-cyan-500 disabled:opacity-50"
            >
              {testingSpeed && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
              {testingSpeed ? "กำลังทดสอบ…" : "Run Speed Test"}
            </button>
          </div>

          {speedError && <p className="text-rose-300">{speedError}</p>}
          {speedResult && (
            <div className="flex flex-wrap gap-4 rounded-lg bg-slate-950/70 p-3 font-mono tabular-nums">
              <span className="text-emerald-300">
                Download: <strong>{speedResult.download_mbps} Mbps</strong>
              </span>
              <span className="text-cyan-300">
                Latency: <strong>{speedResult.latency_ms} ms</strong>
              </span>
              <span className="text-slate-400">({speedResult.duration_seconds}s)</span>
            </div>
          )}

          <form onSubmit={handleTraceroute} className="flex items-end gap-2 border-t border-slate-800 pt-3">
            <div className="flex-1">
              <label htmlFor="trace-target" className="block text-[11px] font-medium text-slate-300">
                Traceroute Target (IP หรือ Domain)
              </label>
              <input
                id="trace-target"
                type="text"
                value={traceTarget}
                onChange={(e) => setTraceTarget(e.target.value)}
                placeholder="1.1.1.1"
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-slate-100"
              />
            </div>
            <button
              type="submit"
              disabled={tracing}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 font-semibold text-slate-200 transition-colors duration-150 hover:bg-slate-700 disabled:opacity-50"
            >
              {tracing ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Route className="h-3.5 w-3.5" aria-hidden="true" />}
              {tracing ? "Tracing…" : "Traceroute"}
            </button>
          </form>
          {traceError && <p className="text-rose-300">{traceError}</p>}

          {hops.length > 0 && (
            <div className="max-h-48 overflow-y-auto rounded-lg bg-slate-950/70 p-2 font-mono text-[11px] tabular-nums">
              {hops.map((h) => (
                <div key={h.hop} className="flex justify-between border-b border-slate-900 py-1">
                  <span className="text-slate-400">Hop {h.hop}</span>
                  <span className={h.timed_out ? "text-slate-500" : "text-cyan-300"} translate="no">
                    {h.ip}
                  </span>
                  <span className="text-emerald-300">
                    {h.rtt_ms !== null ? `${h.rtt_ms} ms` : "Timeout"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Wi-Fi Signal & Neighbor Channels */}
        <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
          <div className="flex items-center justify-between">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Wifi className="h-4 w-4 text-emerald-400" aria-hidden="true" />
              Wi-Fi Signal &amp; Nearby Channels
            </h3>
            <button
              type="button"
              onClick={() => loadAll()}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-slate-200 hover:bg-slate-700"
            >
              <RefreshCw className="h-3 w-3" aria-hidden="true" />
              Refresh
            </button>
          </div>

          {!wifi?.available ? (
            <EmptyState
              title="ไม่พบข้อมูล Wi-Fi Adapter"
              description={wifi?.note ?? "เครื่องนี้อาจเชื่อมต่อผ่านสาย LAN หรือระบบไม่มี WLAN interface"}
            />
          ) : (
            <>
              <div className="flex flex-wrap gap-3 rounded-lg bg-slate-950/70 p-3 font-mono tabular-nums">
                <span className="text-cyan-300" translate="no">
                  SSID: <strong>{wifi.current.ssid ?? "-"}</strong>
                </span>
                <span className="text-emerald-300">
                  Signal: <strong>{wifi.current.signal_pct ?? "-"}%</strong>
                </span>
                <span className="text-slate-300">Ch: {wifi.current.channel ?? "-"}</span>
                {wifi.current.rx_mbps && (
                  <span className="text-slate-400">Link: {wifi.current.rx_mbps} Mbps</span>
                )}
                <span className="text-amber-300">
                  แนะนำ 2.4G Ch: <strong>{wifi.recommended_24ghz_channel}</strong>
                </span>
              </div>

              <div className="max-h-48 overflow-y-auto">
                <table className="w-full text-left">
                  <thead className="border-b border-slate-800 text-slate-400">
                    <tr>
                      <th className="py-1.5 font-medium">SSID</th>
                      <th className="py-1.5 font-medium">Band / Ch</th>
                      <th className="py-1.5 text-right font-medium">Signal</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70 font-mono tabular-nums">
                    {wifi.neighbors.slice(0, 12).map((n, i) => (
                      <tr key={`${n.bssid}-${i}`}>
                        <td className="py-1.5 text-slate-200" translate="no">{n.ssid}</td>
                        <td className="py-1.5 text-slate-400">
                          {n.band} · Ch {n.channel ?? "-"}
                        </td>
                        <td className="py-1.5 text-right text-emerald-300">
                          {n.signal_pct !== null ? `${n.signal_pct}%` : "-"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Row 2: Process-to-Network Monitor */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Cpu className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            Local Process-to-Network Sockets ({connections.length})
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {procSummary.slice(0, 6).map((p) => (
              <span
                key={p.process}
                translate="no"
                className="rounded-md bg-slate-800 px-2 py-0.5 font-mono text-[11px] tabular-nums text-slate-200"
              >
                {p.process}: {p.count}
              </span>
            ))}
          </div>
        </div>

        {procError ? (
          <ErrorState message={procError} onRetry={() => loadAll()} />
        ) : connections.length === 0 ? (
          <EmptyState title="ไม่พบ Socket ที่เปิดอยู่" description="ลองกด Refresh อีกครั้ง" />
        ) : (
          <div className="max-h-72 overflow-y-auto">
            <table className="w-full text-left">
              <thead className="sticky top-0 border-b border-slate-800 bg-slate-900 text-slate-400">
                <tr>
                  <th className="py-2 pr-3 font-medium">Process</th>
                  <th className="py-2 pr-3 font-medium">Proto</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 pr-3 font-medium">Local Address</th>
                  <th className="py-2 font-medium">Remote Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 font-mono tabular-nums">
                {connections.slice(0, 60).map((c, idx) => (
                  <tr key={`${c.pid}-${c.local}-${c.remote}-${idx}`}>
                    <td className="py-1.5 pr-3 font-semibold text-cyan-300" translate="no">
                      {c.process} <span className="text-slate-500">({c.pid})</span>
                    </td>
                    <td className="py-1.5 pr-3 text-slate-300" translate="no">{c.protocol}</td>
                    <td className="py-1.5 pr-3 text-emerald-300" translate="no">{c.status}</td>
                    <td className="py-1.5 pr-3 text-slate-300" translate="no">{c.local}</td>
                    <td className="py-1.5 text-amber-300" translate="no">{c.remote}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Row 3: HTTP / SSL Certificate Uptime Monitor */}
      <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Globe className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          HTTP / SSL Certificate Uptime Monitor
        </h3>

        <form onSubmit={handleAddMonitor} className="grid grid-cols-1 items-end gap-3 sm:grid-cols-4">
          <div>
            <label htmlFor="http-mon-name" className="block text-[11px] font-medium text-slate-300">
              ชื่อบริการ / เว็บ
            </label>
            <input
              id="http-mon-name"
              type="text"
              value={monName}
              onChange={(e) => setMonName(e.target.value)}
              placeholder="เช่น Home Router / My Site"
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100"
            />
          </div>
          <div className="sm:col-span-2">
            <label htmlFor="http-mon-url" className="block text-[11px] font-medium text-slate-300">
              URL (http:// หรือ https://)
            </label>
            <input
              id="http-mon-url"
              type="url"
              value={monUrl}
              onChange={(e) => setMonUrl(e.target.value)}
              placeholder="https://example.com"
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-slate-100"
            />
          </div>
          <button
            type="submit"
            className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-2 font-semibold text-white transition-colors duration-150 hover:bg-cyan-500"
          >
            <Plus className="h-4 w-4" aria-hidden="true" />
            เพิ่ม Monitor
          </button>
        </form>

        {monError && <p className="text-rose-300">{monError}</p>}

        {monitors.length === 0 ? (
          <EmptyState
            title="ยังไม่มี HTTP / SSL Monitor"
            description="ลองเพิ่ม URL เว็บไซต์หรือหน้า Router (เช่น http://192.168.1.1) เพื่อเช็ก Latency และวันหมดอายุ SSL Certificate"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2 pr-3 font-medium">Name / URL</th>
                  <th className="py-2 pr-3 font-medium">HTTP Status</th>
                  <th className="py-2 pr-3 font-medium">Latency</th>
                  <th className="py-2 pr-3 font-medium">SSL Expiry</th>
                  <th className="py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 tabular-nums">
                {monitors.map((m) => (
                  <tr key={m.id}>
                    <td className="py-2 pr-3">
                      <div className="font-medium text-slate-100">{m.name}</div>
                      <div className="font-mono text-[11px] text-slate-400" translate="no">{m.url}</div>
                    </td>
                    <td className="py-2 pr-3 font-mono" translate="no">
                      {m.last_error ? (
                        <span className="text-rose-300">Error</span>
                      ) : m.last_status_code ? (
                        <span className={m.last_status_code < 400 ? "text-emerald-300" : "text-amber-300"}>
                          HTTP {m.last_status_code}
                        </span>
                      ) : (
                        <span className="text-slate-500">Not checked</span>
                      )}
                    </td>
                    <td className="py-2 pr-3 font-mono text-slate-300">
                      {m.last_latency_ms !== null ? `${m.last_latency_ms} ms` : "-"}
                    </td>
                    <td className="py-2 pr-3 font-mono">
                      {m.ssl_days_remaining !== null ? (
                        <span className={m.ssl_days_remaining < 14 ? "text-rose-300" : "text-emerald-300"}>
                          {m.ssl_days_remaining} วัน ({m.ssl_issuer || "TLS"})
                        </span>
                      ) : (
                        <span className="text-slate-500">-</span>
                      )}
                    </td>
                    <td className="py-2 text-right">
                      <div className="inline-flex gap-1.5">
                        <button
                          type="button"
                          disabled={checkingId === m.id}
                          onClick={() => handleCheckMonitor(m.id)}
                          className="rounded border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[11px] text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50"
                        >
                          {checkingId === m.id ? "Checking…" : "Check Now"}
                        </button>
                        <button
                          type="button"
                          onClick={() => setDeleteTarget(m)}
                          aria-label={`ลบ monitor ${m.name}`}
                          className="rounded border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/20"
                        >
                          <Trash2 className="h-3 w-3" aria-hidden="true" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={deleteTarget !== null}
        title={`ยืนยันการลบ ${deleteTarget?.name ?? ""}`}
        description={`ต้องการลบตัวเฝ้าดู ${deleteTarget?.url ?? ""} ออกจากระบบหรือไม่?`}
        confirmLabel="ลบ Monitor"
        onConfirm={confirmDeleteMonitor}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}
