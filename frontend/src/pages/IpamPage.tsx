import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Activity, GitCompare, Grid, Play, Plus, Radio, RefreshCw, Square, Trash2 } from "lucide-react";
import { api } from "../api";
import type { ConfigSnapshot, IpamGrid, NetFlowSummary, SnmpTrapsResponse } from "../types";
import { EmptyState, ErrorState, LearnBanner, LoadingState } from "../components/StateViews";

interface IpamPageProps {
  defaultSubnet: string;
}

type SectionTab = "ipam" | "netflow" | "traps" | "drift";

export function IpamPage({ defaultSubnet }: IpamPageProps) {
  const [section, setSection] = useState<SectionTab>("ipam");

  // IPAM state
  const [cidr, setCidr] = useState(defaultSubnet || "192.168.1.0/24");
  const [ipam, setIpam] = useState<IpamGrid | null>(null);
  const [resIp, setResIp] = useState("");
  const [resHost, setResHost] = useState("");
  const [resMac, setResMac] = useState("");
  const [resNote, setResNote] = useState("");

  // NetFlow & Traps state
  const [netflow, setNetflow] = useState<NetFlowSummary | null>(null);
  const [traps, setTraps] = useState<SnmpTrapsResponse | null>(null);

  // Snapshots & Drift state
  const [snapshots, setSnapshots] = useState<ConfigSnapshot[]>([]);
  const [snapName, setSnapName] = useState("");
  const [diffA, setDiffA] = useState<string>("");
  const [diffB, setDiffB] = useState<string>("");
  const [diffResult, setDiffResult] = useState<{ drifted: boolean; diff: string } | null>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  const loadAll = useCallback(async (signal?: AbortSignal) => {
    setError(null);
    try {
      const [ipamData, nfData, trapData, snapData] = await Promise.all([
        api.getIpamGrid(cidr.trim() || undefined, signal),
        api.getNetFlow(signal),
        api.getSnmpTraps(signal),
        api.listSnapshots(signal),
      ]);
      setIpam(ipamData);
      setNetflow(nfData);
      setTraps(trapData);
      setSnapshots(snapData.snapshots);
      if (snapData.snapshots.length >= 2) {
        setDiffB((prev) => prev || String(snapData.snapshots[0].id));
        setDiffA((prev) => prev || String(snapData.snapshots[1].id));
      } else if (snapData.snapshots.length === 1) {
        setDiffA((prev) => prev || String(snapData.snapshots[0].id));
        setDiffB((prev) => prev || String(snapData.snapshots[0].id));
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError(err instanceof Error ? err.message : "Failed to load network engineering data");
      }
    } finally {
      setLoading(false);
    }
  }, [cidr]);

  useEffect(() => {
    const ctrl = new AbortController();
    loadAll(ctrl.signal);
    return () => ctrl.abort();
  }, [loadAll]);

  const handleReserve = async (e: FormEvent) => {
    e.preventDefault();
    if (!resIp.trim()) return;
    setError(null);
    setFeedback(null);
    try {
      await api.reserveIp({
        ip: resIp.trim(),
        hostname: resHost.trim(),
        mac: resMac.trim(),
        note: resNote.trim(),
      });
      setFeedback(`จอง IP ${resIp.trim()} สำเร็จ`);
      setResIp("");
      setResHost("");
      setResMac("");
      setResNote("");
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reserve IP");
    }
  };

  const handleRelease = async (ip: string) => {
    setError(null);
    try {
      await api.releaseIpReservation(ip);
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to release reservation");
    }
  };

  const handleCreateSnapshot = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setFeedback(null);
    try {
      const snap = await api.createSnapshot(snapName.trim() || "Manual Snapshot");
      setSnapName("");
      setFeedback(`บันทึก Snapshot #${snap.id} (${snap.name}) เรียบร้อย`);
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create snapshot");
    }
  };

  const handleCompareDiff = async () => {
    if (!diffA || !diffB) return;
    setError(null);
    try {
      const res = await api.diffSnapshots(Number(diffA), Number(diffB));
      setDiffResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Diff failed");
    }
  };

  const slotColor = (state: string) => {
    if (state === "online") return "border-emerald-500/50 bg-emerald-500/20 text-emerald-200";
    if (state === "reserved") return "border-sky-500/50 bg-sky-500/20 text-sky-200";
    if (state === "offline") return "border-amber-500/40 bg-amber-500/15 text-amber-200";
    return "border-slate-800 bg-slate-950/60 text-slate-500 hover:border-slate-600";
  };

  return (
    <div className="space-y-6">
      <LearnBanner
        title="IPAM, NetFlow v5, SNMP Traps & Config Drift"
        summary="จัดการ IP Reservation ป้องกัน IP ชนกัน, รับสถิติ NetFlow จาก Router (UDP 2055), รับ SNMP Trap แจ้งเตือนฉุกเฉิน (UDP 1162) และบันทึก Configuration Snapshot เพื่อตรวจหาการเปลี่ยนแปลง (Drift)"
      />

      {/* Section switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2">
          {(
            [
              { id: "ipam", label: "IPAM Subnet Grid", icon: Grid },
              { id: "netflow", label: "NetFlow v5 (UDP 2055)", icon: Activity },
              { id: "traps", label: "SNMP Traps (UDP 1162)", icon: Radio },
              { id: "drift", label: "Config Snapshot & Drift", icon: GitCompare },
            ] as const
          ).map((item) => {
            const Icon = item.icon;
            const active = section === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setSection(item.id)}
                className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium ${
                  active
                    ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-200"
                    : "border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800"
                }`}
              >
                <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                {item.label}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          onClick={() => loadAll()}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-700"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
          รีเฟรช
        </button>
      </div>

      {error && <ErrorState message={error} onRetry={() => loadAll()} />}
      {feedback && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-xs text-emerald-200">
          {feedback}
        </div>
      )}

      {loading ? (
        <LoadingState />
      ) : (
        <>
          {section === "ipam" && ipam && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-end justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    loadAll();
                  }}
                  className="flex flex-wrap items-end gap-2"
                >
                  <div>
                    <label htmlFor="ipam-cidr" className="block text-[11px] font-medium text-slate-300">
                      Subnet CIDR
                    </label>
                    <input
                      id="ipam-cidr"
                      type="text"
                      value={cidr}
                      onChange={(e) => setCidr(e.target.value)}
                      className="mt-1 w-48 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100"
                    />
                  </div>
                  <button
                    type="submit"
                    className="rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500"
                  >
                    แสดง Grid
                  </button>
                </form>

                <div className="flex flex-wrap items-center gap-4 text-xs tabular-nums">
                  <span className="text-slate-300">
                    Usage: <strong className="text-cyan-300">{ipam.utilization_pct}%</strong>
                  </span>
                  <span className="text-emerald-300">Online: {ipam.counts.online}</span>
                  <span className="text-sky-300">Reserved: {ipam.counts.reserved}</span>
                  <span className="text-amber-300">Offline Known: {ipam.counts.offline}</span>
                  <span className="text-slate-400">Free: {ipam.counts.free}</span>
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <p className="mb-2 text-xs text-slate-400">
                  คลิกที่ช่อง IP เพื่อดึงข้อมูลลงฟอร์มจองด้านล่าง ({ipam.slots.length} hosts)
                </p>
                <div className="grid grid-cols-8 gap-1 sm:grid-cols-16">
                  {ipam.slots.map((slot) => {
                    const lastOctet = slot.ip.split(".").pop();
                    return (
                      <button
                        key={slot.ip}
                        type="button"
                        onClick={() => {
                          setResIp(slot.ip);
                          setResHost(slot.hostname);
                          setResMac(slot.mac);
                          setResNote(slot.note);
                        }}
                        title={`${slot.ip} [${slot.state}] ${slot.hostname}`}
                        className={`rounded border py-1 text-center font-mono text-[11px] tabular-nums ${slotColor(slot.state)}`}
                      >
                        <span translate="no">.{lastOctet}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              <form
                onSubmit={handleReserve}
                className="grid grid-cols-1 items-end gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4 sm:grid-cols-5"
              >
                <div>
                  <label htmlFor="res-ip" className="block text-[11px] font-medium text-slate-300">
                    Reserve IP
                  </label>
                  <input
                    id="res-ip"
                    type="text"
                    value={resIp}
                    onChange={(e) => setResIp(e.target.value)}
                    placeholder="192.168.1.50"
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="res-host" className="block text-[11px] font-medium text-slate-300">
                    Hostname / Label
                  </label>
                  <input
                    id="res-host"
                    type="text"
                    value={resHost}
                    onChange={(e) => setResHost(e.target.value)}
                    placeholder="nurse-station-01"
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="res-mac" className="block text-[11px] font-medium text-slate-300">
                    MAC Address
                  </label>
                  <input
                    id="res-mac"
                    type="text"
                    value={resMac}
                    onChange={(e) => setResMac(e.target.value)}
                    placeholder="AA:BB:CC:DD:EE:FF"
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="res-note" className="block text-[11px] font-medium text-slate-300">
                    Note
                  </label>
                  <input
                    id="res-note"
                    type="text"
                    value={resNote}
                    onChange={(e) => setResNote(e.target.value)}
                    placeholder="Static DHCP"
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100"
                  />
                </div>
                <button
                  type="submit"
                  className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500"
                >
                  <Plus className="h-3.5 w-3.5" />
                  จอง IP นี้
                </button>
              </form>

              {ipam.reservations.length > 0 && (
                <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/70">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-slate-400">
                      <tr>
                        <th className="px-4 py-2.5">IP</th>
                        <th className="px-4 py-2.5">Hostname</th>
                        <th className="px-4 py-2.5">MAC</th>
                        <th className="px-4 py-2.5">Note</th>
                        <th className="px-4 py-2.5 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {ipam.reservations.map((r) => (
                        <tr key={r.ip}>
                          <td translate="no" className="px-4 py-2 font-mono text-sky-300 tabular-nums">{r.ip}</td>
                          <td className="px-4 py-2 text-slate-200">{r.hostname || "-"}</td>
                          <td translate="no" className="px-4 py-2 font-mono text-slate-400">{r.mac || "-"}</td>
                          <td className="px-4 py-2 text-slate-400">{r.note || "-"}</td>
                          <td className="px-4 py-2 text-right">
                            <button
                              type="button"
                              onClick={() => handleRelease(r.ip)}
                              className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 text-[11px] text-rose-300 hover:bg-rose-500/20"
                            >
                              <Trash2 className="h-3 w-3" />
                              ยกเลิกจอง
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {section === "netflow" && netflow && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="text-xs text-slate-300">
                  NetFlow v5 Collector UDP Port <span translate="no" className="font-mono text-cyan-300">{netflow.status.port}</span>{" "}
                  — สถานะ:{" "}
                  <strong className={netflow.status.running ? "text-emerald-300" : "text-slate-400"}>
                    {netflow.status.running ? `กำลังฟังข้อมูล (${netflow.status.flow_count} flows)` : "หยุดทำงาน"}
                  </strong>
                  {netflow.status.last_error && (
                    <span className="ml-2 text-rose-300">({netflow.status.last_error})</span>
                  )}
                </div>
                <div className="flex gap-2">
                  {netflow.status.running ? (
                    <button
                      type="button"
                      onClick={async () => {
                        await api.stopNetFlow();
                        await loadAll();
                      }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-500/15 px-3 py-1.5 text-xs font-medium text-rose-200"
                    >
                      <Square className="h-3.5 w-3.5" />
                      Stop Collector
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={async () => {
                        await api.startNetFlow(2055);
                        await loadAll();
                      }}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500"
                    >
                      <Play className="h-3.5 w-3.5" />
                      Start NetFlow UDP 2055
                    </button>
                  )}
                </div>
              </div>

              {netflow.top_conversations.length === 0 ? (
                <EmptyState
                  title="ยังไม่มีข้อมูล NetFlow v5"
                  description="เปิดปุ่ม Start ด้านบน แล้วตั้งค่า Router/MikroTik/Switch ให้ Export NetFlow v5 มายัง IP เครื่องนี้พอร์ต UDP 2055"
                />
              ) : (
                <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/70">
                  <table className="w-full text-left text-xs tabular-nums">
                    <thead className="border-b border-slate-800 text-slate-400">
                      <tr>
                        <th className="px-4 py-2.5">Source IP</th>
                        <th className="px-4 py-2.5">Destination IP</th>
                        <th className="px-4 py-2.5">Protocol</th>
                        <th className="px-4 py-2.5 text-right">Packets</th>
                        <th className="px-4 py-2.5 text-right">Bytes</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {netflow.top_conversations.map((c, idx) => (
                        <tr key={`${c.src_ip}-${c.dst_ip}-${idx}`}>
                          <td translate="no" className="px-4 py-2 font-mono text-slate-200">{c.src_ip}</td>
                          <td translate="no" className="px-4 py-2 font-mono text-slate-300">{c.dst_ip}</td>
                          <td translate="no" className="px-4 py-2 text-cyan-300">{c.protocol}</td>
                          <td className="px-4 py-2 text-right">{c.packets.toLocaleString()}</td>
                          <td className="px-4 py-2 text-right">{c.bytes.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {section === "traps" && traps && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="text-xs text-slate-300">
                  SNMP Trap Receiver UDP Port <span translate="no" className="font-mono text-cyan-300">{traps.status.port}</span>{" "}
                  —{" "}
                  <strong className={traps.status.running ? "text-emerald-300" : "text-slate-400"}>
                    {traps.status.running ? `กำลังรอรับ Trap (${traps.status.count})` : "ปิดอยู่"}
                  </strong>
                  {traps.status.last_error && (
                    <span className="ml-2 text-rose-300">({traps.status.last_error})</span>
                  )}
                </div>
                {traps.status.running ? (
                  <button
                    type="button"
                    onClick={async () => {
                      await api.stopSnmpTraps();
                      await loadAll();
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-500/15 px-3 py-1.5 text-xs font-medium text-rose-200"
                  >
                    <Square className="h-3.5 w-3.5" />
                    Stop Receiver
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={async () => {
                      await api.startSnmpTraps(1162);
                      await loadAll();
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500"
                  >
                    <Play className="h-3.5 w-3.5" />
                    Start Trap Listener UDP 1162
                  </button>
                )}
              </div>

              {traps.traps.length === 0 ? (
                <EmptyState
                  title="ยังไม่มี SNMP Trap เข้ามา"
                  description="เมื่อ Switch, UPS หรือ Printer ส่ง LinkDown / AuthFail Trap มายังพอร์ต UDP 1162 เหตุการณ์จะแสดงที่นี่ทันที"
                />
              ) : (
                <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
                  {traps.traps.map((t, i) => (
                    <div
                      key={`${t.received_at}-${i}`}
                      className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/70 pb-2 last:border-0 last:pb-0"
                    >
                      <span translate="no" className="font-mono text-cyan-300">{t.source_ip}</span>
                      <span className="flex-1 text-slate-200">{t.summary}</span>
                      <span className="text-[11px] text-slate-500 tabular-nums">
                        {new Date(t.received_at).toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {section === "drift" && (
            <div className="space-y-4">
              <form
                onSubmit={handleCreateSnapshot}
                className="flex flex-wrap items-end gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4"
              >
                <div className="min-w-60 flex-1">
                  <label htmlFor="snap-name" className="block text-[11px] font-medium text-slate-300">
                    ชื่อ Configuration Snapshot (บันทึก Policy + Snort Rules + IDS Tuning)
                  </label>
                  <input
                    id="snap-name"
                    type="text"
                    value={snapName}
                    onChange={(e) => setSnapName(e.target.value)}
                    placeholder="เช่น Baseline ก่อนปรับกฎ Snort"
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100"
                  />
                </div>
                <button
                  type="submit"
                  className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500"
                >
                  <Plus className="h-3.5 w-3.5" />
                  บันทึก Snapshot
                </button>
              </form>

              {snapshots.length === 0 ? (
                <EmptyState
                  title="ยังไม่มี Configuration Snapshot"
                  description="กดบันทึก Snapshot ด้านบนเพื่อเก็บค่า Baseline ของนโยบาย Firewall และกฎ Snort ไว้ตรวจหา Drift ในอนาคต"
                />
              ) : (
                <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                  <div className="grid grid-cols-1 items-end gap-3 sm:grid-cols-3">
                    <div>
                      <label htmlFor="diff-a" className="block text-[11px] font-medium text-slate-300">
                        Snapshot A (Baseline)
                      </label>
                      <select
                        id="diff-a"
                        value={diffA}
                        onChange={(e) => setDiffA(e.target.value)}
                        className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100"
                      >
                        {snapshots.map((s) => (
                          <option key={s.id} value={s.id}>
                            #{s.id} {s.name} ({s.sha256.slice(0, 8)})
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label htmlFor="diff-b" className="block text-[11px] font-medium text-slate-300">
                        Snapshot B (Target)
                      </label>
                      <select
                        id="diff-b"
                        value={diffB}
                        onChange={(e) => setDiffB(e.target.value)}
                        className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100"
                      >
                        {snapshots.map((s) => (
                          <option key={s.id} value={s.id}>
                            #{s.id} {s.name} ({s.sha256.slice(0, 8)})
                          </option>
                        ))}
                      </select>
                    </div>
                    <button
                      type="button"
                      onClick={handleCompareDiff}
                      className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-500/15 px-3 py-1.5 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/25"
                    >
                      <GitCompare className="h-3.5 w-3.5" />
                      เปรียบเทียบ Config Drift
                    </button>
                  </div>

                  {diffResult && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium">
                        สถานะ:{" "}
                        <span className={diffResult.drifted ? "text-amber-300" : "text-emerald-300"}>
                          {diffResult.drifted ? "พบการเปลี่ยนแปลงค่าคอนฟิก (Config Drifted)" : "ตรงกันทุกบรรทัด (No Drift)"}
                        </span>
                      </p>
                      <pre
                        translate="no"
                        className="max-h-72 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] text-slate-200"
                      >
                        {diffResult.diff}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
