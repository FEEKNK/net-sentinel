import { useEffect, useState } from "react";
import { Flame, Play, Save, Square, Trash2 } from "lucide-react";
import { api } from "../api";
import type { AlertRecord, PacketSummary, SnifferStatus, SnortRuleItem } from "../types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState, ErrorState, LearnBanner, LoadingState, SeverityBadge } from "../components/StateViews";

interface IdsPageProps {
  alerts: AlertRecord[];
  packets: PacketSummary[];
  sniffer: SnifferStatus | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

const SIMULATIONS = [
  { id: "port_scan", label: "Simulate Port Scan", desc: "ยิง 12 พอร์ตติดกัน -> จับโดย Behavioral Detector" },
  { id: "syn_flood", label: "Simulate SYN Flood", desc: "ยิง SYN รัว 45 ครั้ง -> จับโดย Behavioral DoS Detector" },
  { id: "arp_spoof", label: "Simulate ARP Spoof", desc: "เปลี่ยน MAC Gateway กะทันหัน -> Critical Alert" },
  { id: "snort_telnet", label: "Simulate Telnet (SID:1000001)", desc: "ทราฟฟิกพอร์ต 23 -> จับโดยกฎ Snort" },
  { id: "snort_sqli", label: "Simulate SQLi (SID:1000003)", desc: "คำว่า UNION SELECT -> จับโดยกฎ Snort Content" },
];

export function IdsPage({
  alerts,
  packets,
  sniffer,
  loading,
  error,
  onRefresh,
}: IdsPageProps) {
  const [severityFilter, setSeverityFilter] = useState("all");
  const [rulesText, setRulesText] = useState("");
  const [parsedRules, setParsedRules] = useState<SnortRuleItem[]>([]);
  const [ruleErrors, setRuleErrors] = useState<Array<{ line: number; error: string; raw: string }>>([]);
  const [rulesLoaded, setRulesLoaded] = useState(false);

  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmClearOpen, setConfirmClearOpen] = useState(false);
  const [confirmSaveRulesOpen, setConfirmSaveRulesOpen] = useState(false);

  const fetchRules = async (signal?: AbortSignal) => {
    try {
      const data = await api.getRules(signal);
      setRulesText(data.content);
      setParsedRules(data.rules);
      setRuleErrors(data.errors);
      setRulesLoaded(true);
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setActionError(err instanceof Error ? err.message : "Failed to load rules");
      }
    }
  };

  useEffect(() => {
    const ctrl = new AbortController();
    fetchRules(ctrl.signal);
    return () => ctrl.abort();
  }, []);

  const toggleSniffer = async () => {
    setActionError(null);
    setBusyAction("sniffer");
    try {
      if (sniffer?.running) {
        await api.stopSniffer();
      } else {
        await api.startSniffer();
      }
      onRefresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Failed to toggle sniffer");
    } finally {
      setBusyAction(null);
    }
  };

  const runSimulation = async (attackId: string) => {
    setActionError(null);
    setFeedback(null);
    setBusyAction(attackId);
    try {
      const res = await api.simulateAttack(attackId, "203.0.113.55", "192.168.1.10");
      setFeedback(
        `จำลอง ${res.attack_type}: ส่ง ${res.packets_injected} packets เข้า IDS Engine -> ตรวจพบ ${res.alerts_triggered} alerts`
      );
      onRefresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setBusyAction(null);
    }
  };

  const confirmClear = async () => {
    setBusyAction("clear");
    setActionError(null);
    try {
      await api.clearAlerts(true);
      setConfirmClearOpen(false);
      onRefresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Clear alerts failed");
      setConfirmClearOpen(false);
    } finally {
      setBusyAction(null);
    }
  };

  const confirmSaveRules = async () => {
    setBusyAction("save_rules");
    setActionError(null);
    setFeedback(null);
    try {
      const res = await api.saveRules(rulesText, true);
      setConfirmSaveRulesOpen(false);
      setFeedback(`บันทึกและโหลดกฎ Snort ใหม่สำเร็จ (${res.loaded_count} กฎ, errors: ${res.error_count})`);
      await fetchRules();
      onRefresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Failed to save rules");
      setConfirmSaveRulesOpen(false);
    } finally {
      setBusyAction(null);
    }
  };

  const filteredAlerts =
    severityFilter === "all"
      ? alerts
      : alerts.filter((a) => a.severity.toLowerCase() === severityFilter);

  return (
    <div className="space-y-6">
      <LearnBanner
        title="Packet Sniffer & Hybrid IDS (ยามจับพิรุธ + สมุดกฎ Snort)"
        summary="ผสาน 2 เทคนิค: (1) Behavioral Detectors จับพฤติกรรม Port Scan, SYN Flood, ARP Spoofing แบบ Sliding Window และ (2) Snort .rules ตรวจจับตามลายเซ็น (Signature) คุณสามารถกดปุ่มจำลองการโจมตีด้านล่างเพื่อเรียนรู้ได้ทันทีโดยไม่กระทบเครือข่ายจริง"
      />

      {/* Sniffer & Attack Simulator Bar */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">Live Packet Sniffer</h3>
              <p className="mt-0.5 text-xs text-slate-400">
                Captured: {sniffer?.packet_count ?? 0} packets
              </p>
            </div>
            <button
              type="button"
              onClick={toggleSniffer}
              disabled={busyAction === "sniffer"}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold text-white disabled:opacity-50 ${
                sniffer?.running
                  ? "bg-rose-600 hover:bg-rose-500"
                  : "bg-emerald-600 hover:bg-emerald-500"
              }`}
            >
              {sniffer?.running ? <Square className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
              {sniffer?.running ? "Stop Sniffer" : "Start Sniffer"}
            </button>
          </div>
          {sniffer?.last_error && (
            <p className="mt-2 rounded bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-300">
              {sniffer.last_error}
            </p>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 lg:col-span-2">
          <div className="mb-2.5 flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Flame className="h-4 w-4 text-orange-400" />
            Safe Attack Simulator (จำลองส่งเข้า IDS Engine จริงเพื่อเรียนรู้)
          </div>
          <div className="flex flex-wrap gap-2">
            {SIMULATIONS.map((sim) => (
              <button
                key={sim.id}
                type="button"
                title={sim.desc}
                disabled={busyAction !== null}
                onClick={() => runSimulation(sim.id)}
                className="rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-orange-500/50 hover:bg-slate-800 disabled:opacity-50"
              >
                {busyAction === sim.id ? "กำลังจำลอง..." : sim.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {feedback && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 px-4 py-2.5 text-xs text-emerald-200">
          {feedback}
        </div>
      )}
      {actionError && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-2.5 text-xs text-rose-200">
          {actionError}
        </div>
      )}

      {/* Alerts Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-semibold text-slate-100">
            IDS Alert Log ({filteredAlerts.length})
          </h3>
          <div className="flex flex-wrap items-center gap-2">
            {["all", "critical", "high", "medium", "low"].map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverityFilter(sev)}
                className={`rounded-lg px-2.5 py-1 text-xs font-medium uppercase ${
                  severityFilter === sev
                    ? "bg-cyan-600 text-white"
                    : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                }`}
              >
                {sev}
              </button>
            ))}
            <button
              type="button"
              disabled={alerts.length === 0}
              onClick={() => setConfirmClearOpen(true)}
              className="inline-flex items-center gap-1 rounded-lg border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 text-xs font-medium text-rose-300 hover:bg-rose-500/20 disabled:opacity-40"
            >
              <Trash2 className="h-3.5 w-3.5" />
              ล้าง Alerts
            </button>
          </div>
        </div>

        {error ? (
          <ErrorState message={error} onRetry={onRefresh} />
        ) : loading ? (
          <LoadingState />
        ) : filteredAlerts.length === 0 ? (
          <EmptyState
            title="ยังไม่มี Alert ในเงื่อนไขนี้"
            description="ลองกดปุ่ม Attack Simulator ด้านบน หรือเปิด Live Sniffer เพื่อดูการตรวจจับแบบ Real-time"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2.5 pr-3 font-medium">Severity</th>
                  <th className="py-2.5 pr-3 font-medium">Title / Rule</th>
                  <th className="py-2.5 pr-3 font-medium">Source -&gt; Dest</th>
                  <th className="py-2.5 pr-3 font-medium">Detector</th>
                  <th className="py-2.5 font-medium">Action Taken</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {filteredAlerts.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-800/30">
                    <td className="py-2.5 pr-3">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="py-2.5 pr-3">
                      <div className="font-medium text-slate-100">{a.title}</div>
                      <div className="text-[11px] text-slate-400">{a.description}</div>
                    </td>
                    <td className="py-2.5 pr-3 font-mono text-slate-300">
                      {a.source_ip}
                      {a.dest_ip ? ` -> ${a.dest_ip}` : ""}
                      {a.dest_port ? `:${a.dest_port}` : ""}
                    </td>
                    <td className="py-2.5 pr-3 text-slate-300">
                      {a.detector_type}
                      {a.rule_sid ? ` (SID:${a.rule_sid})` : ""}
                    </td>
                    <td className="py-2.5">
                      <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
                        {a.action_taken}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Snort Rules Editor + Live Packet Buffer */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100">
              Snort Rules Editor ({parsedRules.length} active)
            </h3>
            <button
              type="button"
              disabled={!rulesLoaded || busyAction === "save_rules"}
              onClick={() => setConfirmSaveRulesOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
            >
              <Save className="h-3.5 w-3.5" />
              Save & Reload Rules
            </button>
          </div>
          <textarea
            value={rulesText}
            onChange={(e) => setRulesText(e.target.value)}
            rows={10}
            aria-label="Snort rules editor"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-200 focus:border-cyan-500 focus:outline-none"
          />
          {ruleErrors.length > 0 && (
            <div className="mt-2 rounded border border-amber-500/40 bg-amber-950/30 p-2 text-[11px] text-amber-200">
              Syntax errors: {ruleErrors.map((e) => `Line ${e.line}: ${e.error}`).join("; ")}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h3 className="mb-3 text-sm font-semibold text-slate-100">
            Recent Packet Buffer ({packets.length})
          </h3>
          {packets.length === 0 ? (
            <EmptyState
              title="ยังไม่มี Packet ในบัฟเฟอร์"
              description="กด Start Sniffer (ต้องใช้สิทธิ์ Admin/Npcap) หรือกดปุ่ม Attack Simulator"
            />
          ) : (
            <div className="max-h-72 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950 p-2 font-mono text-[11px]">
              {packets.slice(0, 40).map((pkt, idx) => (
                <div
                  key={`${pkt.timestamp}-${pkt.src_ip}-${pkt.dst_ip}-${idx}`}
                  className="border-b border-slate-900 py-1 text-slate-300"
                >
                  <span className="text-cyan-400">[{pkt.protocol}]</span> {pkt.src_ip}
                  {pkt.src_port ? `:${pkt.src_port}` : ""} -&gt; {pkt.dst_ip}
                  {pkt.dst_port ? `:${pkt.dst_port}` : ""}{" "}
                  <span className="text-slate-500">({pkt.length}B)</span>{" "}
                  {pkt.preview && <span className="text-amber-300">{pkt.preview}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={confirmClearOpen}
        title="ยืนยันการล้าง Alert Log ทั้งหมด"
        description="การล้าง Alert Log จะลบประวัติการแจ้งเตือนทั้งหมดออกจากฐานข้อมูล SQLite อย่างถาวรและไม่สามารถกู้คืนได้"
        confirmLabel="ลบทั้งหมด"
        busy={busyAction === "clear"}
        onConfirm={confirmClear}
        onCancel={() => setConfirmClearOpen(false)}
      />

      <ConfirmDialog
        open={confirmSaveRulesOpen}
        title="ยืนยันการบันทึกและโหลดกฎ Snort ใหม่"
        description="ระบบจะเขียนทับไฟล์ default.rules และนำกฎชุดใหม่มาใช้ตรวจจับแพ็กเก็ตทันที"
        confirmLabel="บันทึกและ Reload"
        danger={false}
        busy={busyAction === "save_rules"}
        onConfirm={confirmSaveRules}
        onCancel={() => setConfirmSaveRulesOpen(false)}
      />
    </div>
  );
}
