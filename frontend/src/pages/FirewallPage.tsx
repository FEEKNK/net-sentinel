import { useEffect, useState, type FormEvent } from "react";
import { Lock, Plus, ShieldCheck, ShieldOff, Trash2 } from "lucide-react";
import { api } from "../api";
import type { BlockedIpRecord, PolicyState } from "../types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState, ErrorState, LearnBanner, LoadingState } from "../components/StateViews";

interface FirewallPageProps {
  onPolicyChanged: () => void;
}

type PendingAction =
  | { kind: "toggle_dry_run"; nextDryRun: boolean }
  | { kind: "toggle_auto_block"; nextAuto: boolean }
  | { kind: "unblock"; ip: string }
  | { kind: "manual_block"; ip: string; reason: string }
  | null;

export function FirewallPage({ onPolicyChanged }: FirewallPageProps) {
  const [policy, setPolicy] = useState<PolicyState | null>(null);
  const [blocked, setBlocked] = useState<BlockedIpRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  const [newWhitelist, setNewWhitelist] = useState("");
  const [manualIp, setManualIp] = useState("");
  const [manualReason, setManualReason] = useState("");
  const [pending, setPending] = useState<PendingAction>(null);
  const [busy, setBusy] = useState(false);

  const loadStatus = async (signal?: AbortSignal) => {
    setError(null);
    try {
      const data = await api.getFirewallStatus(signal);
      setPolicy(data.policy);
      setBlocked(data.blocked_ips);
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError(err instanceof Error ? err.message : "Failed to load firewall status");
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const ctrl = new AbortController();
    loadStatus(ctrl.signal);
    return () => ctrl.abort();
  }, []);

  const executePending = async () => {
    if (!pending) return;
    setBusy(true);
    setError(null);
    setFeedback(null);
    try {
      if (pending.kind === "toggle_dry_run") {
        await api.updateFirewallPolicy({ dry_run: pending.nextDryRun, confirm: true });
        setFeedback(
          pending.nextDryRun
            ? "เปลี่ยนเป็นโหมด DRY-RUN (โหมดซ้อมปลอดภัย) เรียบร้อยแล้ว"
            : "เปิดใช้โหมด LIVE ENFORCE แล้ว — การบล็อกจะมีผลกับ Firewall ของ OS จริง"
        );
      } else if (pending.kind === "toggle_auto_block") {
        await api.updateFirewallPolicy({ auto_block_enabled: pending.nextAuto, confirm: true });
        setFeedback(
          pending.nextAuto ? "เปิดใช้งาน Auto-Block แล้ว" : "ปิดใช้งาน Auto-Block แล้ว"
        );
      } else if (pending.kind === "unblock") {
        const res = await api.unblockIp(pending.ip, true);
        setFeedback(res.message);
      } else if (pending.kind === "manual_block") {
        const res = await api.blockIp(
          pending.ip,
          pending.reason || "Manual block from Firewall panel",
          true
        );
        setFeedback(res.message);
        setManualIp("");
        setManualReason("");
      }
      setPending(null);
      await loadStatus();
      onPolicyChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Firewall action failed");
      setPending(null);
    } finally {
      setBusy(false);
    }
  };

  const handleAddWhitelist = async (e: FormEvent) => {
    e.preventDefault();
    if (!newWhitelist.trim()) return;
    setError(null);
    try {
      await api.addWhitelist(newWhitelist.trim());
      setNewWhitelist("");
      await loadStatus();
      onPolicyChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add whitelist IP");
    }
  };

  const handleRemoveWhitelist = async (ip: string) => {
    setError(null);
    try {
      await api.removeWhitelist(ip);
      await loadStatus();
      onPolicyChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove whitelist IP");
    }
  };

  const handleManualBlockSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!manualIp.trim()) {
      setError("กรุณาระบุ IP Address ที่ต้องการบล็อก");
      return;
    }
    setPending({ kind: "manual_block", ip: manualIp.trim(), reason: manualReason.trim() });
  };

  if (loading) return <LoadingState />;
  if (error && !policy) return <ErrorState message={error} onRetry={() => loadStatus()} />;

  return (
    <div className="space-y-6">
      <LearnBanner
        title="Active Response / Auto-Block (ระบบล็อกประตูอัตโนมัติ)"
        summary="สั่งเพิ่มกฎลงใน Firewall ของเครื่อง (Windows ใช้ netsh advfirewall / Linux ใช้ iptables) โดยเปิดโหมด Dry-Run (ซ้อม) ไว้เป็นค่าเริ่มต้น และล็อกรายชื่อ IP เครื่องตัวเองกับ Gateway ไว้ใน Whitelist เสมอเพื่อกันเน็ตหลุด"
      />

      {feedback && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 px-4 py-2.5 text-xs text-emerald-200">
          {feedback}
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-2.5 text-xs text-rose-200">
          {error}
        </div>
      )}

      {policy && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {/* Policy Controls */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-100">
              Enforcement Policy ({policy.firewall_backend})
            </h3>

            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 p-3">
              <div>
                <p className="text-xs font-semibold text-slate-200">โหมดปลอดภัย (Dry-Run Mode)</p>
                <p className="text-[11px] text-slate-400">
                  {policy.dry_run
                    ? "เปิดอยู่ — บันทึก Log เท่านั้น ไม่แก้ Firewall จริง"
                    : "ปิดอยู่ — บล็อก IP บน OS Firewall จริง!"}
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  setPending({ kind: "toggle_dry_run", nextDryRun: !policy.dry_run })
                }
                className={`rounded-lg px-3 py-1.5 text-xs font-semibold text-white ${
                  policy.dry_run
                    ? "bg-rose-600 hover:bg-rose-500"
                    : "bg-cyan-600 hover:bg-cyan-500"
                }`}
              >
                {policy.dry_run ? "สลับเป็น Live Enforce" : "เปิด Dry-Run Mode"}
              </button>
            </div>

            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 p-3">
              <div>
                <p className="text-xs font-semibold text-slate-200">Auto-Block เมื่อพบ Critical Alert</p>
                <p className="text-[11px] text-slate-400">
                  Threshold: {policy.auto_block_threshold.toUpperCase()} | TTL: {policy.block_ttl_seconds}s
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  setPending({
                    kind: "toggle_auto_block",
                    nextAuto: !policy.auto_block_enabled,
                  })
                }
                className={`rounded-lg px-3 py-1.5 text-xs font-semibold text-white ${
                  policy.auto_block_enabled
                    ? "bg-amber-600 hover:bg-amber-500"
                    : "bg-emerald-600 hover:bg-emerald-500"
                }`}
              >
                {policy.auto_block_enabled ? "ปิด Auto-Block" : "เปิด Auto-Block"}
              </button>
            </div>

            <form onSubmit={handleManualBlockSubmit} className="space-y-2 border-t border-slate-800 pt-3">
              <p className="text-xs font-medium text-slate-300">Manual Block IP</p>
              <div className="flex flex-wrap gap-2">
                <input
                  type="text"
                  value={manualIp}
                  onChange={(e) => setManualIp(e.target.value)}
                  placeholder="IP เช่น 203.0.113.55"
                  aria-label="Manual block IP"
                  className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100"
                />
                <input
                  type="text"
                  value={manualReason}
                  onChange={(e) => setManualReason(e.target.value)}
                  placeholder="เหตุผล (ไม่บังคับ)"
                  aria-label="Block reason"
                  className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100"
                />
                <button
                  type="submit"
                  className="rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-500"
                >
                  Block IP
                </button>
              </div>
            </form>
          </div>

          {/* Whitelist Guardrails */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-100">
              Whitelist Guardrails (ห้ามบล็อกเด็ดขาด)
            </h3>

            <div>
              <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-slate-400">
                System Protected (Locked)
              </p>
              <div className="flex flex-wrap gap-1.5">
                {policy.system_protected_ips.map((ip) => (
                  <span
                    key={`sys-${ip}`}
                    className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 font-mono text-xs text-emerald-300"
                  >
                    <Lock className="h-3 w-3" />
                    {ip}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-slate-400">
                Custom Whitelist
              </p>
              <div className="flex flex-wrap gap-1.5">
                {policy.custom_whitelist_ips.map((ip) => (
                  <span
                    key={`wl-${ip}`}
                    className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-200"
                  >
                    {ip}
                    <button
                      type="button"
                      onClick={() => handleRemoveWhitelist(ip)}
                      aria-label={`ลบ ${ip} ออกจาก whitelist`}
                      className="text-slate-400 hover:text-rose-400"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </span>
                ))}
              </div>
            </div>

            <form onSubmit={handleAddWhitelist} className="flex gap-2 border-t border-slate-800 pt-3">
              <input
                type="text"
                value={newWhitelist}
                onChange={(e) => setNewWhitelist(e.target.value)}
                placeholder="เพิ่ม IP เข้า Whitelist"
                aria-label="New whitelist IP"
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100"
              />
              <button
                type="submit"
                className="inline-flex items-center gap-1 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
              >
                <Plus className="h-3.5 w-3.5" />
                เพิ่ม
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Blocked IPs Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-100">
          Blocked IP Records ({blocked.length})
        </h3>
        {blocked.length === 0 ? (
          <EmptyState
            title="ยังไม่มีประวัติการบล็อก IP"
            description="ลองเปิด Auto-Block (ในโหมด Dry-Run) แล้วกด Simulate SYN Flood ในหน้า IDS หรือทดสอบ Manual Block ด้านบน"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2.5 pr-3 font-medium">IP Address</th>
                  <th className="py-2.5 pr-3 font-medium">Mode</th>
                  <th className="py-2.5 pr-3 font-medium">Status</th>
                  <th className="py-2.5 pr-3 font-medium">Reason</th>
                  <th className="py-2.5 text-right font-medium">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {blocked.map((b) => (
                  <tr key={b.ip}>
                    <td className="py-2.5 pr-3 font-mono font-semibold text-rose-300">{b.ip}</td>
                    <td className="py-2.5 pr-3">
                      <span
                        className={`rounded px-2 py-0.5 text-[11px] font-medium ${
                          b.is_dry_run
                            ? "bg-cyan-500/15 text-cyan-300"
                            : "bg-rose-500/20 text-rose-300"
                        }`}
                      >
                        {b.is_dry_run ? "DRY-RUN" : "ENFORCED"}
                      </span>
                    </td>
                    <td className="py-2.5 pr-3">
                      <span
                        className={`inline-flex items-center gap-1 text-[11px] ${
                          b.active ? "text-emerald-300" : "text-slate-500"
                        }`}
                      >
                        {b.active ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldOff className="h-3.5 w-3.5" />}
                        {b.active ? "Active" : "Unblocked"}
                      </span>
                    </td>
                    <td className="py-2.5 pr-3 text-slate-300">{b.reason}</td>
                    <td className="py-2.5 text-right">
                      {b.active && (
                        <button
                          type="button"
                          onClick={() => setPending({ kind: "unblock", ip: b.ip })}
                          className="rounded border border-slate-700 bg-slate-800 px-2.5 py-1 text-[11px] text-slate-200 hover:bg-slate-700"
                        >
                          Unblock
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={pending !== null}
        title={
          pending?.kind === "toggle_dry_run"
            ? pending.nextDryRun
              ? "เปิดโหมด Dry-Run Safe Mode?"
              : "คำเตือน: เปิดโหมด Live Firewall Enforcement?"
            : pending?.kind === "toggle_auto_block"
              ? pending.nextAuto
                ? "เปิดใช้งาน Auto-Block?"
                : "ปิดใช้งาน Auto-Block?"
              : pending?.kind === "unblock"
                ? `ยืนยันปลดบล็อก IP ${pending.ip}`
                : `ยืนยันการบล็อก IP ${pending?.ip ?? ""}`
        }
        description={
          pending?.kind === "toggle_dry_run" && !pending.nextDryRun
            ? "เมื่อปิด Dry-Run ระบบจะสั่งแก้กฎ Firewall ของเครื่องจริงเมื่อมีการบล็อก (ต้องรัน Backend ด้วยสิทธิ์ Admin/sudo)"
            : "โปรดตรวจสอบให้แน่ใจก่อนดำเนินการ การเปลี่ยนแปลงนี้จะมีผลกับระบบทันที"
        }
        danger={pending?.kind === "manual_block" || (pending?.kind === "toggle_dry_run" && !pending.nextDryRun)}
        busy={busy}
        onConfirm={executePending}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}
