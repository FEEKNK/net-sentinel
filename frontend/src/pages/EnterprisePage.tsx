import { useEffect, useState, type FormEvent } from "react";
import { AlertCircle, Award, Building2, CheckCircle2, HeartPulse, Lock, Plus, Radio, ShieldCheck, Trash2, Users } from "lucide-react";
import { api } from "../api";
import type { AuditLogEntry, ComplianceScorecard, RbacUser, RemoteSensor, SafetyState } from "../types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState, ErrorState, LearnBanner, LoadingState } from "../components/StateViews";

export function EnterprisePage({ onUpdated }: { onUpdated: () => void }) {
  const [safety, setSafety] = useState<SafetyState | null>(null);
  const [compliance, setCompliance] = useState<ComplianceScorecard | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [sensors, setSensors] = useState<RemoteSensor[]>([]);
  const [users, setUsers] = useState<RbacUser[]>([]);

  const [newCidr, setNewCidr] = useState("");
  const [retentionInput, setRetentionInput] = useState("90");
  const [sensorName, setSensorName] = useState("");
  const [sensorVlan, setSensorVlan] = useState("");
  const [issuedKey, setIssuedKey] = useState<string | null>(null);

  const [eveText, setEveText] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<"viewer" | "analyst" | "admin">("analyst");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [confirmPurge, setConfirmPurge] = useState(false);

  const loadAll = async (signal?: AbortSignal) => {
    setError(null);
    try {
      const [sRes, logRes, senRes, compRes] = await Promise.all([
        api.getSafetyState(signal),
        api.listAuditLogs(signal),
        api.listSensors(signal),
        api.getComplianceScorecard(signal),
      ]);
      setSafety(sRes);
      setRetentionInput(String(sRes.retention_days));
      setAuditLogs(logRes.logs);
      setSensors(senRes.sensors);
      setCompliance(compRes);
      try {
        const uRes = await api.listUsers(signal);
        setUsers(uRes.users);
      } catch {
        setUsers([]);
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError(err instanceof Error ? err.message : "Failed to load enterprise settings");
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

  const updateSafety = async (patch: Parameters<typeof api.updateSafetyState>[0]) => {
    setError(null);
    setFeedback(null);
    try {
      const res = await api.updateSafetyState(patch);
      setSafety(res);
      setFeedback(`อัปเดตนโยบายความปลอดภัยเป็น ${res.profile} เรียบร้อย`);
      onUpdated();
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update safety policy");
    }
  };

  const handleAddCidr = async (e: FormEvent) => {
    e.preventDefault();
    if (!newCidr.trim()) return;
    setError(null);
    try {
      await api.addExclusionCidr(newCidr.trim());
      setNewCidr("");
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid CIDR");
    }
  };

  const handleRemoveCidr = async (cidr: string) => {
    setError(null);
    try {
      await api.removeExclusionCidr(cidr);
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove CIDR");
    }
  };

  const handleRegisterSensor = async (e: FormEvent) => {
    e.preventDefault();
    if (!sensorName.trim()) return;
    setError(null);
    setIssuedKey(null);
    try {
      const res = await api.registerSensor(sensorName.trim(), sensorVlan.trim());
      setIssuedKey(res.api_key);
      setSensorName("");
      setSensorVlan("");
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to register sensor");
    }
  };

  const handleImportSuricata = async (e: FormEvent) => {
    e.preventDefault();
    if (!eveText.trim()) return;
    setError(null);
    setFeedback(null);
    try {
      const res = await api.importSuricataEve(eveText);
      setFeedback(`นำเข้าเหตุการณ์จาก Suricata eve.json สำเร็จ (${res.alerts_imported} alerts)`);
      setEveText("");
      onUpdated();
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to import Suricata eve.json");
    }
  };

  const handleCreateUser = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setFeedback(null);
    try {
      await api.createUser(newUsername.trim(), newPassword, newRole);
      setNewUsername("");
      setNewPassword("");
      setFeedback("สร้างบัญชีผู้ใช้ RBAC สำเร็จ");
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create user");
    }
  };

  const handlePurge = async () => {
    try {
      const res = await api.purgeRetentionLogs(true);
      setConfirmPurge(false);
      setFeedback(
        `ล้าง Log ที่เก่าเกิน ${res.retention_days} วันแล้ว (Alerts: ${res.deleted.alerts ?? 0})`
      );
      await loadAll();
    } catch (err) {
      setConfirmPurge(false);
      setError(err instanceof Error ? err.message : "Purge failed");
    }
  };

  if (loading) return <LoadingState message="กำลังโหลดการตั้งค่าองค์กรและโรงพยาบาล…" />;
  if (error && !safety) return <ErrorState message={error} onRetry={() => loadAll()} />;

  return (
    <div className="space-y-6">
      <LearnBanner
        title="Enterprise & Hospital Governance"
        summary="ตั้งค่าความปลอดภัยระดับองค์กรและโรงพยาบาล: โหมด Hospital Safe ปิด Auto-Block และปิดการสแกนพอร์ตเชิงรุก, ล็อกวง Medical VLAN ห้ามแตะต้อง, โหมด PDPA Header-Only ตัด Payload, เก็บ Log 90 วัน, Multi-VLAN Sensor + Suricata eve.json และ RBAC + Immutable Audit Log"
      />

      {compliance && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Award className="h-4 w-4 text-cyan-400" aria-hidden="true" />
              Hospital &amp; Enterprise Compliance Scorecard
            </h3>
            <span className="rounded-lg border border-cyan-500/40 bg-cyan-500/15 px-3 py-1 font-mono font-semibold text-cyan-200 tabular-nums">
              {compliance.score_pct}% ({compliance.passed_count}/{compliance.total_checks} Passed)
            </span>
          </div>
          <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {compliance.checks.map((c) => (
              <div
                key={c.id}
                className={`flex items-start gap-2 rounded-lg border p-3 ${
                  c.passed
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
                    : "border-amber-500/30 bg-amber-500/10 text-amber-100"
                }`}
              >
                {c.passed ? (
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                ) : (
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
                )}
                <div>
                  <p className="font-semibold">{c.control}</p>
                  <p className="mt-0.5 text-[11px] opacity-85">{c.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

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

      {safety && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Deployment Safety Profile & PDPA */}
          <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <HeartPulse className="h-4 w-4 text-rose-400" aria-hidden="true" />
              Deployment Profile &amp; PDPA / Retention Policy
            </h3>

            <div className="grid grid-cols-3 gap-2">
              {(
                [
                  { id: "standard", label: "Standard" },
                  { id: "enterprise", label: "Enterprise" },
                  { id: "hospital_safe", label: "Hospital Safe" },
                ] as const
              ).map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => updateSafety({ profile: p.id })}
                  className={`rounded-lg border px-3 py-2 font-semibold transition-colors duration-150 ${
                    safety.profile === p.id
                      ? "border-cyan-500 bg-cyan-600 text-white"
                      : "border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700"
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>

            {safety.is_hospital_safe && (
              <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 p-3 text-emerald-200">
                <strong>Hospital Safe Mode Active:</strong> ปิด Auto-Block อัตโนมัติ, ปิด Port/Banner Scan เชิงรุก และเปิด PDPA Header-Only Privacy Mode เพื่อไม่รบกวนเครื่องมือแพทย์
              </div>
            )}

            <div className="flex items-center justify-between border-t border-slate-800 pt-3">
              <div>
                <p className="font-semibold text-slate-200">PDPA / PHI Header-Only Privacy Mode</p>
                <p className="text-[11px] text-slate-400">
                  ตัด Packet Payload และชื่อโดเมน DNS ออกก่อนบันทึก (เก็บเฉพาะ IP/Port/Protocol)
                </p>
              </div>
              <button
                type="button"
                onClick={() => updateSafety({ privacy_mode: !safety.privacy_mode })}
                className={`rounded-lg px-3 py-1.5 font-semibold text-white ${
                  safety.privacy_mode ? "bg-emerald-600" : "bg-slate-700"
                }`}
              >
                {safety.privacy_mode ? "ON" : "OFF"}
              </button>
            </div>

            <div className="flex flex-wrap items-end gap-2 border-t border-slate-800 pt-3">
              <div className="flex-1">
                <label htmlFor="retention-days" className="block text-[11px] text-slate-300">
                  Log Retention (วัน — พ.ร.บ. คอมฯ แนะนำ ≥ 90 วัน)
                </label>
                <input
                  id="retention-days"
                  type="number"
                  min={1}
                  max={3650}
                  value={retentionInput}
                  onChange={(e) => setRetentionInput(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono tabular-nums text-slate-100"
                />
              </div>
              <button
                type="button"
                onClick={() => updateSafety({ retention_days: Number(retentionInput) || 90 })}
                className="rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500"
              >
                บันทึก
              </button>
              <button
                type="button"
                onClick={() => setConfirmPurge(true)}
                className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 font-semibold text-rose-300 hover:bg-rose-500/20"
              >
                ล้าง Log เก่า
              </button>
            </div>
          </div>

          {/* Protected Medical / Critical VLAN Exclusion CIDRs */}
          <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Building2 className="h-4 w-4 text-cyan-400" aria-hidden="true" />
              Protected VLAN / Medical Exclusion CIDRs
            </h3>
            <p className="text-[11px] leading-relaxed text-slate-400">
              วง IP ที่อยู่ในรายการนี้จะถูกห้ามสแกน (403) และห้ามสั่งบล็อก Firewall เด็ดขาด เหมาะสำหรับวงเครื่องมือแพทย์ (IoMT), PACS, หรือ Core Server
            </p>

            <form onSubmit={handleAddCidr} className="flex items-end gap-2">
              <div className="flex-1">
                <label htmlFor="excl-cidr" className="block text-[11px] text-slate-300">
                  เพิ่มวง Subnet ยกเว้น (CIDR)
                </label>
                <input
                  id="excl-cidr"
                  type="text"
                  value={newCidr}
                  onChange={(e) => setNewCidr(e.target.value)}
                  placeholder="10.50.0.0/16"
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-slate-100"
                />
              </div>
              <button
                type="submit"
                className="inline-flex items-center gap-1 rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500"
              >
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                เพิ่มวง
              </button>
            </form>

            {safety.excluded_cidrs.length === 0 ? (
              <EmptyState
                title="ยังไม่มีวง Exclusion"
                description="เพิ่ม CIDR เช่น 10.10.0.0/24 เพื่อป้องกันไม่ให้ระบบสแกนหรือบล็อกวงอุปกรณ์สำคัญ"
              />
            ) : (
              <div className="flex flex-wrap gap-2">
                {safety.excluded_cidrs.map((cidr) => (
                  <span
                    key={cidr}
                    translate="no"
                    className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 font-mono text-emerald-300"
                  >
                    <Lock className="h-3 w-3" aria-hidden="true" />
                    {cidr}
                    <button
                      type="button"
                      onClick={() => handleRemoveCidr(cidr)}
                      aria-label={`ลบวงยกเว้น ${cidr}`}
                      className="text-slate-400 hover:text-rose-400"
                    >
                      <Trash2 className="h-3 w-3" aria-hidden="true" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Multi-VLAN Sensors & Suricata eve.json */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Radio className="h-4 w-4 text-emerald-400" aria-hidden="true" />
            Multi-VLAN Remote Sensors ({sensors.length})
          </h3>

          <form onSubmit={handleRegisterSensor} className="grid grid-cols-1 items-end gap-2 sm:grid-cols-3">
            <div>
              <label htmlFor="sen-name" className="block text-[11px] text-slate-300">ชื่อ Sensor</label>
              <input
                id="sen-name"
                type="text"
                value={sensorName}
                onChange={(e) => setSensorName(e.target.value)}
                placeholder="OPD-Switch-Mirror"
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
              />
            </div>
            <div>
              <label htmlFor="sen-vlan" className="block text-[11px] text-slate-300">VLAN / Zone</label>
              <input
                id="sen-vlan"
                type="text"
                value={sensorVlan}
                onChange={(e) => setSensorVlan(e.target.value)}
                placeholder="VLAN-20"
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-slate-100"
              />
            </div>
            <button
              type="submit"
              className="rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500"
            >
              ออก Sensor Key
            </button>
          </form>

          {issuedKey && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-950/30 p-3 font-mono text-[11px] text-amber-200">
              บันทึก Sensor Key นี้ทันที (แสดงครั้งเดียว): <strong>{issuedKey}</strong>
            </div>
          )}

          {sensors.length > 0 && (
            <div className="divide-y divide-slate-800/70">
              {sensors.map((s) => (
                <div key={s.id} className="flex items-center justify-between py-2 font-mono">
                  <div>
                    <span className="text-cyan-300">{s.name}</span>{" "}
                    <span className="text-slate-400">({s.vlan || "default"})</span>
                  </div>
                  <span className="tabular-nums text-emerald-300">{s.events_received} events</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <form
          onSubmit={handleImportSuricata}
          className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs"
        >
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <ShieldCheck className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            Suricata eve.json Ingest (10Gbps Sensor Feed)
          </h3>
          <div>
            <label htmlFor="suricata-eve" className="block text-[11px] text-slate-300">
              วางบรรทัด JSON จาก Suricata eve.json เพื่อนำเข้าสู่ระบบ Alert
            </label>
            <textarea
              id="suricata-eve"
              rows={4}
              value={eveText}
              onChange={(e) => setEveText(e.target.value)}
              placeholder='{"event_type":"alert","src_ip":"203.0.113.9","dest_ip":"192.168.1.10","proto":"TCP","alert":{"signature":"ET SCAN Nmap","signature_id":2000543,"severity":2}}'
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-2.5 font-mono text-[11px] text-slate-200"
            />
          </div>
          <button
            type="submit"
            className="rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500"
          >
            Import eve.json Alerts
          </button>
        </form>
      </div>

      {/* Multi-User RBAC & Immutable Audit Trail */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Users className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            Multi-User RBAC Accounts ({users.length})
          </h3>
          <form onSubmit={handleCreateUser} className="grid grid-cols-1 items-end gap-2 sm:grid-cols-4">
            <div>
              <label htmlFor="rbac-user" className="block text-[11px] text-slate-300">Username</label>
              <input
                id="rbac-user"
                type="text"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="soc_analyst"
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
              />
            </div>
            <div>
              <label htmlFor="rbac-pass" className="block text-[11px] text-slate-300">Password</label>
              <input
                id="rbac-pass"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="min 6 chars"
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
              />
            </div>
            <div>
              <label htmlFor="rbac-role" className="block text-[11px] text-slate-300">Role</label>
              <select
                id="rbac-role"
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as "viewer" | "analyst" | "admin")}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-200"
              >
                <option value="viewer">Viewer (Read-Only)</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <button
              type="submit"
              className="rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500"
            >
              สร้างผู้ใช้
            </button>
          </form>

          {users.length > 0 && (
            <div className="divide-y divide-slate-800/70">
              {users.map((u) => (
                <div key={u.id} className="flex items-center justify-between py-2">
                  <span className="font-mono text-slate-200" translate="no">
                    {u.username} <span className="text-cyan-300">[{u.role}]</span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs">
          <h3 className="text-sm font-semibold text-slate-100">
            Immutable Audit Trail ({auditLogs.length})
          </h3>
          {auditLogs.length === 0 ? (
            <EmptyState
              title="ยังไม่มีประวัติ Audit"
              description="ทุกการเปลี่ยนสิทธิ์, เพิ่มวงยกเว้น, สร้างผู้ใช้ หรือตั้งค่าความปลอดภัยจะถูกบันทึกแบบลบไม่ได้"
            />
          ) : (
            <div className="max-h-60 overflow-y-auto divide-y divide-slate-800/70 font-mono text-[11px]">
              {auditLogs.map((log) => (
                <div key={log.id} className="py-1.5 text-slate-300">
                  <span className="text-cyan-300">{log.actor}</span>{" "}
                  <span className="text-slate-500">({log.role})</span> -&gt;{" "}
                  <span className="text-amber-300">{log.action}</span>{" "}
                  {log.target && <span>[{log.target}]</span>}{" "}
                  {log.detail && <span className="text-slate-400">{log.detail}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={confirmPurge}
        title="ยืนยันการล้าง Log ที่เกินอายุจัดเก็บ"
        description={`ระบบจะลบ Alerts, Syslog และประวัติที่เก่าเกิน ${safety?.retention_days ?? 90} วันออกจากฐานข้อมูล (Audit Trail จะไม่ถูกลบ)`}
        confirmLabel="ล้าง Log เก่า"
        onConfirm={handlePurge}
        onCancel={() => setConfirmPurge(false)}
      />
    </div>
  );
}
