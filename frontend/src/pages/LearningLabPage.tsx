import { useState } from "react";
import { BookOpenCheck, CheckCircle2, Play, ShieldAlert } from "lucide-react";
import { api } from "../api";
import type { AlertRecord, TabId } from "../types";
import { LearnBanner } from "../components/StateViews";

interface LearningLabPageProps {
  defaultSubnet: string;
  onRefresh: () => void;
  onNavigate: (tab: TabId) => void;
}

interface MissionResult {
  done: boolean;
  summary: string;
  alerts?: AlertRecord[];
}

export function LearningLabPage({ defaultSubnet, onRefresh, onNavigate }: LearningLabPageProps) {
  const [results, setResults] = useState<Record<string, MissionResult>>({});
  const [runningId, setRunningId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runMission = async (id: string, task: () => Promise<MissionResult>) => {
    setRunningId(id);
    setError(null);
    try {
      const res = await task();
      setResults((prev) => ({ ...prev, [id]: res }));
      onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Mission execution failed");
    } finally {
      setRunningId(null);
    }
  };

  const missions = [
    {
      id: "recon",
      title: "ภารกิจที่ 1: Asset Inventory & Open Port Triage",
      concept: "Blue Team ต้องรู้ก่อนว่าในวง LAN มีเครื่องอะไรออนไลน์อยู่บ้าง และเครื่องไหนเปิดพอร์ตอันตรายโดยไม่จำเป็น",
      actionLabel: "สแกน Subnet จริงในวงแลน",
      targetTab: "scanner" as TabId,
      run: async (): Promise<MissionResult> => {
        const res = await api.scanSubnet(defaultSubnet || "192.168.1.0/24", true);
        return {
          done: true,
          summary: `สแกน ${res.cidr} สำเร็จ พบเครื่องออนไลน์ ${res.online_count} เครื่อง ใน ${res.duration_ms} ms`,
        };
      },
    },
    {
      id: "bruteforce",
      title: "ภารกิจที่ 2: จับสัญญาณ Brute-Force SSH/RDP",
      concept: "เมื่อแฮกเกอร์ใช้โปรแกรมเดารหัสผ่านยิงเข้าพอร์ต 22 (SSH) หรือ 3389 (RDP) ซ้ำๆ เกิน Threshold Behavioral IDS จะเตือนทันที",
      actionLabel: "จำลองโจมตี Brute-Force",
      targetTab: "ids" as TabId,
      run: async (): Promise<MissionResult> => {
        const res = await api.simulateAttack("bruteforce", "192.0.2.77", "192.168.1.10");
        return {
          done: res.alerts_triggered > 0,
          summary: `ส่งแพ็กเก็ตทดสอบ ${res.packets_injected} ครั้ง -> แจ้งเตือนทำงาน ${res.alerts_triggered} รายการ`,
          alerts: res.alerts,
        };
      },
    },
    {
      id: "dns_tunnel",
      title: "ภารกิจที่ 3: ล่ามัลแวร์แอบขโมยข้อมูลผ่าน DNS Tunnel (Entropy)",
      concept: "มัลแวร์สมัยใหม่มักเข้ารหัสข้อมูลเป็นข้อความยาวผิดปกติในชื่อโดเมน (เช่น a9f2d8c7...evil.com) ซึ่งมีค่า Shannon Entropy สูงผิดปกติ",
      actionLabel: "จำลอง DNS Tunneling",
      targetTab: "ids" as TabId,
      run: async (): Promise<MissionResult> => {
        const res = await api.simulateAttack("dns_tunnel", "192.168.1.88", "8.8.8.8");
        return {
          done: res.alerts_triggered > 0,
          summary: `ส่ง DNS Entropy สูงทดสอบ -> ตรวจพบ Alert ${res.alerts_triggered} รายการ`,
          alerts: res.alerts,
        };
      },
    },
    {
      id: "scorecard",
      title: "ภารกิจที่ 4: ตรวจความพร้อม Blue Team & Safe Active Response",
      concept: "ตรวจสอบนโยบาย Dry-Run Firewall และเกณฑ์ Compliance Scorecard ก่อนเปิดใช้งานจริงในองค์กรหรือโรงพยาบาล",
      actionLabel: "รัน Compliance Audit",
      targetTab: "enterprise" as TabId,
      run: async (): Promise<MissionResult> => {
        const [fw, comp] = await Promise.all([
          api.getFirewallStatus(),
          api.getComplianceScorecard(),
        ]);
        return {
          done: true,
          summary: `Firewall Mode: ${fw.policy.dry_run ? "Dry-Run (ปลอดภัย)" : "Live Active"} | Compliance Score: ${comp.score_pct}% (${comp.passed_count}/${comp.total_checks})`,
        };
      },
    },
  ];

  const completedCount = Object.values(results).filter((r) => r.done).length;

  return (
    <div className="space-y-6">
      <LearnBanner
        title="Interactive Blue Team Learning Lab (ห้องฝึกเฝ้าระวังภัยไซเบอร์)"
        summary="ฝึกใช้งานจริงผ่านระบบจริงของ NetSentinel ทีละขั้นตอน ตั้งแต่ทำ Asset Inventory, ทดสอบ Behavioral/Entropy IDS, จนถึงการตรวจสอบ Compliance Scorecard"
      />

      <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/70 px-4 py-3 text-xs">
        <span className="flex items-center gap-2 font-medium text-slate-200">
          <BookOpenCheck className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          ความคืบหน้าการฝึกปฏิบัติ
        </span>
        <span className="font-mono text-cyan-300 tabular-nums">
          {completedCount} / {missions.length} ภารกิจสำเร็จ
        </span>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-xs text-rose-200">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {missions.map((m) => {
          const result = results[m.id];
          const busy = runningId === m.id;
          return (
            <div
              key={m.id}
              className="flex flex-col justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <h3 className="text-sm font-semibold text-slate-100">{m.title}</h3>
                  {result?.done && (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-label="สำเร็จ" />
                  )}
                </div>
                <p className="text-xs leading-relaxed text-slate-400">{m.concept}</p>

                {result && (
                  <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-200">
                    <p>{result.summary}</p>
                    {result.alerts && result.alerts.length > 0 && (
                      <ul className="mt-2 space-y-1 text-[11px] text-slate-200">
                        {result.alerts.map((a) => (
                          <li key={a.id} className="flex items-center gap-1.5">
                            <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
                            <span>{a.title}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => runMission(m.id, m.run)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5" />
                  {busy ? "กำลังทำงาน…" : m.actionLabel}
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate(m.targetTab)}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-700"
                >
                  ดูผลลัพธ์ในหน้าจริง
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
