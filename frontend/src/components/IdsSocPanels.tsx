import { useCallback, useEffect, useState, type FormEvent } from "react";
import { AlertTriangle, Bot, Check, ShieldPlus, Sliders, Trash2 } from "lucide-react";
import { api } from "../api";
import type { IdsTuning, IncidentCase, IocItem, PlaybookItem } from "../types";
import { EmptyState, SeverityBadge } from "./StateViews";

interface IdsSocPanelsProps {
  onRefresh: () => void;
}

const DETECTORS = [
  "behavioral_port_scan",
  "behavioral_syn_flood",
  "behavioral_bruteforce",
  "behavioral_dns_tunnel",
  "behavioral_icmp_tunnel",
  "behavioral_icmp_flood",
  "behavioral_dhcp_rogue",
  "behavioral_arp_spoof",
  "ioc_match",
  "snort_rule",
];

export function IdsSocPanels({ onRefresh }: IdsSocPanelsProps) {
  const [incidents, setIncidents] = useState<IncidentCase[]>([]);
  const [playbooks, setPlaybooks] = useState<PlaybookItem[]>([]);
  const [iocs, setIocs] = useState<IocItem[]>([]);
  const [iocStats, setIocStats] = useState({ ip: 0, domain: 0 });
  const [tuning, setTuning] = useState<IdsTuning | null>(null);

  // Playbook form
  const [pbName, setPbName] = useState("");
  const [pbSeverity, setPbSeverity] = useState<"low" | "medium" | "high" | "critical">("critical");
  const [pbDetector, setPbDetector] = useState("any");
  const [pbAction, setPbAction] = useState<"create_incident" | "notify_webhook" | "dry_run_block">("create_incident");

  // IOC import form
  const [iocText, setIocText] = useState("");
  const [iocSource, setIocSource] = useState("manual");
  const [iocSeverity, setIocSeverity] = useState<"medium" | "high" | "critical">("critical");

  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const loadSoc = useCallback(async (signal?: AbortSignal) => {
    try {
      const [incRes, pbRes, iocRes, tuneRes] = await Promise.all([
        api.listIncidents(signal),
        api.listPlaybooks(signal),
        api.listIocs(signal),
        api.getIdsTuning(signal),
      ]);
      setIncidents(incRes.incidents);
      setPlaybooks(pbRes.playbooks);
      setIocs(iocRes.iocs);
      setIocStats({ ip: iocRes.ip_count, domain: iocRes.domain_count });
      setTuning(tuneRes);
    } catch (e) {
      if ((e as Error).name !== "AbortError") {
        setErr(e instanceof Error ? e.message : "Failed to load SOC modules");
      }
    }
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    loadSoc(ctrl.signal);
    return () => ctrl.abort();
  }, [loadSoc]);

  const handleIncidentStatus = async (
    id: number,
    status: "open" | "investigating" | "resolved" | "false_positive"
  ) => {
    setErr(null);
    try {
      await api.updateIncident(id, { status });
      await loadSoc();
      onRefresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to update incident");
    }
  };

  const handleCreatePlaybook = async (e: FormEvent) => {
    e.preventDefault();
    if (!pbName.trim()) return;
    setErr(null);
    setMsg(null);
    try {
      await api.createPlaybook({
        name: pbName.trim(),
        trigger_severity: pbSeverity,
        trigger_detector: pbDetector,
        action_type: pbAction,
      });
      setPbName("");
      setMsg("สร้าง Mini-SOAR Playbook สำเร็จ");
      await loadSoc();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to create playbook");
    }
  };

  const handleImportIocs = async (e: FormEvent) => {
    e.preventDefault();
    if (!iocText.trim()) return;
    setErr(null);
    setMsg(null);
    try {
      const res = await api.importIocs(iocText, iocSource.trim() || "manual", iocSeverity);
      setIocText("");
      setMsg(`นำเข้า IOC สำเร็จ ${res.imported} รายการ (ข้ามบรรทัดไม่ถูกต้อง ${res.invalid})`);
      await loadSoc();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "IOC import failed");
    }
  };

  const handleSaveTuning = async (e: FormEvent) => {
    e.preventDefault();
    if (!tuning) return;
    setErr(null);
    setMsg(null);
    try {
      const updated = await api.updateIdsTuning(tuning);
      setTuning(updated);
      setMsg("บันทึก IDS Threshold Tuning ลงฐานข้อมูลเรียบร้อย");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to save IDS tuning");
    }
  };

  return (
    <div className="space-y-6">
      {err && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-2 text-xs text-rose-200">
          {err}
        </div>
      )}
      {msg && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 px-4 py-2 text-xs text-emerald-200">
          {msg}
        </div>
      )}

      {/* Incident Case Management & Mini-SOAR Playbooks */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <AlertTriangle className="h-4 w-4 text-amber-400" aria-hidden="true" />
            Incident Cases ({incidents.length})
          </h3>
          {incidents.length === 0 ? (
            <EmptyState
              title="ยังไม่มี Incident Case"
              description="เมื่อมี Critical/High Alert หรือ Mini-SOAR Trigger ระบบจะรวมกลุ่มเป็น Case ให้อัตโนมัติ"
            />
          ) : (
            <div className="max-h-72 space-y-2 overflow-y-auto">
              {incidents.map((inc) => (
                <div
                  key={inc.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/70 p-3"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-slate-400">#{inc.id}</span>
                      <span className="truncate font-semibold text-slate-100">{inc.title}</span>
                      <SeverityBadge severity={inc.severity} />
                    </div>
                    <p className="mt-1 font-mono text-[11px] text-slate-400 tabular-nums">
                      <span translate="no">{inc.source_ip}</span> · Hits: {inc.alert_count}
                    </p>
                  </div>
                  <label className="sr-only" htmlFor={`inc-status-${inc.id}`}>
                    สถานะเคส {inc.id}
                  </label>
                  <select
                    id={`inc-status-${inc.id}`}
                    value={inc.status}
                    onChange={(e) =>
                      handleIncidentStatus(
                        inc.id,
                        e.target.value as "open" | "investigating" | "resolved" | "false_positive"
                      )
                    }
                    className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] text-slate-200"
                  >
                    <option value="open">open</option>
                    <option value="investigating">investigating</option>
                    <option value="resolved">resolved</option>
                    <option value="false_positive">false_positive</option>
                  </select>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Bot className="h-4 w-4 text-cyan-400" aria-hidden="true" />
            Mini-SOAR Playbooks ({playbooks.length})
          </h3>
          <form onSubmit={handleCreatePlaybook} className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div>
              <label htmlFor="pb-name" className="block text-[11px] text-slate-300">ชื่อ Playbook</label>
              <input
                id="pb-name"
                type="text"
                value={pbName}
                onChange={(e) => setPbName(e.target.value)}
                placeholder="Auto Open Case on Critical"
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
              />
            </div>
            <div>
              <label htmlFor="pb-sev" className="block text-[11px] text-slate-300">Min Severity</label>
              <select
                id="pb-sev"
                value={pbSeverity}
                onChange={(e) => setPbSeverity(e.target.value as "low" | "medium" | "high" | "critical")}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-200"
              >
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
            </div>
            <div>
              <label htmlFor="pb-det" className="block text-[11px] text-slate-300">Detector Trigger</label>
              <select
                id="pb-det"
                value={pbDetector}
                onChange={(e) => setPbDetector(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-200"
              >
                <option value="any">any</option>
                {DETECTORS.map((d) => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="pb-act" className="block text-[11px] text-slate-300">Action</label>
              <select
                id="pb-act"
                value={pbAction}
                onChange={(e) =>
                  setPbAction(e.target.value as "create_incident" | "notify_webhook" | "dry_run_block")
                }
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-200"
              >
                <option value="create_incident">Create Incident Case</option>
                <option value="notify_webhook">Send Webhook Alert</option>
                <option value="dry_run_block">Dry-Run Firewall Block</option>
              </select>
            </div>
            <button
              type="submit"
              className="sm:col-span-2 rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500"
            >
              เพิ่ม Playbook อัตโนมัติ
            </button>
          </form>

          {playbooks.length > 0 && (
            <div className="space-y-1.5 pt-2">
              {playbooks.map((pb) => (
                <div
                  key={pb.id}
                  className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium text-slate-200">{pb.name}</p>
                    <p translate="no" className="font-mono text-[11px] text-slate-400">
                      {pb.trigger_severity}+ / {pb.trigger_detector} -&gt; {pb.action_type}
                    </p>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={async () => {
                        await api.togglePlaybook(pb.id, !pb.enabled);
                        await loadSoc();
                      }}
                      className={`rounded px-2 py-0.5 text-[11px] font-medium ${
                        pb.enabled ? "bg-emerald-500/20 text-emerald-300" : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {pb.enabled ? "ON" : "OFF"}
                    </button>
                    <button
                      type="button"
                      aria-label={`ลบ Playbook ${pb.name}`}
                      onClick={async () => {
                        await api.deletePlaybook(pb.id, true);
                        await loadSoc();
                      }}
                      className="rounded p-1 text-rose-300 hover:bg-rose-500/20"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* IOC Feed Matcher & IDS Threshold Tuning */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <ShieldPlus className="h-4 w-4 text-rose-400" aria-hidden="true" />
            IOC Blocklist Feed ({iocStats.ip} IPs · {iocStats.domain} Domains)
          </h3>
          <form onSubmit={handleImportIocs} className="space-y-2">
            <div>
              <label htmlFor="ioc-raw" className="block text-[11px] text-slate-300">
                วางรายการ Malicious IP / Domain (บรรทัดละ 1 ค่า)
              </label>
              <textarea
                id="ioc-raw"
                rows={4}
                value={iocText}
                onChange={(e) => setIocText(e.target.value)}
                placeholder={"185.220.101.5\nbad-c2-domain.example"}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-2.5 font-mono text-[11px] text-slate-100"
              />
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <div className="flex-1">
                <label htmlFor="ioc-src" className="block text-[11px] text-slate-300">Feed Source</label>
                <input
                  id="ioc-src"
                  type="text"
                  value={iocSource}
                  onChange={(e) => setIocSource(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="ioc-sev" className="block text-[11px] text-slate-300">Severity</label>
                <select
                  id="ioc-sev"
                  value={iocSeverity}
                  onChange={(e) => setIocSeverity(e.target.value as "medium" | "high" | "critical")}
                  className="mt-1 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-200"
                >
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                </select>
              </div>
              <button
                type="submit"
                className="rounded-lg bg-rose-600 px-3 py-1.5 font-semibold text-white hover:bg-rose-500"
              >
                Import IOCs
              </button>
            </div>
          </form>

          {iocs.length > 0 && (
            <div className="max-h-40 divide-y divide-slate-800 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950/60 px-3">
              {iocs.slice(0, 20).map((item) => (
                <div key={item.id} className="flex items-center justify-between py-1.5">
                  <span translate="no" className="font-mono text-slate-200">
                    {item.indicator} <span className="text-slate-500">({item.kind})</span>
                  </span>
                  <button
                    type="button"
                    onClick={async () => {
                      await api.deleteIoc(item.id, true);
                      await loadSoc();
                    }}
                    aria-label={`ลบ IOC ${item.indicator}`}
                    className="text-rose-400 hover:text-rose-300"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {tuning && (
          <form
            onSubmit={handleSaveTuning}
            className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-xs"
          >
            <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Sliders className="h-4 w-4 text-cyan-400" aria-hidden="true" />
              IDS Sensitivity &amp; Threshold Tuning
            </h3>

            <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 tabular-nums">
              <div>
                <label htmlFor="t-ps" className="block text-[11px] text-slate-300">Port Scan Ports</label>
                <input
                  id="t-ps"
                  type="number"
                  value={tuning.port_scan_threshold}
                  onChange={(e) => setTuning({ ...tuning, port_scan_threshold: Number(e.target.value) })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="t-syn" className="block text-[11px] text-slate-300">SYN Flood / 5s</label>
                <input
                  id="t-syn"
                  type="number"
                  value={tuning.syn_flood_threshold}
                  onChange={(e) => setTuning({ ...tuning, syn_flood_threshold: Number(e.target.value) })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="t-bf" className="block text-[11px] text-slate-300">Brute-Force Hits</label>
                <input
                  id="t-bf"
                  type="number"
                  value={tuning.bruteforce_threshold}
                  onChange={(e) => setTuning({ ...tuning, bruteforce_threshold: Number(e.target.value) })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="t-dns" className="block text-[11px] text-slate-300">DNS Entropy Min</label>
                <input
                  id="t-dns"
                  type="number"
                  step="0.1"
                  value={tuning.dns_entropy_threshold}
                  onChange={(e) => setTuning({ ...tuning, dns_entropy_threshold: Number(e.target.value) })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="t-icmp" className="block text-[11px] text-slate-300">ICMP Flood Hits</label>
                <input
                  id="t-icmp"
                  type="number"
                  value={tuning.icmp_flood_threshold}
                  onChange={(e) => setTuning({ ...tuning, icmp_flood_threshold: Number(e.target.value) })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-100"
                />
              </div>
              <div>
                <label htmlFor="t-cd" className="block text-[11px] text-slate-300">Cooldown (sec)</label>
                <input
                  id="t-cd"
                  type="number"
                  value={tuning.cooldown_seconds}
                  onChange={(e) => setTuning({ ...tuning, cooldown_seconds: Number(e.target.value) })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-100"
                />
              </div>
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500"
              >
                <Check className="h-3.5 w-3.5" />
                บันทึก IDS Tuning
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
