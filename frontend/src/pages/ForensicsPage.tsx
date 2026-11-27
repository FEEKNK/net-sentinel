import { useEffect, useState, type ChangeEvent, type FormEvent } from "react";
import { Download, FileText, Globe, Printer, RefreshCw, Search, Server, ShieldAlert, Upload } from "lucide-react";
import { api } from "../api";
import type { AuditSummary, PcapAnalysisResult, SyslogEvent } from "../types";
import { EmptyState, ErrorState, LearnBanner, LoadingState, SeverityBadge } from "../components/StateViews";

function formatBytes(bytes: number): string {
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function ForensicsPage() {
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // PCAP Upload Analyzer state
  const [pcapResult, setPcapResult] = useState<PcapAnalysisResult | null>(null);
  const [pcapError, setPcapError] = useState<string | null>(null);
  const [analyzingPcap, setAnalyzingPcap] = useState(false);

  // Syslog Receiver state
  const [syslogStatus, setSyslogStatus] = useState<{
    running: boolean;
    port: number;
    received_count: number;
    last_error: string | null;
  } | null>(null);
  const [syslogEvents, setSyslogEvents] = useState<SyslogEvent[]>([]);

  // Threat Intel (AbuseIPDB) state
  const [tiConfigured, setTiConfigured] = useState(false);
  const [tiMasked, setTiMasked] = useState("");
  const [tiKeyInput, setTiKeyInput] = useState("");
  const [tiResult, setTiResult] = useState<string | null>(null);

  const loadAll = async (signal?: AbortSignal) => {
    setError(null);
    try {
      const [sumData, sysData, tiData] = await Promise.all([
        api.getAuditSummary(signal),
        api.getSyslog(signal),
        api.getThreatIntelStatus(signal),
      ]);
      setSummary(sumData);
      setSyslogStatus(sysData.status);
      setSyslogEvents(sysData.events);
      setTiConfigured(tiData.configured);
      setTiMasked(tiData.key_masked);
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError(err instanceof Error ? err.message : "Failed to load forensics & audit summary");
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

  const handlePcapUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setPcapError(null);
    setAnalyzingPcap(true);
    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const base64Data = btoa(binary);
      const res = await api.analyzePcap(file.name, base64Data);
      setPcapResult(res);
    } catch (err) {
      setPcapError(err instanceof Error ? err.message : "Failed to analyze uploaded PCAP");
    } finally {
      setAnalyzingPcap(false);
      e.target.value = "";
    }
  };

  const toggleSyslog = async () => {
    try {
      const next = syslogStatus?.running ? await api.stopSyslog() : await api.startSyslog(5140);
      setSyslogStatus(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to toggle Syslog server");
    }
  };

  const handleSaveThreatIntelKey = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const res = await api.setThreatIntelKey(tiKeyInput);
      setTiConfigured(res.configured);
      setTiMasked(res.key_masked);
      setTiKeyInput("");
      setTiResult("บันทึก AbuseIPDB API Key เรียบร้อย");
    } catch (err) {
      setTiResult(err instanceof Error ? err.message : "Failed to save key");
    }
  };

  const handleCheckIpReputation = async (ip: string) => {
    setTiResult(`กำลังเช็ก ${ip}...`);
    try {
      const r = await api.checkThreatIntelIp(ip);
      setTiResult(
        `${r.ip} -> Abuse Score: ${r.abuse_confidence_score}% | Country: ${r.country_code || "-"} | ISP: ${r.isp || "-"} | Reports: ${r.total_reports}${r.is_tor ? " [TOR]" : ""}`
      );
    } catch (err) {
      setTiResult(err instanceof Error ? err.message : "Lookup failed");
    }
  };

  if (loading) return <LoadingState message="กำลังสรุปข้อมูล Forensics, Syslog และ Audit Report..." />;
  if (error || !summary) {
    return <ErrorState message={error ?? "Unable to load summary"} onRetry={() => loadAll()} />;
  }

  const protoEntries = Object.entries(summary.telemetry.protocol_counts);
  const totalProto = Math.max(1, protoEntries.reduce((acc, [, v]) => acc + v, 0));

  return (
    <div className="space-y-6">
      <LearnBanner
        title="Traffic Forensics, Offline PCAP Analyzer, Syslog & Audit Report"
        summary="วิเคราะห์ทราฟฟิกทั้งสดและจากไฟล์ .pcap ที่อัปโหลด, รับ Syslog จาก Router/NAS (UDP 5140), เช็กประวัติ IP อันตรายผ่าน Threat Intel และส่งออกรายงาน CSV / Print PDF ได้ทันที"
      />

      {/* Export & Upload PCAP Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4 print:hidden">
        <div className="text-xs text-slate-300">
          <span>Average LAN Risk Score: </span>
          <strong className="font-mono text-sm text-amber-300">
            {summary.device_summary.average_risk_score}/100
          </strong>
          <span className="ml-3 text-slate-400">
            High-Risk Devices: {summary.device_summary.high_risk_count}
          </span>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => loadAll()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
          <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-300 hover:bg-amber-500/20">
            <Upload className="h-3.5 w-3.5" />
            {analyzingPcap ? "Analyzing..." : "Upload .PCAP"}
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handlePcapUpload}
              className="hidden"
            />
          </label>
          <a
            href="/api/system/pcap/export"
            download="netsentinel-capture.pcap"
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20"
          >
            <Download className="h-3.5 w-3.5" />
            Export .PCAP
          </a>
          <a
            href="/api/reports/export.csv"
            download="netsentinel-audit-report.csv"
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-500/20"
          >
            <FileText className="h-3.5 w-3.5" />
            Export CSV
          </a>
          <button
            type="button"
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500"
          >
            <Printer className="h-3.5 w-3.5" />
            Print / PDF
          </button>
        </div>
      </div>

      {pcapError && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-2.5 text-xs text-rose-200">
          {pcapError}
        </div>
      )}

      {pcapResult && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-950/20 p-5 text-xs">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-sm font-bold text-amber-300">
              Offline PCAP Analysis Result ({pcapResult.packet_count} packets)
            </h3>
            <button
              type="button"
              onClick={() => setPcapResult(null)}
              className="text-slate-400 hover:text-white"
            >
              ปิดผลลัพธ์
            </button>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <div>
              <p className="font-semibold text-slate-200">Protocols</p>
              <p className="mt-1 font-mono text-slate-300">
                {Object.entries(pcapResult.protocol_counts)
                  .map(([k, v]) => `${k}:${v}`)
                  .join(" | ") || "-"}
              </p>
            </div>
            <div>
              <p className="font-semibold text-slate-200">Snort Rule Matches ({pcapResult.matched_rules.length})</p>
              <ul className="mt-1 space-y-0.5 text-rose-300">
                {pcapResult.matched_rules.slice(0, 5).map((m, i) => (
                  <li key={`${m.sid}-${i}`}>SID:{m.sid} {m.msg} ({m.src_ip})</li>
                ))}
                {pcapResult.matched_rules.length === 0 && <li className="text-slate-400">None</li>}
              </ul>
            </div>
            <div>
              <p className="font-semibold text-slate-200">Top DNS Domains</p>
              <p className="mt-1 font-mono text-cyan-300">
                {pcapResult.dns_queries.slice(0, 5).map((d) => d.domain).join(", ") || "-"}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Protocol Breakdown & Top Talkers */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <h3 className="mb-3 text-sm font-semibold text-slate-100">
            Protocol Distribution ({summary.telemetry.total_packets} packets)
          </h3>
          {protoEntries.length === 0 ? (
            <EmptyState
              title="ยังไม่มีสถิติโปรโตคอล"
              description="เปิด Live Sniffer หรือกด Attack Simulator เพื่อเริ่มสะสมสถิติแพ็กเก็ต"
            />
          ) : (
            <div className="space-y-3 text-xs">
              {protoEntries.map(([proto, count]) => {
                const pct = Math.round((count / totalProto) * 100);
                return (
                  <div key={proto}>
                    <div className="mb-1 flex justify-between font-mono">
                      <span className="text-cyan-300">{proto}</span>
                      <span className="text-slate-300">
                        {count} pkts ({pct}%)
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                      <div className="h-full rounded-full bg-cyan-500" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <h3 className="mb-3 text-sm font-semibold text-slate-100">Top Talkers (Source IPs)</h3>
          {summary.telemetry.top_talkers.length === 0 ? (
            <EmptyState
              title="ยังไม่มีข้อมูล Top Talkers"
              description="เปิด Live Sniffer เพื่อดูว่า IP ไหนส่งแพ็กเก็ตมากที่สุด"
            />
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2 font-medium">Source IP</th>
                  <th className="py-2 font-medium">Packets</th>
                  <th className="py-2 text-right font-medium">Volume</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 font-mono">
                {summary.telemetry.top_talkers.map((t) => (
                  <tr key={t.ip}>
                    <td className="py-2 text-cyan-300">{t.ip}</td>
                    <td className="py-2 text-slate-300">{t.packets}</td>
                    <td className="py-2 text-right text-emerald-300">{formatBytes(t.bytes_total)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* DNS & Outbound + Threat Intel Lookup */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Search className="h-4 w-4 text-cyan-400" />
            Live DNS Query Monitor (UDP 53)
          </h3>
          {summary.telemetry.dns_queries.length === 0 ? (
            <EmptyState
              title="ยังไม่พบการถาม DNS"
              description="ต้องเปิด Live Sniffer (สิทธิ์ Admin + Npcap) เพื่อดักจับ DNS Request จริงในเครือข่าย"
            />
          ) : (
            <div className="max-h-64 overflow-y-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="py-2 font-medium">Client IP</th>
                    <th className="py-2 font-medium">Queried Domain</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 font-mono">
                  {summary.telemetry.dns_queries.map((q, idx) => (
                    <tr key={`${q.timestamp}-${q.domain}-${idx}`}>
                      <td className="py-2 text-slate-300">{q.src_ip}</td>
                      <td className="py-2 text-amber-300">{q.domain}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Globe className="h-4 w-4 text-emerald-400" />
            Outbound Public IPs &amp; Threat Intel
          </h3>

          <form onSubmit={handleSaveThreatIntelKey} className="mb-3 flex gap-2 text-xs">
            <input
              type="password"
              value={tiKeyInput}
              onChange={(e) => setTiKeyInput(e.target.value)}
              placeholder={
                tiConfigured ? `AbuseIPDB Key (${tiMasked})` : "AbuseIPDB API Key (optional)"
              }
              aria-label="AbuseIPDB API Key"
              className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 font-mono text-slate-100"
            />
            <button
              type="submit"
              className="rounded-lg bg-slate-800 px-3 py-1.5 font-medium text-slate-200 hover:bg-slate-700"
            >
              บันทึก Key
            </button>
          </form>
          {tiResult && (
            <p className="mb-2 rounded bg-slate-950 px-2.5 py-1.5 font-mono text-[11px] text-cyan-300">
              {tiResult}
            </p>
          )}

          {summary.telemetry.outbound_connections.length === 0 ? (
            <EmptyState
              title="ยังไม่มีการเชื่อมต่อออก Public IP"
              description="แสดงเฉพาะทราฟฟิกที่วิ่งไปยัง IP สาธารณะภายนอกวง LAN"
            />
          ) : (
            <div className="max-h-56 overflow-y-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="py-2 font-medium">Public Dest</th>
                    <th className="py-2 font-medium">Data</th>
                    <th className="py-2 text-right font-medium">Threat Intel</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 font-mono">
                  {summary.telemetry.outbound_connections.map((flow) => (
                    <tr key={`${flow.dst_ip}-${flow.dst_port}-${flow.protocol}`}>
                      <td className="py-2 text-cyan-300">
                        {flow.dst_ip}
                        {flow.dst_port ? `:${flow.dst_port}` : ""}
                      </td>
                      <td className="py-2 text-emerald-300">{formatBytes(flow.bytes_total)}</td>
                      <td className="py-2 text-right">
                        <button
                          type="button"
                          disabled={!tiConfigured}
                          onClick={() => handleCheckIpReputation(flow.dst_ip)}
                          className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-300 disabled:opacity-40"
                        >
                          <ShieldAlert className="h-3 w-3" />
                          Check IP
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Syslog Server Receiver */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Syslog Server Receiver (UDP Port {syslogStatus?.port ?? 5140})
            </h3>
          </div>
          <button
            type="button"
            onClick={toggleSyslog}
            className={`rounded-lg px-3 py-1.5 text-xs font-semibold text-white ${
              syslogStatus?.running ? "bg-rose-600 hover:bg-rose-500" : "bg-emerald-600 hover:bg-emerald-500"
            }`}
          >
            {syslogStatus?.running ? "Stop Syslog Listener" : "Start Syslog Listener"}
          </button>
        </div>

        {syslogEvents.length === 0 ? (
          <EmptyState
            title="ยังไม่มี Syslog เข้ามา"
            description="เปิด Listener แล้วตั้งค่าให้ Router/NAS/Switch ส่ง Syslog มายัง IP เครื่องนี้พอร์ต UDP 5140"
          />
        ) : (
          <div className="max-h-56 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950 p-2 font-mono text-[11px]">
            {syslogEvents.map((ev) => (
              <div key={ev.id} className="border-b border-slate-900 py-1 text-slate-300">
                <span className="text-amber-300">[{ev.severity.toUpperCase()}]</span>{" "}
                <span className="text-cyan-300">{ev.source_ip}</span>: {ev.message}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Risk Inventory Summary */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h3 className="mb-3 text-sm font-semibold text-slate-100">
          Device Security Risk Audit ({summary.scored_devices.length} devices)
        </h3>
        {summary.scored_devices.length === 0 ? (
          <EmptyState
            title="ยังไม่มีข้อมูลอุปกรณ์สำหรับจัดทำรายงาน"
            description="ไปที่หน้า IP Scanner แล้วกด Scan Now ก่อนจัดทำรายงาน"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2 pr-3 font-medium">Grade</th>
                  <th className="py-2 pr-3 font-medium">IP / Name</th>
                  <th className="py-2 pr-3 font-medium">Risk Factors</th>
                  <th className="py-2 font-medium">Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {summary.scored_devices.map((d) => (
                  <tr key={d.ip}>
                    <td className="py-2 pr-3 font-mono font-bold">
                      <span
                        className={`rounded px-2 py-0.5 ${
                          d.risk_grade === "A"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : d.risk_grade === "B"
                              ? "bg-cyan-500/15 text-cyan-300"
                              : d.risk_grade === "C"
                                ? "bg-amber-500/15 text-amber-300"
                                : "bg-rose-500/20 text-rose-300"
                        }`}
                      >
                        {d.risk_grade ?? "A"} ({d.risk_score ?? 0})
                      </span>
                    </td>
                    <td className="py-2 pr-3 font-mono text-slate-200">
                      {d.ip} {d.custom_name || d.hostname ? `(${d.custom_name || d.hostname})` : ""}
                    </td>
                    <td className="py-2 pr-3 text-slate-400">
                      {(d.risk_reasons ?? []).length > 0 ? d.risk_reasons?.join(" · ") : "No elevated risks"}
                    </td>
                    <td className="py-2">
                      <SeverityBadge severity={(d.risk_score ?? 0) >= 50 ? "high" : "low"} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
