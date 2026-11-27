import { useEffect, useState, type FormEvent } from "react";
import { Bell, Download, Flame, Play, Save, Send, Square, Trash2, X } from "lucide-react";
import { api } from "../api";
import type { AlertRecord, PacketSummary, SnifferStatus, SnortRuleItem, WebhookStatus } from "../types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { IdsSocPanels } from "../components/IdsSocPanels";
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
  { id: "bruteforce", label: "Simulate Brute-Force SSH", desc: "ยิงพอร์ต 22 ซ้ำๆ 18 ครั้ง -> Brute-Force Detector" },
  { id: "dns_tunnel", label: "Simulate DNS Tunnel", desc: "ส่ง DNS ชื่อโดเมน Entropy สูง -> DNS Tunnel Detector" },
  { id: "icmp_flood", label: "Simulate ICMP Flood", desc: "ส่ง ICMP Ping ขนาดใหญ่รัว -> ICMP Tunnel/Flood" },
  { id: "dhcp_rogue", label: "Simulate Rogue DHCP", desc: "ตรวจพบ DHCP Server แปลกปลอมจ่าย IP -> Critical Alert" },
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

  const [webhookStatus, setWebhookStatus] = useState<WebhookStatus | null>(null);
  const [discordUrl, setDiscordUrl] = useState("");
  const [telegramToken, setTelegramToken] = useState("");
  const [telegramChatId, setTelegramChatId] = useState("");
  const [enterpriseUrl, setEnterpriseUrl] = useState("");
  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState("587");
  const [smtpTo, setSmtpTo] = useState("");
  const [webhookSeverity, setWebhookSeverity] = useState<"low" | "medium" | "high" | "critical">("high");

  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmClearOpen, setConfirmClearOpen] = useState(false);
  const [confirmSaveRulesOpen, setConfirmSaveRulesOpen] = useState(false);
  const [packetFilter, setPacketFilter] = useState("");
  const [inspectedPacket, setInspectedPacket] = useState<PacketSummary | null>(null);
  const [streamData, setStreamData] = useState<{
    client_to_server: string;
    server_to_client: string;
  } | null>(null);
  const [streamError, setStreamError] = useState<string | null>(null);

  useEffect(() => {
    if (!inspectedPacket) {
      setStreamData(null);
      setStreamError(null);
      return;
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setInspectedPacket(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [inspectedPacket]);

  const handleFollowStream = async () => {
    if (!inspectedPacket || !inspectedPacket.src_port || !inspectedPacket.dst_port) {
      setStreamError("Follow Stream requires TCP source & destination ports");
      return;
    }
    setStreamError(null);
    try {
      const data = await api.followTcpStream(
        inspectedPacket.src_ip,
        inspectedPacket.src_port,
        inspectedPacket.dst_ip,
        inspectedPacket.dst_port
      );
      setStreamData(data);
    } catch (err) {
      setStreamError(err instanceof Error ? err.message : "Failed to load TCP stream");
    }
  };

  const fetchRulesAndWebhooks = async (signal?: AbortSignal) => {
    try {
      const [rulesData, whData] = await Promise.all([
        api.getRules(signal),
        api.getWebhookStatus(signal),
      ]);
      setRulesText(rulesData.content);
      setParsedRules(rulesData.rules);
      setRuleErrors(rulesData.errors);
      setRulesLoaded(true);
      setWebhookStatus(whData);
      setWebhookSeverity(whData.min_severity);
      setTelegramChatId(whData.telegram_chat_id);
      setSmtpHost(whData.smtp_host ?? "");
      setSmtpTo(whData.smtp_to ?? "");
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setActionError(err instanceof Error ? err.message : "Failed to load IDS config");
      }
    }
  };

  useEffect(() => {
    const ctrl = new AbortController();
    fetchRulesAndWebhooks(ctrl.signal);
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
      await fetchRulesAndWebhooks();
      onRefresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Failed to save rules");
      setConfirmSaveRulesOpen(false);
    } finally {
      setBusyAction(null);
    }
  };

  const handleSaveWebhooks = async (e: FormEvent) => {
    e.preventDefault();
    setBusyAction("save_webhook");
    setActionError(null);
    setFeedback(null);
    try {
      const payload: Parameters<typeof api.updateWebhookSettings>[0] = {
        enabled: webhookStatus?.enabled ?? true,
        min_severity: webhookSeverity,
        telegram_chat_id: telegramChatId,
        smtp_host: smtpHost.trim(),
        smtp_port: Number(smtpPort) || 587,
        smtp_to: smtpTo.trim(),
      };
      if (discordUrl.trim()) payload.discord_webhook_url = discordUrl.trim();
      if (telegramToken.trim()) payload.telegram_bot_token = telegramToken.trim();
      if (enterpriseUrl.trim()) payload.enterprise_webhook_url = enterpriseUrl.trim();
      const updated = await api.updateWebhookSettings(payload);
      setWebhookStatus(updated);
      setDiscordUrl("");
      setTelegramToken("");
      setEnterpriseUrl("");
      setFeedback("บันทึกการตั้งค่า Webhook / Enterprise & SMTP เรียบร้อย (Token ถูกซ่อนเพื่อความปลอดภัย)");
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Webhook save failed");
    } finally {
      setBusyAction(null);
    }
  };

  const handleToggleWebhookEnabled = async () => {
    if (!webhookStatus) return;
    setBusyAction("toggle_webhook");
    setActionError(null);
    try {
      const updated = await api.updateWebhookSettings({ enabled: !webhookStatus.enabled });
      setWebhookStatus(updated);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Toggle webhook failed");
    } finally {
      setBusyAction(null);
    }
  };

  const handleTestWebhook = async () => {
    setBusyAction("test_webhook");
    setActionError(null);
    setFeedback(null);
    try {
      const res = await api.testWebhook();
      setWebhookStatus(res.status);
      if (res.sent) {
        setFeedback(`ส่งข้อความทดสอบไปยัง ${res.delivered?.join(", ")} สำเร็จ!`);
      } else {
        setActionError(res.errors?.join("; ") || res.reason || "ยังไม่ได้ตั้งค่า Webhook");
      }
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Webhook test failed");
    } finally {
      setBusyAction(null);
    }
  };

  const filteredAlerts =
    severityFilter === "all"
      ? alerts
      : alerts.filter((a) => a.severity.toLowerCase() === severityFilter);

  const filteredPackets = packets.filter((pkt) => {
    const q = packetFilter.trim().toLowerCase();
    if (!q) return true;
    if (q.startsWith("proto:")) return pkt.protocol.toLowerCase() === q.slice(6).trim();
    if (q.startsWith("ip:")) {
      const ipq = q.slice(3).trim();
      return pkt.src_ip.includes(ipq) || pkt.dst_ip.includes(ipq);
    }
    if (q.startsWith("port:")) {
      const pq = Number(q.slice(5).trim());
      return pkt.src_port === pq || pkt.dst_port === pq;
    }
    return (
      pkt.protocol.toLowerCase().includes(q) ||
      pkt.src_ip.toLowerCase().includes(q) ||
      pkt.dst_ip.toLowerCase().includes(q) ||
      pkt.preview.toLowerCase().includes(q) ||
      (pkt.dns_query ?? "").toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      <LearnBanner
        title="Packet Sniffer, Hybrid IDS & Mobile Alerting"
        summary="ตรวจจับทั้ง Port Scan, SYN Flood, ARP Spoofing, อุปกรณ์แปลกหน้าเข้า LAN (Rogue Device) และกฎ Snort พร้อมส่งแจ้งเตือนเข้า Discord หรือ Telegram ได้ทันทีเมื่อเกิดเหตุการณ์สำคัญ"
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
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-slate-100">
              Recent Packet Buffer ({filteredPackets.length}) — คลิกเพื่อดู Hex Dump / Follow Stream
            </h3>
            <a
              href="/api/system/pcap/export"
              download="netsentinel-capture.pcap"
              className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-semibold text-cyan-300 hover:bg-cyan-500/20"
            >
              <Download className="h-3 w-3" />
              .PCAP
            </a>
          </div>
          <input
            type="text"
            aria-label="Wireshark style packet display filter"
            value={packetFilter}
            onChange={(e) => setPacketFilter(e.target.value)}
            placeholder="Filter เช่น proto:tcp | ip:192.168.1 | port:80 | UNION"
            className="mb-2.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-100 focus:border-cyan-500 focus:outline-none"
          />
          {filteredPackets.length === 0 ? (
            <EmptyState
              title="ยังไม่มี Packet ที่ตรงเงื่อนไข"
              description="กด Start Sniffer (ต้องใช้สิทธิ์ Admin/Npcap) หรือกดปุ่ม Attack Simulator"
            />
          ) : (
            <div className="max-h-72 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950 p-2 font-mono text-[11px]">
              {filteredPackets.slice(0, 40).map((pkt, idx) => (
                <button
                  key={`${pkt.timestamp}-${pkt.src_ip}-${pkt.dst_ip}-${idx}`}
                  type="button"
                  onClick={() => setInspectedPacket(pkt)}
                  className="block w-full border-b border-slate-900 py-1 text-left text-slate-300 hover:bg-slate-900/90"
                >
                  <span className="text-cyan-400">[{pkt.protocol}]</span> {pkt.src_ip}
                  {pkt.src_port ? `:${pkt.src_port}` : ""} -&gt; {pkt.dst_ip}
                  {pkt.dst_port ? `:${pkt.dst_port}` : ""}{" "}
                  <span className="text-slate-500">({pkt.length}B)</span>{" "}
                  {pkt.preview && <span className="text-amber-300">{pkt.preview}</span>}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Discord & Telegram Webhook Alerting */}
      <form
        onSubmit={handleSaveWebhooks}
        className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 text-xs"
      >
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Bell className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Discord & Telegram Webhook Alerting
            </h3>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={handleToggleWebhookEnabled}
              className={`rounded-lg px-3 py-1.5 font-semibold text-white ${
                webhookStatus?.enabled
                  ? "bg-emerald-600 hover:bg-emerald-500"
                  : "bg-slate-700 hover:bg-slate-600"
              }`}
            >
              {webhookStatus?.enabled ? "Notifications: ON" : "Notifications: OFF"}
            </button>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={handleTestWebhook}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 font-semibold text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" />
              ทดสอบส่งข้อความ
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          <div className="md:col-span-2">
            <label htmlFor="discord-webhook" className="block text-slate-300">
              Discord Webhook URL{" "}
              {webhookStatus?.discord_configured && (
                <span className="text-emerald-400">({webhookStatus.discord_masked})</span>
              )}
            </label>
            <input
              id="discord-webhook"
              type="password"
              value={discordUrl}
              onChange={(e) => setDiscordUrl(e.target.value)}
              placeholder="https://discord.com/api/webhooks/..."
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="tg-token" className="block text-slate-300">
              Telegram Bot Token{" "}
              {webhookStatus?.telegram_configured && (
                <span className="text-emerald-400">({webhookStatus.telegram_token_masked})</span>
              )}
            </label>
            <input
              id="tg-token"
              type="password"
              value={telegramToken}
              onChange={(e) => setTelegramToken(e.target.value)}
              placeholder="123456:ABC-DEF..."
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="tg-chat" className="block text-slate-300">
              Telegram Chat ID &amp; Min Severity
            </label>
            <div className="mt-1 flex gap-2">
              <input
                id="tg-chat"
                type="text"
                value={telegramChatId}
                onChange={(e) => setTelegramChatId(e.target.value)}
                placeholder="Chat ID"
                className="w-1/2 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2 font-mono text-slate-100"
              />
              <select
                aria-label="Webhook minimum severity"
                value={webhookSeverity}
                onChange={(e) =>
                  setWebhookSeverity(e.target.value as "low" | "medium" | "high" | "critical")
                }
                className="w-1/2 rounded-lg border border-slate-700 bg-slate-950 px-2 py-2 text-slate-200"
              >
                <option value="low">LOW+</option>
                <option value="medium">MEDIUM+</option>
                <option value="high">HIGH+</option>
                <option value="critical">CRITICAL</option>
              </select>
            </div>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-4">
          <div className="md:col-span-2">
            <label htmlFor="enterprise-webhook" className="block text-slate-300">
              Enterprise Webhook URL (MS Teams / Ticket HTTPS){" "}
              {webhookStatus?.enterprise_configured && (
                <span className="text-emerald-400">({webhookStatus.enterprise_masked})</span>
              )}
            </label>
            <input
              id="enterprise-webhook"
              type="password"
              value={enterpriseUrl}
              onChange={(e) => setEnterpriseUrl(e.target.value)}
              placeholder="https://outlook.office.com/webhook/..."
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="smtp-host" className="block text-slate-300">
              SMTP Relay Host &amp; Port
            </label>
            <div className="mt-1 flex gap-2">
              <input
                id="smtp-host"
                type="text"
                value={smtpHost}
                onChange={(e) => setSmtpHost(e.target.value)}
                placeholder="smtp.hospital.local"
                className="w-2/3 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2 font-mono text-slate-100"
              />
              <input
                aria-label="SMTP Port"
                type="number"
                value={smtpPort}
                onChange={(e) => setSmtpPort(e.target.value)}
                className="w-1/3 rounded-lg border border-slate-700 bg-slate-950 px-2 py-2 font-mono text-slate-100 tabular-nums"
              />
            </div>
          </div>
          <div>
            <label htmlFor="smtp-to" className="block text-slate-300">
              Alert Email Recipient
            </label>
            <input
              id="smtp-to"
              type="email"
              value={smtpTo}
              onChange={(e) => setSmtpTo(e.target.value)}
              placeholder="soc@example.org"
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-slate-100"
            />
          </div>
        </div>

        <div className="mt-3 flex justify-end">
          <button
            type="submit"
            disabled={busyAction !== null}
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-2 font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
          >
            <Save className="h-3.5 w-3.5" />
            บันทึกการตั้งค่า Webhook
          </button>
        </div>
      </form>

      <IdsSocPanels onRefresh={onRefresh} />

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

      {/* Deep Packet Inspector Modal */}
      {inspectedPacket && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-xs"
          role="dialog"
          aria-modal="true"
          aria-label="Deep Packet Inspector"
        >
          <div className="w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-cyan-300">
                Deep Packet Inspector [{inspectedPacket.protocol}]
              </h3>
              <button
                type="button"
                onClick={() => setInspectedPacket(null)}
                aria-label="ปิด Packet Inspector"
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-3 grid grid-cols-2 gap-2 rounded-lg bg-slate-950 p-3 font-mono text-xs text-slate-300 sm:grid-cols-3">
              <div>Src: {inspectedPacket.src_ip}{inspectedPacket.src_port ? `:${inspectedPacket.src_port}` : ""}</div>
              <div>Dst: {inspectedPacket.dst_ip}{inspectedPacket.dst_port ? `:${inspectedPacket.dst_port}` : ""}</div>
              <div>Length: {inspectedPacket.length} bytes</div>
              <div>TTL: {inspectedPacket.ttl ?? "-"}</div>
              <div>TCP Flags: {inspectedPacket.tcp_flags || "-"}</div>
              <div>DNS: {inspectedPacket.dns_query || "-"}</div>
            </div>

            <div className="mt-3">
              <div className="mb-1 flex items-center justify-between">
                <p className="text-xs font-semibold text-slate-300">Hex &amp; ASCII Dump</p>
                {inspectedPacket.protocol === "TCP" && inspectedPacket.src_port && inspectedPacket.dst_port && (
                  <button
                    type="button"
                    onClick={handleFollowStream}
                    className="rounded border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-semibold text-cyan-300 hover:bg-cyan-500/20"
                  >
                    Follow TCP Stream
                  </button>
                )}
              </div>
              <pre className="max-h-56 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] leading-relaxed text-emerald-300">
                {inspectedPacket.hex_dump || "(No payload bytes captured)"}
              </pre>
            </div>

            {streamError && (
              <p className="mt-2 text-xs text-rose-300">{streamError}</p>
            )}
            {streamData && (
              <div className="mt-3 space-y-2 rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-[11px]">
                <div className="font-semibold text-cyan-300">Reassembled TCP Stream</div>
                <div className="text-amber-300">
                  Client -&gt; Server: {streamData.client_to_server || "(empty)"}
                </div>
                <div className="text-emerald-300">
                  Server -&gt; Client: {streamData.server_to_client || "(empty)"}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
