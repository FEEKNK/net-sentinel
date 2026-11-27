import type {
  AlertRecord,
  AlertCounts,
  AuditLogEntry,
  AuditSummary,
  BlockedIpRecord,
  ComplianceScorecard,
  ConfigSnapshot,
  Device360Response,
  DeviceHistoryPoint,
  DeviceRecord,
  HttpMonitor,
  IdsTuning,
  IncidentCase,
  IocItem,
  IpamGrid,
  IpamReservation,
  NetFlowSummary,
  PacketSummary,
  PcapAnalysisResult,
  PlaybookItem,
  PolicyState,
  ProcessConnection,
  RbacUser,
  RemoteSensor,
  SafetyState,
  ScanSchedule,
  SnmpMetric,
  SnmpTarget,
  SnmpTrapsResponse,
  SnifferStatus,
  SnortRuleItem,
  SyslogEvent,
  SystemStatus,
  TracerouteHop,
  TrafficTelemetry,
  WatchdogPing,
  WebhookStatus,
  WifiAnalysis,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const TOKEN_KEY = "netsentinel_session_token";

export function getSessionToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setSessionToken(token: string): void {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
    }
  } catch {
    // Ignore storage errors
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getSessionToken();
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "X-NetSentinel-Token": token } : {}),
      ...(init?.headers ?? {}),
    },
  });

  const text = await res.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { detail: text };
    }
  }

  if (!res.ok) {
    const detail =
      typeof parsed === "object" && parsed !== null && "detail" in parsed
        ? (parsed as { detail: unknown }).detail
        : `HTTP ${res.status}`;
    const msg = typeof detail === "string" ? detail : JSON.stringify(detail);
    throw new ApiError(res.status, msg);
  }

  return parsed as T;
}

export const api = {
  getAuthStatus: (signal?: AbortSignal) =>
    request<{ lock_enabled: boolean; authenticated: boolean }>("/api/auth/status", { signal }),

  setupPasscode: (passcode: string) =>
    request<{ enabled: boolean; token: string }>("/api/auth/setup", {
      method: "POST",
      body: JSON.stringify({ passcode }),
    }),

  loginPasscode: (passcode: string) =>
    request<{ authenticated: boolean; token: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ passcode }),
    }),

  logoutPasscode: () =>
    request<{ authenticated: boolean }>("/api/auth/logout", { method: "POST" }),

  disablePasscode: (passcode: string) =>
    request<{ enabled: boolean }>("/api/auth/disable", {
      method: "POST",
      body: JSON.stringify({ passcode }),
    }),

  getSystemStatus: (signal?: AbortSignal) =>
    request<SystemStatus>("/api/system/status", { signal }),

  startSniffer: (interfaceName?: string) => {
    const qs = interfaceName ? `?interface=${encodeURIComponent(interfaceName)}` : "";
    return request<SnifferStatus>(`/api/system/sniffer/start${qs}`, { method: "POST" });
  },

  stopSniffer: () =>
    request<SnifferStatus>("/api/system/sniffer/stop", { method: "POST" }),

  getPackets: (limit = 60, signal?: AbortSignal) =>
    request<{ packets: PacketSummary[]; total_captured: number }>(
      `/api/system/packets?limit=${limit}`,
      { signal }
    ),

  followTcpStream: (srcIp: string, srcPort: number, dstIp: string, dstPort: number) =>
    request<{ client_to_server: string; server_to_client: string }>(
      `/api/system/follow-stream?src_ip=${encodeURIComponent(srcIp)}&src_port=${srcPort}&dst_ip=${encodeURIComponent(dstIp)}&dst_port=${dstPort}`
    ),

  analyzePcap: (filename: string, base64Data: string) =>
    request<PcapAnalysisResult>("/api/system/pcap/analyze", {
      method: "POST",
      body: JSON.stringify({ filename, base64_data: base64Data }),
    }),

  getSyslog: (signal?: AbortSignal) =>
    request<{
      status: { running: boolean; port: number; received_count: number; last_error: string | null };
      events: SyslogEvent[];
    }>("/api/system/syslog", { signal }),

  startSyslog: (port = 5140) =>
    request<{ running: boolean; port: number; received_count: number; last_error: string | null }>(
      `/api/system/syslog/start?port=${port}`,
      { method: "POST" }
    ),

  stopSyslog: () =>
    request<{ running: boolean; port: number; received_count: number; last_error: string | null }>(
      "/api/system/syslog/stop",
      { method: "POST" }
    ),

  getWatchdog: (signal?: AbortSignal) =>
    request<{ enabled: boolean; target_ip: string; pings: WatchdogPing[] }>(
      "/api/system/watchdog",
      { signal }
    ),

  updateWatchdog: (payload: { enabled?: boolean; target_ip?: string }) =>
    request<{ enabled: boolean; target_ip: string }>("/api/system/watchdog", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  checkWatchdogNow: () =>
    request<WatchdogPing>("/api/system/watchdog/check", { method: "POST" }),

  getThreatIntelStatus: (signal?: AbortSignal) =>
    request<{ configured: boolean; key_masked: string; cached_count: number }>(
      "/api/system/threat-intel",
      { signal }
    ),

  setThreatIntelKey: (apiKey: string) =>
    request<{ configured: boolean; key_masked: string; cached_count: number }>(
      "/api/system/threat-intel",
      {
        method: "PUT",
        body: JSON.stringify({ api_key: apiKey }),
      }
    ),

  checkThreatIntelIp: (ip: string) =>
    request<{
      ip: string;
      abuse_confidence_score: number;
      country_code: string;
      isp: string;
      total_reports: number;
      is_tor: boolean;
    }>("/api/system/threat-intel/check", {
      method: "POST",
      body: JSON.stringify({ ip }),
    }),

  listDevices: (signal?: AbortSignal) =>
    request<{
      devices: DeviceRecord[];
      online_count: number;
      total_count: number;
      default_subnet: string;
      schedule: ScanSchedule;
    }>("/api/devices", { signal }),

  scanSubnet: (cidr: string, scanPorts: boolean, portSpec?: string, scanUdp = false) =>
    request<{
      cidr: string;
      scanned_hosts: number;
      online_count: number;
      duration_ms: number;
      devices: DeviceRecord[];
    }>("/api/devices/scan", {
      method: "POST",
      body: JSON.stringify({
        cidr,
        scan_ports: scanPorts,
        port_spec: portSpec || null,
        scan_udp: scanUdp,
      }),
    }),

  quickHealthCheck: () =>
    request<{
      scan: { cidr: string; online_count: number; duration_ms: number };
      watchdog: WatchdogPing;
      metrics_sampled: number;
    }>("/api/devices/quick-check", { method: "POST" }),

  updateDevice: (
    ip: string,
    payload: { custom_name?: string; trusted?: boolean; device_type?: string }
  ) =>
    request<DeviceRecord>(`/api/devices/${encodeURIComponent(ip)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  getDeviceHistory: (ip: string, limit = 60, signal?: AbortSignal) =>
    request<{ ip: string; history: DeviceHistoryPoint[] }>(
      `/api/devices/${encodeURIComponent(ip)}/history?limit=${limit}`,
      { signal }
    ),

  sendWakeOnLan: (ip: string, confirm: boolean) =>
    request<{ sent: boolean; mac: string; port: number; broadcast: string }>(
      `/api/devices/${encodeURIComponent(ip)}/wol`,
      {
        method: "POST",
        body: JSON.stringify({ confirm }),
      }
    ),

  updateScanSchedule: (payload: {
    enabled?: boolean;
    interval_seconds?: number;
    cidr?: string;
    scan_ports?: boolean;
  }) =>
    request<ScanSchedule>("/api/devices/schedule", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  listAlerts: (severity = "all", limit = 100, signal?: AbortSignal) =>
    request<{ alerts: AlertRecord[]; counts: AlertCounts }>(
      `/api/alerts?severity=${encodeURIComponent(severity)}&limit=${limit}`,
      { signal }
    ),

  clearAlerts: (confirm: boolean) =>
    request<{ deleted: number }>(`/api/alerts?confirm=${confirm}`, {
      method: "DELETE",
    }),

  simulateAttack: (attackType: string, attackerIp: string, targetIp: string) =>
    request<{
      attack_type: string;
      packets_injected: number;
      alerts_triggered: number;
      alerts: AlertRecord[];
    }>("/api/alerts/simulate", {
      method: "POST",
      body: JSON.stringify({
        attack_type: attackType,
        attacker_ip: attackerIp,
        target_ip: targetIp,
      }),
    }),

  getRules: (signal?: AbortSignal) =>
    request<{
      path: string;
      content: string;
      rules: SnortRuleItem[];
      errors: Array<{ line: number; error: string; raw: string }>;
    }>("/api/rules", { signal }),

  saveRules: (content: string, confirm: boolean) =>
    request<{
      saved: boolean;
      loaded_count: number;
      error_count: number;
      errors: Array<{ line: number; error: string; raw: string }>;
    }>("/api/rules", {
      method: "PUT",
      body: JSON.stringify({ content, confirm }),
    }),

  getSnmpMetrics: (limit = 60, signal?: AbortSignal) =>
    request<{ metrics: SnmpMetric[] }>(`/api/snmp/metrics?limit=${limit}`, { signal }),

  pollSnmpNow: () =>
    request<{ sampled_count: number; metrics: SnmpMetric[] }>("/api/snmp/poll", {
      method: "POST",
    }),

  listSnmpTargets: (signal?: AbortSignal) =>
    request<{ targets: SnmpTarget[] }>("/api/snmp/targets", { signal }),

  createSnmpTarget: (payload: {
    name: string;
    host: string;
    community: string;
    port: number;
  }) =>
    request<SnmpTarget>("/api/snmp/targets", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  deleteSnmpTarget: (id: number, confirm: boolean) =>
    request<{ deleted: boolean; id: number }>(`/api/snmp/targets/${id}?confirm=${confirm}`, {
      method: "DELETE",
    }),

  getFirewallStatus: (signal?: AbortSignal) =>
    request<{
      policy: PolicyState;
      blocked_ips: BlockedIpRecord[];
      active_count: number;
    }>("/api/firewall/status", { signal }),

  updateFirewallPolicy: (payload: {
    dry_run?: boolean;
    auto_block_enabled?: boolean;
    auto_block_threshold?: "high" | "critical";
    confirm: boolean;
  }) =>
    request<PolicyState>("/api/firewall/policy", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  blockIp: (ip: string, reason: string, confirm: boolean) =>
    request<{ status: string; ip: string; message: string }>("/api/firewall/block", {
      method: "POST",
      body: JSON.stringify({ ip, reason, confirm }),
    }),

  unblockIp: (ip: string, confirm: boolean) =>
    request<{ status: string; ip: string; message: string }>("/api/firewall/unblock", {
      method: "POST",
      body: JSON.stringify({ ip, reason: "Manual unblock", confirm }),
    }),

  addWhitelist: (ip: string) =>
    request<{ protected_ips: string[]; policy: PolicyState }>("/api/firewall/whitelist", {
      method: "POST",
      body: JSON.stringify({ ip }),
    }),

  removeWhitelist: (ip: string) =>
    request<{ protected_ips: string[]; policy: PolicyState }>(
      `/api/firewall/whitelist?ip=${encodeURIComponent(ip)}`,
      { method: "DELETE" }
    ),

  getWebhookStatus: (signal?: AbortSignal) =>
    request<WebhookStatus>("/api/webhooks", { signal }),

  updateWebhookSettings: (payload: {
    enabled?: boolean;
    min_severity?: "low" | "medium" | "high" | "critical";
    discord_webhook_url?: string;
    telegram_bot_token?: string;
    telegram_chat_id?: string;
    enterprise_webhook_url?: string;
    smtp_host?: string;
    smtp_port?: number;
    smtp_to?: string;
  }) =>
    request<WebhookStatus>("/api/webhooks", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  testWebhook: () =>
    request<{
      sent: boolean;
      delivered?: string[];
      errors?: string[];
      reason?: string;
      status: WebhookStatus;
    }>("/api/webhooks/test", { method: "POST" }),

  getTelemetry: (signal?: AbortSignal) =>
    request<TrafficTelemetry>("/api/system/telemetry", { signal }),

  getAuditSummary: (signal?: AbortSignal) =>
    request<AuditSummary>("/api/reports/summary", { signal }),

  getProcessConnections: (limit = 150, signal?: AbortSignal) =>
    request<{
      error: string | null;
      total?: number;
      connections: ProcessConnection[];
      process_summary: Array<{ process: string; count: number }>;
    }>(`/api/tools/process-connections?limit=${limit}`, { signal }),

  getWifiAnalysis: (signal?: AbortSignal) =>
    request<WifiAnalysis>("/api/tools/wifi", { signal }),

  runTraceroute: (target: string, maxHops = 15) =>
    request<{
      target: string;
      hops: TracerouteHop[];
      error?: string;
    }>("/api/tools/traceroute", {
      method: "POST",
      body: JSON.stringify({ target, max_hops: maxHops }),
    }),

  runSpeedTest: () =>
    request<{
      success: boolean;
      latency_ms?: number;
      download_mbps?: number;
      bytes_downloaded?: number;
      duration_seconds?: number;
      error?: string;
    }>("/api/tools/speedtest", { method: "POST" }),

  listHttpMonitors: (signal?: AbortSignal) =>
    request<{ monitors: HttpMonitor[] }>("/api/tools/monitors", { signal }),

  createHttpMonitor: (name: string, url: string) =>
    request<HttpMonitor>("/api/tools/monitors", {
      method: "POST",
      body: JSON.stringify({ name, url }),
    }),

  checkHttpMonitor: (id: number) =>
    request<HttpMonitor>(`/api/tools/monitors/${id}/check`, { method: "POST" }),

  deleteHttpMonitor: (id: number, confirm: boolean) =>
    request<{ deleted: boolean; id: number }>(`/api/tools/monitors/${id}?confirm=${confirm}`, {
      method: "DELETE",
    }),

  // Enterprise & Hospital Governance
  getSafetyState: (signal?: AbortSignal) =>
    request<SafetyState>("/api/enterprise/safety", { signal }),

  updateSafetyState: (payload: {
    profile?: "standard" | "enterprise" | "hospital_safe";
    privacy_mode?: boolean;
    retention_days?: number;
  }) =>
    request<SafetyState>("/api/enterprise/safety", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  addExclusionCidr: (cidr: string) =>
    request<{ excluded_cidrs: string[] }>("/api/enterprise/exclusions", {
      method: "POST",
      body: JSON.stringify({ cidr }),
    }),

  removeExclusionCidr: (cidr: string) =>
    request<{ excluded_cidrs: string[] }>(
      `/api/enterprise/exclusions?cidr=${encodeURIComponent(cidr)}`,
      { method: "DELETE" }
    ),

  purgeRetentionLogs: (confirm: boolean) =>
    request<{ retention_days: number; deleted: Record<string, number> }>(
      `/api/enterprise/retention/purge?confirm=${confirm}`,
      { method: "POST" }
    ),

  listAuditLogs: (signal?: AbortSignal) =>
    request<{ logs: AuditLogEntry[] }>("/api/enterprise/audit-logs", { signal }),

  listSensors: (signal?: AbortSignal) =>
    request<{ sensors: RemoteSensor[] }>("/api/enterprise/sensors", { signal }),

  registerSensor: (name: string, vlan: string) =>
    request<RemoteSensor & { api_key: string }>("/api/enterprise/sensors", {
      method: "POST",
      body: JSON.stringify({ name, vlan }),
    }),

  deleteSensor: (id: number, confirm: boolean) =>
    request<{ deleted: boolean }>(`/api/enterprise/sensors/${id}?confirm=${confirm}`, {
      method: "DELETE",
    }),

  importSuricataEve: (ndjson: string) =>
    request<{ alerts_imported: number; dns_found: number; errors: Array<{ line: number; error: string }> }>(
      "/api/enterprise/suricata/import",
      {
        method: "POST",
        body: JSON.stringify({ ndjson }),
      }
    ),

  listUsers: (signal?: AbortSignal) =>
    request<{ users: RbacUser[] }>("/api/auth/users", { signal }),

  createUser: (username: string, password: string, role: "viewer" | "analyst" | "admin") =>
    request<RbacUser>("/api/auth/users", {
      method: "POST",
      body: JSON.stringify({ username, password, role }),
    }),

  deleteUser: (username: string, confirm: boolean) =>
    request<{ deleted: boolean }>(`/api/auth/users/${encodeURIComponent(username)}?confirm=${confirm}`, {
      method: "DELETE",
    }),

  userLogin: (username: string, password: string) =>
    request<{ authenticated: boolean; token: string; username: string; role: string }>(
      "/api/auth/user-login",
      {
        method: "POST",
        body: JSON.stringify({ username, password }),
      }
    ),

  // Network Engineering: IPAM, SNMP Traps, NetFlow v5, Config Drift
  getIpamGrid: (cidr?: string, signal?: AbortSignal) => {
    const qs = cidr ? `?cidr=${encodeURIComponent(cidr)}` : "";
    return request<IpamGrid>(`/api/network/ipam${qs}`, { signal });
  },

  reserveIp: (payload: { ip: string; hostname: string; mac: string; note: string }) =>
    request<IpamReservation>("/api/network/ipam/reserve", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  releaseIpReservation: (ip: string) =>
    request<{ deleted: boolean; ip: string }>(
      `/api/network/ipam/reserve?ip=${encodeURIComponent(ip)}`,
      { method: "DELETE" }
    ),

  getSnmpTraps: (signal?: AbortSignal) =>
    request<SnmpTrapsResponse>("/api/network/traps", { signal }),

  startSnmpTraps: (port = 1162) =>
    request<SnmpTrapsResponse["status"]>(`/api/network/traps/start?port=${port}`, {
      method: "POST",
    }),

  stopSnmpTraps: () =>
    request<SnmpTrapsResponse["status"]>("/api/network/traps/stop", { method: "POST" }),

  getNetFlow: (signal?: AbortSignal) =>
    request<NetFlowSummary>("/api/network/netflow", { signal }),

  startNetFlow: (port = 2055) =>
    request<NetFlowSummary["status"]>(`/api/network/netflow/start?port=${port}`, {
      method: "POST",
    }),

  stopNetFlow: () =>
    request<NetFlowSummary["status"]>("/api/network/netflow/stop", { method: "POST" }),

  listSnapshots: (signal?: AbortSignal) =>
    request<{ snapshots: ConfigSnapshot[] }>("/api/network/snapshots", { signal }),

  createSnapshot: (name: string) =>
    request<ConfigSnapshot>("/api/network/snapshots", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),

  diffSnapshots: (aId: number, bId: number) =>
    request<{ drifted: boolean; diff: string }>(
      `/api/network/snapshots/diff?a_id=${aId}&b_id=${bId}`
    ),

  // SOC Operations: Incidents, Playbooks, IOCs, IDS Tuning, Compliance, Device 360
  listIncidents: (signal?: AbortSignal) =>
    request<{ incidents: IncidentCase[] }>("/api/soc/incidents", { signal }),

  updateIncident: (
    id: number,
    payload: {
      status?: "open" | "investigating" | "resolved" | "false_positive";
      notes?: string;
    }
  ) =>
    request<IncidentCase>(`/api/soc/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  listPlaybooks: (signal?: AbortSignal) =>
    request<{ playbooks: PlaybookItem[] }>("/api/soc/playbooks", { signal }),

  createPlaybook: (payload: {
    name: string;
    trigger_severity: "low" | "medium" | "high" | "critical";
    trigger_detector: string;
    action_type: "create_incident" | "notify_webhook" | "dry_run_block";
  }) =>
    request<PlaybookItem>("/api/soc/playbooks", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  togglePlaybook: (id: number, enabled: boolean) =>
    request<{ id: number; enabled: boolean }>(`/api/soc/playbooks/${id}?enabled=${enabled}`, {
      method: "PATCH",
    }),

  deletePlaybook: (id: number, confirm: boolean) =>
    request<{ deleted: boolean; id: number }>(`/api/soc/playbooks/${id}?confirm=${confirm}`, {
      method: "DELETE",
    }),

  listIocs: (signal?: AbortSignal) =>
    request<{ iocs: IocItem[]; ip_count: number; domain_count: number }>("/api/soc/iocs", {
      signal,
    }),

  importIocs: (rawText: string, source: string, severity: "medium" | "high" | "critical") =>
    request<{ imported: number; invalid: number }>("/api/soc/iocs/import", {
      method: "POST",
      body: JSON.stringify({ raw_text: rawText, source, severity }),
    }),

  deleteIoc: (id: number, confirm: boolean) =>
    request<{ deleted: boolean; id: number }>(`/api/soc/iocs/${id}?confirm=${confirm}`, {
      method: "DELETE",
    }),

  getIdsTuning: (signal?: AbortSignal) =>
    request<IdsTuning>("/api/soc/ids-tuning", { signal }),

  updateIdsTuning: (payload: Partial<IdsTuning>) =>
    request<IdsTuning>("/api/soc/ids-tuning", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  getComplianceScorecard: (signal?: AbortSignal) =>
    request<ComplianceScorecard>("/api/soc/compliance", { signal }),

  getDevice360: (ip: string, signal?: AbortSignal) =>
    request<Device360Response>(`/api/soc/device-360/${encodeURIComponent(ip)}`, { signal }),
};
