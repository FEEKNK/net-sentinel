import type {
  AlertRecord,
  AlertCounts,
  BlockedIpRecord,
  DeviceRecord,
  PacketSummary,
  PolicyState,
  SnmpMetric,
  SnmpTarget,
  SnifferStatus,
  SnortRuleItem,
  SystemStatus,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
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
    const msg =
      typeof detail === "string" ? detail : JSON.stringify(detail);
    throw new ApiError(res.status, msg);
  }

  return parsed as T;
}

export const api = {
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

  listDevices: (signal?: AbortSignal) =>
    request<{
      devices: DeviceRecord[];
      online_count: number;
      total_count: number;
      default_subnet: string;
    }>("/api/devices", { signal }),

  scanSubnet: (cidr: string, scanPorts: boolean) =>
    request<{
      cidr: string;
      scanned_hosts: number;
      online_count: number;
      duration_ms: number;
      devices: DeviceRecord[];
    }>("/api/devices/scan", {
      method: "POST",
      body: JSON.stringify({ cidr, scan_ports: scanPorts }),
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
};
