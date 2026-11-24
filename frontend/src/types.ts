export type TabId = "overview" | "scanner" | "ids" | "snmp" | "firewall";

export interface PlatformCapabilities {
  os_name: string;
  is_admin: boolean;
  firewall_backend: string;
  npcap_available: boolean;
  default_interface: string;
  default_subnet: string;
  gateway_ip: string | null;
  local_ips: string[];
}

export interface SnifferStatus {
  running: boolean;
  interface: string;
  packet_count: number;
  buffered_count: number;
  last_error: string | null;
}

export interface PolicyState {
  dry_run: boolean;
  auto_block_enabled: boolean;
  auto_block_threshold: "high" | "critical";
  block_ttl_seconds: number;
  firewall_backend: string;
  system_protected_ips: string[];
  custom_whitelist_ips: string[];
}

export interface AlertCounts {
  total: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface SystemStatus {
  db_healthy: boolean;
  capabilities: PlatformCapabilities;
  sniffer: SnifferStatus;
  scanner_busy: boolean;
  policy: PolicyState;
  alert_counts: AlertCounts;
  rules_loaded: number;
  rule_errors: number;
}

export interface OpenPort {
  port: number;
  service: string;
}

export interface DeviceRecord {
  ip: string;
  mac: string;
  vendor: string;
  hostname: string;
  latency_ms: number | null;
  open_ports: OpenPort[];
  status: string;
  first_seen: string;
  last_seen: string;
}

export interface AlertRecord {
  id: number;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  src_port: number | null;
  dest_port: number | null;
  protocol: string;
  rule_sid: number | null;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  detector_type: string;
  action_taken: string;
}

export interface PacketSummary {
  timestamp: number;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  tcp_flags: string;
  length: number;
  preview: string;
}

export interface SnortRuleItem {
  sid: number;
  action: string;
  protocol: string;
  src_ip: string;
  src_port: string;
  direction: string;
  dst_ip: string;
  dst_port: string;
  msg: string;
  classtype: string;
  priority: number;
  severity: string;
  raw: string;
}

export interface SnmpMetric {
  id: number;
  target_id: number | null;
  target_name: string;
  timestamp: string;
  cpu_pct: number | null;
  mem_pct: number | null;
  in_bps: number;
  out_bps: number;
  source_type: string;
}

export interface SnmpTarget {
  id: number;
  name: string;
  host: string;
  community: string;
  port: number;
  enabled: number;
  created_at: string;
  runtime?: {
    status: string;
    message?: string;
    sys_name?: string;
  };
}

export interface BlockedIpRecord {
  ip: string;
  reason: string;
  blocked_at: string;
  expires_at: string | null;
  is_dry_run: boolean;
  active: boolean;
}
