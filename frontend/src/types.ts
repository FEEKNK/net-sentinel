export type TabId =
  | "overview"
  | "scanner"
  | "topology"
  | "ipam"
  | "ids"
  | "forensics"
  | "tools"
  | "snmp"
  | "firewall"
  | "enterprise"
  | "lab";

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
  syslog?: {
    running: boolean;
    port: number;
    received_count: number;
    last_error: string | null;
  };
  scanner_busy: boolean;
  policy: PolicyState;
  alert_counts: AlertCounts;
  rules_loaded: number;
  rule_errors: number;
  lock_enabled?: boolean;
}

export interface OpenPort {
  port: number;
  service: string;
  banner?: string;
}

export interface DeviceRecord {
  ip: string;
  mac: string;
  vendor: string;
  hostname: string;
  custom_name: string;
  trusted: boolean;
  device_type: string;
  os_guess?: string;
  latency_ms: number | null;
  uptime_pct?: number;
  risk_score?: number;
  risk_grade?: string;
  risk_reasons?: string[];
  open_ports: OpenPort[];
  status: string;
  first_seen: string;
  last_seen: string;
}

export interface DeviceHistoryPoint {
  id: number;
  ip: string;
  status: string;
  latency_ms: number | null;
  recorded_at: string;
}

export interface ScanSchedule {
  enabled: boolean;
  interval_seconds: number;
  cidr: string;
  scan_ports: boolean;
  last_run_at: number;
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
  ttl?: number | null;
  dns_query?: string;
  preview: string;
  hex_dump?: string;
}

export interface TrafficTelemetry {
  total_packets: number;
  protocol_counts: Record<string, number>;
  top_talkers: Array<{
    ip: string;
    packets: number;
    bytes_total: number;
    last_seen: number;
  }>;
  dns_queries: Array<{
    timestamp: number;
    src_ip: string;
    domain: string;
  }>;
  outbound_connections: Array<{
    dst_ip: string;
    dst_port: number | null;
    protocol: string;
    packets: number;
    bytes_total: number;
    sources: string[];
    last_seen: number;
  }>;
}

export interface AuditSummary {
  generated_at: string;
  device_summary: {
    total: number;
    online: number;
    trusted: number;
    high_risk_count: number;
    average_risk_score: number;
  };
  alert_summary: AlertCounts;
  firewall_summary: {
    dry_run: boolean;
    active_blocks: number;
    total_block_records: number;
  };
  telemetry: TrafficTelemetry;
  scored_devices: DeviceRecord[];
  recent_alerts: AlertRecord[];
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
    lldp_neighbors?: Array<{ system: string; port: string }>;
  };
}

export interface SyslogEvent {
  id: number;
  received_at: string;
  source_ip: string;
  severity: string;
  facility: string;
  message: string;
}

export interface WatchdogPing {
  id: number;
  target_ip: string;
  online: boolean;
  latency_ms: number | null;
  checked_at: string;
}

export interface PcapAnalysisResult {
  packet_count: number;
  protocol_counts: Record<string, number>;
  top_talkers: Array<{ ip: string; packets: number; bytes_total: number }>;
  dns_queries: Array<{ src_ip: string; domain: string }>;
  outbound_connections: Array<{
    dst_ip: string;
    dst_port: number | null;
    protocol: string;
    packets: number;
    bytes_total: number;
  }>;
  matched_rules: Array<{
    sid: number;
    msg: string;
    severity: string;
    src_ip: string;
    dst_ip: string;
    dst_port: number | null;
  }>;
  packets: PacketSummary[];
}
export interface ProcessConnection {
  pid: number;
  process: string;
  protocol: string;
  status: string;
  local: string;
  remote: string;
  remote_ip: string;
}

export interface WifiAnalysis {
  available: boolean;
  current: {
    name?: string;
    ssid?: string;
    bssid?: string;
    radio_type?: string;
    channel?: number;
    signal_pct?: number;
    rx_mbps?: number;
    tx_mbps?: number;
    state?: string;
  };
  neighbors: Array<{
    ssid: string;
    bssid: string;
    authentication?: string;
    signal_pct: number | null;
    channel: number | null;
    band: string;
  }>;
  recommended_24ghz_channel: number;
  note: string | null;
}

export interface TracerouteHop {
  hop: number;
  ip: string;
  rtt_ms: number | null;
  timed_out: boolean;
}

export interface HttpMonitor {
  id: number;
  name: string;
  url: string;
  last_status_code: number | null;
  last_latency_ms: number | null;
  ssl_days_remaining: number | null;
  ssl_issuer: string;
  last_error: string | null;
  last_checked_at: string | null;
}

export interface SafetyState {
  profile: "standard" | "enterprise" | "hospital_safe";
  is_hospital_safe: boolean;
  privacy_mode: boolean;
  retention_days: number;
  excluded_cidrs: string[];
}

export interface RbacUser {
  id: number;
  username: string;
  role: "viewer" | "analyst" | "admin";
  created_at: string;
}

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  actor: string;
  role: string;
  action: string;
  target: string;
  detail: string;
}

export interface RemoteSensor {
  id: number;
  name: string;
  vlan: string;
  last_seen: string | null;
  events_received: number;
  created_at: string;
}

export interface BlockedIpRecord {
  ip: string;
  reason: string;
  blocked_at: string;
  expires_at: string | null;
  is_dry_run: boolean;
  active: boolean;
}

export interface WebhookStatus {
  enabled: boolean;
  min_severity: "low" | "medium" | "high" | "critical";
  discord_configured: boolean;
  discord_masked: string;
  telegram_configured: boolean;
  telegram_chat_id: string;
  telegram_token_masked: string;
  enterprise_configured?: boolean;
  enterprise_masked?: string;
  smtp_configured?: boolean;
  smtp_host?: string;
  smtp_to?: string;
  last_error: string | null;
}

export interface IpamSlot {
  ip: string;
  state: "online" | "offline" | "reserved" | "free";
  hostname: string;
  mac: string;
  note: string;
}

export interface IpamReservation {
  ip: string;
  hostname: string;
  mac: string;
  note: string;
  created_at: string;
}

export interface IpamGrid {
  cidr: string;
  utilization_pct: number;
  counts: { online: number; offline: number; reserved: number; free: number };
  slots: IpamSlot[];
  reservations: IpamReservation[];
}

export interface SnmpTrap {
  received_at: string;
  source_ip: string;
  length: number;
  summary: string;
}

export interface SnmpTrapsResponse {
  status: {
    running: boolean;
    port: number;
    count: number;
    last_error: string | null;
  };
  traps: SnmpTrap[];
}

export interface NetFlowRecord {
  exporter: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packets: number;
  bytes: number;
}

export interface NetFlowSummary {
  status: {
    running: boolean;
    port: number;
    flow_count: number;
    last_error: string | null;
  };
  top_conversations: Array<{
    src_ip: string;
    dst_ip: string;
    protocol: string;
    bytes: number;
    packets: number;
  }>;
  recent_flows: NetFlowRecord[];
}

export interface ConfigSnapshot {
  id: number;
  name: string;
  sha256: string;
  content: string;
  created_at: string;
}

export interface IncidentCase {
  id: number;
  title: string;
  source_ip: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "investigating" | "resolved" | "false_positive";
  alert_count: number;
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface PlaybookItem {
  id: number;
  name: string;
  trigger_severity: "low" | "medium" | "high" | "critical";
  trigger_detector: string;
  action_type: "create_incident" | "notify_webhook" | "dry_run_block";
  enabled: boolean;
  created_at: string;
}

export interface IocItem {
  id: number;
  indicator: string;
  kind: string;
  source: string;
  severity: string;
  created_at: string;
}

export interface IdsTuning {
  port_scan_threshold: number;
  syn_flood_threshold: number;
  bruteforce_threshold: number;
  icmp_flood_threshold: number;
  icmp_oversize_bytes: number;
  dns_length_threshold: number;
  dns_entropy_threshold: number;
  cooldown_seconds: number;
  disabled_detectors: string[];
}

export interface ComplianceCheck {
  id: string;
  control: string;
  passed: boolean;
  detail: string;
}

export interface ComplianceScorecard {
  score_pct: number;
  passed_count: number;
  total_checks: number;
  checks: ComplianceCheck[];
}

export interface Device360Response {
  ip: string;
  device: DeviceRecord | null;
  risk: {
    risk_score: number;
    risk_grade: string;
    risk_reasons: string[];
  };
  history: DeviceHistoryPoint[];
  alerts: AlertRecord[];
}
