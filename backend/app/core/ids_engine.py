"""Hybrid IDS Engine: Behavioral Detectors (Port Scan, SYN Flood, ARP Spoof, Brute Force, DNS Tunnel, ICMP, DHCP), IOCs, Stream Reassembly & Snort Rules."""

from __future__ import annotations

import ipaddress
import math
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from app.core.blocker import ActiveResponseBlocker
from app.core.snort_parser import SnortRule, match_rule, parse_snort_rules
from app.db.database import Database


BRUTE_FORCE_PORTS = {21, 22, 23, 445, 3389, 5900}


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits/char for DNS Tunneling / DGA detection."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def format_hex_dump(data: bytes, max_bytes: int = 512) -> str:
    """Format raw packet bytes as classic Wireshark-style Hex + ASCII dump."""
    if not data:
        return ""
    sliced = data[:max_bytes]
    lines: list[str] = []
    for offset in range(0, len(sliced), 16):
        chunk = sliced[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


@dataclass(slots=True)
class PacketEvent:
    """Normalized packet representation consumed by IDS detectors."""

    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str = ""
    arp_op: int | None = None
    arp_psrc: str | None = None
    arp_hwsrc: str | None = None
    payload: str = ""
    length: int = 0
    ttl: int | None = None
    dns_query: str = ""
    raw_bytes: bytes = b""

    def to_summary(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "protocol": self.protocol.upper(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "length": self.length,
            "ttl": self.ttl,
            "dns_query": self.dns_query,
            "preview": self.payload[:80]
            if self.payload
            else (f"DNS: {self.dns_query}" if self.dns_query else ""),
            "hex_dump": format_hex_dump(
                self.raw_bytes or self.payload.encode("utf-8", errors="ignore")
            ),
        }


class IDSEngine:
    """Stateful packet analysis engine with tunable thresholds and 8 behavioral + signature detectors."""

    def __init__(
        self,
        *,
        db: Database,
        blocker: ActiveResponseBlocker,
        home_nets: list[ipaddress.IPv4Network] | None = None,
        trusted_dhcp_servers: set[str] | None = None,
        ioc_matcher: Any | None = None,
        on_alert: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        port_scan_threshold: int = 10,
        port_scan_window_s: float = 10.0,
        syn_flood_threshold: int = 40,
        syn_flood_window_s: float = 5.0,
        bruteforce_threshold: int = 15,
        bruteforce_window_s: float = 15.0,
        icmp_flood_threshold: int = 30,
        icmp_oversize_bytes: int = 256,
        dns_length_threshold: int = 45,
        dns_entropy_threshold: float = 3.7,
        cooldown_seconds: float = 15.0,
    ) -> None:
        self.db = db
        self.blocker = blocker
        self.home_nets = home_nets or [ipaddress.IPv4Network("192.168.0.0/16")]
        self.trusted_dhcp_servers = trusted_dhcp_servers or set()
        self.ioc_matcher = ioc_matcher
        self.on_alert = on_alert

        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_s = port_scan_window_s
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window_s = syn_flood_window_s
        self.bruteforce_threshold = bruteforce_threshold
        self.bruteforce_window_s = bruteforce_window_s
        self.icmp_flood_threshold = icmp_flood_threshold
        self.icmp_oversize_bytes = icmp_oversize_bytes
        self.dns_length_threshold = dns_length_threshold
        self.dns_entropy_threshold = dns_entropy_threshold
        self.cooldown_seconds = cooldown_seconds

        self.disabled_detectors: set[str] = set()
        self.rules: list[SnortRule] = []
        self.rule_errors: list[dict[str, str | int]] = []

        # Bounded sliding-window trackers
        self._port_hits: dict[str, deque[tuple[float, int]]] = defaultdict(lambda: deque(maxlen=500))
        self._syn_hits: dict[tuple[str, str], deque[float]] = defaultdict(lambda: deque(maxlen=500))
        self._brute_hits: dict[tuple[str, int], deque[float]] = defaultdict(lambda: deque(maxlen=500))
        self._icmp_hits: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=500))
        self._arp_table: dict[str, str] = {}
        self._cooldowns: dict[tuple[str, str, str], float] = {}
        self._tcp_streams: dict[tuple[str, int, str, int], str] = {}

    def get_tuning(self) -> dict[str, Any]:
        return {
            "port_scan_threshold": self.port_scan_threshold,
            "syn_flood_threshold": self.syn_flood_threshold,
            "bruteforce_threshold": self.bruteforce_threshold,
            "icmp_flood_threshold": self.icmp_flood_threshold,
            "icmp_oversize_bytes": self.icmp_oversize_bytes,
            "dns_length_threshold": self.dns_length_threshold,
            "dns_entropy_threshold": self.dns_entropy_threshold,
            "cooldown_seconds": self.cooldown_seconds,
            "disabled_detectors": sorted(self.disabled_detectors),
        }

    def update_tuning(self, patch: dict[str, Any]) -> dict[str, Any]:
        int_fields = (
            "port_scan_threshold",
            "syn_flood_threshold",
            "bruteforce_threshold",
            "icmp_flood_threshold",
            "icmp_oversize_bytes",
            "dns_length_threshold",
        )
        for field_name in int_fields:
            if field_name in patch and patch[field_name] is not None:
                setattr(self, field_name, max(2, min(int(patch[field_name]), 5000)))
        if "dns_entropy_threshold" in patch and patch["dns_entropy_threshold"] is not None:
            self.dns_entropy_threshold = max(2.0, min(float(patch["dns_entropy_threshold"]), 6.0))
        if "cooldown_seconds" in patch and patch["cooldown_seconds"] is not None:
            self.cooldown_seconds = max(1.0, min(float(patch["cooldown_seconds"]), 3600.0))
        if "disabled_detectors" in patch and isinstance(patch["disabled_detectors"], list):
            self.disabled_detectors = {str(d) for d in patch["disabled_detectors"]}
        return self.get_tuning()

    def load_rules_text(self, rules_text: str) -> dict[str, Any]:
        """Parse and hot-reload Snort rules."""
        res = parse_snort_rules(rules_text)
        self.rules = res.rules
        self.rule_errors = res.errors
        return {
            "loaded_count": len(self.rules),
            "error_count": len(self.rule_errors),
            "errors": self.rule_errors,
        }

    async def process_packet(self, pkt: PacketEvent) -> list[dict[str, Any]]:
        """Run behavioral detectors, IOC check, and Snort rules against a PacketEvent."""
        generated_alerts: list[dict[str, Any]] = []
        now = pkt.timestamp or time.time()
        proto = pkt.protocol.lower()

        # 0) IOC Threat Feed Match
        if (
            self.ioc_matcher is not None
            and "ioc_match" not in self.disabled_detectors
        ):
            hit = self.ioc_matcher.match_packet(
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, dns_query=pkt.dns_query
            )
            if hit:
                indicator, kind = hit
                alert = await self._emit_alert(
                    now=now,
                    source_ip=pkt.src_ip or indicator,
                    dest_ip=pkt.dst_ip,
                    dest_port=pkt.dst_port,
                    protocol=pkt.protocol.upper(),
                    title=f"IOC Threat Indicator Matched ({kind.upper()}: {indicator})",
                    description=f"Packet matched imported IOC blocklist indicator '{indicator}'.",
                    severity="critical",
                    detector_type="ioc_match",
                )
                if alert:
                    generated_alerts.append(alert)

        # 1) ARP Spoofing Detector
        if (
            proto == "arp"
            and pkt.arp_psrc
            and pkt.arp_hwsrc
            and "behavioral_arp_spoof" not in self.disabled_detectors
        ):
            norm_mac = pkt.arp_hwsrc.upper().replace("-", ":")
            prev_mac = self._arp_table.get(pkt.arp_psrc)
            if prev_mac and prev_mac != norm_mac:
                alert = await self._emit_alert(
                    now=now,
                    source_ip=pkt.arp_psrc,
                    dest_ip=pkt.dst_ip,
                    protocol="ARP",
                    title="ARP Spoofing Detected (MAC Address Changed)",
                    description=(
                        f"IP {pkt.arp_psrc} changed MAC from {prev_mac} to {norm_mac} "
                        "(possible Man-in-the-Middle attack)."
                    ),
                    severity="critical",
                    detector_type="behavioral_arp_spoof",
                )
                if alert:
                    generated_alerts.append(alert)
            if len(self._arp_table) >= 2048 and pkt.arp_psrc not in self._arp_table:
                del self._arp_table[next(iter(self._arp_table))]
            self._arp_table[pkt.arp_psrc] = norm_mac

        # 2) Behavioral TCP Detectors (Port Scan, SYN Flood, Brute Force)
        if proto == "tcp" and pkt.src_ip and pkt.dst_port is not None:
            if "behavioral_port_scan" not in self.disabled_detectors:
                if len(self._port_hits) > 2048 and pkt.src_ip not in self._port_hits:
                    self._prune_stale_trackers(now)
                port_q = self._port_hits[pkt.src_ip]
                port_q.append((now, pkt.dst_port))
                while port_q and (now - port_q[0][0]) > self.port_scan_window_s:
                    port_q.popleft()
                distinct_ports = {p for _, p in port_q}
                if len(distinct_ports) >= self.port_scan_threshold:
                    alert = await self._emit_alert(
                        now=now,
                        source_ip=pkt.src_ip,
                        dest_ip=pkt.dst_ip,
                        dest_port=pkt.dst_port,
                        protocol="TCP",
                        title="Port Scan Activity Detected",
                        description=(
                            f"{pkt.src_ip} probed {len(distinct_ports)} distinct ports "
                            f"on {pkt.dst_ip} within {self.port_scan_window_s:.0f}s."
                        ),
                        severity="high",
                        detector_type="behavioral_port_scan",
                    )
                    if alert:
                        generated_alerts.append(alert)

            flags = pkt.tcp_flags.upper()
            if (
                "S" in flags
                and "A" not in flags
                and "behavioral_syn_flood" not in self.disabled_detectors
            ):
                key = (pkt.src_ip, pkt.dst_ip)
                syn_q = self._syn_hits[key]
                syn_q.append(now)
                while syn_q and (now - syn_q[0]) > self.syn_flood_window_s:
                    syn_q.popleft()
                if len(syn_q) >= self.syn_flood_threshold:
                    alert = await self._emit_alert(
                        now=now,
                        source_ip=pkt.src_ip,
                        dest_ip=pkt.dst_ip,
                        dest_port=pkt.dst_port,
                        protocol="TCP",
                        title="TCP SYN Flood Suspected",
                        description=(
                            f"{pkt.src_ip} sent {len(syn_q)} SYN packets to {pkt.dst_ip} "
                            f"within {self.syn_flood_window_s:.0f}s."
                        ),
                        severity="critical",
                        detector_type="behavioral_syn_flood",
                    )
                    if alert:
                        generated_alerts.append(alert)

            # Brute Force Login Spike on authentication/remote-access ports (new SYN handshakes only)
            if (
                pkt.dst_port in BRUTE_FORCE_PORTS
                and ("S" in flags and "A" not in flags)
                and "behavioral_bruteforce" not in self.disabled_detectors
            ):
                bkey = (pkt.src_ip, pkt.dst_port)
                bq = self._brute_hits[bkey]
                bq.append(now)
                while bq and (now - bq[0]) > self.bruteforce_window_s:
                    bq.popleft()
                if len(bq) >= self.bruteforce_threshold:
                    alert = await self._emit_alert(
                        now=now,
                        source_ip=pkt.src_ip,
                        dest_ip=pkt.dst_ip,
                        dest_port=pkt.dst_port,
                        protocol="TCP",
                        title=f"Brute-Force Connection Spike (Port {pkt.dst_port})",
                        description=(
                            f"{pkt.src_ip} opened {len(bq)} rapid connections to port {pkt.dst_port} "
                            f"within {self.bruteforce_window_s:.0f}s."
                        ),
                        severity="high",
                        detector_type="behavioral_bruteforce",
                    )
                    if alert:
                        generated_alerts.append(alert)

        # 3) DNS Tunneling / DGA Entropy Detector
        if pkt.dns_query and "behavioral_dns_tunnel" not in self.disabled_detectors:
            clean_dom = pkt.dns_query.strip().rstrip(".")
            longest_label = max(clean_dom.split("."), key=len, default="")
            ent = shannon_entropy(longest_label)
            if len(clean_dom) >= self.dns_length_threshold or (
                len(longest_label) >= 16 and ent >= self.dns_entropy_threshold
            ):
                alert = await self._emit_alert(
                    now=now,
                    source_ip=pkt.src_ip,
                    dest_ip=pkt.dst_ip,
                    dest_port=53,
                    protocol="DNS",
                    title="Suspicious DNS Tunneling / High-Entropy Domain",
                    description=(
                        f"Client {pkt.src_ip} queried '{clean_dom[:80]}' "
                        f"(len={len(clean_dom)}, entropy={ent:.2f})."
                    ),
                    severity="high",
                    detector_type="behavioral_dns_tunnel",
                )
                if alert:
                    generated_alerts.append(alert)

        # 4) ICMP Oversize Tunnel & Ping Flood Detector
        if proto == "icmp" and pkt.src_ip:
            if (
                pkt.length > self.icmp_oversize_bytes
                and "behavioral_icmp_tunnel" not in self.disabled_detectors
            ):
                alert = await self._emit_alert(
                    now=now,
                    source_ip=pkt.src_ip,
                    dest_ip=pkt.dst_ip,
                    protocol="ICMP",
                    title="Oversized ICMP Packet (Possible ICMP Tunnel)",
                    description=f"{pkt.src_ip} sent ICMP packet of {pkt.length} bytes (limit {self.icmp_oversize_bytes}B).",
                    severity="high",
                    detector_type="behavioral_icmp_tunnel",
                )
                if alert:
                    generated_alerts.append(alert)
            if "behavioral_icmp_flood" not in self.disabled_detectors:
                iq = self._icmp_hits[pkt.src_ip]
                iq.append(now)
                while iq and (now - iq[0]) > 5.0:
                    iq.popleft()
                if len(iq) >= self.icmp_flood_threshold:
                    alert = await self._emit_alert(
                        now=now,
                        source_ip=pkt.src_ip,
                        dest_ip=pkt.dst_ip,
                        protocol="ICMP",
                        title="ICMP Ping Flood Suspected",
                        description=f"{pkt.src_ip} sent {len(iq)} ICMP packets in 5s.",
                        severity="high",
                        detector_type="behavioral_icmp_flood",
                    )
                    if alert:
                        generated_alerts.append(alert)

        # 5) DHCP Rogue Server Detector (UDP 67 -> 68 from untrusted server)
        if (
            proto == "udp"
            and pkt.src_port == 67
            and pkt.dst_port == 68
            and pkt.src_ip
            and "behavioral_dhcp_rogue" not in self.disabled_detectors
        ):
            if self.trusted_dhcp_servers and pkt.src_ip not in self.trusted_dhcp_servers:
                alert = await self._emit_alert(
                    now=now,
                    source_ip=pkt.src_ip,
                    dest_ip=pkt.dst_ip,
                    src_port=67,
                    dest_port=68,
                    protocol="DHCP",
                    title="Rogue DHCP Server Detected",
                    description=f"Untrusted IP {pkt.src_ip} sent DHCP Server Offer/Ack (expected {sorted(self.trusted_dhcp_servers)}).",
                    severity="critical",
                    detector_type="behavioral_dhcp_rogue",
                )
                if alert:
                    generated_alerts.append(alert)

        # 6) TCP Stream Reassembly & Snort Signature Rules
        eval_payload = pkt.payload
        if proto == "tcp" and pkt.payload and pkt.src_port is not None and pkt.dst_port is not None:
            flow_key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            if len(self._tcp_streams) >= 512 and flow_key not in self._tcp_streams:
                del self._tcp_streams[next(iter(self._tcp_streams))]
            assembled = (self._tcp_streams.get(flow_key, "") + pkt.payload)[-4096:]
            self._tcp_streams[flow_key] = assembled
            eval_payload = assembled

        for rule in self.rules:
            if match_rule(
                rule,
                protocol=pkt.protocol,
                src_ip=pkt.src_ip,
                src_port=pkt.src_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                payload=eval_payload,
                home_nets=self.home_nets,
            ):
                alert = await self._emit_alert(
                    now=now,
                    source_ip=pkt.src_ip,
                    dest_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dest_port=pkt.dst_port,
                    protocol=pkt.protocol.upper(),
                    rule_sid=rule.sid,
                    title=rule.msg,
                    description=f"Matched Snort rule SID:{rule.sid} ({rule.classtype})",
                    severity=rule.severity,
                    detector_type="snort_rule",
                )
                if alert:
                    generated_alerts.append(alert)

        return generated_alerts

    def follow_tcp_stream(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> dict[str, str]:
        """Return reassembled bidirectional TCP stream text for Follow Stream UI."""
        fwd = self._tcp_streams.get((src_ip, src_port, dst_ip, dst_port), "")
        rev = self._tcp_streams.get((dst_ip, dst_port, src_ip, src_port), "")
        return {"client_to_server": fwd, "server_to_client": rev}

    async def _emit_alert(
        self,
        *,
        now: float,
        source_ip: str,
        dest_ip: str = "",
        src_port: int | None = None,
        dest_port: int | None = None,
        protocol: str = "ANY",
        rule_sid: int | None = None,
        title: str,
        description: str,
        severity: str,
        detector_type: str,
    ) -> dict[str, Any] | None:
        cooldown_key = (detector_type, source_ip, title)
        last_ts = self._cooldowns.get(cooldown_key)
        if last_ts is not None and (now - last_ts) < self.cooldown_seconds:
            return None

        if len(self._cooldowns) > 2048:
            self._cooldowns.clear()
        self._cooldowns[cooldown_key] = now

        action_taken = await self.blocker.evaluate_alert(
            source_ip=source_ip, severity=severity, title=title
        )
        saved = await self.db.insert_alert(
            source_ip=source_ip,
            dest_ip=dest_ip,
            src_port=src_port,
            dest_port=dest_port,
            protocol=protocol,
            rule_sid=rule_sid,
            title=title,
            description=description,
            severity=severity,
            detector_type=detector_type,
            action_taken=action_taken,
        )
        if self.on_alert:
            await self.on_alert(saved)
        return saved

    def _prune_stale_trackers(self, now: float) -> None:
        for ip in [
            ip
            for ip, q in self._port_hits.items()
            if not q or (now - q[-1][0]) > self.port_scan_window_s
        ]:
            del self._port_hits[ip]
        for k in [
            k
            for k, q in self._syn_hits.items()
            if not q or (now - q[-1]) > self.syn_flood_window_s
        ]:
            del self._syn_hits[k]
        for k in [
            k
            for k, q in self._brute_hits.items()
            if not q or (now - q[-1]) > self.bruteforce_window_s
        ]:
            del self._brute_hits[k]
        for ip in [
            ip
            for ip, q in self._icmp_hits.items()
            if not q or (now - q[-1]) > 5.0
        ]:
            del self._icmp_hits[ip]

    async def simulate_attack(
        self,
        attack_type: str,
        *,
        attacker_ip: str = "203.0.113.55",
        target_ip: str = "192.168.1.10",
    ) -> dict[str, Any]:
        """Inject synthetic educational packets directly into IDSEngine for safe testing."""
        now = time.time()
        packets: list[PacketEvent] = []
        restore_trusted_dhcp = False

        if attack_type == "port_scan":
            for idx in range(self.port_scan_threshold + 2):
                packets.append(
                    PacketEvent(
                        timestamp=now + idx * 0.01,
                        protocol="tcp",
                        src_ip=attacker_ip,
                        dst_ip=target_ip,
                        src_port=52000 + idx,
                        dst_port=3000 + idx,
                        tcp_flags="S",
                        length=60,
                    )
                )
        elif attack_type == "syn_flood":
            for idx in range(self.syn_flood_threshold + 5):
                packets.append(
                    PacketEvent(
                        timestamp=now + idx * 0.005,
                        protocol="tcp",
                        src_ip=attacker_ip,
                        dst_ip=target_ip,
                        src_port=40000 + idx,
                        dst_port=80,
                        tcp_flags="S",
                        length=64,
                    )
                )
        elif attack_type == "arp_spoof":
            packets.append(
                PacketEvent(
                    timestamp=now,
                    protocol="arp",
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    arp_op=2,
                    arp_psrc=target_ip,
                    arp_hwsrc="AA:BB:CC:11:22:33",
                    length=42,
                )
            )
            packets.append(
                PacketEvent(
                    timestamp=now + 0.05,
                    protocol="arp",
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    arp_op=2,
                    arp_psrc=target_ip,
                    arp_hwsrc="DE:AD:BE:EF:00:99",
                    length=42,
                )
            )
        elif attack_type == "bruteforce":
            for idx in range(self.bruteforce_threshold + 2):
                packets.append(
                    PacketEvent(
                        timestamp=now + idx * 0.02,
                        protocol="tcp",
                        src_ip=attacker_ip,
                        dst_ip=target_ip,
                        src_port=41000 + idx,
                        dst_port=22,
                        tcp_flags="S",
                        length=64,
                    )
                )
        elif attack_type == "dns_tunnel":
            packets.append(
                PacketEvent(
                    timestamp=now,
                    protocol="udp",
                    src_ip=attacker_ip,
                    dst_ip="8.8.8.8",
                    src_port=53100,
                    dst_port=53,
                    dns_query="a9x7k2p4m8q1z6w3n5r2t8y4u7i9o1p3.exfil.example.com",
                    length=110,
                )
            )
        elif attack_type == "icmp_flood":
            for idx in range(self.icmp_flood_threshold + 2):
                packets.append(
                    PacketEvent(
                        timestamp=now + idx * 0.01,
                        protocol="icmp",
                        src_ip=attacker_ip,
                        dst_ip=target_ip,
                        length=512 if idx == 0 else 64,
                    )
                )
        elif attack_type == "dhcp_rogue":
            if not self.trusted_dhcp_servers:
                self.trusted_dhcp_servers.add(target_ip or "192.168.1.1")
                restore_trusted_dhcp = True
            packets.append(
                PacketEvent(
                    timestamp=now,
                    protocol="udp",
                    src_ip=attacker_ip,
                    dst_ip="255.255.255.255",
                    src_port=67,
                    dst_port=68,
                    length=300,
                )
            )
        elif attack_type == "snort_telnet":
            packets.append(
                PacketEvent(
                    timestamp=now,
                    protocol="tcp",
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    src_port=55123,
                    dst_port=23,
                    tcp_flags="PA",
                    payload="login: admin",
                    length=96,
                )
            )
        elif attack_type == "snort_sqli":
            packets.append(
                PacketEvent(
                    timestamp=now,
                    protocol="tcp",
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    src_port=55444,
                    dst_port=80,
                    tcp_flags="PA",
                    payload="GET /items?id=1 UNION SELECT username,password FROM users HTTP/1.1",
                    length=180,
                )
            )
        else:
            raise ValueError(f"Unsupported simulation type: {attack_type}")

        alerts: list[dict[str, Any]] = []
        try:
            for pkt in packets:
                emitted = await self.process_packet(pkt)
                alerts.extend(emitted)
        finally:
            if restore_trusted_dhcp:
                self.trusted_dhcp_servers.clear()

        return {
            "attack_type": attack_type,
            "packets_injected": len(packets),
            "alerts_triggered": len(alerts),
            "alerts": alerts,
        }
