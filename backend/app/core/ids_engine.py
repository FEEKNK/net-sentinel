"""Hybrid IDS Engine combining Behavioral Detectors and Snort Rule Matching."""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from app.core.blocker import ActiveResponseBlocker
from app.core.snort_parser import SnortRule, match_rule, parse_snort_rules
from app.db.database import Database


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
            "preview": self.payload[:80] if self.payload else "",
        }


class IDSEngine:
    """Stateful packet analysis engine (Port Scan, SYN Flood, ARP Spoof, Snort Rules)."""

    def __init__(
        self,
        *,
        db: Database,
        blocker: ActiveResponseBlocker,
        home_nets: list[ipaddress.IPv4Network] | None = None,
        on_alert: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        port_scan_threshold: int = 10,
        port_scan_window_s: float = 10.0,
        syn_flood_threshold: int = 40,
        syn_flood_window_s: float = 5.0,
        cooldown_seconds: float = 15.0,
    ) -> None:
        self.db = db
        self.blocker = blocker
        self.home_nets = home_nets or [ipaddress.IPv4Network("192.168.0.0/16")]
        self.on_alert = on_alert

        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_s = port_scan_window_s
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window_s = syn_flood_window_s
        self.cooldown_seconds = cooldown_seconds

        self.rules: list[SnortRule] = []
        self.rule_errors: list[dict[str, str | int]] = []

        # Bounded sliding-window structures to prevent memory leaks
        self._port_hits: dict[str, deque[tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._syn_hits: dict[tuple[str, str], deque[float]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._arp_table: dict[str, str] = {}
        self._cooldowns: dict[tuple[str, str, str], float] = {}

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
        """Run behavioral detectors and Snort rules against a single PacketEvent."""
        generated_alerts: list[dict[str, Any]] = []
        now = pkt.timestamp or time.time()

        # 1) ARP Spoofing Detector
        if pkt.protocol.lower() == "arp" and pkt.arp_psrc and pkt.arp_hwsrc:
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
                oldest_key = next(iter(self._arp_table))
                del self._arp_table[oldest_key]
            self._arp_table[pkt.arp_psrc] = norm_mac

        # 2) Behavioral TCP Detectors (Port Scan & SYN Flood)
        if pkt.protocol.lower() == "tcp" and pkt.src_ip and pkt.dst_port is not None:
            # 2a) Port Scan: distinct destination ports within sliding window
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

            # 2b) SYN Flood: SYN set without ACK
            flags = pkt.tcp_flags.upper()
            if "S" in flags and "A" not in flags:
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

        # 3) Snort Signature Rules
        for rule in self.rules:
            if match_rule(
                rule,
                protocol=pkt.protocol,
                src_ip=pkt.src_ip,
                src_port=pkt.src_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                payload=pkt.payload,
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
        last_ts = self._cooldowns.get(cooldown_key, 0.0)
        if (now - last_ts) < self.cooldown_seconds:
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
        stale_ips = [
            ip
            for ip, q in self._port_hits.items()
            if not q or (now - q[-1][0]) > self.port_scan_window_s
        ]
        for ip in stale_ips:
            del self._port_hits[ip]

        stale_syn = [
            k
            for k, q in self._syn_hits.items()
            if not q or (now - q[-1]) > self.syn_flood_window_s
        ]
        for k in stale_syn:
            del self._syn_hits[k]

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
        for pkt in packets:
            emitted = await self.process_packet(pkt)
            alerts.extend(emitted)

        return {
            "attack_type": attack_type,
            "packets_injected": len(packets),
            "alerts_triggered": len(alerts),
            "alerts": alerts,
        }
