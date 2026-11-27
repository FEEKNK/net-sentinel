"""Wake-on-LAN (Magic Packet) sender with strict MAC validation."""

from __future__ import annotations

import ipaddress
import socket

from app.core.oui import normalize_mac


def build_magic_packet(mac: str) -> bytes:
    """Build a 102-byte Wake-on-LAN Magic Packet for a validated MAC address."""
    normalized = normalize_mac(mac)
    mac_bytes = bytes.fromhex(normalized.replace(":", ""))
    return b"\xff" * 6 + mac_bytes * 16


def send_wake_on_lan(mac: str, target_ip: str | None = None, port: int = 9) -> dict[str, str | int]:
    """Send a Wake-on-LAN UDP Magic Packet on the local network."""
    normalized = normalize_mac(mac)
    packet = build_magic_packet(normalized)

    broadcast_targets = ["255.255.255.255"]
    if target_ip:
        try:
            addr = ipaddress.IPv4Address(target_ip.strip())
            # Also try /24 subnet broadcast for multi-NIC Windows hosts
            subnet_bcast = str(ipaddress.IPv4Network(f"{addr}/24", strict=False).broadcast_address)
            if subnet_bcast not in broadcast_targets:
                broadcast_targets.append(subnet_bcast)
        except ValueError:
            pass

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for dest in broadcast_targets:
            sock.sendto(packet, (dest, port))

    return {
        "mac": normalized,
        "port": port,
        "broadcast": ", ".join(broadcast_targets),
    }
