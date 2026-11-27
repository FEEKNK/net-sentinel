"""Offline IEEE OUI vendor lookup and randomized/private MAC detection."""

from __future__ import annotations

import re

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

# Curated offline OUI prefix table covering common home, enterprise, mobile, and IoT vendors
OUI_VENDORS: dict[str, str] = {
    # Virtualization & Hypervisors
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "0A:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU / KVM",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1C:42": "Parallels",
    # Apple
    "00:03:93": "Apple",
    "00:1B:63": "Apple",
    "00:1F:F3": "Apple",
    "04:0C:CE": "Apple",
    "18:E7:F4": "Apple",
    "28:CF:E9": "Apple",
    "3C:15:C2": "Apple",
    "5C:95:AE": "Apple",
    "68:96:7B": "Apple",
    "70:56:81": "Apple",
    "7C:D1:C3": "Apple",
    "88:66:5A": "Apple",
    "A4:83:E7": "Apple",
    "AC:BC:32": "Apple",
    "B8:E8:56": "Apple",
    "D0:23:DB": "Apple",
    "DC:A9:04": "Apple",
    "F0:18:98": "Apple",
    "F4:5C:89": "Apple",
    # Samsung
    "00:12:47": "Samsung",
    "00:16:32": "Samsung",
    "00:21:19": "Samsung",
    "18:3A:2D": "Samsung",
    "24:4B:81": "Samsung",
    "34:23:BA": "Samsung",
    "50:01:BB": "Samsung",
    "5C:0A:5B": "Samsung",
    "78:47:1D": "Samsung",
    "84:25:DB": "Samsung",
    "94:35:0A": "Samsung",
    "AC:5F:3E": "Samsung",
    "BC:14:EF": "Samsung",
    "CC:07:AB": "Samsung",
    "D0:22:BE": "Samsung",
    "E4:92:FB": "Samsung",
    "F4:42:8F": "Samsung",
    # Xiaomi / Redmi / Poco
    "04:CF:8C": "Xiaomi",
    "10:2A:B3": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "34:CE:00": "Xiaomi",
    "50:64:2B": "Xiaomi",
    "64:09:80": "Xiaomi",
    "78:11:DC": "Xiaomi",
    "8C:BE:BE": "Xiaomi",
    "98:FA:E3": "Xiaomi",
    "AC:F7:F3": "Xiaomi",
    "C4:0B:CB": "Xiaomi",
    "F0:B4:29": "Xiaomi",
    "F8:A4:5F": "Xiaomi",
    # Huawei / Honor / OPPO / vivo / Realme
    "00:E0:FC": "Huawei",
    "20:A6:80": "Huawei",
    "48:46:FB": "Huawei",
    "70:72:3C": "Huawei",
    "88:28:B3": "Huawei",
    "D4:6A:A8": "Huawei",
    "1C:77:F6": "OPPO",
    "4C:18:9A": "OPPO",
    "A4:3B:FA": "OPPO",
    "C8:3A:35": "Tenda",
    "2C:26:17": "vivo",
    "8C:FD:F0": "vivo",
    # Routers & Networking (TP-Link, ASUS, MikroTik, Ubiquiti, Cisco, Netgear, D-Link, Zyxel)
    "14:CC:20": "TP-Link",
    "18:D6:C7": "TP-Link",
    "30:B5:C2": "TP-Link",
    "50:C7:BF": "TP-Link",
    "54:AF:97": "TP-Link",
    "60:32:B1": "TP-Link",
    "74:DA:88": "TP-Link",
    "98:DA:C4": "TP-Link",
    "B0:BE:76": "TP-Link",
    "C0:25:E9": "TP-Link",
    "D8:07:B6": "TP-Link",
    "EC:08:6B": "TP-Link",
    "04:D4:C4": "ASUS",
    "08:60:6E": "ASUS",
    "1C:87:2C": "ASUS",
    "2C:FD:A1": "ASUS",
    "38:D5:47": "ASUS",
    "50:46:5D": "ASUS",
    "60:45:CB": "ASUS",
    "AC:9E:17": "ASUS",
    "18:E8:29": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "74:83:C2": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",
    "48:A9:8A": "MikroTik",
    "4C:5E:0C": "MikroTik",
    "64:D1:54": "MikroTik",
    "74:4D:28": "MikroTik",
    "B8:69:F4": "MikroTik",
    "CC:2D:E0": "MikroTik",
    "D4:CA:6D": "MikroTik",
    "00:00:0C": "Cisco",
    "00:1A:A1": "Cisco",
    "00:26:CB": "Cisco",
    "58:97:1E": "Cisco",
    "00:09:5B": "Netgear",
    "20:4E:7F": "Netgear",
    "84:1B:5E": "Netgear",
    "A0:63:91": "Netgear",
    "00:1B:11": "D-Link",
    "1C:7E:E5": "D-Link",
    "84:C9:B2": "D-Link",
    "00:1A:2B": "Ayecom / Router",
    "40:4A:03": "Zyxel",
    "5C:F4:AB": "Zyxel",
    # PC, NIC & Chipsets (Intel, Realtek, Dell, HP, Lenovo, MSI, ASRock, Gigabyte)
    "00:1B:21": "Intel",
    "00:1E:67": "Intel",
    "34:13:E8": "Intel",
    "48:51:B7": "Intel",
    "68:05:CA": "Intel",
    "7C:B2:7D": "Intel",
    "80:86:F2": "Intel",
    "94:65:9C": "Intel",
    "A4:34:D9": "Intel",
    "D8:FC:93": "Intel",
    "00:E0:4C": "Realtek",
    "52:54:4C": "Realtek",
    "18:03:73": "Dell",
    "24:6E:96": "Dell",
    "F8:BC:12": "Dell",
    "00:21:5A": "HP",
    "3C:D9:2B": "HP",
    "94:57:A5": "HP",
    "3C:97:0E": "Lenovo",
    "98:FA:9B": "Lenovo",
    "C8:5B:76": "Lenovo",
    "D8:BB:C1": "MSI",
    "4C:CC:6A": "MSI",
    "70:85:C2": "ASRock",
    "A8:A1:59": "ASRock",
    "1C:1B:0D": "Gigabyte",
    "E0:D5:5E": "Gigabyte",
    # IoT, NAS, SBC, Smart TV & Consoles
    "28:CD:C1": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:11:32": "Synology NAS",
    "24:5E:BE": "QNAP NAS",
    "18:FE:34": "Espressif IoT",
    "24:0A:C4": "Espressif IoT",
    "24:6F:28": "Espressif IoT",
    "30:AE:A4": "Espressif IoT",
    "7C:9E:BD": "Espressif IoT",
    "A4:CF:12": "Espressif IoT",
    "DC:4F:22": "Espressif IoT",
    "10:D5:61": "Tuya Smart",
    "D8:F1:5B": "Tuya / Espressif",
    "54:60:09": "Google / Chromecast",
    "F4:F5:D8": "Google / Nest",
    "00:FC:8B": "Amazon Echo / Fire",
    "74:C2:46": "Amazon Echo / Fire",
    "00:04:1F": "Sony PlayStation",
    "28:0D:FC": "Sony PlayStation",
    "A8:6B:AD": "LG Electronics",
    "C4:36:6C": "LG Electronics",
    "98:B6:E9": "Nintendo",
}


def normalize_mac(mac: str) -> str:
    """Validate and normalize a MAC address to AA:BB:CC:DD:EE:FF."""
    cleaned = mac.strip().upper().replace("-", ":")
    if not MAC_RE.match(cleaned):
        raise ValueError(f"Invalid MAC address format: {mac}")
    return cleaned


def is_randomized_mac(mac: str) -> bool:
    """Return True if the MAC locally-administered bit (U/L bit) is set (e.g. iOS/Android private MAC)."""
    cleaned = mac.strip().upper().replace("-", ":")
    if len(cleaned) < 2:
        return False
    try:
        first_octet = int(cleaned[:2], 16)
        return (first_octet & 0x02) != 0 and (first_octet & 0x01) == 0
    except ValueError:
        return False


def lookup_vendor(mac: str) -> str:
    """Resolve vendor name from MAC OUI prefix offline, flagging private/randomized MACs."""
    if not mac:
        return "Unknown"
    normalized = mac.strip().upper().replace("-", ":")
    prefix = normalized[:8]
    if prefix in OUI_VENDORS:
        return OUI_VENDORS[prefix]
    if is_randomized_mac(normalized):
        return "Private / Randomized MAC (Mobile)"
    return "Unknown"
