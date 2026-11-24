"""Cross-platform OS adapter factory."""

from __future__ import annotations

import platform

from app.platform.base import FirewallAdapter, NetworkHelper, PlatformCapabilities
from app.platform.linux import LinuxFirewallAdapter, LinuxNetworkHelper
from app.platform.windows import WindowsFirewallAdapter, WindowsNetworkHelper


def get_firewall_adapter() -> FirewallAdapter:
    """Return the OS-appropriate firewall adapter."""
    system = platform.system().lower()
    if system == "windows":
        return WindowsFirewallAdapter()
    return LinuxFirewallAdapter()


def get_network_helper() -> NetworkHelper:
    """Return the OS-appropriate network helper."""
    system = platform.system().lower()
    if system == "windows":
        return WindowsNetworkHelper()
    return LinuxNetworkHelper()


def get_platform_capabilities() -> PlatformCapabilities:
    """Inspect current OS privileges and network environment."""
    helper = get_network_helper()
    fw = get_firewall_adapter()
    return helper.detect_capabilities(firewall_backend=fw.backend_name)
