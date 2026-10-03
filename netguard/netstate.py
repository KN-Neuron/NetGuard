"""Collect the current network state from the OS.

Primary source is NetworkManager's CLI (``nmcli``); when it is missing or a
field is unavailable we fall back to ``ip``, ``iw`` and ``resolvectl``. Every
failure is swallowed so collection always returns a (possibly partial) state.
"""

from __future__ import annotations

import re
from typing import List

from .models import AccessPoint, Neighbor, NetworkState
from .util import run, split_terse, tool_available, normalize_mac

_TOOLS = ("nmcli", "ip", "iw", "resolvectl", "arp", "openssl")


def collect(timeout: float = 6.0) -> NetworkState:
    """Gather a snapshot of the active network link."""
    state = NetworkState()
    state.tools = {name: tool_available(name) for name in _TOOLS}

    if state.tools.get("nmcli"):
        _collect_nmcli(state, timeout)

    # Fallbacks / top-ups for anything nmcli did not provide.
    if not state.gateway or not state.interface:
        _collect_ip_routes(state, timeout)
    if not state.dns_servers:
        _collect_resolvectl(state, timeout)
    if state.is_wifi and (not state.ssid or not state.bssid):
        _collect_iw(state, timeout)

    _collect_neighbors(state, timeout)
    _collect_gateway_mac(state, timeout)

    state.available = bool(state.interface)
    return state


# ---------------------------------------------------------------------------
def _collect_nmcli(state: NetworkState, timeout: float) -> None:
    status = run(
        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
        timeout=timeout,
    )
    if not status:
        return
    for line in status.splitlines():
        parts = split_terse(line)
        if len(parts) < 4:
            continue
        device, device_type, dev_state = parts[0], parts[1], parts[2]
        connection = ":".join(parts[3:])
        if device_type in ("loopback", "wifi-p2p", "bridge"):
            continue
        if dev_state.startswith("connected") and device_type in ("wifi", "ethernet"):
            state.interface = device
            state.device_type = device_type
            state.connection_name = connection
            break
    if not state.interface:
        return

    details = run(["nmcli", "-t", "device", "show", state.interface], timeout=timeout)
    if details:
        _parse_device_show(state, details)

    if state.device_type == "wifi":
        _collect_wifi_list(state, timeout)
        _collect_mac_randomization(state, timeout)
        if not state.ssid and state.connection_name:
            state.ssid = state.connection_name


def _parse_device_show(state: NetworkState, details: str) -> None:
    dns: List[str] = []
    for line in details.splitlines():
        parts = split_terse(line)
        if len(parts) < 2:
            continue
        # nmcli does not always escape colons inside device-show values, so
        # rejoin everything after the key to recover MAC addresses intact.
        key = parts[0]
        value = ":".join(parts[1:])
        base = key.split("[")[0]
        if base == "GENERAL.HWADDR":
            state.mac_address = value
        elif base == "GENERAL.CONNECTION" and value:
            state.connection_name = value
        elif base == "IP4.ADDRESS" and not state.ip_address:
            addr, _, prefix = value.partition("/")
            state.ip_address, state.prefix = addr, prefix
        elif base == "IP4.GATEWAY":
            state.gateway = value
        elif base in ("IP4.DNS", "IP4.NAMESERVER"):
            if value and value not in dns:
                dns.append(value)
        elif base.startswith("DHCP4.OPTION") and "dhcp_server_identifier" in value:
            state.dhcp_server = value.split("=", 1)[1].strip()
    state.dns_servers = dns


def _collect_wifi_list(state: NetworkState, timeout: float) -> None:
    listing = run(
        ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SECURITY,SIGNAL,CHAN",
         "device", "wifi", "list", "--rescan", "no"],
        timeout=timeout,
    )
    if not listing:
        return
    aps: List[AccessPoint] = []
    for line in listing.splitlines():
        parts = split_terse(line)
        if len(parts) < 6:
            continue
        # Fields are ACTIVE,SSID,BSSID,SECURITY,SIGNAL,CHAN. The BSSID may or
        # may not have its colons escaped, so rebuild it from the middle.
        active = parts[0].strip().lower() in ("yes", "*")
        ssid = parts[1]
        bssid = normalize_mac(":".join(parts[2:-3]))
        security = parts[-3]
        try:
            signal = int(parts[-2])
        except (ValueError, IndexError):
            signal = 0
        channel = parts[-1]
        aps.append(AccessPoint(ssid=ssid, bssid=bssid, security=security,
                               signal=signal, channel=channel, active=active))
        if active and not state.ssid:
            state.ssid, state.bssid, state.security = ssid, bssid, security
    state.aps = aps


def _collect_mac_randomization(state: NetworkState, timeout: float) -> None:
    value = ""
    if state.connection_name:
        out = run(
            ["nmcli", "-t", "-f", "802-11-wireless.cloned-mac-address",
             "connection", "show", state.connection_name],
            timeout=timeout,
        )
        if out:
            for line in out.splitlines():
                parts = split_terse(line)
                if len(parts) >= 2 and parts[0].startswith("802-11-wireless.cloned-mac-address"):
                    value = parts[1]
    if not value:
        out = run(["nmcli", "-t", "-f", "wifi.cloned-mac-address", "general"], timeout=timeout)
        if out and out.strip():
            value = out.strip().splitlines()[-1].strip()
    state.mac_randomization = value or "default"


def _collect_ip_routes(state: NetworkState, timeout: float) -> None:
    if not state.tools.get("ip"):
        return
    routes = run(["ip", "-o", "route"], timeout=timeout)
    if routes:
        for line in routes.splitlines():
            fields = line.split()
            if fields and fields[0] == "default" and "via" in fields:
                if not state.gateway:
                    state.gateway = fields[fields.index("via") + 1]
                if not state.interface and "dev" in fields:
                    state.interface = fields[fields.index("dev") + 1]
                break
    if state.interface and not state.ip_address:
        addr = run(["ip", "-o", "-f", "inet", "addr", "show", state.interface], timeout=timeout)
        if addr:
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", addr)
            if match:
                state.ip_address, state.prefix = match.group(1), match.group(2)
    if not state.device_type and state.interface:
        if state.interface.startswith("wl"):
            state.device_type = "wifi"
        elif state.interface.startswith(("en", "eth")):
            state.device_type = "ethernet"


def _collect_resolvectl(state: NetworkState, timeout: float) -> None:
    if not state.tools.get("resolvectl"):
        return
    out = run(["resolvectl", "status", state.interface], timeout=timeout) if state.interface else None
    out = out or run(["resolvectl", "status"], timeout=timeout)
    if not out:
        return
    dns: List[str] = []
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith(("DNS Servers:", "Current DNS Server:")):
            for token in re.findall(r"\d+\.\d+\.\d+\.\d+|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,}", stripped.split(":", 1)[1]):
                if token not in dns:
                    dns.append(token)
    if dns:
        state.dns_servers = dns


def _collect_iw(state: NetworkState, timeout: float) -> None:
    if not state.tools.get("iw"):
        return
    out = run(["iw", "dev", state.interface, "link"], timeout=timeout)
    if not out:
        return
    match = re.search(r"SSID:\s*(.+)", out)
    if match and not state.ssid:
        state.ssid = match.group(1).strip()
    match = re.search(r"Connected to ([0-9a-fA-F:]{17})", out)
    if match and not state.bssid:
        state.bssid = normalize_mac(match.group(1))


def _collect_neighbors(state: NetworkState, timeout: float) -> None:
    if not state.tools.get("ip"):
        return
    out = run(["ip", "-o", "neigh", "show"], timeout=timeout)
    if not out:
        return
    neighbors: List[Neighbor] = []
    for line in out.splitlines():
        fields = line.split()
        if not fields:
            continue
        ip = fields[0]
        mac = normalize_mac(fields[fields.index("lladdr") + 1]) if "lladdr" in fields else ""
        dev = fields[fields.index("dev") + 1] if "dev" in fields else ""
        neighbors.append(Neighbor(ip=ip, mac=mac, interface=dev, state=fields[-1]))
    state.neighbors = neighbors


def _collect_gateway_mac(state: NetworkState, timeout: float) -> None:
    if state.gateway_mac or not state.gateway:
        return
    for neighbor in state.neighbors:
        if neighbor.ip == state.gateway and neighbor.mac:
            state.gateway_mac = neighbor.mac
            return
    if state.tools.get("ip"):
        out = run(["ip", "neigh", "show", state.gateway], timeout=timeout)
        if out:
            match = re.search(r"lladdr ([0-9a-fA-F:]{17})", out)
            if match:
                state.gateway_mac = normalize_mac(match.group(1))
                return
    if state.tools.get("arp"):
        out = run(["arp", "-n", state.gateway], timeout=timeout)
        if out:
            match = re.search(r"([0-9a-fA-F:]{17})", out)
            if match:
                state.gateway_mac = normalize_mac(match.group(1))
