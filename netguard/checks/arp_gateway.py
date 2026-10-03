"""Gateway identity / ARP-spoofing check."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from ..models import Severity
from .base import Check, CheckContext


class ArpGatewayCheck(Check):
    id = "arp_gateway"
    title = "Gateway identity (ARP)"
    severity = Severity.HIGH
    description = "Detects ARP-cache anomalies and rogue-gateway indicators."

    def run(self, ctx: CheckContext):
        state = ctx.state
        if not state.gateway:
            return self.skip("No default gateway detected")

        by_mac: Dict[str, Set[str]] = defaultdict(set)
        for neighbor in state.neighbors:
            if neighbor.mac:
                by_mac[neighbor.mac].add(neighbor.ip)
        duplicate_macs: Dict[str, List[str]] = {
            mac: sorted(ips) for mac, ips in by_mac.items() if len(ips) > 1
        }

        evidence = {
            "gateway": state.gateway,
            "gateway_mac": state.gateway_mac,
            "neighbors": len(state.neighbors),
        }

        if state.gateway_mac and state.mac_address and state.gateway_mac == state.mac_address:
            return self.fail(
                "Gateway MAC equals this host's MAC address",
                severity=Severity.CRITICAL,
                detail="The gateway is impersonating this machine, or the ARP cache is poisoned.",
                evidence=evidence,
                remediation="Disconnect immediately — ARP spoofing is likely.",
            )
        if state.gateway_mac and state.gateway_mac in duplicate_macs:
            return self.fail(
                "Gateway MAC address claims multiple IP addresses (ARP spoofing)",
                severity=Severity.CRITICAL,
                detail=f"{state.gateway_mac} is advertised for {duplicate_macs[state.gateway_mac]}.",
                evidence={**evidence, "duplicate_macs": duplicate_macs},
                remediation="Disconnect from this network — a device is impersonating the gateway.",
            )
        if duplicate_macs:
            return self.warn(
                "Multiple IP addresses map to the same MAC address",
                detail="This can indicate an ARP anomaly such as a proxy-ARP or spoofing setup.",
                evidence={**evidence, "duplicate_macs": duplicate_macs},
                remediation="Avoid sensitive traffic until the network is verified.",
            )

        previous_mac = (ctx.history.get(ctx.network_key) or {}).get("gateway_mac")
        if previous_mac and state.gateway_mac and previous_mac.lower() != state.gateway_mac.lower():
            return self.warn(
                "Gateway MAC changed since this network was last seen",
                detail=f"Previously {previous_mac}, now {state.gateway_mac}.",
                evidence={**evidence, "previous_gateway_mac": previous_mac},
                remediation="Verify the gateway — a changed identity can indicate a MITM.",
            )

        if state.gateway_mac:
            return self.pass_("Gateway MAC is consistent and unique", evidence=evidence)
        return self.skip("Gateway MAC not yet available in the ARP cache")
