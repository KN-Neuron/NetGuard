"""Gateway exposure check (limited port probe)."""

from __future__ import annotations

from ..models import Severity
from .base import Check, CheckContext


class RouterExposureCheck(Check):
    id = "router_exposure"
    title = "Gateway exposure"
    severity = Severity.MEDIUM
    description = "Probes a short list of management ports on the default gateway."

    def run(self, ctx: CheckContext):
        gateway = ctx.state.gateway
        if not gateway:
            return self.skip("No gateway to probe")

        open_ports = [port for port in ctx.config.router_ports if ctx.probes.tcp_open(gateway, port)]
        evidence = {"gateway": gateway, "open_ports": open_ports}

        if 23 in open_ports:
            return self.fail(
                "Gateway exposes Telnet (cleartext administration)",
                severity=Severity.HIGH,
                evidence=evidence,
                remediation="Telnet sends credentials in the clear; the gateway is misconfigured or compromised.",
            )
        if 1900 in open_ports:
            return self.warn(
                "UPnP/SSDP is responding on the gateway",
                severity=Severity.MEDIUM,
                evidence=evidence,
                remediation="UPnP can silently open firewall ports; disable it if not needed.",
            )
        if any(p in open_ports for p in (80, 443, 8080, 8443)):
            return self.info(
                "Gateway management interface is reachable",
                evidence=evidence,
                remediation="Change any default router credentials.",
            )
        if open_ports:
            return self.info(f"Gateway exposes ports: {open_ports}", evidence=evidence)
        return self.pass_("No unexpected management ports exposed on the gateway", evidence=evidence)
