"""Wi-Fi MAC address privacy check."""

from __future__ import annotations

from ..models import Severity
from .base import Check, CheckContext


class MacRandomizationCheck(Check):
    id = "mac_randomization"
    title = "MAC address privacy"
    severity = Severity.LOW
    wifi_only = True
    description = "Checks whether the Wi-Fi hardware address is randomised on this network."

    def run(self, ctx: CheckContext):
        state = ctx.state
        if not state.is_wifi:
            return self.skip("Not a Wi-Fi connection")

        mode = (state.mac_randomization or "").strip().lower()
        evidence = {"mode": mode or "default"}

        if mode in ("random", "stable", "random-ssid", "stable-ssid"):
            return self.pass_(f"Wi-Fi MAC randomisation is enabled ({mode})", evidence=evidence)
        if mode in ("", "permanent"):
            return self.warn(
                "Wi-Fi MAC address is not randomised",
                severity=Severity.LOW,
                detail="Your real hardware address is broadcast, allowing tracking across networks.",
                evidence={"mode": mode or "permanent"},
                remediation="Enable MAC randomisation in NetworkManager for public networks.",
            )
        return self.info(f"Wi-Fi MAC randomisation is set to '{mode}'", evidence=evidence)
