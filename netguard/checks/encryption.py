"""Wi-Fi link encryption check."""

from __future__ import annotations

from ..models import Severity
from .base import Check, CheckContext


class EncryptionCheck(Check):
    id = "wifi_encryption"
    title = "Wi-Fi link encryption"
    severity = Severity.HIGH
    wifi_only = True
    description = "Confirms the wireless link uses modern encryption (WPA2/WPA3)."

    def run(self, ctx: CheckContext):
        state = ctx.state
        if not state.is_wifi:
            return self.skip("Not a Wi-Fi connection")

        security = (state.security or "").strip()
        upper = security.upper()
        evidence = {"security": security or "OPEN"}

        if upper in ("", "--", "OPEN", "NONE", "NONE (OPEN)"):
            return self.fail(
                "Open network — wireless traffic is not encrypted",
                severity=Severity.HIGH,
                detail="Anyone nearby can passively capture this network's traffic.",
                evidence=evidence,
                remediation="Avoid logins and sensitive data, or route traffic through a VPN/phone hotspot.",
            )
        if "WEP" in upper:
            return self.fail(
                "WEP encryption is broken and trivially cracked",
                severity=Severity.HIGH,
                detail="WEP can be defeated in minutes with widely available tools.",
                evidence=evidence,
                remediation="Treat this network as untrusted; use a VPN.",
            )
        if "WPA3" in upper:
            return self.pass_("WPA3 (SAE) protects the wireless link", evidence=evidence)
        if "WPA2" in upper:
            if "TKIP" in upper:
                return self.warn(
                    "WPA2 uses the deprecated TKIP cipher",
                    detail="TKIP is a legacy cipher with known weaknesses.",
                    evidence=evidence,
                    remediation="Prefer a network offering WPA2-CCMP or WPA3.",
                )
            return self.pass_("WPA2 (CCMP) protects the wireless link", evidence=evidence)
        if "WPA" in upper:
            return self.warn(
                "Legacy WPA1 is in use",
                detail="WPA1 (TKIP) is deprecated and vulnerable to offline attacks.",
                evidence=evidence,
                remediation="Prefer WPA2/WPA3 networks.",
            )
        return self.info(f"Unrecognised security type: {security!r}", evidence=evidence)
