"""Evil-twin / duplicate-SSID detection."""

from __future__ import annotations

from ..models import Severity
from .base import Check, CheckContext


def _normalise_security(security: str) -> str:
    return (security or "").strip().upper() or "OPEN"


class EvilTwinCheck(Check):
    id = "evil_twin"
    title = "Evil-twin / duplicate SSID"
    severity = Severity.HIGH
    wifi_only = True
    description = "Looks for other access points advertising the same SSID with different security."

    def run(self, ctx: CheckContext):
        state = ctx.state
        if not state.is_wifi:
            return self.skip("Not a Wi-Fi connection")
        if not state.aps:
            return self.skip("Wi-Fi scan data unavailable")

        same_ssid = [ap for ap in state.aps if ap.ssid == state.ssid]
        others = [ap for ap in same_ssid if ap.bssid and ap.bssid != state.bssid]
        current = _normalise_security(state.security)

        if others:
            mismatched = [ap for ap in others if _normalise_security(ap.security) != current]
            if mismatched:
                return self.fail(
                    f"{len(mismatched)} other AP(s) advertise '{state.ssid}' with different security",
                    severity=Severity.HIGH,
                    detail=(
                        "Advertising the same network name with a different security "
                        "configuration is a strong evil-twin/rogue-AP indicator."
                    ),
                    evidence={
                        "current": {"bssid": state.bssid, "security": current},
                        "others": [ap.to_dict() for ap in mismatched],
                    },
                    remediation="Disconnect and confirm the correct network with staff; use a hotspot/VPN.",
                )
            return self.pass_(f"Only matching-security APs seen for '{state.ssid}'")

        previous_bssid = (ctx.history.get(ctx.network_key) or {}).get("bssid")
        if previous_bssid and state.bssid and previous_bssid.lower() != state.bssid.lower():
            return self.warn(
                f"BSSID for '{state.ssid}' changed since it was last seen",
                detail=f"Previously {previous_bssid}, now {state.bssid}.",
                evidence={"previous_bssid": previous_bssid, "current_bssid": state.bssid},
                remediation="Confirm you joined the intended access point.",
            )
        return self.pass_(f"No duplicate SSID detected for '{state.ssid}'")
