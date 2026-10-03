"""Captive-portal detection."""

from __future__ import annotations

from typing import List

from ..models import Severity
from .base import Check, CheckContext


class CaptivePortalCheck(Check):
    id = "captive_portal"
    title = "Captive portal"
    severity = Severity.MEDIUM
    description = "Detects captive portals that intercept and redirect browser traffic."

    def run(self, ctx: CheckContext):
        observations: List[dict] = []
        for url in ctx.config.captive_portal_urls:
            response = ctx.probes.http_get(url, allow_redirects=False)
            if response.error:
                continue
            observations.append(
                {"url": url, "status": response.status, "location": response.location}
            )

            healthy = response.status == 204 or (
                response.status == 200 and response.body.strip().lower() == "success"
            )
            if not healthy:
                return self.warn(
                    "A captive portal is intercepting traffic",
                    detail=(
                        f"{url} returned status {response.status}"
                        + (f" redirecting to {response.location}" if response.location else "")
                        + "."
                    ),
                    evidence={"observations": observations, "portal": response.location},
                    remediation=(
                        "Portal login pages can be spoofed. Avoid sensitive accounts and "
                        "prefer a VPN or phone hotspot for anything important."
                    ),
                )

        if not observations:
            return self.skip("Could not reach any captive-portal probe endpoint")
        return self.pass_(
            "No captive portal interception detected",
            evidence={"observations": observations},
        )
