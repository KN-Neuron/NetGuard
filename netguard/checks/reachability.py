"""Internet reachability (informational)."""

from __future__ import annotations

from ..models import Severity
from .base import Check, CheckContext


class ReachabilityCheck(Check):
    id = "reachability"
    title = "Internet reachability"
    severity = Severity.INFO
    description = "Confirms whether the network has working internet egress."

    def run(self, ctx: CheckContext):
        state = ctx.state
        # Probe a literal IP so a broken/hijacked resolver cannot mask egress.
        if ctx.probes.tcp_open("1.1.1.1", 443):
            return self.pass_("Internet egress is available")
        if state.gateway and ctx.probes.tcp_open(state.gateway, 80, timeout=1.0):
            return self.info("Local network is reachable but there is no internet egress")
        return self.info("No internet egress detected (offline or fully restricted)")
