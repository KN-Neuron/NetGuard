"""DNS integrity / hijacking check."""

from __future__ import annotations

import secrets
from typing import List

from ..models import Severity
from .base import Check, CheckContext


class DnsIntegrityCheck(Check):
    id = "dns_integrity"
    title = "DNS integrity"
    severity = Severity.HIGH
    description = (
        "Detects DNS hijacking by testing a guaranteed non-existent name and by "
        "comparing system answers with a trusted DNS-over-HTTPS resolver."
    )

    def run(self, ctx: CheckContext):
        state = ctx.state
        probes = ctx.probes
        config = ctx.config
        evidence = {"dns_servers": list(state.dns_servers), "doh_enabled": bool(config.use_doh)}

        # (1) A name that must NOT exist: any answer means the resolver rewrites.
        probe_name = f"nx-{secrets.token_hex(8)}.example.com"
        try:
            bogus = probes.resolve(probe_name)
        except Exception:
            bogus = []
        if bogus:
            return self.fail(
                "Resolver answered a non-existent domain (DNS hijacking)",
                severity=Severity.CRITICAL,
                detail=f"{probe_name} unexpectedly resolved to {bogus}.",
                evidence={**evidence, "probe": probe_name, "answer": bogus},
                remediation="The router/ISP is rewriting DNS answers. Switch to DoH/DoT or use a VPN.",
            )

        # (2) Compare answers for real domains against a trusted resolver.
        checked = 0
        mismatches: List[dict] = []
        for domain in config.dns_test_domains:
            try:
                local = probes.resolve(domain)
                trusted = probes.doh_resolve(domain)
            except Exception:
                continue
            if trusted is None:
                break
            checked += 1
            if not local:
                mismatches.append({"domain": domain, "local": [], "trusted": trusted})
            elif not (set(local) & set(trusted)):
                mismatches.append({"domain": domain, "local": local, "trusted": trusted})

        if checked == 0:
            return self.skip(
                "Trusted DNS (DoH) unavailable; comparison skipped",
                evidence=evidence,
            )
        if mismatches:
            return self.warn(
                "DNS answers differ from a trusted resolver",
                detail=f"{len(mismatches)} of {checked} test domains returned different addresses.",
                evidence={**evidence, "checked": checked, "mismatches": mismatches},
                remediation="Possible DNS manipulation; verify sensitive destinations or use a VPN.",
            )
        return self.pass_(
            f"DNS answers match a trusted resolver ({checked} domains)",
            evidence=evidence,
        )
