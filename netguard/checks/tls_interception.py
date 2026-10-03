"""TLS interception (man-in-the-middle) detection."""

from __future__ import annotations

from ..models import Severity
from .base import Check, CheckContext


class TLSInterceptionCheck(Check):
    id = "tls_interception"
    title = "TLS interception (MITM)"
    severity = Severity.CRITICAL
    description = (
        "Performs TLS handshakes to well-known hosts and inspects the presented "
        "certificates to detect an active man-in-the-middle."
    )

    def run(self, ctx: CheckContext):
        peers = [ctx.probes.tls_peer(host) for host in ctx.config.tls_test_hosts]
        available = [peer for peer in peers if peer.available]
        evidence = {"peers": [peer.to_dict() for peer in available]}

        if not available:
            return self.skip(
                "Could not complete TLS handshakes to any test host",
                evidence={"peers": [peer.to_dict() for peer in peers]},
            )

        untrusted = [peer for peer in available if not peer.validated]
        if untrusted:
            private = [peer for peer in untrusted if not peer.issuer_is_public_ca]
            if private:
                culprit = private[0]
                return self.fail(
                    "TLS traffic is being intercepted (untrusted certificate)",
                    severity=Severity.CRITICAL,
                    detail=(
                        f"{culprit.host} presented a certificate issued by "
                        f"'{culprit.issuer_org or culprit.issuer}', which is not a public CA."
                    ),
                    evidence=evidence,
                    remediation="Active MITM detected. Leave this network and do not enter credentials.",
                )
            return self.warn(
                "TLS certificate validation failed for well-known hosts",
                detail=untrusted[0].error,
                evidence=evidence,
                remediation="Could be interception, an expired certificate, or an incorrect system clock.",
            )

        private = [peer for peer in available if not peer.issuer_is_public_ca]
        if private:
            culprit = private[0]
            return self.warn(
                "TLS is terminated by a non-public certificate authority",
                detail=(
                    f"{culprit.host}'s certificate was issued by "
                    f"'{culprit.issuer_org or culprit.issuer}'."
                ),
                evidence=evidence,
                remediation=(
                    "A locally-trusted interception proxy is present (e.g. corporate/ISP). "
                    "It can read all TLS traffic from this network."
                ),
            )
        return self.pass_(
            "TLS to well-known hosts is end-to-end and publicly trusted",
            evidence=evidence,
        )
