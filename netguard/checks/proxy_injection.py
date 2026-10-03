"""Transparent HTTP proxy / traffic-rewriting detection."""

from __future__ import annotations

from ..models import Severity
from .base import Check, CheckContext

_PROXY_HEADERS = ("via", "x-cache", "x-squid", "proxy-connection", "x-forwarded-for", "x-proxy-id")


class ProxyInjectionCheck(Check):
    id = "proxy_injection"
    title = "Transparent HTTP proxy"
    severity = Severity.MEDIUM
    description = "Detects an inline proxy that rewrites or relays plain-HTTP traffic."

    def run(self, ctx: CheckContext):
        response = ctx.probes.http_get(ctx.config.http_probe_url, allow_redirects=False)
        if response.error or not response.ok:
            return self.skip("Plain-HTTP probe could not complete")

        indicators = {h: response.header(h) for h in _PROXY_HEADERS if response.header(h)}
        redirected = 300 <= response.status < 400 and bool(response.location)

        if indicators or redirected:
            return self.warn(
                "The network is transparently proxying HTTP traffic",
                detail="Response headers or a redirect reveal an intermediary proxy.",
                evidence={
                    "status": response.status,
                    "location": response.location,
                    "headers": indicators,
                },
                remediation="Prefer HTTPS; a proxy can inspect or modify unencrypted traffic.",
            )
        return self.pass_("No transparent HTTP proxy observed")
