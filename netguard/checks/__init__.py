"""Posture-check registry."""

from __future__ import annotations

from typing import List

from .base import Check, CheckContext
from .arp_gateway import ArpGatewayCheck
from .captive_portal import CaptivePortalCheck
from .dns_integrity import DnsIntegrityCheck
from .encryption import EncryptionCheck
from .evil_twin import EvilTwinCheck
from .mac_randomization import MacRandomizationCheck
from .proxy_injection import ProxyInjectionCheck
from .reachability import ReachabilityCheck
from .router_exposure import RouterExposureCheck
from .tls_interception import TLSInterceptionCheck

# Order matters only for presentation; the verdict engine sorts by severity.
ALL_CHECKS: List[Check] = [
    EncryptionCheck(),
    TLSInterceptionCheck(),
    DnsIntegrityCheck(),
    ArpGatewayCheck(),
    EvilTwinCheck(),
    CaptivePortalCheck(),
    ProxyInjectionCheck(),
    RouterExposureCheck(),
    MacRandomizationCheck(),
    ReachabilityCheck(),
]


def get_checks() -> List[Check]:
    """Return a fresh list of check instances."""
    return list(ALL_CHECKS)


__all__ = ["Check", "CheckContext", "get_checks", "ALL_CHECKS"]
