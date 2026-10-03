"""Core data models shared by every NetGuard component."""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Status(str, Enum):
    """Outcome of a single posture check."""

    PASS = "pass"
    INFO = "info"      # informational, never counts against the score
    WARN = "warn"      # suspicious, small penalty
    FAIL = "fail"      # insecure, weighted penalty
    SKIP = "skip"      # not applicable / no data to run the check


class Severity(str, Enum):
    """How much a failure matters."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Points subtracted from a perfect 100 when a check FAILs at each severity.
SEVERITY_FAIL_PENALTY: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 7,
    Severity.MEDIUM: 14,
    Severity.HIGH: 25,
    Severity.CRITICAL: 45,
}

# A WARN costs this fraction of the equivalent FAIL penalty.
WARN_PENALTY_FACTOR = 0.45


class VerdictLevel(str, Enum):
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    UNSAFE = "UNSAFE"
    UNKNOWN = "UNKNOWN"


@dataclass
class AccessPoint:
    """A single BSSID seen in the scan results."""

    ssid: str
    bssid: str
    security: str = ""
    signal: int = 0
    channel: str = ""
    active: bool = False

    @property
    def is_open(self) -> bool:
        sec = (self.security or "").strip().upper()
        return sec in ("", "--", "OPEN", "NONE")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Neighbor:
    """An entry from the kernel ARP/neighbour table."""

    ip: str
    mac: str = ""
    interface: str = ""
    state: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkState:
    """Everything NetGuard knows about the currently active network link."""

    timestamp: float = field(default_factory=time.time)
    available: bool = False
    interface: str = ""
    device_type: str = ""           # "wifi" | "ethernet" | ""
    connection_name: str = ""
    ssid: str = ""
    bssid: str = ""
    security: str = ""
    ip_address: str = ""
    prefix: str = ""
    gateway: str = ""
    dns_servers: List[str] = field(default_factory=list)
    dhcp_server: str = ""
    gateway_mac: str = ""
    mac_address: str = ""
    mac_randomization: str = ""
    aps: List[AccessPoint] = field(default_factory=list)
    neighbors: List[Neighbor] = field(default_factory=list)
    tools: Dict[str, bool] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_wifi(self) -> bool:
        return self.device_type == "wifi"

    @property
    def is_open(self) -> bool:
        sec = (self.security or "").strip().upper()
        return sec in ("", "--", "OPEN", "NONE")

    @property
    def label(self) -> str:
        if self.is_wifi:
            return self.ssid or self.connection_name or self.interface or "unknown network"
        return self.connection_name or self.interface or "unknown network"

    def signature(self) -> str:
        """Stable fingerprint of the link; changes => the network changed."""
        parts = [
            self.interface,
            self.connection_name,
            self.ssid,
            self.bssid,
            self.gateway,
            self.ip_address,
            ",".join(sorted(self.dns_servers)),
        ]
        return hashlib.sha1("|".join(parts).encode("utf-8", "replace")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CheckResult:
    """Result of one posture check."""

    id: str
    title: str
    status: Status
    summary: str
    severity: Severity = Severity.MEDIUM
    detail: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity"] = self.severity.value
        return data

    @property
    def is_fail(self) -> bool:
        return self.status is Status.FAIL

    @property
    def is_warn(self) -> bool:
        return self.status is Status.WARN


@dataclass
class Verdict:
    """Aggregated security judgement for a network."""

    level: VerdictLevel
    score: int
    headline: str
    reasons: List[str] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["level"] = self.level.value
        return data
