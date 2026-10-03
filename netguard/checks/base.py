"""Base class and shared context for posture checks."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..models import CheckResult, NetworkState, Severity, Status


@dataclass
class CheckContext:
    """Everything a check may need to evaluate one network."""

    state: NetworkState
    probes: Any
    config: Any
    history: Dict[str, Any] = field(default_factory=dict)
    network_key: str = ""
    now: float = field(default_factory=time.time)


class Check:
    """A single posture check.

    Subclasses set ``id``/``title``/``severity``/``description`` and implement
    :meth:`run`. The result helpers (`pass_`, `warn`, `fail`, `info`, `skip`)
    build :class:`CheckResult` objects with the check metadata filled in.
    """

    id: str = "check"
    title: str = "Check"
    severity: Severity = Severity.MEDIUM
    description: str = ""
    wifi_only: bool = False

    def _result(
        self,
        status: Status,
        summary: str,
        severity: Optional[Severity] = None,
        detail: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        remediation: str = "",
    ) -> CheckResult:
        return CheckResult(
            id=self.id,
            title=self.title,
            status=status,
            summary=summary,
            severity=severity or self.severity,
            detail=detail,
            evidence=evidence or {},
            remediation=remediation,
        )

    def pass_(self, summary: str, **kw) -> CheckResult:
        return self._result(Status.PASS, summary, **kw)

    def info(self, summary: str, **kw) -> CheckResult:
        return self._result(Status.INFO, summary, **kw)

    def warn(self, summary: str, **kw) -> CheckResult:
        return self._result(Status.WARN, summary, **kw)

    def fail(self, summary: str, **kw) -> CheckResult:
        return self._result(Status.FAIL, summary, **kw)

    def skip(self, summary: str, **kw) -> CheckResult:
        return self._result(Status.SKIP, summary, **kw)

    def run(self, ctx: CheckContext) -> CheckResult:  # pragma: no cover - abstract
        raise NotImplementedError
