"""Orchestrates running every posture check against a network state."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from .checks import Check, CheckContext, get_checks
from .models import CheckResult, NetworkState, Verdict
from .probe import Probes
from .store import Store
from .util import now_iso
from .verdict import verdict_for


@dataclass
class Report:
    state: NetworkState
    results: List[CheckResult]
    verdict: Verdict
    timestamp: float = field(default_factory=time.time)
    simulated: bool = False

    def to_dict(self) -> dict:
        return {
            "tool": "netguard",
            "timestamp": now_iso(),
            "simulated": self.simulated,
            "network": self.state.to_dict(),
            "verdict": self.verdict.to_dict(),
            "results": [result.to_dict() for result in self.results],
        }


def run_checks(
    state: NetworkState,
    config,
    probes: Optional[Probes] = None,
    store: Optional[Store] = None,
    checks: Optional[List[Check]] = None,
    simulated: bool = False,
) -> Report:
    """Run all checks against ``state`` and aggregate a verdict.

    History is read *before* checks run and recorded *after*, so a check can
    compare the current link against how the same network looked previously.
    """
    active_checks = checks if checks is not None else get_checks()
    active_probes = probes if probes is not None else Probes(config)

    network_key = Store.key_for(state)
    history = {network_key: (store.get(network_key) or {})} if store else {}

    ctx = CheckContext(
        state=state,
        probes=active_probes,
        config=config,
        history=history,
        network_key=network_key,
    )

    results: List[CheckResult] = []
    for check in active_checks:
        try:
            results.append(check.run(ctx))
        except Exception as exc:  # a broken check must never kill the run
            results.append(
                check.skip(
                    f"Check could not complete: {type(exc).__name__}: {exc}",
                    detail="The check raised an unexpected error and was skipped.",
                )
            )

    verdict = verdict_for(results, network_label=state.label)
    report = Report(state=state, results=results, verdict=verdict, simulated=simulated)

    if store is not None:
        store.observe(state)
        store.record_event(state, verdict)
        store.write_last_report(report.to_dict())

    return report
