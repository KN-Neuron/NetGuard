"""Turn individual check results into a single posture score and verdict."""

from __future__ import annotations

from typing import List

from .models import (
    CheckResult,
    SEVERITY_FAIL_PENALTY,
    SEVERITY_ORDER,
    Severity,
    Status,
    Verdict,
    VerdictLevel,
    WARN_PENALTY_FACTOR,
)


def _penalty(result: CheckResult) -> float:
    if result.status is Status.FAIL:
        return float(SEVERITY_FAIL_PENALTY[result.severity])
    if result.status is Status.WARN:
        return SEVERITY_FAIL_PENALTY[result.severity] * WARN_PENALTY_FACTOR
    return 0.0


def compute_score(results: List[CheckResult]) -> int:
    """100 minus the weighted penalty of every failure/warning, clamped to 0."""
    score = 100.0
    for result in results:
        score -= _penalty(result)
    return int(max(0.0, min(100.0, round(score))))


def _apply_caps(score: int, results: List[CheckResult]) -> int:
    """Hard ceilings so a single severe finding can never read as 'safe'."""
    fails = [r for r in results if r.status is Status.FAIL]
    if any(r.severity is Severity.CRITICAL for r in fails):
        return min(score, 25)
    if any(r.severity is Severity.HIGH for r in fails):
        return min(score, 55)
    return score


def level_for(score: int) -> VerdictLevel:
    if score >= 80:
        return VerdictLevel.SAFE
    if score >= 45:
        return VerdictLevel.CAUTION
    return VerdictLevel.UNSAFE


def verdict_for(results: List[CheckResult], network_label: str = "this network") -> Verdict:
    if not results:
        return Verdict(
            level=VerdictLevel.UNKNOWN,
            score=0,
            headline="No posture checks could be run for this network.",
        )

    score = _apply_caps(compute_score(results), results)
    level = level_for(score)

    problems = [r for r in results if r.status in (Status.FAIL, Status.WARN)]
    problems.sort(key=lambda r: (-SEVERITY_ORDER[r.severity], r.status is Status.WARN))
    reasons = [r.summary for r in problems]

    counts = {status.value: sum(1 for r in results if r.status is status) for status in Status}

    if level is VerdictLevel.SAFE:
        headline = f"{network_label} looks safe to use"
    elif level is VerdictLevel.CAUTION:
        headline = f"{network_label} is usable but has risks"
    elif level is VerdictLevel.UNSAFE:
        headline = f"{network_label} is NOT safe — avoid sensitive data"
    else:  # pragma: no cover - defensive
        headline = "Security posture could not be determined"

    return Verdict(
        level=level,
        score=score,
        headline=headline,
        reasons=reasons,
        counts=counts,
    )
