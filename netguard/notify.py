"""Desktop notifications via notify-send, with a file-log fallback."""

from __future__ import annotations

import shutil
from typing import Any, Dict, List, Optional

from .models import NetworkState, VerdictLevel
from .util import ensure_dir, now_iso, run_proc

_ICONS = {
    VerdictLevel.SAFE: "security-high",
    VerdictLevel.CAUTION: "security-medium",
    VerdictLevel.UNSAFE: "security-low",
    VerdictLevel.UNKNOWN: "dialog-question",
}
_URGENCY = {
    VerdictLevel.SAFE: "low",
    VerdictLevel.CAUTION: "normal",
    VerdictLevel.UNSAFE: "critical",
    VerdictLevel.UNKNOWN: "normal",
}
_TIMEOUT_MS = {
    VerdictLevel.SAFE: 6000,
    VerdictLevel.CAUTION: 12000,
    VerdictLevel.UNSAFE: 0,  # 0 = do not auto-expire
    VerdictLevel.UNKNOWN: 8000,
}


class Notifier:
    """Sends notifications and always keeps a durable log of what was sent."""

    def __init__(self, config, enabled: bool = True) -> None:
        self.config = config
        self.enabled = bool(enabled and config.notify)
        self.available = shutil.which("notify-send") is not None
        self.history: List[Dict[str, Any]] = []

    def _log(self, title: str, body: str) -> None:
        ensure_dir(self.config.state_dir)
        try:
            with open(self.config.log_file, "a", encoding="utf-8") as handle:
                flat = body.replace("\n", " | ")
                handle.write(f"{now_iso()}\t{title}\t{flat}\n")
        except OSError:
            pass

    def _send(
        self,
        title: str,
        body: str,
        urgency: str = "normal",
        icon: Optional[str] = None,
        timeout: int = 8000,
    ) -> bool:
        self.history.append({"title": title, "body": body, "urgency": urgency})
        self._log(title, body)
        if not self.enabled or not self.available:
            return False
        cmd = ["notify-send", "-a", "NetGuard", "-u", urgency]
        if icon:
            cmd += ["-i", icon]
        cmd += ["-t", str(timeout), title, body]
        proc = run_proc(cmd, timeout=5)
        return bool(proc and proc.returncode == 0)

    def notify_start(self, state: NetworkState) -> bool:
        kind = "Wi-Fi" if state.is_wifi else "wired"
        return self._send(
            f"NetGuard: checking {state.label}",
            f"Network changed — running posture checks on this {kind} network…",
            urgency="low",
            icon="security-medium",
            timeout=4000,
        )

    def notify_verdict(self, report) -> bool:
        verdict = report.verdict
        level = verdict.level

        fails = [r for r in report.results if r.status.value == "fail"]
        warns = [r for r in report.results if r.status.value == "warn"]

        lines = [
            f"Posture score {verdict.score}/100 · {len(fails)} failed, {len(warns)} warning(s)"
        ]
        for result in (fails + warns)[:3]:
            lines.append(f"• {result.summary}")
        if not fails and not warns:
            lines.append("All posture checks passed.")

        top = (fails or warns)
        if top and top[0].remediation:
            lines.append("")
            lines.append(f"Advice: {top[0].remediation}")

        return self._send(
            f"NetGuard: {level.value} — {report.state.label}",
            "\n".join(lines),
            urgency=_URGENCY[level],
            icon=_ICONS[level],
            timeout=_TIMEOUT_MS[level],
        )
