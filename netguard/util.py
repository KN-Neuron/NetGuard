"""Small, dependency-free helpers used across NetGuard."""

from __future__ import annotations

import datetime as _dt
import os
import shutil
import subprocess
from typing import List, Optional, Sequence


def tool_available(name: str) -> bool:
    """True when an executable is on PATH."""
    return shutil.which(name) is not None


def run_proc(cmd: Sequence[str], timeout: float = 6.0) -> Optional[subprocess.CompletedProcess]:
    """Run a command, returning the CompletedProcess or None on any failure.

    Never raises: missing binaries, timeouts and permissions errors all map to
    None so that callers can degrade gracefully on machines that lack a tool.
    """
    try:
        return subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def run(cmd: Sequence[str], timeout: float = 6.0) -> Optional[str]:
    """Run a command and return stdout, or None if it failed/does not exist."""
    proc = run_proc(cmd, timeout=timeout)
    if proc is None or proc.returncode != 0:
        return None
    return proc.stdout


def split_terse(line: str) -> List[str]:
    """Split an ``nmcli -t`` (terse) line on unescaped colons.

    nmcli escapes literal colons as ``\\:`` and backslashes as ``\\\\`` inside a
    terse value (e.g. MAC addresses and BSSIDs). This splitter honours that so
    ``GENERAL.HWADDR:AA\\:BB\\:CC`` becomes ``['GENERAL.HWADDR', 'AA:BB:CC']``.
    """
    parts: List[str] = []
    cur: List[str] = []
    escaped = False
    for ch in line:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if escaped:  # trailing backslash
        cur.append("\\")
    parts.append("".join(cur))
    return parts


def is_mac(value: str) -> bool:
    """Loose MAC-address validation (12 hex chars, optionally separated)."""
    if not value:
        return False
    hexdigits = value.replace(":", "").replace("-", "").replace(".", "")
    return len(hexdigits) == 12 and all(c in "0123456789abcdefABCDEF" for c in hexdigits)


def normalize_mac(value: str) -> str:
    return (value or "").strip().lower()


def now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def ensure_dir(path) -> None:
    os.makedirs(str(path), exist_ok=True)
