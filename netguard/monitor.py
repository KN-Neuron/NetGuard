"""Watch for network changes.

Two strategies: a fast path that streams ``nmcli monitor`` events (near-instant
reaction, no extra dependencies), and a polling fallback that works on any
Linux host by fingerprinting the network state every few seconds.
"""

from __future__ import annotations

import subprocess
import time
from typing import Callable, Optional

from . import netstate
from .models import NetworkState
from .util import tool_available


class NetworkMonitor:
    def __init__(
        self,
        config,
        on_change: Callable[[NetworkState], None],
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.config = config
        self.on_change = on_change
        self.logger = logger or (lambda message: None)

    def current_state(self) -> NetworkState:
        return netstate.collect()

    def _settle_and_emit(self, state: NetworkState, last_signature: Optional[str]) -> Optional[str]:
        """Let the link stabilise, then emit once if the signature is new."""
        time.sleep(self.config.settle)
        settled = self.current_state()
        if not settled.available:
            return last_signature
        signature = settled.signature()
        if signature == last_signature:
            return last_signature
        self.logger(f"network change detected: {settled.label}")
        self.on_change(settled)
        return signature

    def watch(self, check_initial: bool = True, iterations: Optional[int] = None) -> None:
        """Block, invoking ``on_change`` for the current and each new network."""
        if self.config.use_dbus and tool_available("nmcli"):
            try:
                return self._watch_nmcli(check_initial, iterations)
            except Exception as exc:  # fall back rather than die
                self.logger(f"nmcli monitor unavailable ({exc}); using polling")
        return self._watch_poll(check_initial, iterations)

    def _watch_poll(self, check_initial: bool, iterations: Optional[int]) -> None:
        emitted = 0
        last_signature: Optional[str] = None
        if check_initial:
            state = self.current_state()
            if state.available:
                last_signature = self._settle_and_emit(state, None)
                emitted += 1
                if iterations and emitted >= iterations:
                    return
        while True:
            state = self.current_state()
            if state.available and state.signature() != last_signature:
                last_signature = self._settle_and_emit(state, last_signature)
                emitted += 1
                if iterations and emitted >= iterations:
                    return
            time.sleep(self.config.interval)

    def _watch_nmcli(self, check_initial: bool, iterations: Optional[int]) -> None:
        emitted = 0
        last_signature: Optional[str] = None
        if check_initial:
            state = self.current_state()
            if state.available:
                last_signature = self._settle_and_emit(state, None)
                emitted += 1
                if iterations and emitted >= iterations:
                    return

        proc = subprocess.Popen(
            ["nmcli", "monitor"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if not line.strip():
                    continue
                state = self.current_state()
                if not state.available:
                    continue
                last_signature = self._settle_and_emit(state, last_signature)
                emitted += 1
                if iterations and emitted >= iterations:
                    return
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
