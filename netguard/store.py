"""Persistent history of seen networks, used for change detection."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from .models import NetworkState, Verdict
from .util import ensure_dir, now_iso


class Store:
    """A tiny JSON-backed store of previously observed networks and events."""

    def __init__(self, config) -> None:
        self.config = config
        self.path = config.history_file
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"version": 1, "networks": {}, "events": []}

    def save(self) -> None:
        ensure_dir(self.config.state_dir)
        tmp = f"{self.path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError:
            pass

    # -- networks ----------------------------------------------------------
    @staticmethod
    def key_for(state: NetworkState) -> str:
        name = state.ssid or state.connection_name or state.interface or "unknown"
        identity = state.bssid or state.gateway or state.interface or "?"
        return f"{name}::{identity}"

    def networks(self) -> Dict[str, Any]:
        return self.data.setdefault("networks", {})

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return self.networks().get(key)

    def observe(self, state: NetworkState) -> bool:
        """Record the network; returns True if this is the first time we see it."""
        key = self.key_for(state)
        networks = self.networks()
        first_seen = key not in networks
        entry = networks.get(key, {"first_seen": now_iso(), "seen_count": 0})
        entry["last_seen"] = now_iso()
        entry["seen_count"] = int(entry.get("seen_count", 0)) + 1
        entry["label"] = state.label
        entry["ssid"] = state.ssid
        entry["bssid"] = state.bssid
        entry["security"] = state.security
        entry["device_type"] = state.device_type
        if state.gateway:
            entry["gateway"] = state.gateway
        if state.gateway_mac:
            entry["gateway_mac"] = state.gateway_mac
        if state.dns_servers:
            entry["dns_servers"] = list(state.dns_servers)
        networks[key] = entry
        return first_seen

    # -- events ------------------------------------------------------------
    def record_event(self, state: NetworkState, verdict: Verdict) -> None:
        events = self.data.setdefault("events", [])
        events.append(
            {
                "time": now_iso(),
                "network": state.label,
                "key": self.key_for(state),
                "level": verdict.level.value,
                "score": verdict.score,
            }
        )
        limit = int(self.config.history_limit)
        if len(events) > limit:
            del events[: len(events) - limit]

    def write_last_report(self, payload: Dict[str, Any]) -> None:
        ensure_dir(self.config.state_dir)
        try:
            self.config.last_report_file.write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
        except OSError:
            pass

    def save_all(self) -> None:
        self.save()
