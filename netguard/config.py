"""Runtime configuration for NetGuard.

Configuration is plain data with sensible defaults; an optional JSON file can
override any subset of fields (see :meth:`Config.load`).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


def _xdg_dir(env: str, fallback: str) -> Path:
    base = os.environ.get(env)
    if base:
        return Path(base)
    return Path(os.path.expanduser(fallback))


def _default_state_dir() -> Path:
    return _xdg_dir("XDG_STATE_HOME", "~/.local/state") / "netguard"


def _default_config_path() -> Path:
    return _xdg_dir("XDG_CONFIG_HOME", "~/.config") / "netguard" / "config.json"


@dataclass
class Config:
    # --- monitoring -------------------------------------------------------
    interval: float = 3.0        # seconds between polls of the network state
    settle: float = 2.5          # seconds to let a new link stabilise before probing
    use_dbus: bool = True        # use NetworkManager D-Bus signals if available
    notify: bool = True          # send desktop notifications
    notify_on_start: bool = True # notify that checks are being run

    # --- storage ----------------------------------------------------------
    state_dir: Path = field(default_factory=_default_state_dir)
    history_limit: int = 200

    # --- probe timeouts ---------------------------------------------------
    connect_timeout: float = 4.0
    http_timeout: float = 6.0
    tcp_timeout: float = 1.5
    dns_timeout: float = 4.0

    # --- check configuration ---------------------------------------------
    use_doh: bool = True
    doh_endpoints: List[str] = field(
        default_factory=lambda: [
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
        ]
    )
    dns_test_domains: List[str] = field(
        default_factory=lambda: ["example.com", "wikipedia.org", "github.com"]
    )
    tls_test_hosts: List[str] = field(
        default_factory=lambda: ["example.com", "www.google.com", "github.com"]
    )
    captive_portal_urls: List[str] = field(
        default_factory=lambda: [
            "http://connectivity-check.ubuntu.com/",
            "http://detectportal.firefox.com/success.txt",
        ]
    )
    http_probe_url: str = "http://neverssl.com/"
    router_ports: List[int] = field(
        default_factory=lambda: [22, 23, 53, 80, 443, 1900, 8080, 8443]
    )

    # --- heuristics -------------------------------------------------------
    # Security strings that mean "no encryption at all".
    open_security_tokens: List[str] = field(
        default_factory=lambda: ["", "--", "OPEN", "NONE", "NONE (OPEN)"]
    )
    # Weak/deprecated security markers worth flagging.
    weak_security_tokens: List[str] = field(
        default_factory=lambda: ["WEP", "WPA1", "TKIP"]
    )
    # SSIDs commonly used by public/hotspot networks (informational only).
    common_public_ssids: List[str] = field(
        default_factory=lambda: [
            "free wifi", "freewifi", "public wifi", "guest", "guest wifi",
            "airport", "hotel", "cafe", "coffee", "starbucks", "mcdonalds",
        ]
    )

    # ---------------------------------------------------------------------
    @property
    def history_file(self) -> Path:
        return self.state_dir / "history.json"

    @property
    def log_file(self) -> Path:
        return self.state_dir / "netguard.log"

    @property
    def last_report_file(self) -> Path:
        return self.state_dir / "last-report.json"

    def ensure_dirs(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        """Load defaults, optionally overlaying a JSON config file."""
        cfg = cls()
        cfg_path = Path(path) if path else _default_config_path()
        if cfg_path.exists():
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return cfg
            known = {f for f in cfg.__dataclass_fields__}
            for key, value in data.items():
                if key in known:
                    if key == "state_dir":
                        setattr(cfg, key, Path(value))
                    else:
                        setattr(cfg, key, value)
        return cfg

    def to_dict(self) -> dict:
        data = {}
        for key in self.__dataclass_fields__:
            value = getattr(self, key)
            data[key] = str(value) if isinstance(value, Path) else value
        return data
