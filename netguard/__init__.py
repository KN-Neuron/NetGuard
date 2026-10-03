"""NetGuard - network-change security posture monitor for Linux.

NetGuard watches for network changes (Wi-Fi association, gateway/DNS changes,
VPN up/down) and, whenever the network changes, runs a battery of passive and
active posture checks against the new network. It then renders a plain-language
verdict (SAFE / CAUTION / UNSAFE) and notifies the user through the desktop
notification daemon.

The whole tool is intentionally dependency-free: it only uses the Python
standard library plus utilities that ship with a normal Linux desktop
(nmcli, ip, iw, resolvectl, openssl, notify-send).
"""

__version__ = "1.0.0"
APP_NAME = "NetGuard"
APP_ID = "netguard"

__all__ = ["__version__", "APP_NAME", "APP_ID"]
