"""Simulated network scenarios for demos, tests and training.

The simulator swaps only the *probe* layer: the real check logic, scoring,
verdict, notifications and reports all run unchanged, so demonstrations
exercise the exact same code path as a live capture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import AccessPoint, Neighbor, NetworkState
from .probe import HttpResponse, Probes, TLSPeer

TLS_HOSTS = ("example.com", "www.google.com", "github.com")
CAPTIVE_UBUNTU = "http://connectivity-check.ubuntu.com/"
CAPTIVE_FIREFOX = "http://detectportal.firefox.com/success.txt"
HTTP_PROBE = "http://neverssl.com/"
NONEXISTENT_FALLBACK = "127.0.0.1"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
def _ap(ssid: str, bssid: str, security: str, signal: int = 72, active: bool = False) -> AccessPoint:
    return AccessPoint(ssid=ssid, bssid=bssid, security=security, signal=signal,
                       channel="6", active=active)


def _neighbor(ip: str, mac: str, interface: str = "wlan0") -> Neighbor:
    return Neighbor(ip=ip, mac=mac, interface=interface, state="REACHABLE")


def _http(status: int = 200, body: str = "", location: str = "",
          headers: Optional[dict] = None, url: str = "") -> HttpResponse:
    response = HttpResponse(url=url, status=status, body=body, location=location,
                            ok=True, final_url=url or location)
    response.headers = {k.lower(): v for k, v in (headers or {}).items()}
    return response


def _tls(host: str, validated: bool = True,
         issuer: str = "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
         subject: str = "", issuer_org: str = "DigiCert Inc") -> TLSPeer:
    return TLSPeer(host=host, available=True, validated=validated, subject=subject or f"CN={host}",
                   issuer=issuer, issuer_org=issuer_org, not_after="Aug 1 2027")


def _tls_ok() -> Dict[str, TLSPeer]:
    return {host: _tls(host) for host in TLS_HOSTS}


def _http_ok() -> Dict[str, HttpResponse]:
    return {
        CAPTIVE_UBUNTU: _http(204, url=CAPTIVE_UBUNTU),
        CAPTIVE_FIREFOX: _http(200, body="success", url=CAPTIVE_FIREFOX),
        HTTP_PROBE: _http(200, body="<html>NeverSSL</html>", url=HTTP_PROBE),
    }


def _http_portal(portal: str, probes: Tuple[str, ...] = (CAPTIVE_UBUNTU, CAPTIVE_FIREFOX, HTTP_PROBE)) -> Dict[str, HttpResponse]:
    return {url: _http(302, location=portal, url=url) for url in probes}


def _dns_ok() -> Dict[str, List[str]]:
    return {
        "example.com": ["93.184.216.34"],
        "wikipedia.org": ["208.80.154.224"],
        "github.com": ["140.82.121.4"],
    }


def _wifi_state(name: str, ssid: str, bssid: str, security: str, gateway: str,
                gateway_mac: str, dns: List[str], ip: str = "10.0.0.42",
                mac_mode: str = "permanent", aps: Optional[List[AccessPoint]] = None,
                neighbors: Optional[List[Neighbor]] = None) -> NetworkState:
    return NetworkState(
        available=True, interface="wlan0", device_type="wifi",
        connection_name=name, ssid=ssid, bssid=bssid, security=security,
        ip_address=ip, prefix="24", gateway=gateway, gateway_mac=gateway_mac,
        dns_servers=list(dns), mac_address="de:ad:be:ef:00:01",
        mac_randomization=mac_mode,
        aps=aps if aps is not None else [_ap(ssid, bssid, security, active=True)],
        neighbors=neighbors if neighbors is not None else [_neighbor(gateway, gateway_mac)],
        tools={"nmcli": True, "ip": True, "iw": True, "resolvectl": True, "openssl": True},
    )


# ---------------------------------------------------------------------------
# Scenario model + simulated probe layer
# ---------------------------------------------------------------------------
@dataclass
class Scenario:
    key: str
    name: str
    summary: str
    state: NetworkState
    dns_system: Dict[str, List[str]] = field(default_factory=dict)
    dns_doh: Optional[Dict[str, List[str]]] = field(default_factory=dict)
    dns_always_answers: bool = False
    tls: Dict[str, TLSPeer] = field(default_factory=dict)
    http: Dict[str, HttpResponse] = field(default_factory=dict)
    tcp: Dict[Tuple[str, int], bool] = field(default_factory=dict)


class SimulatedProbes(Probes):
    """A Probes implementation that answers from a Scenario definition."""

    def __init__(self, scenario: Scenario, config) -> None:
        super().__init__(config)
        self.scenario = scenario

    def resolve(self, host: str) -> List[str]:
        if self.scenario.dns_always_answers:
            return [NONEXISTENT_FALLBACK]
        return list(self.scenario.dns_system.get(host, []))

    def doh_resolve(self, host: str) -> Optional[List[str]]:
        if self.scenario.dns_doh is None:
            return None
        return list(self.scenario.dns_doh.get(host, []))

    def tls_peer(self, host: str, port: int = 443) -> TLSPeer:
        return self.scenario.tls.get(host, TLSPeer(host=host, available=False,
                                                   error="simulated: no data"))

    def http_get(self, url: str, allow_redirects: bool = False, timeout: Optional[float] = None) -> HttpResponse:
        return self.scenario.http.get(url, HttpResponse(url=url, error="simulated: no data"))

    def tcp_open(self, host: str, port: int, timeout: Optional[float] = None) -> bool:
        return bool(self.scenario.tcp.get((host, port), False))


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------
def _scenario_home() -> Scenario:
    gw = "192.168.1.1"
    return Scenario(
        key="home-safe",
        name="Home network (WPA3)",
        summary="A well-configured home network: WPA3, no interception, consistent DNS.",
        state=_wifi_state("HomeWiFi-5G", "HomeWiFi-5G", "a4:2b:b0:11:22:33", "WPA3",
                          gw, "a4:2b:b0:11:22:33", [gw], ip="192.168.1.24", mac_mode="random"),
        dns_system=_dns_ok(), dns_doh=_dns_ok(), tls=_tls_ok(), http=_http_ok(),
        tcp={("1.1.1.1", 443): True, (gw, 80): True, (gw, 443): True},
    )


def _scenario_cafe() -> Scenario:
    gw = "10.0.5.1"
    return Scenario(
        key="cafe-open",
        name="Café open Wi-Fi with captive portal",
        summary="An unencrypted hotspot behind a captive portal — common and risky, not malicious.",
        state=_wifi_state("Cafe_Free_WiFi", "Cafe_Free_WiFi", "00:11:22:33:44:55", "",
                          gw, "00:11:22:33:44:55", [gw], ip="10.0.5.42", mac_mode="permanent"),
        dns_system=_dns_ok(), dns_doh=_dns_ok(), tls=_tls_ok(),
        http=_http_portal("http://portal.cafe.local/login"),
        tcp={("1.1.1.1", 443): True, (gw, 80): True},
    )


def _scenario_airport() -> Scenario:
    gw = "172.16.9.1"
    return Scenario(
        key="airport-captive",
        name="Airport Wi-Fi with portal and UPnP",
        summary="Open airport network with a captive portal and UPnP exposed on the gateway.",
        state=_wifi_state("Airport_WiFi", "Airport_WiFi", "5c:5b:35:aa:bb:cc", "",
                          gw, "5c:5b:35:aa:bb:cc", [gw], ip="172.16.9.77", mac_mode="permanent"),
        dns_system=_dns_ok(), dns_doh=_dns_ok(), tls=_tls_ok(),
        http=_http_portal("http://wifi.airport.example/login"),
        tcp={("1.1.1.1", 443): True, (gw, 80): True, (gw, 1900): True},
    )


def _scenario_hotel() -> Scenario:
    gw = "10.20.30.1"
    bssid = "aa:bb:cc:11:22:33"
    rogue = _ap("GrandHotel_Guest", bssid, "", active=True)
    twin = _ap("GrandHotel_Guest", "66:77:88:99:aa:bb", "WPA2", signal=55)
    return Scenario(
        key="hotel-mitm",
        name="Compromised hotel network (active MITM)",
        summary="Open SSID, an evil twin, hijacked DNS and a TLS interception proxy.",
        state=_wifi_state("GrandHotel_Guest", "GrandHotel_Guest", bssid, "", gw,
                          "aa:bb:cc:11:22:33", [gw], ip="10.20.30.42",
                          mac_mode="permanent", aps=[rogue, twin]),
        dns_system=_dns_ok(), dns_doh=_dns_ok(), dns_always_answers=True,
        tls={host: _tls(host, validated=False,
                        issuer="C=XX, O=Grand Hotel Surveillance, CN=Hotel Proxy CA",
                        issuer_org="Grand Hotel Surveillance") for host in TLS_HOSTS},
        http=_http_portal("http://10.20.30.1/login"),
        tcp={("1.1.1.1", 443): True, (gw, 80): True, (gw, 443): True},
    )


def _scenario_corp() -> Scenario:
    gw = "10.0.0.1"
    internal = "10.0.0.53"
    return Scenario(
        key="corp-interception",
        name="Corporate network with TLS inspection",
        summary="WPA2-Enterprise with a managed TLS interception proxy and split-horizon DNS.",
        state=_wifi_state("Corp-Secure", "Corp-Secure", "de:ad:00:11:22:33", "WPA2 802.1X",
                          gw, "de:ad:00:11:22:33", [internal], ip="10.0.0.42", mac_mode="random"),
        dns_system={d: [internal] for d in _dns_ok()},
        dns_doh=_dns_ok(),
        tls={host: _tls(host, validated=True,
                        issuer="C=US, O=Example Corp, CN=Corp Root CA",
                        issuer_org="Example Corp") for host in TLS_HOSTS},
        http=_http_ok(),
        tcp={("1.1.1.1", 443): True, (gw, 443): True},
    )


def _scenario_office() -> Scenario:
    gw = "192.168.10.1"
    return Scenario(
        key="wired-office",
        name="Wired office network",
        summary="A conventional wired connection — Wi-Fi-only checks are skipped by design.",
        state=NetworkState(
            available=True, interface="enp3s0", device_type="ethernet",
            connection_name="Wired connection 1", ip_address="192.168.10.20", prefix="24",
            gateway=gw, gateway_mac="b8:27:eb:00:11:22",
            dns_servers=[gw], mac_address="3c:7c:3f:00:aa:bb",
            neighbors=[_neighbor(gw, "b8:27:eb:00:11:22", "enp3s0")],
            tools={"nmcli": True, "ip": True, "iw": True, "resolvectl": True, "openssl": True},
        ),
        dns_system=_dns_ok(), dns_doh=_dns_ok(), tls=_tls_ok(), http=_http_ok(),
        tcp={("1.1.1.1", 443): True, (gw, 80): True, (gw, 443): True},
    )


SCENARIOS: Dict[str, Scenario] = {
    s.key: s
    for s in (
        _scenario_home(),
        _scenario_cafe(),
        _scenario_airport(),
        _scenario_hotel(),
        _scenario_corp(),
        _scenario_office(),
    )
}


def list_scenarios() -> List[Scenario]:
    return list(SCENARIOS.values())


def get_scenario(key: str) -> Scenario:
    if key not in SCENARIOS:
        raise KeyError(f"unknown scenario '{key}'. Available: {', '.join(SCENARIOS)}")
    return SCENARIOS[key]


def run_scenario(key: str, config, store=None):
    """Run the real engine against a simulated scenario."""
    from .engine import run_checks

    scenario = get_scenario(key)
    probes = SimulatedProbes(scenario, config)
    return run_checks(scenario.state, config, probes=probes, store=store, simulated=True)
