import unittest

from netguard.checks.arp_gateway import ArpGatewayCheck
from netguard.checks.base import CheckContext
from netguard.checks.dns_integrity import DnsIntegrityCheck
from netguard.checks.encryption import EncryptionCheck
from netguard.checks.evil_twin import EvilTwinCheck
from netguard.checks.mac_randomization import MacRandomizationCheck
from netguard.checks.tls_interception import TLSInterceptionCheck
from netguard.config import Config
from netguard.models import AccessPoint, Neighbor, NetworkState, Severity, Status
from netguard.probe import HttpResponse, TLSPeer


class FakeProbes:
    """A Probes stand-in driven by simple callables."""

    def __init__(self, resolve=None, doh=None, tls=None, http=None, tcp=None):
        self.resolve = resolve or (lambda host: [])
        self.doh_resolve = doh or (lambda host: None)
        self.tls_peer = tls or (lambda host, port=443: TLSPeer(host=host, available=False))
        self.http_get = http or (
            lambda url, allow_redirects=False, timeout=None: HttpResponse(url=url, error="none")
        )
        self.tcp_open = tcp or (lambda host, port, timeout=None: False)


def make_ctx(state, probes=None, config=None):
    return CheckContext(
        state=state,
        probes=probes or FakeProbes(),
        config=config or Config(),
        history={},
        network_key="test-key",
    )


def wifi_state(**kwargs):
    base = dict(
        available=True, interface="wlan0", device_type="wifi",
        ssid="Net", bssid="aa:bb:cc:dd:ee:ff", security="WPA2",
    )
    base.update(kwargs)
    return NetworkState(**base)


def ethernet_state(**kwargs):
    base = dict(available=True, interface="enp3s0", device_type="ethernet")
    base.update(kwargs)
    return NetworkState(**base)


class EncryptionTests(unittest.TestCase):
    def test_open_fails(self):
        self.assertEqual(EncryptionCheck().run(make_ctx(wifi_state(security=""))).status, Status.FAIL)

    def test_wep_fails(self):
        self.assertEqual(EncryptionCheck().run(make_ctx(wifi_state(security="WEP"))).status, Status.FAIL)

    def test_wpa2_passes(self):
        self.assertEqual(EncryptionCheck().run(make_ctx(wifi_state(security="WPA2"))).status, Status.PASS)

    def test_wpa3_passes(self):
        self.assertEqual(EncryptionCheck().run(make_ctx(wifi_state(security="WPA3"))).status, Status.PASS)

    def test_wpa1_warns(self):
        self.assertEqual(EncryptionCheck().run(make_ctx(wifi_state(security="WPA1"))).status, Status.WARN)

    def test_wpa2_tkip_warns(self):
        self.assertEqual(
            EncryptionCheck().run(make_ctx(wifi_state(security="WPA2 TKIP"))).status, Status.WARN
        )

    def test_ethernet_skipped(self):
        self.assertEqual(EncryptionCheck().run(make_ctx(ethernet_state())).status, Status.SKIP)


class EvilTwinTests(unittest.TestCase):
    def test_mismatched_security_fails(self):
        state = wifi_state(
            security="",
            aps=[
                AccessPoint(ssid="Net", bssid="aa:bb:cc:dd:ee:ff", security="", active=True),
                AccessPoint(ssid="Net", bssid="11:22:33:44:55:66", security="WPA2"),
            ],
        )
        self.assertEqual(EvilTwinCheck().run(make_ctx(state)).status, Status.FAIL)

    def test_single_ap_passes(self):
        state = wifi_state(
            aps=[AccessPoint(ssid="Net", bssid="aa:bb:cc:dd:ee:ff", security="WPA2", active=True)]
        )
        self.assertEqual(EvilTwinCheck().run(make_ctx(state)).status, Status.PASS)

    def test_no_scan_data_skips(self):
        self.assertEqual(EvilTwinCheck().run(make_ctx(wifi_state(aps=[]))).status, Status.SKIP)


class ArpGatewayTests(unittest.TestCase):
    def test_gateway_mac_equals_host_mac(self):
        state = NetworkState(
            available=True, interface="wlan0", device_type="wifi",
            gateway="10.0.0.1", gateway_mac="de:ad:be:ef:00:01", mac_address="de:ad:be:ef:00:01",
            neighbors=[Neighbor(ip="10.0.0.1", mac="de:ad:be:ef:00:01")],
        )
        result = ArpGatewayCheck().run(make_ctx(state))
        self.assertEqual(result.status, Status.FAIL)
        self.assertEqual(result.severity, Severity.CRITICAL)

    def test_duplicate_mac_fails(self):
        state = NetworkState(
            available=True, interface="wlan0", device_type="wifi",
            gateway="10.0.0.1", gateway_mac="aa:aa:aa:aa:aa:aa", mac_address="bb:bb:bb:bb:bb:bb",
            neighbors=[
                Neighbor(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:aa"),
                Neighbor(ip="10.0.0.99", mac="aa:aa:aa:aa:aa:aa"),
            ],
        )
        self.assertEqual(ArpGatewayCheck().run(make_ctx(state)).status, Status.FAIL)

    def test_clean_gateway_passes(self):
        state = NetworkState(
            available=True, interface="wlan0", device_type="wifi",
            gateway="10.0.0.1", gateway_mac="aa:aa:aa:aa:aa:aa", mac_address="bb:bb:bb:bb:bb:bb",
            neighbors=[Neighbor(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:aa")],
        )
        self.assertEqual(ArpGatewayCheck().run(make_ctx(state)).status, Status.PASS)


class DnsIntegrityTests(unittest.TestCase):
    def test_hijack_detected(self):
        probes = FakeProbes(resolve=lambda host: ["1.2.3.4"])
        result = DnsIntegrityCheck().run(make_ctx(ethernet_state(dns_servers=["10.0.0.1"]), probes))
        self.assertEqual(result.status, Status.FAIL)
        self.assertEqual(result.severity, Severity.CRITICAL)

    def test_doh_unavailable_skips(self):
        probes = FakeProbes(resolve=lambda host: [], doh=lambda host: None)
        self.assertEqual(
            DnsIntegrityCheck().run(make_ctx(ethernet_state(), probes)).status, Status.SKIP
        )

    def test_mismatch_warns(self):
        # The random non-existent probe must NOT resolve; the test domains must.
        probes = FakeProbes(
            resolve=lambda host: [] if host.startswith("nx-") else ["10.0.0.5"],
            doh=lambda host: ["93.184.216.34"],
        )
        self.assertEqual(
            DnsIntegrityCheck().run(make_ctx(ethernet_state(), probes)).status, Status.WARN
        )


class TlsInterceptionTests(unittest.TestCase):
    def test_untrusted_private_issuer_fails(self):
        probes = FakeProbes(
            tls=lambda host, port=443: TLSPeer(
                host=host, available=True, validated=False,
                issuer="CN=Evil Proxy CA, O=Evil", issuer_org="Evil",
            )
        )
        result = TLSInterceptionCheck().run(make_ctx(ethernet_state(), probes))
        self.assertEqual(result.status, Status.FAIL)
        self.assertEqual(result.severity, Severity.CRITICAL)

    def test_validated_public_passes(self):
        probes = FakeProbes(
            tls=lambda host, port=443: TLSPeer(
                host=host, available=True, validated=True,
                issuer="O=DigiCert Inc, CN=DigiCert", issuer_org="DigiCert Inc",
            )
        )
        self.assertEqual(TLSInterceptionCheck().run(make_ctx(ethernet_state(), probes)).status, Status.PASS)

    def test_validated_private_issuer_warns(self):
        probes = FakeProbes(
            tls=lambda host, port=443: TLSPeer(
                host=host, available=True, validated=True,
                issuer="O=Example Corp, CN=Corp Root CA", issuer_org="Example Corp",
            )
        )
        self.assertEqual(TLSInterceptionCheck().run(make_ctx(ethernet_state(), probes)).status, Status.WARN)

    def test_no_handshake_skips(self):
        self.assertEqual(
            TLSInterceptionCheck().run(make_ctx(ethernet_state(), FakeProbes())).status, Status.SKIP
        )


class MacRandomizationTests(unittest.TestCase):
    def test_random_passes(self):
        self.assertEqual(
            MacRandomizationCheck().run(make_ctx(wifi_state(mac_randomization="random"))).status,
            Status.PASS,
        )

    def test_permanent_warns(self):
        self.assertEqual(
            MacRandomizationCheck().run(make_ctx(wifi_state(mac_randomization="permanent"))).status,
            Status.WARN,
        )

    def test_ethernet_skipped(self):
        self.assertEqual(
            MacRandomizationCheck().run(make_ctx(ethernet_state())).status, Status.SKIP
        )


if __name__ == "__main__":
    unittest.main()
