import unittest

from netguard.models import NetworkState
from netguard.netstate import _parse_device_show

DEVICE_SHOW = "\n".join(
    [
        "GENERAL.HWADDR:2A:0C:03:F9:D2:77",
        "GENERAL.CONNECTION:Home",
        "IP4.ADDRESS[1]:192.168.1.5/24",
        "IP4.GATEWAY:192.168.1.1",
        "IP4.DNS[1]:192.168.1.1",
        "IP4.DNS[2]:1.1.1.1",
        "DHCP4.OPTION[1]:dhcp_server_identifier = 192.168.1.1",
    ]
)


class ParseDeviceShowTests(unittest.TestCase):
    def setUp(self):
        self.state = NetworkState()
        _parse_device_show(self.state, DEVICE_SHOW)

    def test_mac_recovered_with_colons(self):
        self.assertEqual(self.state.mac_address, "2A:0C:03:F9:D2:77")

    def test_connection_name(self):
        self.assertEqual(self.state.connection_name, "Home")

    def test_address_split(self):
        self.assertEqual(self.state.ip_address, "192.168.1.5")
        self.assertEqual(self.state.prefix, "24")

    def test_gateway(self):
        self.assertEqual(self.state.gateway, "192.168.1.1")

    def test_dns_list(self):
        self.assertEqual(self.state.dns_servers, ["192.168.1.1", "1.1.1.1"])

    def test_dhcp_server(self):
        self.assertEqual(self.state.dhcp_server, "192.168.1.1")


class SignatureTests(unittest.TestCase):
    def test_signature_changes_with_network(self):
        a = NetworkState(interface="wlan0", ssid="A", bssid="aa:aa:aa:aa:aa:aa")
        b = NetworkState(interface="wlan0", ssid="B", bssid="aa:aa:aa:aa:aa:aa")
        self.assertNotEqual(a.signature(), b.signature())

    def test_signature_is_stable(self):
        a = NetworkState(interface="wlan0", ssid="A", bssid="aa:aa:aa:aa:aa:aa")
        b = NetworkState(interface="wlan0", ssid="A", bssid="aa:aa:aa:aa:aa:aa")
        self.assertEqual(a.signature(), b.signature())


if __name__ == "__main__":
    unittest.main()
