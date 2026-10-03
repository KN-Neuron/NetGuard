import unittest

from netguard.util import human_duration, is_mac, normalize_mac, split_terse


class SplitTerseTests(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(split_terse("a:b:c"), ["a", "b", "c"])

    def test_empty_fields(self):
        self.assertEqual(split_terse("no:SSID::80:6"), ["no", "SSID", "", "80", "6"])

    def test_escaped_colons(self):
        self.assertEqual(
            split_terse(r"GENERAL.HWADDR:AA\:BB\:CC"),
            ["GENERAL.HWADDR", "AA:BB:CC"],
        )

    def test_unescaped_colons(self):
        self.assertEqual(
            split_terse("GENERAL.HWADDR:2A:0C:03:F9:D2:77"),
            ["GENERAL.HWADDR", "2A", "0C", "03", "F9", "D2", "77"],
        )

    def test_escaped_backslash(self):
        self.assertEqual(split_terse(r"a\\b:c"), ["a\\b", "c"])


class MacHelperTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(is_mac("AA:BB:CC:DD:EE:FF"))
        self.assertTrue(is_mac("aa-bb-cc-dd-ee-ff"))

    def test_invalid(self):
        self.assertFalse(is_mac(""))
        self.assertFalse(is_mac("not-a-mac"))

    def test_normalize(self):
        self.assertEqual(normalize_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")


class DurationTests(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(human_duration(5), "5s")
        self.assertEqual(human_duration(65), "1m05s")
        self.assertEqual(human_duration(3661), "1h01m")


if __name__ == "__main__":
    unittest.main()
