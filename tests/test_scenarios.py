import unittest

from netguard.config import Config
from netguard.demo import SCENARIOS, get_scenario, run_scenario
from netguard.models import VerdictLevel

EXPECTED_VERDICTS = {
    "home-safe": VerdictLevel.SAFE,
    "cafe-open": VerdictLevel.CAUTION,
    "airport-captive": VerdictLevel.CAUTION,
    "hotel-mitm": VerdictLevel.UNSAFE,
    "corp-interception": VerdictLevel.CAUTION,
    "wired-office": VerdictLevel.SAFE,
}


class ScenarioTests(unittest.TestCase):
    def test_all_scenarios_have_expectations(self):
        self.assertEqual(set(SCENARIOS), set(EXPECTED_VERDICTS))

    def test_expected_verdicts(self):
        config = Config()
        for key, expected in EXPECTED_VERDICTS.items():
            with self.subTest(scenario=key):
                report = run_scenario(key, config)
                self.assertTrue(report.simulated)
                self.assertEqual(report.verdict.level, expected, f"{key}: {report.verdict.headline}")

    def test_hotel_has_critical_findings(self):
        report = run_scenario("hotel-mitm", Config())
        failing = [r.id for r in report.results if r.status.value == "fail"]
        self.assertIn("tls_interception", failing)
        self.assertIn("dns_integrity", failing)
        self.assertIn("evil_twin", failing)

    def test_unknown_scenario_raises(self):
        with self.assertRaises(KeyError):
            get_scenario("does-not-exist")

    def test_wifi_checks_skipped_on_wired(self):
        report = run_scenario("wired-office", Config())
        skipped = {r.id for r in report.results if r.status.value == "skip"}
        self.assertIn("wifi_encryption", skipped)
        self.assertIn("evil_twin", skipped)


if __name__ == "__main__":
    unittest.main()
