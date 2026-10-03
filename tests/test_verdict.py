import unittest

from netguard.models import CheckResult, Severity, Status, VerdictLevel
from netguard.verdict import compute_score, level_for, verdict_for


def result(status, severity, check_id="check"):
    return CheckResult(id=check_id, title=check_id, status=status, summary="summary", severity=severity)


class ScoreTests(unittest.TestCase):
    def test_all_pass_is_perfect(self):
        results = [result(Status.PASS, Severity.HIGH) for _ in range(5)]
        self.assertEqual(compute_score(results), 100)

    def test_skip_and_info_do_not_count(self):
        results = [result(Status.SKIP, Severity.CRITICAL), result(Status.INFO, Severity.HIGH)]
        self.assertEqual(compute_score(results), 100)

    def test_fail_penalty_scales_with_severity(self):
        low = compute_score([result(Status.FAIL, Severity.LOW)])
        high = compute_score([result(Status.FAIL, Severity.HIGH)])
        self.assertGreater(low, high)

    def test_score_clamped_at_zero(self):
        results = [result(Status.FAIL, Severity.CRITICAL) for _ in range(5)]
        self.assertEqual(compute_score(results), 0)


class LevelTests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(level_for(100), VerdictLevel.SAFE)
        self.assertEqual(level_for(80), VerdictLevel.SAFE)
        self.assertEqual(level_for(79), VerdictLevel.CAUTION)
        self.assertEqual(level_for(45), VerdictLevel.CAUTION)
        self.assertEqual(level_for(44), VerdictLevel.UNSAFE)


class VerdictTests(unittest.TestCase):
    def test_empty_is_unknown(self):
        self.assertEqual(verdict_for([]).level, VerdictLevel.UNKNOWN)

    def test_critical_fail_caps_to_unsafe(self):
        results = [result(Status.PASS, Severity.HIGH) for _ in range(9)]
        results.append(result(Status.FAIL, Severity.CRITICAL, "mitm"))
        verdict = verdict_for(results)
        self.assertEqual(verdict.level, VerdictLevel.UNSAFE)
        self.assertLessEqual(verdict.score, 25)

    def test_high_fail_caps_to_caution(self):
        verdict = verdict_for([result(Status.FAIL, Severity.HIGH)])
        self.assertEqual(verdict.level, VerdictLevel.CAUTION)
        self.assertLessEqual(verdict.score, 55)

    def test_warn_only_stays_safe(self):
        self.assertEqual(verdict_for([result(Status.WARN, Severity.LOW)]).level, VerdictLevel.SAFE)

    def test_reasons_are_ordered_by_severity(self):
        results = [
            result(Status.WARN, Severity.LOW, "low"),
            result(Status.FAIL, Severity.CRITICAL, "critical"),
            result(Status.FAIL, Severity.MEDIUM, "medium"),
        ]
        verdict = verdict_for(results)
        self.assertEqual(verdict.reasons[0], "summary")
        self.assertEqual(verdict.counts["fail"], 2)
        self.assertEqual(verdict.counts["warn"], 1)


if __name__ == "__main__":
    unittest.main()
