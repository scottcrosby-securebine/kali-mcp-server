"""The mutation check's verdict must reject every run that proves nothing.

The check exists to prove an assertion pins behaviour. It only does that when
tests were collected, an ASSERTION failed, and nothing errored. Its previous two
versions read the runner's text (`grep -c '^FAILED ('`), which cannot separate
`FAILED (errors=1)` from `FAILED (failures=1)`, so an import error in the
mutated source was accepted as proof. These cases pin the separation.
"""
import importlib.util
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "mutation-check"
_spec = importlib.util.spec_from_loader("mutation_check", SourceFileLoader("mutation_check", str(SCRIPT)))
mutation_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mutation_check)

CAUGHT, SUITE_PASSED, INCONCLUSIVE = 0, 1, 2


class VerdictTests(unittest.TestCase):
    def verdict(self, tests_run, failures, errors):
        return mutation_check.verdict(tests_run, failures, errors, "BASE")

    def test_genuine_assertion_failure_is_the_only_accepted_proof(self):
        code, message = self.verdict(12, 3, 0)
        self.assertEqual(CAUGHT, code)
        self.assertIn("OK", message)

    def test_errors_only_run_is_rejected(self):
        # An unimportable mutated source: `Ran 1 test` + `FAILED (errors=1)`,
        # which is exactly what the old text-parsing gate accepted.
        code, message = self.verdict(1, 0, 1)
        self.assertEqual(INCONCLUSIVE, code)
        self.assertIn("ERROR(s)", message)

    def test_errors_alongside_failures_are_still_rejected(self):
        code, message = self.verdict(12, 3, 1)
        self.assertEqual(INCONCLUSIVE, code)
        self.assertIn("ERROR(s)", message)

    def test_zero_collected_run_is_rejected(self):
        code, message = self.verdict(0, 0, 0)
        self.assertEqual(INCONCLUSIVE, code)
        self.assertIn("collected 0 tests", message)

    def test_clean_run_is_rejected_as_a_failed_check(self):
        code, message = self.verdict(12, 0, 0)
        self.assertEqual(SUITE_PASSED, code)
        self.assertIn("pin nothing", message)

    def test_each_rejection_carries_a_distinguishable_message(self):
        messages = {self.verdict(*counts)[1] for counts in [(1, 0, 1), (0, 0, 0), (12, 0, 0)]}
        self.assertEqual(3, len(messages))


if __name__ == "__main__":
    unittest.main()
