"""#44 and #46: one scheme predicate, and a wpscan flag that wpscan accepts.

#44 as filed names five case-sensitive sites. There were nine, and they carried
two distinct defects:

  CASE       `startswith("http://")` missed `HTTP://host`, so a second scheme was
             glued on: `http://HTTP://host`.
  PRECISION  five sites tested `startswith("http")` with no `://`, so a bare host
             named `httpfoo.example` counted as already-schemed and reached the
             tool with no scheme at all.

Both are now one predicate. The coverage test reads the source, so a tenth site
spelled by hand fails here rather than shipping.

#46 rides along because its line sits inside `wpscan_scan`, one of the nine.
"""
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


class TheSchemePredicate(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def test_an_uppercase_scheme_counts_as_already_schemed(self):
        for target in ("HTTP://host", "HTTPS://host", "HtTp://host"):
            with self.subTest(target=target):
                self.assertTrue(self.server.has_web_scheme(target))
                self.assertEqual(target, self.server.with_web_scheme(target))

    def test_a_host_merely_starting_with_http_is_not_schemed(self):
        # The precision half: `startswith("http")` called this already-schemed.
        for target in ("httpfoo.example", "https-host.example", "http.example"):
            with self.subTest(target=target):
                self.assertFalse(self.server.has_web_scheme(target))
                self.assertEqual(f"http://{target}", self.server.with_web_scheme(target))

    def test_a_bare_host_gets_one_scheme_and_only_one(self):
        self.assertEqual("http://host", self.server.with_web_scheme("host"))
        self.assertEqual(
            "http://host", self.server.with_web_scheme(self.server.with_web_scheme("host"))
        )

    def test_a_callers_https_is_never_downgraded(self):
        self.assertEqual("https://host", self.server.with_web_scheme("https://host"))

    def test_only_http_and_https_count_as_a_web_scheme(self):
        # Testing for "://" anywhere would admit these, and the launcher runs
        # --network=host. This is why the predicate is a fixed tuple.
        for target in ("file:///etc/passwd", "gopher://host", "telnet://host"):
            with self.subTest(target=target):
                self.assertFalse(self.server.has_web_scheme(target))


class NoToolSpellsItsOwnSchemeTest(unittest.TestCase):
    """The drift guard. Nine hand-written tests drifted two ways; a tenth would
    drift a third. Read the source, not a copy of the site list."""

    # The two helper bodies ARE the one spelling, so they are the only lines
    # allowed to test a scheme directly. Matched narrowly, on the whole line, so
    # that an imprecise `return target.lower().startswith("http")` would not
    # slip through this exemption.
    CANONICAL = {
        'return target.lower().startswith(WEB_SCHEMES)',
        'return target.lower().startswith("https://")',
    }

    def test_no_hand_written_scheme_test_remains(self):
        source = (REPO / "kali_pentest_server.py").read_text(encoding="utf-8")
        offenders = []
        canonical_seen = 0
        for number, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("- "):
                continue  # prose, including this fix's own docstring
            if stripped in self.CANONICAL:
                canonical_seen += 1
                continue
            if re.search(r'\.startswith\(\s*["\']http|startswith\(WEB_SCHEMES', stripped):
                offenders.append(f"{number}: {stripped}")
        self.assertEqual(
            [],
            offenders,
            "a scheme test was spelled by hand again; call has_web_scheme()",
        )
        # And the exemption cannot hollow the test out: both helpers must exist.
        self.assertEqual(2, canonical_seen, "a scheme helper body changed shape")

    def test_the_predicate_is_actually_used_by_the_tools(self):
        # Guards the opposite failure: a helper nobody calls proves nothing.
        source = (REPO / "kali_pentest_server.py").read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("with_web_scheme("), 9)


class WpscanArgumentIsValid(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def test_plugins_detection_uses_a_value_wpscan_accepts(self):
        # wpscan aborts during argument parsing on anything else, so the tool
        # never ran against any target regardless of what was passed to it.
        source = (REPO / "kali_pentest_server.py").read_text(encoding="utf-8")
        match = re.search(r'"--plugins-detection",\s*"([a-z]+)"', source)
        self.assertIsNotNone(match, "the wpscan flag moved; update this test")
        self.assertIn(match.group(1), {"mixed", "passive", "aggressive"})

    def test_the_invalid_value_is_gone(self):
        source = (REPO / "kali_pentest_server.py").read_text(encoding="utf-8")
        self.assertNotIn('"popular"', source)


if __name__ == "__main__":
    unittest.main()
