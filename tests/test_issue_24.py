"""#24: report tool versions must resolve for the names callers actually pass.

`_tool_version_metadata` keyed its package map on tool-FUNCTION names
("whatweb_scan"), but `_capture_findings` and the single-ref report path both
pass the SCANNER label a result is stored under ("whatweb"). So the map resolved
for trivy/syft/oletools and returned {} for every other scanner, on both report
paths, not only the combined one the issue describes.

The coverage test is the one that matters: it derives the scanner list from the
same filter `generate_report` uses, so adding a scanner without a package fails
here instead of silently rendering "Not reported".
"""
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


def _scanners_generate_report_accepts():
    """The scanner set from the source, not a hand-kept copy of it.

    A second list here would drift from the filter the way the terminator set
    drifted four times in #27, and this test would then pass while the report
    it guards rendered "Not reported".
    """
    source = (REPO / "kali_pentest_server.py").read_text(encoding="utf-8")
    match = re.search(r'document\.get\("scanner"\) not in \{([^}]*)\}', source)
    assert match, "the generate_report scanner filter moved; update this reader"
    return set(re.findall(r'"([a-z_0-9]+)"', match.group(1)))


class ScannerNamesResolveToVersions(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def test_every_scanner_the_report_accepts_has_a_package_version(self):
        scanners = _scanners_generate_report_accepts()
        self.assertGreater(len(scanners), 20, "the filter reader matched too little")
        unresolved = {}
        for scanner in sorted(scanners):
            metadata = self.server._tool_version_metadata([scanner])
            if not metadata or "Not available" in metadata.values():
                unresolved[scanner] = metadata
        self.assertEqual({}, unresolved)

    def test_the_scanner_label_is_what_the_capture_path_passes(self):
        # Pins the actual defect: these are scanner labels, not function names.
        self.assertEqual(
            {"whatweb_version": "0.6.4-1"},
            self.server._tool_version_metadata(["whatweb"]),
        )

    def test_a_target_suffixed_scanner_label_still_resolves(self):
        # Results are keyed "scanner:target" in places; the split on ":" must
        # keep working now that the keys are scanner names.
        self.assertEqual(
            {"nikto_version": "1:2.6.1-0kali1"},
            self.server._tool_version_metadata(["nikto:example.test:443"]),
        )

    def test_the_tool_function_spellings_still_resolve(self):
        # Kept deliberately. Dropping them would silently empty any caller that
        # does pass one.
        self.assertEqual(
            {"whatweb_scan_version": "0.6.4-1"},
            self.server._tool_version_metadata(["whatweb_scan"]),
        )

    def test_an_unknown_name_contributes_nothing(self):
        self.assertEqual({}, self.server._tool_version_metadata(["not_a_scanner"]))


if __name__ == "__main__":
    unittest.main()
