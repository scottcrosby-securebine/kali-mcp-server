"""Row 19: #28 (findings carry remediation and references) + #24-INFO
(the Remediation line is suppressed on informational findings that have none).

The render layer already promoted Remediation/References when a finding carried
them; row 19 makes the parsers populate them (nikto See: URL and missing-header
fix, nuclei's nested info.reference/info.remediation, TLS weak-protocol/cipher
canonical fixes) and stops the renderer printing "Remediation: Not reported" on
bare INFO findings while keeping it on actionable ones so genuinely missing
guidance still surfaces.
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


def _doc(findings, scanner="nikto"):
    return {
        "schema_version": 1, "scanner": scanner, "target_ref": "h",
        "status": "success", "findings": findings, "metadata": {},
    }


def _article_for(report, title):
    """The one <article> whose body contains `title`."""
    for chunk in report.split("<article>")[1:]:
        body = chunk.split("</article>")[0]
        if title in body:
            return body
    raise AssertionError(f"no article for {title!r}")


class InfoRemediationLineIsSuppressed(unittest.TestCase):
    """#24-INFO: an INFO finding with nothing to remediate shows no Remediation
    line; an actionable finding without one still shows 'Not reported'."""

    def setUp(self):
        self.server, _ = load_server()

    def test_info_without_remediation_drops_the_line(self):
        art = _article_for(self.server._render_report(
            _doc([{"id": "i1", "Severity": "INFO", "Title": "INFONOREM"}])), "INFONOREM")
        self.assertNotIn("Remediation:", art)

    def test_info_with_remediation_keeps_the_line(self):
        art = _article_for(self.server._render_report(
            _doc([{"id": "i2", "Severity": "INFO", "Title": "INFOREM",
                   "remediation": "rotate the key"}])), "INFOREM")
        self.assertIn("Remediation:", art)
        self.assertIn("rotate the key", art)

    def test_actionable_without_remediation_still_says_not_reported(self):
        # A MEDIUM/HIGH/CRITICAL with no guidance must NOT be silently blanked:
        # missing remediation on a real finding is itself a signal.
        for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            with self.subTest(sev=sev):
                art = _article_for(self.server._render_report(
                    _doc([{"id": "x", "Severity": sev, "Title": f"ACT{sev}"}])), f"ACT{sev}")
                self.assertIn("Remediation:", art)
                self.assertIn("Not reported", art)


class NiktoPromotesReferenceAndHeaderFix(unittest.TestCase):
    """#28: the See: URL reaches the reference slot and the missing-header class
    gets its canonical one-line fix; unrelated findings get neither."""

    def setUp(self):
        self.server, _ = load_server()

    def test_missing_header_gets_reference_and_remediation(self):
        findings = self.server._parse_nikto_json(
            '{"vulnerabilities":[{"OSVDB":"0",'
            '"msg":"Suggested security header missing: content-security-policy.",'
            '"url":"/","references":"https://developer.mozilla.org/CSP"}]}')
        self.assertEqual(1, len(findings))
        self.assertEqual("https://developer.mozilla.org/CSP", findings[0].get("reference"))
        self.assertIn("security header", findings[0].get("remediation", ""))

    def test_a_non_header_finding_carries_no_invented_guidance(self):
        findings = self.server._parse_nikto_json(
            '{"vulnerabilities":[{"OSVDB":"12345",'
            '"msg":"Server leaks inodes via ETags","url":"/x"}]}')
        self.assertEqual(1, len(findings))
        self.assertNotIn("remediation", findings[0])
        self.assertNotIn("reference", findings[0])

    def test_the_promoted_reference_renders(self):
        report = self.server._render_report(_doc(self.server._parse_nikto_json(
            '{"vulnerabilities":[{"OSVDB":"0",'
            '"msg":"Suggested security header missing: x-frame-options.",'
            '"url":"/","references":"https://example.test/xfo"}]}')))
        self.assertIn("https://example.test/xfo", report)


class NucleiPromotesTemplateRemediationAndReference(unittest.TestCase):
    """#28: nuclei's nested info.remediation / info.reference are lifted to the
    top-level slots the report reads."""

    def setUp(self):
        self.server, _ = load_server()

    def _capture_normalized(self):
        captured = {}
        outcome = {"summary": "1 finding", "findings": [{
            "template-id": "CVE-2021-1", "matched-at": "http://x/",
            "info": {"name": "Example RCE", "severity": "high",
                     "remediation": "Apply vendor patch 1.2.3",
                     "reference": ["https://nvd.example/CVE-2021-1"]},
        }]}

        def _grab(document):
            captured["doc"] = document
            return "/results/x.json"

        with (
            patch.object(self.server, "_nuclei_template_match", return_value=(3, 3)),
            patch.object(self.server, "_run_nuclei_capture", return_value=outcome),
            patch.object(self.server, "_nuclei_report_versions", return_value={}),
            patch.object(self.server, "_write_scanner_result", side_effect=_grab),
        ):
            asyncio.run(self.server.nuclei_scan("example.test"))
        return captured["doc"]["findings"][0]

    def test_remediation_and_reference_are_promoted(self):
        entry = self._capture_normalized()
        self.assertEqual("Apply vendor patch 1.2.3", entry.get("remediation"))
        self.assertEqual(["https://nvd.example/CVE-2021-1"], entry.get("reference"))

    def test_the_promoted_fields_render(self):
        entry = self._capture_normalized()
        report = self.server._render_report(_doc([entry], scanner="nuclei"))
        self.assertIn("Apply vendor patch 1.2.3", report)
        self.assertIn("https://nvd.example/CVE-2021-1", report)


class SslscanCarriesCanonicalTlsRemediation(unittest.TestCase):
    """#28: weak protocols and weak ciphers get the standard hardening fix; a
    strong accepted cipher does not."""

    def setUp(self):
        self.server, _ = load_server()

    def _parse(self):
        xml = (
            '<document><ssltest>'
            '<protocol type="ssl" version="3" enabled="1"/>'
            '<cipher status="accepted" cipher="RC4-MD5" sslversion="TLSv1.0" bits="128"/>'
            '<cipher status="accepted" cipher="ECDHE-RSA-AES256-GCM-SHA384" sslversion="TLSv1.2" bits="256"/>'
            '</ssltest></document>')
        return {f["Title"]: f for f in self.server._parse_sslscan_xml(xml)}

    def test_weak_protocol_gets_remediation(self):
        f = self._parse()["Weak protocol enabled: SSLv3"]
        self.assertIn("TLS 1.2", f.get("remediation", ""))

    def test_weak_cipher_gets_remediation(self):
        f = self._parse()["Accepted cipher: RC4-MD5"]
        self.assertIn("weak ciphers", f.get("remediation", ""))

    def test_strong_cipher_gets_no_remediation(self):
        f = self._parse()["Accepted cipher: ECDHE-RSA-AES256-GCM-SHA384"]
        self.assertNotIn("remediation", f)


if __name__ == "__main__":
    unittest.main()
