import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playwright.sync_api import sync_playwright

from server_test_support import load_server


class ReportBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_opening_hostile_report_makes_zero_network_requests(self):
        result_id = "P" * 32
        payload = '<img src="https://evil.invalid/beacon" onerror="fetch(\'https://evil.invalid/x\')">'
        document = {
            "schema_version": 1,
            "scanner": "trivy",
            "source_type": "filesystem",
            "target_ref": payload,
            "status": "success",
            "findings": [{"Title": payload, "Severity": "HIGH"}],
            "metadata": {},
        }
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            (results / f"{result_id}.json").write_text(json.dumps(document), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server.secrets, "token_urlsafe", return_value="Q" * 32),
            ):
                asyncio.run(self.server.generate_report(result_id))

            report_uri = (reports / f"{'Q' * 32}.html").as_uri()
            attempted_network = []
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.on(
                    "request",
                    lambda request: attempted_network.append(request.url)
                    if request.url.startswith(("http://", "https://", "ws://", "wss://"))
                    else None,
                )
                page.goto(report_uri)
                self.assertEqual("trivy report", page.locator("h1").inner_text())
                self.assertGreaterEqual(page.locator("table").count(), 3)
                self.assertEqual(0, page.locator("script,img,iframe,object,embed,link,base,form").count())
                browser.close()
            self.assertEqual([], attempted_network)

    def test_combined_report_has_zero_embedded_elements_and_no_network(self):
        payload = '<img src="https://evil.invalid/beacon" onerror="fetch(\'https://evil.invalid/x\')">'
        docs = [
            {"schema_version": 1, "scanner": "nmap", "target_ref": payload, "status": "success",
             "findings": [{"id": "p80", "Severity": "INFO", "Title": payload}], "metadata": {}},
            {"schema_version": 1, "scanner": "nuclei", "target_ref": "http://x", "status": "success",
             "findings": [{"VulnerabilityID": "CVE-9", "Severity": "HIGH", "Title": "RCE"}], "metadata": {}},
        ]
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            for index, doc in enumerate(docs):
                (results / f"{chr(65 + index) * 32}.json").write_text(json.dumps(doc), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server.secrets, "token_urlsafe", return_value="Q" * 32),
            ):
                asyncio.run(self.server.generate_report())

            report_uri = (reports / f"{'Q' * 32}.html").as_uri()
            attempted_network = []
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.on(
                    "request",
                    lambda request: attempted_network.append(request.url)
                    if request.url.startswith(("http://", "https://", "ws://", "wss://"))
                    else None,
                )
                page.goto(report_uri)
                self.assertEqual("Combined scan report", page.locator("h1").inner_text())
                self.assertEqual(0, page.locator("script,img,iframe,object,embed,link,base,form").count())
                browser.close()
            self.assertEqual([], attempted_network)


if __name__ == "__main__":
    unittest.main()
