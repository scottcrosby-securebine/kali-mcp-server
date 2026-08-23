"""Behavior tests for the bounded Nuclei adapter and web audit integration."""

import asyncio
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server_test_support import load_server


class NucleiAdapterTests(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def test_default_scan_uses_only_the_promoted_subset_and_fixed_safety_bounds(self):
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(self.server, "execute_command", return_value=completed) as run:
            result = asyncio.run(self.server.nuclei_scan("https://example.test"))

        self.assertIn("completed", result)
        self.assertEqual(self.server.TIMEOUT_LONG, run.call_args.kwargs["timeout"])
        self.assertEqual(
            [
                "nuclei",
                "-u", "https://example.test",
                "-t", str(self.server.NUCLEI_PROMOTED_ROOT),
                "-s", "critical,high",
                "-rl", "10",
                "-c", "5",
                "-ni",
                "-duc",
                "-ept", "code,javascript,headless,file,workflow",
                "-fuzz=false",
                "-dast=false",
                "-cup=false",
                "-dashboard=false",
                "-auth=false",
                "-no-stdin",
                "-jsonl",
                "-omit-template",
            ],
            run.call_args.args[0],
        )

    def test_templates_and_severities_are_validated_before_execution(self):
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            approved = root / "CVE-2021-41773.yaml"
            approved.write_text("id: CVE-2021-41773\n", encoding="utf-8")
            completed = SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch.object(self.server, "NUCLEI_PROMOTED_ROOT", root), patch.object(
                self.server, "execute_command", return_value=completed
            ) as run:
                result = asyncio.run(
                    self.server.nuclei_scan(
                        "https://example.test", "CVE-2021-41773", "critical,medium"
                    )
                )
                self.assertIn("completed", result)
                command = run.call_args.args[0]
                self.assertEqual(str(approved), command[command.index("-t") + 1])
                self.assertEqual("critical,medium", command[command.index("-s") + 1])

                for templates, severity in (
                    ("../outside.yaml", "high"),
                    ("/etc/passwd", "high"),
                    ("missing.yaml", "high"),
                    ("CVE-2021-41773.yaml", "high,urgent"),
                    ("CVE-2021-41773.yaml", "high,high"),
                ):
                    with self.subTest(templates=templates, severity=severity):
                        before = run.call_count
                        rejected = asyncio.run(
                            self.server.nuclei_scan(
                                "https://example.test", templates, severity
                            )
                        )
                        self.assertIn("Error", rejected)
                        self.assertEqual(before, run.call_count)

    def test_promoted_manifest_pins_reviewed_detection_only_templates(self):
        repository = Path(__file__).resolve().parents[1]
        template_root = repository / "nuclei-templates" / "promoted"
        manifest = json.loads(
            (repository / "nuclei-templates" / "manifest.json").read_text(encoding="utf-8")
        )

        self.assertEqual("v10.4.7", manifest["upstream_version"])
        self.assertEqual(1, manifest["schema_version"])
        self.assertEqual(["CVE-2021-41773.yaml"], [item["path"] for item in manifest["templates"]])
        for item in manifest["templates"]:
            content = (template_root / item["path"]).read_bytes()
            self.assertEqual(item["sha256"], hashlib.sha256(content).hexdigest())
            text = content.decode("utf-8").lower()
            for forbidden in ("interactsh", "javascript:", "code:", "headless:", "workflow:", "post "):
                self.assertNotIn(forbidden, text)

    def test_public_summary_is_bounded_and_redacted_after_full_jsonl_capture(self):
        findings = "\n".join(
            json.dumps(
                {
                    "template-id": f"finding-{index}",
                    "info": {"severity": "high", "name": f"Finding {index}"},
                    "matched-at": "https://example.test/?token=SUPERSECRET",
                }
            )
            for index in range(250)
        )
        completed = SimpleNamespace(returncode=0, stdout=findings + "\n", stderr="")
        with patch.object(self.server, "execute_command", return_value=completed):
            result = asyncio.run(self.server.nuclei_scan("https://example.test"))

        self.assertLessEqual(len(result.splitlines()), self.server.MAX_OUTPUT_LINES)
        self.assertIn("finding-0", result)
        self.assertNotIn("finding-249", result)
        self.assertNotIn("SUPERSECRET", result)
        self.assertEqual(250, len(result.findings))
        self.assertNotIn("SUPERSECRET", json.dumps(result.findings))

    def test_web_audit_combined_summary_never_exceeds_the_public_line_bound(self):
        long_stage = "\n".join(f"line-{index}" for index in range(250))
        child = unittest.mock.AsyncMock(return_value=long_stage)
        headers = unittest.mock.AsyncMock(return_value="headers")
        complete_findings = [{"template-id": f"finding-{index}"} for index in range(250)]
        complete_findings[0]["name"] = '<script>alert("x")</script>'
        nuclei = unittest.mock.AsyncMock(
            return_value=self.server.NucleiScanText("nuclei complete", complete_findings)
        )
        with (
            patch.object(self.server, "whatweb_scan", child),
            patch.object(self.server, "wafw00f_scan", child),
            patch.object(self.server, "web_headers", headers),
            patch.object(self.server, "_deduplicate_url_inventory", unittest.mock.AsyncMock(return_value=["https://example.test"])),
            patch.object(self.server, "nikto_scan", child),
            patch.object(self.server, "nuclei_scan", nuclei),
            patch.object(self.server, "sslscan_scan", child),
        ):
            result = asyncio.run(self.server.web_audit("https://example.test"))
        self.assertLessEqual(len(result.splitlines()), self.server.MAX_OUTPUT_LINES)
        self.assertEqual(250, len(result.report_data["nuclei_findings"]))
        rendered = json.dumps(result.report_data["nuclei_findings"])
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_failed_or_malformed_nuclei_output_fails_readably_without_raw_secrets(self):
        cases = (
            SimpleNamespace(returncode=2, stdout="", stderr="password: SUPERSECRET\nfailed"),
            SimpleNamespace(returncode=0, stdout='{"template-id":', stderr=""),
        )
        for completed in cases:
            with self.subTest(returncode=completed.returncode), patch.object(
                self.server, "execute_command", return_value=completed
            ):
                result = asyncio.run(self.server.nuclei_scan("https://example.test"))
                self.assertIn("Error", result)
                self.assertNotIn("SUPERSECRET", result)

    def test_controlled_update_promotes_only_explicit_detection_only_candidates(self):
        repository = Path(__file__).resolve().parents[1]
        updater = repository / "scripts" / "update-nuclei-templates"
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            source = root / "source"
            destination = root / "managed"
            source.mkdir()
            (source / "safe.yaml").write_text(
                "id: safe-check\ninfo:\n  severity: high\nhttp:\n  - method: GET\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, str(updater), "--source", str(source), "--destination", str(destination), "--version", "v-test", "safe.yaml"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual("v-test", manifest["upstream_version"])
            self.assertEqual(["safe.yaml"], [item["path"] for item in manifest["templates"]])

            (source / "unsafe.yaml").write_text(
                "id: unsafe\nhttp:\n  - method: POST\n    path: ['{{BaseURL}}/change']\n",
                encoding="utf-8",
            )
            rejected = subprocess.run(
                [sys.executable, str(updater), "--source", str(source), "--destination", str(root / "rejected"), "--version", "v-test", "unsafe.yaml"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, rejected.returncode)

    def test_image_installs_and_verifies_the_pinned_promoted_set(self):
        repository = Path(__file__).resolve().parents[1]
        dockerfile = (repository / "Dockerfile").read_text(encoding="utf-8")
        verifier = (repository / "scripts" / "verify-image.sh").read_text(encoding="utf-8")
        self.assertIn(
            "COPY nuclei-templates /usr/local/share/kali-mcp/nuclei-templates",
            dockerfile,
        )
        self.assertIn('manifest_path = root / "manifest.json"', verifier)
        self.assertIn("hashlib.sha256", verifier)


if __name__ == "__main__":
    unittest.main()
