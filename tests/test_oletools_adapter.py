import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from server_test_support import load_server


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "scanners"


class OletoolsAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def invoke(self, analyzer="olevba", stdout=None, stderr="", returncode=0, size=16):
        output = (FIXTURES / f"{analyzer}-success.json").read_text(encoding="utf-8") if stdout is None else stdout
        completed = subprocess.CompletedProcess(args=[], returncode=returncode, stdout=output, stderr=stderr)
        with tempfile.TemporaryDirectory() as artifacts, tempfile.TemporaryDirectory() as results:
            artifact = Path(artifacts, "sample.docm")
            artifact.write_bytes(b"x" * size)
            with (
                patch.object(self.server, "ARTIFACTS_ROOT", Path(artifacts)),
                patch.object(self.server, "RESULTS_ROOT", Path(results)),
                patch.object(self.server.subprocess, "run", return_value=completed) as run,
            ):
                response = asyncio.run(self.server.oletools_scan("sample.docm", analyzer))
                files = [path.read_text(encoding="utf-8") for path in Path(results).iterdir()]
        return response, run, files

    def test_analyzers_use_bounded_json_commands_and_persist_normalized_findings(self):
        expected_prefix = {
            "olevba": ["olevba", "--json", "--analysis", "--no-pcode"],
            "msodde": ["msodde", "--json", "--dde-only"],
        }
        for analyzer, prefix in expected_prefix.items():
            with self.subTest(analyzer=analyzer):
                response, run, files = self.invoke(analyzer)
                command = run.call_args.args[0]
                self.assertEqual(prefix, command[:-1])
                self.assertTrue(command[-1].endswith("/sample.docm"))
                self.assertIn("result-id=", response)
                document = json.loads(files[0])
                self.assertEqual(analyzer, document["scanner"])
                self.assertTrue(document["findings"])
                self.assertNotIn("NEVER-PERSIST-MACRO-CODE", files[0])

    def test_invalid_or_oversized_artifacts_fail_before_execution(self):
        with tempfile.TemporaryDirectory() as artifacts, patch.object(self.server, "ARTIFACTS_ROOT", Path(artifacts)):
            Path(artifacts, "large.docm").write_bytes(b"x")
            cases = (("", "olevba"), ("../escape.doc", "olevba"), ("missing.doc", "olevba"), ("large.docm", "other"))
            for artifact_ref, analyzer in cases:
                with self.subTest(artifact_ref=artifact_ref, analyzer=analyzer), patch.object(self.server.subprocess, "run") as run:
                    response = asyncio.run(self.server.oletools_scan(artifact_ref, analyzer))
                    self.assertIn("Error", response)
                    run.assert_not_called()

            with patch.object(self.server, "MAX_ARTIFACT_BYTES", 0), patch.object(self.server.subprocess, "run") as run:
                response = asyncio.run(self.server.oletools_scan("large.docm", "olevba"))
                self.assertIn("Error", response)
                run.assert_not_called()

    def test_failed_malformed_and_secret_bearing_output_is_safe(self):
        cases = (("", "password: OFFICE-SECRET", 2), ("[{", "", 0), ("[]", "", 0))
        for stdout, stderr, returncode in cases:
            with self.subTest(stdout=stdout, returncode=returncode):
                response, _, files = self.invoke(stdout=stdout, stderr=stderr, returncode=returncode)
                self.assertIn("Error", response)
                self.assertNotIn("OFFICE-SECRET", response)
                self.assertFalse(files)

    def test_web_audit_deduplicates_inventory_with_uro_and_records_counts(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="https://example.test/a\n", stderr="")
        child = AsyncMock(return_value="ok")
        with (
            patch.object(self.server, "execute_command", return_value=completed) as execute,
            patch.object(self.server, "whatweb_scan", child),
            patch.object(self.server, "wafw00f_scan", child),
            patch.object(self.server, "web_headers", child),
            patch.object(self.server, "nikto_scan", child),
            patch.object(self.server, "sslscan_scan", child),
        ):
            response = asyncio.run(self.server.web_audit("https://example.test/a"))
        self.assertEqual(["uro"], execute.call_args.args[0])
        self.assertIn("URL inventory: original=1, deduplicated=1", response)
        self.assertNotIn("uro_scan", [tool.__name__ for tool in self.server.mcp.tools])


if __name__ == "__main__":
    unittest.main()
