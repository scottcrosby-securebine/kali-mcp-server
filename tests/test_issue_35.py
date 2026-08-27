"""Issue #35: the trivy and syft rejections must name the values they accept."""

import asyncio
import unittest
from unittest.mock import patch

from server_test_support import load_server


class SourceTypeDiscoverabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def call(self, coroutine):
        """Run a tool with the process seam blocked; validation must reject first."""
        with patch.object(self.server.subprocess, "run", side_effect=AssertionError("no binary may run")):
            return asyncio.run(coroutine)

    def assert_names_every_value(self, response, accepted):
        self.assertTrue(response.startswith("❌ Error:"), response)
        for value in accepted:
            self.assertIn(value, response)
        self.assertIn(", ".join(sorted(accepted)), response)

    def test_trivy_rejection_names_every_accepted_source_type(self):
        response = self.call(self.server.trivy_scan("alpine:3.10", "image"))
        self.assertIn("image", response)
        self.assert_names_every_value(response, self.server.TRIVY_SOURCE_TYPES)

    def test_syft_rejection_names_every_accepted_source_type(self):
        response = self.call(self.server.syft_sbom("alpine:3.10", "image"))
        self.assert_names_every_value(response, self.server.SYFT_SOURCE_TYPES)

    def test_syft_rejection_names_every_accepted_format(self):
        response = self.call(self.server.syft_sbom("demo", "dir", "table"))
        self.assert_names_every_value(response, self.server.SYFT_FORMATS)

    def test_docstrings_stay_one_line_and_name_the_accepted_values(self):
        cases = (
            (self.server.trivy_scan, (self.server.TRIVY_SOURCE_TYPES,)),
            (self.server.syft_sbom, (self.server.SYFT_SOURCE_TYPES, self.server.SYFT_FORMATS)),
        )
        for tool, expected in cases:
            with self.subTest(tool=tool.__name__):
                doc = tool.__doc__
                self.assertEqual(1, len(doc.strip().splitlines()))
                for accepted in expected:
                    self.assertIn(", ".join(sorted(accepted)), doc)


if __name__ == "__main__":
    unittest.main()
