"""Issue #36: web_headers must audit the scheme and port the target implies."""

import asyncio
import unittest
from unittest.mock import patch

from server_test_support import load_server


class WebHeadersSchemeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def curl_url(self, target):
        """Run web_headers with the subprocess seam stubbed; return curl's URL."""
        with patch.object(self.server, "run_command", return_value="ok") as run_command:
            self.assertEqual("ok", asyncio.run(self.server.web_headers(target)))
        command = run_command.call_args.args[0]
        self.assertEqual("curl", command[0])
        self.assertNotIn("shell", run_command.call_args.kwargs)
        return command[-1]

    def test_every_target_form_audits_the_url_its_port_implies(self):
        cases = (
            ("uptimekuma.local.securebine.com", "https://uptimekuma.local.securebine.com"),
            ("http://uptimekuma.local.securebine.com", "http://uptimekuma.local.securebine.com"),
            ("https://uptimekuma.local.securebine.com", "https://uptimekuma.local.securebine.com"),
            ("https://uptimekuma.local.securebine.com/", "https://uptimekuma.local.securebine.com/"),
            ("10.10.15.8", "https://10.10.15.8"),
            ("uptimekuma.local.securebine.com:443", "https://uptimekuma.local.securebine.com:443"),
            ("uptimekuma.local.securebine.com:8080", "http://uptimekuma.local.securebine.com:8080"),
        )
        for target, expected in cases:
            with self.subTest(target=target):
                self.assertEqual(expected, self.curl_url(target))

    def test_a_cleartext_port_and_a_tls_port_pick_opposite_schemes(self):
        self.assertEqual("http://example.test:80/x", self.curl_url("example.test:80/x"))
        self.assertEqual("https://example.test:8443/x", self.curl_url("example.test:8443/x"))

    def test_a_host_named_like_the_scheme_is_not_mistaken_for_a_url(self):
        self.assertEqual("https://httpbin.org", self.curl_url("httpbin.org"))
        self.assertEqual("https://https.example.test", self.curl_url("https.example.test"))

    def test_an_unparseable_port_still_produces_a_url_without_raising(self):
        self.assertEqual("https://example.test:abc", self.curl_url("example.test:abc"))

    def test_an_empty_target_never_reaches_curl(self):
        with patch.object(self.server, "run_command") as run_command:
            self.assertIn("❌", asyncio.run(self.server.web_headers("   ")))
            run_command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
