"""#43: web_audit must not prefix a blind http:// that defeats scheme resolution.

web_audit used to run `with_web_scheme`, gluing http:// onto a bare host before
calling its children, so web_headers' port-implied resolution (#36) never saw a
bare target and every stage audited HTTP regardless. It resolves the scheme once
now, port-implied, and hands the same schemed target to every child. A bare host
with no port is https, consistently, and the TLS stage runs for it.
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from contextlib import ExitStack

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


class TheSharedPortImpliedResolver(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def test_a_bare_host_with_no_port_resolves_to_https(self):
        self.assertEqual("https://host", self.server.resolve_web_scheme("host"))

    def test_a_cleartext_port_resolves_to_http(self):
        for target in ("host:80", "host:8080"):
            with self.subTest(target=target):
                self.assertEqual(f"http://{target}", self.server.resolve_web_scheme(target))

    def test_a_tls_port_resolves_to_https(self):
        for target in ("host:443", "host:8443"):
            with self.subTest(target=target):
                self.assertEqual(f"https://{target}", self.server.resolve_web_scheme(target))

    def test_an_existing_scheme_is_kept_verbatim(self):
        for target in ("http://host", "https://host", "HTTP://host"):
            with self.subTest(target=target):
                self.assertEqual(target, self.server.resolve_web_scheme(target))

    def test_it_differs_from_with_web_scheme_on_a_bare_host(self):
        # The exact defect: the blind helper says http, the port-implied one says
        # https, and web_audit must use the second.
        self.assertEqual("http://host", self.server.with_web_scheme("host"))
        self.assertEqual("https://host", self.server.resolve_web_scheme("host"))


class WebAuditAuditsOneConsistentScheme(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def _chain(self, target):
        """Run web_audit with every child mocked; return [(name, args), ...]."""
        log = []
        children = [
            "whatweb_scan", "wafw00f_scan", "web_headers", "nikto_scan",
            "nuclei_scan", "sslscan_scan",
        ]
        with ExitStack() as stack:
            stack.enter_context(patch.object(self.server, "run_command", return_value="x"))
            for name in children:
                stack.enter_context(patch.object(
                    self.server, name,
                    AsyncMock(side_effect=lambda *a, _n=name: log.append((_n, a)) or _n),
                ))
            # Support tools web_audit also calls; keep them from doing real work.
            for name in ("_deduplicate_url_inventory",):
                if hasattr(self.server, name):
                    stack.enter_context(patch.object(
                        self.server, name, AsyncMock(return_value=[])))
            asyncio.run(self.server.web_audit(target))
        return log

    def test_a_bare_host_is_audited_over_https_on_every_stage(self):
        chain = dict(self._chain("example.test"))
        # The four blind-prefix children used to get http://; now https://.
        self.assertEqual(("https://example.test", "3"), chain["whatweb_scan"])
        self.assertEqual(("https://example.test",), chain["wafw00f_scan"])
        self.assertEqual(("https://example.test",), chain["web_headers"])
        self.assertEqual(("https://example.test",), chain["nuclei_scan"])

    def test_no_child_receives_a_blind_http_prefix_on_a_bare_host(self):
        chain = self._chain("example.test")
        for name, args in chain:
            for value in args:
                if isinstance(value, str) and value.startswith("http://"):
                    self.fail(f"{name} received a blind http:// target: {value}")

    def test_the_tls_stage_runs_for_a_bare_host(self):
        # Previously skipped: is_https_target(http://host) was False, so a bare
        # host never got TLS analysis inside the composite.
        chain = dict(self._chain("example.test"))
        self.assertIn("sslscan_scan", chain)
        self.assertEqual(("example.test",), chain["sslscan_scan"])

    def test_a_caller_supplied_http_is_still_honoured(self):
        # Resolution never UPGRADES an explicit scheme; the caller's http stays.
        chain = dict(self._chain("http://example.test"))
        self.assertEqual(("http://example.test", "3"), chain["whatweb_scan"])
        self.assertNotIn("sslscan_scan", chain)


if __name__ == "__main__":
    unittest.main()
