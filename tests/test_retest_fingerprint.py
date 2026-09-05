"""Phase 2 (#91 P3d): cross-scan finding fingerprint + registry.

The fingerprint is what lets a re-test recognize "the same finding" across two
runs. It must be stable across benign drift (title/evidence/severity change),
distinct for distinct findings, namespaced per parser, and drawn ONLY from a
whitelist so a run-varying field can never enter identity. Un-vetted parsers get
no fingerprint (advisory only) — that is Option A's false-FIXED protection."""
import unittest

from server_test_support import load_server


class FingerprintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_stable_across_benign_drift(self):
        # Same nmap port id, different Title/evidence/severity (byte size, banner,
        # rescore) → identical fingerprint.
        a = {"id": "port-443-tcp", "Title": "443/tcp https open [4321b]",
             "Severity": "INFO", "evidence": "nginx/1.20"}
        b = {"id": "port-443-tcp", "Title": "443/tcp https open [9999b]",
             "Severity": "MEDIUM", "evidence": "nginx/1.25"}
        self.assertEqual(self.server._finding_fingerprint("nmap", a),
                         self.server._finding_fingerprint("nmap", b))

    def test_distinct_ids_distinct_fingerprints(self):
        a = {"id": "port-443-tcp"}
        b = {"id": "port-80-tcp"}
        self.assertNotEqual(self.server._finding_fingerprint("nmap", a),
                            self.server._finding_fingerprint("nmap", b))

    def test_parser_namespaced(self):
        # Same id string under two scanners must not collide (framing).
        f = {"id": "x"}
        self.assertNotEqual(self.server._finding_fingerprint("nmap", f),
                            self.server._finding_fingerprint("sslscan", f))

    def test_unvetted_and_contaminated_parsers_get_no_fingerprint(self):
        f = {"id": "web-path-200-/admin"}
        for scanner in ("ffuf", "wfuzz", "wpscan", "nikto", "dns_recon", "unknown_tool"):
            self.assertIsNone(self.server._finding_fingerprint(scanner, f),
                              f"{scanner} must be advisory (no fingerprint)")

    def test_vetted_seed_set_has_fingerprints(self):
        f = {"id": "seed-id"}
        for scanner in ("nmap", "amass", "subfinder", "whatweb", "wafw00f",
                        "sqlmap", "sslscan", "testssl", "sslyze"):
            self.assertIsNotNone(self.server._finding_fingerprint(scanner, f),
                                 f"{scanner} is a vetted seed parser")

    def test_whitelist_invariant(self):
        # Every field any parser keys on must be in the global whitelist.
        allowed = self.server.IDENTITY_ALLOWED_FIELDS
        for scanner, fields in self.server.IDENTITY_FIELDS_PER_PARSER.items():
            for field in fields:
                self.assertIn(field, allowed,
                              f"{scanner} keys on non-whitelisted field {field!r}")

    def test_missing_identity_field_is_stable_and_distinct(self):
        # A finding with no id still fingerprints deterministically (null marker),
        # and differs from a present id.
        missing = {"Title": "no id here"}
        fp1 = self.server._finding_fingerprint("nmap", missing)
        fp2 = self.server._finding_fingerprint("nmap", dict(missing))
        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, self.server._finding_fingerprint("nmap", {"id": "port-80-tcp"}))

    def test_non_dict_finding_returns_none(self):
        self.assertIsNone(self.server._finding_fingerprint("nmap", "not a dict"))


if __name__ == "__main__":
    unittest.main()
