"""F1 (red-team, 2026-09-02): an ORPHANED secret (opener whose closing anchor is
absent) in a scanner document's `metadata`/`source` reached the report chokepoint
`_redact_scanner_data` in the clear. That redactor applied only the paired
SECRET_VALUE_PATTERNS, never the orphan guard `_redact_truncated_secret` -- the
guard lived solely in `_clip`, which the trivy/syft metadata/source store bypassed
(kali_pentest_server.py stores them raw). So an unpaired PEM/URL-cred/JWT in a
scanned image's Metadata.ImageConfig rendered cleartext in the combined, web-app,
and attack-surface report version tables.

Root fix: the orphan guard runs INSIDE the chokepoint, so every field and every
output path (report AND direct text) is covered, not only ingested findings.

PAIRED per #27: each case asserts the secret is GONE *and* that legitimate
neighbouring content SURVIVES, so the fix cannot pass by over-redacting.
"""

import unittest
from server_test_support import load_server


class MetadataOrphanRedactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def redact(self, value):
        return self.server._redact_scanner_data(value)

    def test_orphaned_pem_in_metadata_is_redacted(self):
        doc = {"metadata": {"ImageConfig_env":
               "SSH_KEY=-----BEGIN PRIVATE KEY-----\nMIIBVQxxLEAKEDKEYBODYsecretMATERIAL"}}
        out = self.redact(doc)
        flat = repr(out)
        self.assertNotIn("LEAKEDKEYBODYsecretMATERIAL", flat)
        self.assertNotIn("secretMATERIAL", flat)

    def test_orphaned_url_credential_in_source_is_redacted(self):
        doc = {"source": {"repo": "url=https://admin:SUPERSECRETpw"}}
        out = self.redact(doc)
        self.assertNotIn("SUPERSECRETpw", repr(out))

    def test_orphaned_jwt_in_metadata_is_redacted(self):
        doc = {"metadata": {"note": "token eyJhbGciOiJIUzI1NiJ9.PAYLOADSEGMENTleak"}}
        out = self.redact(doc)
        self.assertNotIn("PAYLOADSEGMENTleak", repr(out))

    # PAIRED: legitimate metadata must SURVIVE (the fix must not over-redact).
    def test_legitimate_metadata_survives(self):
        doc = {"metadata": {"tool_version": "trivy 0.66.0",
                            "ImageConfig_env": "PATH=/usr/local/bin:/usr/bin:/bin",
                            "entry_count": "42"}}
        out = self.redact(doc)
        flat = repr(out)
        self.assertIn("trivy 0.66.0", flat)
        self.assertIn("/usr/local/bin", flat)
        self.assertIn("42", flat)

    def test_paired_pem_still_fully_redacted(self):
        doc = {"metadata": {"k":
               "-----BEGIN PRIVATE KEY-----\nPAIREDBODYzzz\n-----END PRIVATE KEY-----"}}
        out = self.redact(doc)
        self.assertNotIn("PAIREDBODYzzz", repr(out))


if __name__ == "__main__":
    unittest.main()
