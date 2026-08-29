"""Credential redaction on the DIRECT tool-output channel (issue #57).

The report and capture paths already redact. The `run_command` return value --
the channel that reaches the calling agent's context, the transcript, and any
logging -- did not, so `web_headers`, `whois`, `hydra_attack`, `sqlmap_scan`,
`wfuzz_scan`, `enum4linux` and `theharvester_scan` returned session material
verbatim while the report of the SAME data was sanitized.

Every case patches `execute_command`, not `run_command`: the redaction lives
inside `run_command` and must run BEFORE its 200-line bound, so a `run_command`
mock would prove nothing.

The tables are PAIRED on purpose. Issue #27 records that a fully green suite
hid every over-redaction regression because each test asserted only that a
secret was ABSENT, never that legitimate content SURVIVED.
"""

import subprocess
import unittest
from unittest.mock import patch

from server_test_support import load_server


class DirectOutputRedactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_output(self, stdout, returncode=0, stderr=""):
        """Drive the real run_command over faked process output."""
        def fake_exec(cmd, timeout=None, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=returncode, stdout=stdout, stderr=stderr)

        with patch.object(self.server, "execute_command", fake_exec):
            return self.server.run_command(["whois", "example.com"])

    # Secret material a tool can put on the direct channel. Each entry is
    # (label, raw tool output, the substring that must NOT survive).
    MUST_REMOVE = (
        # The live repro from #57: web_headers against an internal target.
        ("set-cookie session material",
         "HTTP/1.1 200 OK\nset-cookie: csrftoken=VgH6Pgku8i7bmtlnezOkHdcYL6cNEydE; HttpOnly\n",
         "VgH6Pgku8i7bmtlnezOkHdcYL6cNEydE"),
        ("authorization bearer token",
         "HTTP/1.1 200 OK\nauthorization: Bearer abc123XYZtokenLEAK\n",
         "abc123XYZtokenLEAK"),
        ("a hydra password line",
         "[80][http-post-form] host: 10.0.0.5   login: admin   password: Hunter2LEAK\n",
         "Hunter2LEAK"),
        ("a URL credential",
         "Fetching https://svc:PWLEAK@internal.example/api\n",
         "PWLEAK"),
        ("a github token",
         "found ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGG in config\n",
         "ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGG"),
        ("a private key block",
         "-----BEGIN RSA PRIVATE KEY-----\nKEYBODYLEAK\n-----END RSA PRIVATE KEY-----\n",
         "KEYBODYLEAK"),
        # #74: nikto restates a header value away from its name, past the reach
        # of the keyword pattern.
        ("nikto header-contents prose",
         "+ Uncommon header(s) 'x-api-key' found, with contents: leak_apikey_PLAINTEXTKEY_7f3a9c001122334455.\n",
         "leak_apikey_PLAINTEXTKEY_7f3a9c001122334455"),
        # A bare HTTP-Basic credential not preceded by an Authorization keyword
        # is only caught by the Basic pattern (#74/#78 pair).
        ("a bare Basic auth credential in prose",
         "Server offered Basic dXNlcjpzM2NyZXRQQVNTd29yZA== to the client\n",
         "dXNlcjpzM2NyZXRQQVNTd29yZA=="),
        # #74 red-team R3: short, all-lowercase, and sentence-final bare Basic
        # credentials must ALL redact (the broad run + colon guard, not the
        # base64-shape lookaheads, which leaked these).
        ("a short bare Basic credential", "auth header Basic dTpw end\n", "dTpw"),
        ("an all-lowercase bare Basic credential", "tried Basic ajphamdh here\n", "ajphamdh"),
        ("a sentence-final bare Basic credential", "sent Basic dXNlcjpzM2NyZXQ=.\n", "dXNlcjpzM2NyZXQ="),
        # #74 red-team R5: nikto value under an X-Auth-Key style header name.
        ("nikto x-auth-key contents",
         "+ Uncommon header(s) 'x-auth-key' found, with contents: REAL_SECRET_123abc.\n",
         "REAL_SECRET_123abc"),
        # #74 red-team R2-2: a real colon-terminated Basic credential (base64-
        # shaped) must redact even though the "Basic options:" label survives.
        ("a colon-terminated Basic credential", "proxy log Basic dXNlcjpwYXNz: 401\n", "dXNlcjpwYXNz"),
        # #74 red-team R2-4: X-Auth-Key header value in text must redact.
        ("an X-Auth-Key header value", "X-Auth-Key: LEAKAUTHVALUE987xyz\n", "LEAKAUTHVALUE987xyz"),
    )

    # Ordinary output every one of these tools emits. Redaction must leave it
    # alone -- this is the direction issue #27 says prior tests never checked.
    MUST_KEEP = (
        ("an nmap service line",
         "80/tcp   open  http    nginx 1.24.0\n443/tcp  open  https\n", "nginx 1.24.0"),
        ("a server banner", "HTTP/1.1 200 OK\nServer: nginx/1.24.0\n", "nginx/1.24.0"),
        ("a ported URL",
         "Registrar URL: https://www.markmonitor.com:443/whois\n", "markmonitor.com:443"),
        ("an IPv6 ported URL",
         "Endpoint: https://[2001:db8::1]:8443/status\n", "[2001:db8::1]:8443"),
        ("a whois abuse contact",
         "Registrar Abuse Contact Email: abuse@registrar.tld\n", "abuse@registrar.tld"),
        ("an enum4linux share table",
         "\tACME-FS1        Disk      Company Files\n", "ACME-FS1"),
        # #78: the Basic pattern must not eat the "Basic options:" section label
        # (a base64-charset word followed by ':' is a label, not a credential).
        ("a metasploit Basic options header",
         "Module options (auxiliary/scanner/ssh/ssh_login):\n\nBasic options:\n", "Basic options:"),
    )

    def test_removes_secrets_from_direct_output(self):
        for label, raw, secret in self.MUST_REMOVE:
            with self.subTest(removes=label):
                self.assertNotIn(secret, self.run_output(raw))

    def test_keeps_legitimate_output(self):
        for label, raw, keep in self.MUST_KEEP:
            with self.subTest(keeps=label):
                self.assertIn(keep, self.run_output(raw))

    def test_secret_free_output_is_byte_identical(self):
        """Redaction must not perturb the legacy contract on ordinary output."""
        raw = "80/tcp   open  http\n443/tcp  open  https\n"
        self.assertEqual(
            self.run_output(raw),
            "✅ Scan completed successfully:\n\n" + raw)

    def test_truncation_counter_unchanged_without_secrets(self):
        raw = "".join(f"line {index}\n" for index in range(250))
        self.assertIn("(truncated 51 additional lines)", self.run_output(raw))

    def test_key_split_by_the_line_bound_does_not_leak(self):
        """A hostile server can put the -----END----- past the 200-line bound.

        Redaction therefore runs BEFORE the bound, so the complete pattern is
        matched against the whole output rather than against a slice that has
        already had the closing anchor cut away.
        """
        raw = ("filler\n" * 195) + "-----BEGIN RSA PRIVATE KEY-----\n" \
            + ("SPLITKEYLEAK\n" * 40) + "-----END RSA PRIVATE KEY-----\n"
        self.assertNotIn("SPLITKEYLEAK", self.run_output(raw))

    def test_failure_path_is_redacted_too(self):
        """A non-zero exit takes the ❌ branch (#31), which returns the same text."""
        out = self.run_output("password: FAILPATHLEAK\n", returncode=1)
        self.assertIn("❌ Scan failed", out)
        self.assertNotIn("FAILPATHLEAK", out)

    def test_stderr_is_redacted(self):
        """run_command merges stderr into the returned text."""
        out = self.run_output("", stderr="authorization: Bearer STDERRLEAK\n")
        self.assertNotIn("STDERRLEAK", out)


if __name__ == "__main__":
    unittest.main()
