"""P3c / #90 — internal AD/SMB assessment report.

Covers the spec's Test seams: `_parse_crackmapexec` (incl. ANSI-coloured
variant), `_parse_enum4linux` (users/shares/policy + missing-policy + malformed
fallback), `_sensitive_share`, `render_adsmb` via `_render_report`, and
`internal_ad_report` aggregation. The honesty rules (#90) are the point of the
report, so the assertions have teeth (observed-only posture, observation-limited
poisoning, ATT&CK legend over OBSERVED weaknesses only, masked emails).
"""

import asyncio
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from server_test_support import load_server


# Two hosts: DC01 is clean (signing required, SMBv1 off, no null session); WS01
# is weak (signing off, SMBv1 on) and shows an observed null/guest auth line.
CME_TEXT = (
    "SMB         10.0.0.5    445    DC01    "
    "[*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) "
    "(signing:True) (SMBv1:False)\n"
    "SMB         10.0.0.6    445    WS01    "
    "[*] Windows 10.0 Build 19041 x64 (name:WS01) (domain:CORP.LOCAL) "
    "(signing:False) (SMBv1:True)\n"
    "SMB         10.0.0.6    445    WS01    [+] CORP.LOCAL\\: (Guest)\n"
)

# Same WS01 line with ANSI colour codes around the marker and the signing flag,
# as crackmapexec 5.4.0 emits over a non-TTY pipe. The parser must strip first.
CME_ANSI = (
    "SMB         10.0.0.7    445    WS02    "
    "\x1b[1m[*]\x1b[0m Windows 10.0 Build 19041 x64 (name:WS02) "
    "(domain:CORP.LOCAL) (signing:\x1b[31mFalse\x1b[0m) (SMBv1:\x1b[31mTrue\x1b[0m)\n"
)

ENUM_TEXT = """Starting enum4linux

 =========================( Session Check on 10.0.0.5 )=========================

[+] Server 10.0.0.5 allows sessions using username '', password ''

 =========================( Users on 10.0.0.5 )=========================

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[svc_backup] rid:[0x450]

 =========================( Share Enumeration on 10.0.0.5 )=========================

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	finance         Disk      Finance dept files
	public          Disk      Team wiki

//10.0.0.5/ADMIN$	Mapping: DENIED, Listing: N/A
//10.0.0.5/finance	Mapping: OK, Listing: DENIED
//10.0.0.5/public	Mapping: OK, Listing: OK

 =========================( Password Policy on 10.0.0.5 )=========================

[+] Minimum password length: 7
[+] Password history length: 24
[+] Account Lockout Threshold: 5
[+] Password Complexity Flags: 000001
"""

ENUM_NO_POLICY = """ =========================( Users on 10.0.0.9 )=========================

user:[jdoe] rid:[0x451]

 =========================( Share Enumeration on 10.0.0.9 )=========================

	Sharename       Type      Comment
	---------       ----      -------
	data            Disk      Shared data
"""


def _result(scanner, target, findings):
    return {
        "schema_version": 1, "scanner": scanner, "source_type": "host",
        "target_ref": target, "status": "success", "metadata": {}, "findings": findings,
    }


class ParseCrackmapexecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_parses_host_posture(self):
        findings = self.server._parse_crackmapexec(CME_TEXT, "10.0.0.0/24")
        hosts = {f["ip"]: f for f in findings if f.get("kind") == "host"}
        self.assertEqual({"10.0.0.5", "10.0.0.6"}, set(hosts))
        dc = hosts["10.0.0.5"]
        self.assertEqual("DC01", dc["host"])
        self.assertEqual("CORP.LOCAL", dc["domain"])
        self.assertIn("Windows Server 2019", dc["os"])
        self.assertTrue(dc["signing"])
        self.assertFalse(dc["smbv1"])
        self.assertIs(False, dc["ambiguous"])
        ws = hosts["10.0.0.6"]
        self.assertFalse(ws["signing"])
        self.assertTrue(ws["smbv1"])

    def test_ansi_variant_no_misslice(self):
        findings = self.server._parse_crackmapexec(CME_ANSI, "10.0.0.7")
        host = next(f for f in findings if f.get("kind") == "host")
        self.assertEqual("WS02", host["host"])
        self.assertFalse(host["signing"])
        self.assertTrue(host["smbv1"])
        # No raw ANSI byte survived into the OS banner.
        self.assertNotIn("\x1b", host["os"])
        self.assertNotIn("[31m", host["os"])

    def test_parse_miss_raw_fallback(self):
        findings = self.server._parse_crackmapexec("garbage with no host line", "t")
        self.assertTrue(findings)
        self.assertTrue(all(f.get("kind") == "raw" for f in findings))
        self.assertIn("garbage", findings[0]["evidence"])

    def test_banner_only_dropped(self):
        self.assertEqual([], self.server._parse_crackmapexec("❌ Error: exit code 1", "t"))
        self.assertEqual([], self.server._parse_crackmapexec("", "t"))


class ParseEnum4linuxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_parses_users_shares_policy(self):
        f = self.server._parse_enum4linux(ENUM_TEXT, "10.0.0.5")[0]
        self.assertEqual("enum", f["kind"])
        self.assertEqual(["Administrator", "Guest", "svc_backup"], f["users"])
        shares = {s["name"]: s for s in f["shares"]}
        self.assertEqual({"ADMIN$", "finance", "public"}, set(shares))
        self.assertEqual("Disk", shares["finance"]["type"])
        self.assertEqual("Finance dept files", shares["finance"]["comment"])
        self.assertEqual("DENIED", shares["ADMIN$"]["map"])
        self.assertEqual("OK", shares["finance"]["map"])
        self.assertEqual("7", f["policy"]["min_length"])
        self.assertEqual("5", f["policy"]["lockout"])
        self.assertEqual("24", f["policy"]["history"])
        self.assertEqual("000001", f["policy"]["complexity"])

    def test_null_bind_from_the_session_check(self):
        """The toolkit's ONE real null-session signal. crackmapexec 5.4.0 emits
        no `(Guest)` marker and, given no credentials, no auth-success line at
        all, so this must come from enum4linux or it is dead on every real run."""
        f = self.server._parse_enum4linux(ENUM_TEXT, "10.0.0.5")[0]
        self.assertIs(True, f["null_bind"])

    def test_named_user_session_is_not_a_null_bind(self):
        text = ("[+] Server 10.0.0.5 allows sessions using username 'svc', "
                "password 'hunter2'\nuser:[jdoe] rid:[0x451]\n")
        f = self.server._parse_enum4linux(text, "10.0.0.5")[0]
        self.assertEqual("not observed", f["null_bind"])

    def test_absent_session_check_is_not_observed(self):
        f = self.server._parse_enum4linux(ENUM_NO_POLICY, "10.0.0.9")[0]
        self.assertEqual("not observed", f["null_bind"])

    def test_share_comment_cannot_forge_a_session_check(self):
        text = (
            " =========================( Share Enumeration on t )=====================\n"
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            "\tpublic          Disk      [+] Server t allows sessions using username ''\n")
        f = self.server._parse_enum4linux(text, "t")[0]
        self.assertEqual("not observed", f["null_bind"])

    def test_share_table_is_excluded_from_every_other_extractor(self):
        """The table's three columns are target-controlled, and the share NAME is
        the leftmost field — so a line-start anchor alone is satisfied by a share
        called `[+]x` or `user:[X]`. The whole region is excised instead."""
        text = (
            " =========================( Share Enumeration on t )=====================\n"
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            "\t[+]x            Disk      Minimum password length: 14\n"
            "\tuser:[EVIL] rid:[0x1] Disk  //h/secrets Mapping: OK\n")
        f = self.server._parse_enum4linux(text, "t")[0]
        self.assertEqual("not observed", f["policy"]["min_length"],
                         "a share NAME beginning [+] forged the password policy")
        self.assertEqual([], f["users"], "a share row injected an enumerated user")
        self.assertNotIn("secrets", [sh["name"] for sh in f["shares"]],
                         "a share comment forged a phantom share with an access verdict")

    def test_missing_policy_reads_not_observed(self):
        f = self.server._parse_enum4linux(ENUM_NO_POLICY, "10.0.0.9")[0]
        self.assertEqual(["jdoe"], f["users"])
        for key in ("min_length", "lockout", "history", "complexity"):
            self.assertEqual("not observed", f["policy"][key])

    def test_malformed_raw_fallback(self):
        findings = self.server._parse_enum4linux("total nonsense blob, no sections", "t")
        self.assertTrue(findings)
        self.assertTrue(all(f.get("kind") == "raw" for f in findings))

    def test_banner_only_dropped(self):
        self.assertEqual([], self.server._parse_enum4linux("⏱️ Timeout", "t"))
        self.assertEqual([], self.server._parse_enum4linux("", "t"))


class SensitiveShareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_flags_admin_and_content_hints(self):
        self.assertTrue(self.server._sensitive_share("ADMIN$"))
        self.assertTrue(self.server._sensitive_share("C$"))
        self.assertTrue(self.server._sensitive_share("IPC$"))
        self.assertTrue(self.server._sensitive_share("SYSVOL"))
        self.assertTrue(self.server._sensitive_share("NETLOGON"))
        self.assertTrue(self.server._sensitive_share("finance", "Finance dept"))
        self.assertTrue(self.server._sensitive_share("share", "nightly backup"))
        self.assertTrue(self.server._sensitive_share("hr"))

    def test_plain_share_not_flagged(self):
        self.assertFalse(self.server._sensitive_share("public", "team wiki"))
        self.assertFalse(self.server._sensitive_share("data", "shared data"))

    def test_scales_linearly_on_hostile_comment(self):
        import time

        def elapsed(n):
            comment = "x" * n
            start = time.perf_counter()
            self.server._sensitive_share("share", comment)
            return time.perf_counter() - start

        # Measured UNDER the 4000-char clip: past it the scanned length is
        # constant, so the assertion could not fail whatever the regex did
        # (red-team N8).
        elapsed(500)                        # warmup
        t1 = elapsed(1000)
        t2 = elapsed(2000)
        self.assertLess(t2, t1 * 3.0 + 0.01, f"_sensitive_share superlinear: {t1} -> {t2}")


class RenderAdsmbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _render(self, results):
        document = {
            "schema_version": 1, "report_type": "adsmb", "scanner": "combined",
            "source_type": "host", "target_ref": "x", "status": "success",
            "metadata": {}, "results": results,
        }
        return self.server._render_report(document)

    def _full(self):
        cme = self.server._parse_crackmapexec(CME_TEXT, "10.0.0.0/24")
        enum = self.server._parse_enum4linux(ENUM_TEXT, "10.0.0.5")
        return self._render([
            _result("crackmapexec", "10.0.0.0/24", cme),
            _result("enum4linux", "10.0.0.5", enum),
            _result("nbtscan", "10.0.0.5", [
                {"id": "nbtscan-10.0.0.5", "Severity": "INFO",
                 "Title": "nbtscan 10.0.0.5", "evidence": "10.0.0.5 CORP\\DC01 <00> UNIQUE"}]),
        ])

    def test_posture_rows_observed(self):
        html = self._full()
        # A structured parse, not a raw-fallback card: assert the posture TABLE
        # and a real row. The bare name asserts passed on a fallback-only report.
        self.assertNotIn("could not be parsed", html)
        self.assertIn("<th>SMB signing</th>", html)
        for host, ip in (("DC01", "10.0.0.5"), ("WS01", "10.0.0.6")):
            row = re.search(rf"<tr><th scope=\"row\">{host}</th>.*?</tr>", html, re.S)
            self.assertIsNotNone(row, f"no structured posture row for {host}")
            self.assertIn(ip, row.group(0))
            self.assertIn("CORP.LOCAL", row.group(0))

    def test_share_flag_heuristic(self):
        html = self._full()
        self.assertIn("finance", html)
        self.assertIn("public", html)
        self.assertIn("sensitive-name", html)          # heuristic badge present
        self.assertIn("conf-heuristic", html)

    def test_users_and_policy(self):
        html = self._full()
        self.assertIn("svc_backup", html)
        self.assertIn("Administrator", html)
        # Scoped to the policy row. A bare assertIn("7") is true of the EMPTY
        # report, so it pinned nothing (red-team N8).
        row = re.search(
            r"<tr><th scope=\"row\">Minimum password length</th><td>([^<]*)</td>", html)
        self.assertIsNotNone(row, "password-policy row missing")
        self.assertEqual("7", row.group(1))

    def test_poisoning_observation_limited(self):
        html = self._full()
        self.assertIn("not actively assessed", html)
        self.assertIn("requires elevated", html)
        # The confidence CLASS carries the honesty, not just the words: swapping
        # conf-heuristic for conf-observed previously passed every test.
        self.assertIn('<span class="conf conf-heuristic">not actively assessed', html)

    def test_sensitive_share_badge_stays_advisory(self):
        """The heuristic must never render as a confirmation. Pins the badge
        wording itself, which nothing asserted before (memory:
        keyword-classifiers-flag-not-confirm)."""
        html = self._full()
        self.assertIn(
            '<span class="conf conf-heuristic">sensitive-name — verify</span>', html)
        # Scoped to the badge spans themselves. The page prose legitimately says
        # "never a claim the share is exposed", so a document-wide negative
        # assertion would fail on the honesty sentence rather than on a verdict.
        for badge in re.findall(r'<span class="conf [^"]*">([^<]*)</span>', html):
            for claim in ("confirmed", "exposed", "compromised"):
                self.assertNotIn(claim, badge.lower(),
                                 f"heuristic badge asserts {claim!r}: {badge!r}")

    def test_attack_lists_only_observed_weaknesses(self):
        html = self._full()
        # WS01: SMBv1 on + signing off + null session all observed.
        self.assertIn("T1210", html)          # SMBv1 exploitation
        self.assertIn("T1557.001", html)      # SMB relay (signing off)
        self.assertIn("T1087.002", html)      # null/guest enumeration
        self.assertIn("report-side analysis", html)

    def test_attack_omits_unobserved_weakness(self):
        # A single clean host: signing required, SMBv1 off, no null session.
        clean = (
            "SMB  10.0.0.5  445  DC01  [*] Windows Server 2019 (name:DC01) "
            "(domain:CORP) (signing:True) (SMBv1:False)\n")
        html = self._render([_result("crackmapexec", "10.0.0.5",
                                      self.server._parse_crackmapexec(clean, "10.0.0.5"))])
        for tech in ("T1210", "T1557.001", "T1087.002"):
            self.assertNotIn(tech, html)

    def test_null_bind_not_observed_never_disabled(self):
        clean = (
            "SMB  10.0.0.5  445  DC01  [*] Windows Server 2019 (name:DC01) "
            "(domain:CORP) (signing:True) (SMBv1:False)\n")
        html = self._render([_result("crackmapexec", "10.0.0.5",
                                      self.server._parse_crackmapexec(clean, "10.0.0.5"))])
        # Scoped to the host's own row: a bare assertIn("not observed") also
        # matches the static exec paragraph, so it pinned nothing (R3 Spec N4).
        row = re.search(r"<tr><th scope=\"row\">DC01</th>.*?</tr>", html, re.S)
        self.assertIsNotNone(row)
        self.assertIn("<td>not observed</td>", row.group(0))
        self.assertNotIn("disabled", html)

    def test_no_forbidden_verdict_labels(self):
        html = self._full().lower()
        for word in ("secure", "compliant", "safe"):
            self.assertIsNone(re.search(rf"\b{word}\b", html),
                              f"forbidden verdict label {word!r} emitted")

    def test_emails_masked(self):
        cme = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC01  [*] admin@corp.local box (name:DC01) "
            "(domain:CORP) (signing:True) (SMBv1:False)\n", "10.0.0.5")
        html = self._render([_result("crackmapexec", "10.0.0.5", cme)])
        self.assertNotIn("admin@corp.local", html)
        self.assertIn("a***@corp.local", html)

    def test_attacker_markup_stays_escaped(self):
        enum = self.server._parse_enum4linux(
            " =========================( Share Enumeration on t )====================\n"
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            "\tevil            Disk      <script>alert(1)</script>\n", "t")
        html = self._render([_result("enum4linux", "t", enum)])
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_empty_results_render_without_error(self):
        html = self._render([])
        self.assertIn("AD/SMB", html)


class InternalAdReportAggregationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_aggregates_adsmb_only(self):
        cme_doc = _result("crackmapexec", "10.0.0.6",
                          self.server._parse_crackmapexec(CME_TEXT, "10.0.0.6"))
        # A web-app scanner must be excluded from the AD/SMB report.
        sqlmap_doc = _result("sqlmap", "http://victim/", [
            {"id": "sqlmap-id-GET", "Title": "SQL injection", "Severity": "HIGH"}])
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            (results / ("A" * 32 + ".json")).write_text(json.dumps(cme_doc), encoding="utf-8")
            (results / ("B" * 32 + ".json")).write_text(json.dumps(sqlmap_doc), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports, create=True),
                patch.object(self.server.secrets, "token_urlsafe", return_value="C" * 32),
            ):
                response = asyncio.run(self.server.internal_ad_report(""))
                self.assertEqual(f"/reports/{'C' * 32}.html", response)
                html = (reports / f"{'C' * 32}.html").read_text(encoding="utf-8")
        self.assertIn("WS01", html)
        self.assertNotIn("SQL injection", html)

    def test_empty_store_message(self):
        with tempfile.TemporaryDirectory() as root_text:
            results = Path(root_text) / "results"
            results.mkdir()
            with patch.object(self.server, "RESULTS_ROOT", results):
                response = asyncio.run(self.server.internal_ad_report(""))
        self.assertIn("No captured", response)


# --- R2: verdicts come from an exact observed token, never from a loose
# match or from silence (R1 blockers B1 + Spec-F3 and the sweep sites S4-S6) ---

# The OS banner is target-controlled free text and CME prints it BEFORE the real
# structured group. This host advertises a full fake group in its banner; the
# genuine trailing group says signing off / SMBv1 on.
CME_SPOOF = (
    "SMB         10.0.0.8    445    EVIL    "
    "[*] Windows 7 (name:SAFE) (domain:SAFE.LOCAL) (signing:True) (SMBv1:False) "
    "(name:EVIL) (domain:CORP.LOCAL) (signing:False) (SMBv1:True)\n"
)

# A host line that simply carries no signing/SMBv1 token at all.
CME_NO_FLAGS = (
    "SMB         10.0.0.9    445    HOST9    "
    "[*] Windows 10.0 Build 19041 x64 (name:HOST9) (domain:CORP.LOCAL)\n"
)

# A `[+]` line that is NOT an authentication success: no credential pair at all.
CME_NON_AUTH_PLUS = (
    "SMB         10.0.0.5    445    DC01    "
    "[*] Windows Server 2019 (name:DC01) (domain:CORP) (signing:True) (SMBv1:False)\n"
    "SMB         10.0.0.5    445    DC01    [+] Enumerated shares\n"
    "SMB         10.0.0.5    445    DC01    [+] Dumping password info for domain: CORP\n"
)


class AdsmbExactTokenTests(unittest.TestCase):
    """Every posture verdict must come from an exact token in the trailing
    structured group, tri-state where the token is absent."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_clip_boundary_cannot_be_used_to_forge_an_unambiguous_line(self):
        """The OS banner is unbounded and target-controlled, so the target picks
        where a clip falls. Pad so a forged group ends exactly at the clip and
        the genuine group falls past it: the line then looks unambiguous and the
        forged group is genuinely end-anchored. Over-length must read ambiguous."""
        fake = "(name:SAFE) (domain:SAFE.LOCAL) (signing:True) (SMBv1:False)"
        head = "SMB  10.0.0.9  445  WS01  [*] AAAA " + fake
        line = (head + " " * (self.server.MAX_CME_LINE - len(head))
                + " (name:WS01) (domain:CORP.LOCAL) (signing:False) (SMBv1:True)")
        host = next(f for f in self.server._parse_crackmapexec(line + "\n", "x")
                    if f.get("kind") == "host")
        self.assertEqual("not observed", host["signing"])
        self.assertIs(True, host["ambiguous"])

    def test_osc_escape_cannot_splice_or_erase_a_line(self):
        """`_strip_control_bytes` begins with an ANSI substitution whose OSC arm
        matches newlines. Run over the whole transcript it deleted from an ESC ]
        in one banner to a BEL in the next line, erasing a host or splicing
        another host's posture onto its IP. Normalizing PER LINE stops that."""
        text = ("SMB  10.0.0.9   445  WS01  [*] Win10\x1b]JUNK (name:WS01) "
                "(domain:CORP) (signing:False) (SMBv1:True)\n"
                "SMB  10.0.0.10  445  DC01  [*] \x07(name:DC01) (domain:CORP) "
                "(signing:True) (SMBv1:False)\n")
        hosts = {f["ip"]: f for f in self.server._parse_crackmapexec(text, "x")
                 if f.get("kind") == "host"}
        self.assertEqual({"10.0.0.9", "10.0.0.10"}, set(hosts),
                         "an OSC escape erased or spliced a host line")
        self.assertIs(False, hosts["10.0.0.9"]["signing"])
        self.assertIs(True, hosts["10.0.0.10"]["signing"])

    def test_unparsable_trailing_group_keeps_the_host_and_marks_it(self):
        """`(domain:..)` is target-controlled, so a `)` inside it makes the tail
        unparsable. Dropping the row silently erases an observed host and its
        weakness; the ambiguity branch exists so honesty does not cost
        visibility, and both branches must agree."""
        text = ("SMB  10.0.0.5  445  DC01  [*] W (name:DC01) (domain:CORP) "
                "(signing:True) (SMBv1:False)\n"
                "SMB  10.0.0.6  445  WS01  [*] W (name:WS01) (domain:CO)RP) "
                "(signing:False) (SMBv1:True)\n")
        hosts = {f["ip"]: f for f in self.server._parse_crackmapexec(text, "x")
                 if f.get("kind") == "host"}
        self.assertIn("10.0.0.6", hosts, "an unparsable tail silently erased the host")
        self.assertIs(True, hosts["10.0.0.6"]["ambiguous"])
        self.assertEqual("not observed", hosts["10.0.0.6"]["signing"])
        self.assertEqual("WS01", hosts["10.0.0.6"]["host"])   # from the tool's prefix

    def test_policy_label_must_own_the_whole_plus_line(self):
        """enum4linux prints other `[+]` lines carrying target text. The label
        has to own the line, not merely appear somewhere on one."""
        text = ("[+] Got domain/workgroup name: CORP Minimum password length: 14\n"
                "user:[jdoe] rid:[0x451]\n")
        f = next(x for x in self.server._parse_enum4linux(text, "t")
                 if x.get("kind") == "enum")
        self.assertEqual("not observed", f["policy"]["min_length"])

    def test_banner_spoofed_flags_yield_no_verdict(self):
        # Two structured groups on one line is ambiguous, and no positional rule
        # can pick the genuine one, so NOTHING is asserted. The spoofed
        # (signing:True)/(SMBv1:False) must not win; neither may a guess.
        host = next(f for f in self.server._parse_crackmapexec(CME_SPOOF, "10.0.0.8")
                    if f.get("kind") == "host")
        self.assertEqual("not observed", host["signing"])
        self.assertEqual("not observed", host["smbv1"])

    def test_ambiguous_line_still_reports_the_host_from_the_tool_prefix(self):
        # Honesty must not cost visibility: the host is still listed, using the
        # tool's own start-anchored columns, with the forgeable fields blank.
        host = next(f for f in self.server._parse_crackmapexec(CME_SPOOF, "10.0.0.8")
                    if f.get("kind") == "host")
        self.assertEqual("10.0.0.8", host["ip"])
        self.assertEqual("EVIL", host["host"])          # NetBIOS column, not (name:)
        self.assertEqual("", host["domain"])
        self.assertEqual("", host["os"])

    def test_absent_flag_is_not_observed_never_false(self):
        host = next(f for f in self.server._parse_crackmapexec(CME_NO_FLAGS, "10.0.0.9")
                    if f.get("kind") == "host")
        self.assertEqual("not observed", host["signing"])
        self.assertEqual("not observed", host["smbv1"])

    def test_share_comment_cannot_inject_a_password_policy(self):
        # A share COMMENT is target-controlled; it must not be read as policy.
        text = (
            " =========================( Share Enumeration on t )=========================\n"
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            "\tpublic          Disk      Minimum password length: 14\n")
        enum = next(f for f in self.server._parse_enum4linux(text, "t")
                    if f.get("kind") == "enum")
        self.assertEqual("not observed", enum["policy"]["min_length"])

    def test_real_policy_lines_still_parse(self):
        enum = next(f for f in self.server._parse_enum4linux(ENUM_TEXT, "10.0.0.5")
                    if f.get("kind") == "enum")
        self.assertEqual("7", enum["policy"]["min_length"])
        self.assertEqual("5", enum["policy"]["lockout"])


class AdsmbTristateRenderTests(unittest.TestCase):
    """An unobserved flag must never render, count, or map as a verdict."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _render_cme(self, text, target="t"):
        return self.server._render_report({
            "schema_version": 1, "report_type": "adsmb", "scanner": "combined",
            "source_type": "host", "target_ref": "x", "status": "success",
            "metadata": {}, "results": [
                _result("crackmapexec", target, self.server._parse_crackmapexec(text, target))],
        })

    def test_absent_flags_render_not_observed_not_a_verdict(self):
        # Scoped to the host's own posture row and the counters. "not required"
        # also occurs as a tile LABEL and in the static poisoning paragraph, so
        # a document-wide assertion would fail on prose rather than on a verdict.
        html = self._render_cme(CME_NO_FLAGS, "10.0.0.9")
        row = re.search(r"<tr><th scope=\"row\">HOST9</th>.*?</tr>", html, re.S)
        self.assertIsNotNone(row, "posture row for HOST9 missing")
        self.assertEqual(3, row.group(0).count("<td>not observed</td>"),
                         f"signing/SMBv1/null not all 'not observed': {row.group(0)}")
        for label in ("SMBv1 enabled", "Signing not required", "Null session"):
            self.assertIn(
                f'<span class="label meta">{label}</span><span class="num">0</span>', html,
                f"tile {label!r} counted an unobserved flag")

    def test_absent_flags_map_to_no_attack_technique(self):
        html = self._render_cme(CME_NO_FLAGS, "10.0.0.9")
        for tech in ("T1210", "T1557.001", "T1087.002"):
            self.assertNotIn(tech, html, f"{tech} mapped from an unobserved flag")

    def test_absent_flags_produce_no_remediation_item(self):
        html = self._render_cme(CME_NO_FLAGS, "10.0.0.9")
        self.assertIn("No observed SMB weakness to remediate", html)

    def test_spoofed_banner_maps_to_no_attack_technique(self):
        # An ambiguous line asserts nothing, so it must not reach the ATT&CK
        # legend in EITHER direction -- no forged "secure", no invented weakness.
        html = self._render_cme(CME_SPOOF, "10.0.0.8")
        for tech in ("T1210", "T1557.001", "T1087.002"):
            self.assertNotIn(tech, html, f"{tech} mapped from an ambiguous line")
        self.assertIn("No observed SMB weakness to remediate", html)

    def test_renderer_never_reads_a_tristate_field_for_truthiness(self):
        """Mechanical class check: a tri-state field read in a boolean context
        silently converts "not observed" into a verdict, which is exactly the
        R1 blocker. Every read must be `is True` / `is False` or `_adsmb_flag`.

        This is a LINT, not a proof. It covers `.get("x")`, `.get('x')` and
        `["x"]`/`['x']` spellings in this module; it cannot see an indirect key
        (`k = "smbv1"; h.get(k)`) or a consumer outside this file (red-team N9).
        It catches the regression that actually happened, cheaply, every run.

        Allowed idioms: `is True` / `is False`, `_adsmb_flag(...)`, and an
        explicit `==`/`!=` comparison. Equality is a value comparison, not a
        truthiness read. The cross-doc aggregation reads the flags through an
        INDIRECT key (`f.get(field)` where field is a loop variable), which this
        literal-key lint cannot see anyway. The bug this catches is IMPLICIT truthiness
        (`if h.get("signing")`), which does not NEED `==`/`!=`; a line that mixed
        a truthiness read with an unrelated `==` would slip through. As stated
        above, this is a cheap regression catch, not a proof."""
        source = Path(self.server.__file__).read_text(encoding="utf-8")
        field = r"""(?:\.get\(|\[)['"](signing|smbv1|null_bind)['"]"""
        offenders = [
            (n, line.strip())
            for n, line in enumerate(source.splitlines(), 1)
            if not line.strip().startswith("#")          # prose may quote the bug
            and re.search(field, line)
            # a WRITE (`hosts[ip]["null_bind"] = True`) is not a truthiness read
            and not re.search(r"""\[['"](signing|smbv1|null_bind)['"]\]\s*=[^=]""", line)
            and not re.search(r"\bis (True|False)\b|_adsmb_flag\(|==|!=", line)
        ]
        self.assertEqual([], offenders, f"truthiness read of a tri-state field: {offenders}")


class AdsmbShapeAndEscapingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _render(self, results):
        return self.server._render_report({
            "schema_version": 1, "report_type": "adsmb", "scanner": "combined",
            "source_type": "host", "target_ref": "x", "status": "success",
            "metadata": {}, "results": results,
        })

    def test_usernames_are_escaped_exactly_once(self):
        enum = self.server._parse_enum4linux(
            " =========================( Users on t )=========================\n"
            "user:[a<b>] rid:[0x451]\n", "t")
        html = self._render([_result("enum4linux", "t", enum)])
        self.assertIn("a&lt;b&gt;", html)
        self.assertNotIn("&amp;lt;", html)

    def test_shape_drifted_stored_finding_does_not_break_the_report(self):
        for drift in ({"policy": "garbage"}, {"users": "garbage"}, {"shares": "garbage"}):
            finding = {"kind": "enum", "id": "e", "Severity": "INFO",
                       "users": [], "shares": [], "policy": {}}
            finding.update(drift)
            html = self._render([_result("enum4linux", "t", [finding])])
            self.assertIn("AD/SMB", html, f"report failed on drifted shape {drift}")

    def test_raw_fallback_card_strips_ansi(self):
        findings = self.server._parse_crackmapexec(
            "\x1b[31mgarbage with no host line\x1b[0m", "t")
        self.assertTrue(all(f.get("kind") == "raw" for f in findings))
        self.assertNotIn("\x1b", findings[0]["evidence"])
        self.assertNotIn("[31m", findings[0]["evidence"])


class AdsmbWritePathTests(unittest.TestCase):
    """The SHIPPED path, not `_render_report` directly. `_write_report` renders
    `_redact_scanner_data(document)` first, and a finding KEY that matches
    `SECRET_KEY` has its value replaced with "[REDACTED]" before the renderer
    ever sees it. That silently destroyed an observed null bind: the parser was
    correct, every direct-render test passed, and the shipped report still said
    "not observed". Every honesty verdict needs one assertion on this path."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    OBSERVED = (
        "SMB  10.0.0.5  445  DC01  [*] Windows 10 (name:DC01) (domain:CORP) "
        "(signing:False) (SMBv1:True)\n")

    def _write(self, docs):
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results, reports = root / "results", root / "reports"
            results.mkdir()
            for letter, doc in zip("ABDEF", docs):
                (results / (letter * 32 + ".json")).write_text(
                    json.dumps(doc), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports, create=True),
                patch.object(self.server.secrets, "token_urlsafe", return_value="C" * 32),
            ):
                asyncio.run(self.server.internal_ad_report(""))
                return (reports / f"{'C' * 32}.html").read_text(encoding="utf-8")

    def test_raw_card_scanners_are_registered_for_transcript_dedupe(self):
        """Mechanical class check for the in-code law at `RAW_TRANSCRIPT_SCANNERS`
        ("keep this in step with the callers of `_raw_text_parser`"). A scanner
        whose parse-miss emits a whole-transcript card needs transcript identity:
        its id/Title are constant per (scanner, target) while the embedded
        `(truncated N additional lines)` counter drifts, so whole-content dedupe
        re-renders near-identical cards on every re-run (#48/#49)."""
        source = Path(self.server.__file__).read_text(encoding="utf-8")
        emitters = set(re.findall(r'_adsmb_raw_finding\(\s*"([a-z_0-9]+)"', source))
        emitters |= set(re.findall(r'_raw_text_parser\(\s*"([a-z_0-9]+)"', source))
        missing = sorted(emitters - set(self.server.RAW_TRANSCRIPT_SCANNERS))
        self.assertEqual([], missing,
                         f"raw-transcript emitter(s) absent from RAW_TRANSCRIPT_SCANNERS: {missing}")

    def test_no_finding_key_is_eaten_by_redaction(self):
        """Mechanical class check: a stored finding key matching SECRET_KEY has
        its VALUE destroyed on the write path. Catches the next `*_session`,
        `*_token`, `*_key` field before a reviewer has to."""
        findings = self.server._parse_crackmapexec(self.OBSERVED, "10.0.0.5")
        findings += self.server._parse_enum4linux(ENUM_TEXT, "10.0.0.5")
        eaten = sorted({k for f in findings if isinstance(f, dict) for k in f
                        if self.server.SECRET_KEY.search(k)})
        self.assertEqual([], eaten, f"finding key(s) redacted away on the write path: {eaten}")

    def test_observed_null_bind_survives_to_the_written_report(self):
        html = self._write([
            _result("crackmapexec", "10.0.0.5",
                    self.server._parse_crackmapexec(self.OBSERVED, "10.0.0.5")),
            _result("enum4linux", "10.0.0.5",
                    self.server._parse_enum4linux(ENUM_TEXT, "10.0.0.5")),
        ])
        self.assertNotIn("[REDACTED]", html)
        row = re.search(r"<tr><th scope=\"row\">DC01</th>.*?</tr>", html, re.S)
        self.assertIsNotNone(row, "posture row for DC01 missing")
        self.assertIn("<td>observed</td>", row.group(0),
                      "an OBSERVED null bind rendered as unobserved on the shipped path")
        self.assertIn(
            '<span class="label meta">Null session</span><span class="num">1</span>', html)
        self.assertIn("T1087.002", html)                      # ATT&CK reachable
        self.assertIn("Disable anonymous (null) sessions on", html)  # remediation reachable
        self.assertNotIn("null/guest sessions", html)  # only anonymous binds are observed (R7-B1-REMED)


class AdsmbParserScalingTests(unittest.TestCase):
    """Spec-F1: the bounded-regex claim is only real if it is measured. Gate on
    the scaling RATIO, never wall-clock (memory: wall-clock-perf-asserts-flake-on-ci)."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _ratio(self, build, parse):
        import time

        def elapsed(n):
            payload = build(n)
            start = time.perf_counter()
            parse(payload)
            return time.perf_counter() - start

        elapsed(1000)                    # warmup
        return elapsed(1000), elapsed(2000)

    def test_crackmapexec_scales_on_a_hostile_banner(self):
        t1, t2 = self._ratio(
            lambda n: ("SMB  10.0.0.5  445  H  [*] " + "(" * n
                       + " (name:H) (domain:D) (signing:False) (SMBv1:True)\n"),
            lambda text: self.server._parse_crackmapexec(text, "t"))
        self.assertLess(t2, t1 * 3.0 + 0.01, f"_parse_crackmapexec superlinear: {t1} -> {t2}")

    def test_enum4linux_bounds_the_regex_scan_at_the_clip(self):
        """RT-B5: the old timing test fed two payloads that both exceeded
        MAX_REDACT_CHARS, so the parser's clip made them byte-identical and the
        ratio was a constant 1.0 no matter how catastrophic the regex -- it
        pinned nothing. The real protection is the clip itself: content past it
        is never scanned. Pin THAT with an equality, not a wall clock -- a
        pathological tail beyond the bound must change nothing about the parse."""
        cap = self.server.MAX_ADSMB_TRANSCRIPT
        head = "user:[realuser] rid:[0x1]\n"
        pad = "x" * (cap * 2)                       # pushes the tail past the bound
        tail = "\nuser:[GHOST] rid:[0x2]\n"
        with_tail = self.server._parse_enum4linux(head + pad + tail, "t")
        without = self.server._parse_enum4linux(head + pad, "t")
        self.assertEqual(with_tail, without,
                         "content past MAX_ADSMB_TRANSCRIPT reached the regex scan")
        enum = [f for f in with_tail if isinstance(f, dict) and f.get("kind") == "enum"]
        self.assertTrue(enum, "expected an enum finding")
        self.assertIn("realuser", enum[0]["users"])
        self.assertNotIn("GHOST", enum[0]["users"],
                         "a user beyond the transcript bound was enumerated")


class AdsmbUnobservedNullBindTests(unittest.TestCase):
    """The other direction: with no enum4linux session check, nothing asserts."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_unobserved_null_bind_stays_unobserved_on_the_written_report(self):
        cme = ("SMB  10.0.0.5  445  DC01  [*] Windows 10 (name:DC01) (domain:CORP) "
               "(signing:False) (SMBv1:True)\n")
        doc = _result("crackmapexec", "10.0.0.5",
                      self.server._parse_crackmapexec(cme, "10.0.0.5"))
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results, reports = root / "results", root / "reports"
            results.mkdir()
            (results / ("A" * 32 + ".json")).write_text(json.dumps(doc), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports, create=True),
                patch.object(self.server.secrets, "token_urlsafe", return_value="C" * 32),
            ):
                asyncio.run(self.server.internal_ad_report(""))
                html = (reports / f"{'C' * 32}.html").read_text(encoding="utf-8")
        row = re.search(r"<tr><th scope=\"row\">DC01</th>.*?</tr>", html, re.S)
        self.assertIsNotNone(row)
        self.assertIn("<td>not observed</td>", row.group(0))
        self.assertNotIn("T1087.002", html)


class _ProcResult:
    """Minimal stand-in for execute_command's return (stdout/stderr/returncode)."""
    def __init__(self, stdout, stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


class AdsmbCaptureFullTests(unittest.TestCase):
    """RT-B4: the AD feeders run `out_args=None`, so before the fix the parser was
    handed `run_command`'s 200-line-truncated RETURN, and every host/user/share
    past line 200 vanished from the report while a green suite (no fixture over
    200 lines) said nothing. `capture_full` feeds the parser the whole transcript
    and leaves the operator return bounded. These run the REAL feeder tool through
    the capture seam with execute_command mocked."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _feed(self, coro_fn, stdout):
        captured = {}

        def spy(scanner, target, parse_fn, text, status):
            captured["text"] = text
            captured["findings"] = parse_fn(text)

        with (
            patch.object(self.server, "execute_command",
                         return_value=_ProcResult(stdout)),
            patch.object(self.server, "_capture_findings", side_effect=spy),
        ):
            operator = asyncio.run(coro_fn())
        return operator, captured

    def test_enum4linux_share_and_policy_past_line_200_are_parsed(self):
        # 250 user lines (>200 → truncation fires) THEN the share table and
        # password policy, exactly where a real large domain puts them. Kept under
        # MAX_REDACT_CHARS so the separate char-clip is not what this measures.
        users = "".join(f"user:[u{i:03d}] rid:[0x{i:04x}]\n" for i in range(250))
        transcript = (
            users
            + "\tSharename       Type      Comment\n"
            + "\t---------       ----      -------\n"
            + "\tfinance         Disk      Finance files\n\n"
            + "[+] Minimum password length: 7\n")
        operator, cap = self._feed(
            lambda: self.server.enum4linux_scan("10.0.0.5"), transcript)
        self.assertIn("truncated", operator, "operator return should stay bounded")
        enum = [f for f in cap["findings"] if f.get("kind") == "enum"]
        self.assertTrue(enum, "enum finding missing — parser saw the truncated text")
        self.assertEqual(len(enum[0]["users"]), 250,
                         "users past line 200 were lost")
        self.assertEqual(enum[0]["policy"]["min_length"], "7",
                         "password policy past line 200 was lost")
        self.assertTrue(any(s["name"] == "finance" for s in enum[0]["shares"]),
                        "share table past line 200 was lost")

    def test_crackmapexec_hosts_past_line_200_are_parsed(self):
        # A /24-style sweep: 250 host lines. Before the fix only ~200 reached the
        # posture spine, silently undercounting "Hosts assessed".
        transcript = "".join(
            f"SMB  10.0.{i // 256}.{i % 256}  445  H{i:03d}  [*] Windows "
            f"(name:H{i:03d}) (domain:CORP) (signing:True) (SMBv1:False)\n"
            for i in range(250))
        _operator, cap = self._feed(
            lambda: self.server.crackmapexec_scan("10.0.0.0/24"), transcript)
        hosts = [f for f in cap["findings"] if f.get("kind") == "host"]
        self.assertEqual(len(hosts), 250, "hosts past line 200 were dropped")

    def test_capture_full_off_keeps_the_sibling_truncation(self):
        """The fix is opt-in: a caller that does NOT pass capture_full still gets
        run_command's bounded text, so certified sibling parsers are untouched."""
        big = "".join(f"line{i}\n" for i in range(300))
        seen = {}
        with patch.object(self.server, "execute_command",
                          return_value=_ProcResult(big)):
            self.server._run_with_capture(
                ["x"], "amass", "d", 5, None,
                lambda text: seen.setdefault("text", text) or [])
        self.assertIn("truncated", seen["text"],
                      "a non-opted-in caller unexpectedly received full output")

    def test_a_huge_transcript_is_bounded_not_unbounded(self):
        """RT-B4-UNBOUNDED: capture_full removed the 200-line bound that used to
        cap parser cost; MAX_ADSMB_TRANSCRIPT is the replacement. 20k host lines
        (~1.8 MiB) must NOT yield 20k findings/an unbounded artifact."""
        transcript = "".join(
            f"SMB  10.{i // 65536}.{(i // 256) % 256}.{i % 256}  445  H{i}  [*] Win "
            f"(name:H{i}) (domain:C) (signing:True) (SMBv1:False)\n"
            for i in range(20000))
        self.assertGreater(len(transcript), self.server.MAX_ADSMB_TRANSCRIPT)
        hosts = [f for f in self.server._parse_crackmapexec(transcript, "t")
                 if isinstance(f, dict) and f.get("kind") == "host"]
        self.assertLess(len(hosts), 20000,
                        "the transcript bound did not cap an oversized parse")

    def test_char_cap_does_not_drop_a_real_domains_users_or_maps(self):
        """RT-B4-CHARCAP: capture_full fixed the 200-LINE cut, but the enum scans
        still clipped `flat` at MAX_REDACT_CHARS=8192 CHARS. This fixture's 500
        users are ~12 KB (25 chars/line), so ~170 of them and the share mappings
        after them were dropped by the old clip; a realistic longer user line
        (~46 chars) loses ~322. Parsed directly here (not through the seam) to
        isolate the char bound."""
        users = "".join(f"user:[u{i:03d}] rid:[0x{i:04x}]\n" for i in range(500))
        transcript = (
            users
            + "\tSharename       Type      Comment\n"
            + "\t---------       ----      -------\n"
            + "\tfinance         Disk      files\n\n"
            + "//10.0.0.5/finance\tMapping: OK\n")
        enum = [f for f in self.server._parse_enum4linux(transcript, "10.0.0.5")
                if f.get("kind") == "enum"][0]
        self.assertEqual(len(enum["users"]), 500,
                         "users past the old 8192-char clip were dropped")
        fin = [s for s in enum["shares"] if s["name"] == "finance"][0]
        self.assertEqual(fin["map"], "OK",
                         "a share mapping past the old 8192-char clip was dropped")


class AdsmbResumeR8Tests(unittest.TestCase):
    """RT-B1/B2/B3 and the R7-B1 rendered-claim check, from the R8 resume."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    # --- RT-B2: a decoy header must not defeat share-table excision ------------
    def test_a_decoy_header_cannot_defeat_share_table_excision(self):
        # sAMAccountName permits spaces, so a user "Sharename Type Comment"
        # satisfied the old bare-containment, first-match header test. With a
        # blank line after it the old table_stop halted immediately, so the
        # GENUINE table below was never excised and a malicious share row whose
        # name column reads "[+] Minimum password length: 14" leaked in as policy
        # (RT-B2, reopening A4). The rule-row anchor picks the real header.
        transcript = (
            "user:[Sharename Type Comment] rid:[0x1]\n"     # decoy header
            "\n"                                            # halts old table_stop
            "\tSharename       Type      Comment\n"         # genuine header
            "\t---------       ----      -------\n"
            "\t[+] Minimum password length: 14  Disk  x\n"  # malicious share row
            "\n")
        out = self.server._parse_enum4linux(transcript, "t")
        enum = [f for f in out if isinstance(f, dict) and f.get("kind") == "enum"][0]
        self.assertEqual(enum["policy"]["min_length"], "not observed",
                         "a decoy header defeated excision; a share row leaked as policy")

    def test_a_lone_user_named_like_the_header_makes_no_phantom_table(self):
        out = self.server._parse_enum4linux(
            "user:[Sharename Type Comment] rid:[0x1]\nuser:[realuser] rid:[0x2]\n", "t")
        enum = [f for f in out if isinstance(f, dict) and f.get("kind") == "enum"][0]
        self.assertEqual(enum["shares"], [],
                         "a header-shaped user with no rule row produced a phantom table")

    def test_genuine_header_with_rule_row_still_parses(self):
        out = self.server._parse_enum4linux(ENUM_TEXT, "10.0.0.5")
        enum = [f for f in out if isinstance(f, dict) and f.get("kind") == "enum"][0]
        self.assertTrue(any(s["name"] == "finance" for s in enum["shares"]),
                        "the rule-row anchor broke a genuine share table")
        self.assertEqual(enum["policy"]["min_length"], "7")

    # --- RT-B3: rows past the 500-share store cap are still EXCISED -------------
    def test_share_rows_past_the_500_cap_are_still_excised(self):
        # A `user:[...]` row sits among the table rows PAST the 500 store cap.
        # Before the fix, table_stop halted at the cap, so this row fell into the
        # excised-from text and `_ENUM_USER_RE` enumerated LEAK; after the fix
        # table_stop advances over the whole table so the row is excised. (An
        # earlier version of this test used a forged `[+] policy` row, which the
        # end-anchored policy regex can never match — it pinned nothing: R8-TEST-B3.)
        rows = "".join(f"\tshare{i:04d}       Disk      c{i}\n" for i in range(505))
        rows += "\tuser:[LEAK] rid:[0x9]  Disk  x\n"
        rows += "".join(f"\tshareB{i:04d}      Disk      c{i}\n" for i in range(5))
        transcript = (
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            + rows + "\n")
        out = self.server._parse_enum4linux(transcript, "t")
        enum = [f for f in out if isinstance(f, dict) and f.get("kind") == "enum"][0]
        self.assertLessEqual(len(enum["shares"]), 500, "store cap not enforced")
        self.assertNotIn("LEAK", enum["users"],
                         "a table row past the 500 cap leaked in as an enumerated user")

    # --- RT-B1: a repeated ip withholds verdicts (no silent overwrite) ----------
    def test_a_forged_second_line_for_an_ip_cannot_overwrite_a_verdict(self):
        # First line: a genuinely weak host (signing off). Second line: a forged
        # "secure" line for the SAME ip. Last-wins would render it signing-required.
        cme = (
            "SMB  10.0.0.5  445  DC01  [*] Windows (name:DC01) (domain:CORP) "
            "(signing:False) (SMBv1:True)\n"
            "SMB  10.0.0.5  445  DC01  [*] Windows (name:DC01) (domain:CORP) "
            "(signing:True) (SMBv1:False)\n")
        hosts = [f for f in self.server._parse_crackmapexec(cme, "10.0.0.5")
                 if isinstance(f, dict) and f.get("kind") == "host"]
        self.assertEqual(len(hosts), 1, "one ip should collapse to one row")
        h = hosts[0]
        self.assertTrue(h.get("ambiguous") is True,
                        "a repeated ip must be marked ambiguous")
        self.assertEqual(h.get("signing"), "not observed",
                         "a forged second line overwrote a real verdict")
        self.assertEqual(h.get("smbv1"), "not observed")

    def test_distinct_ips_are_not_treated_as_a_collision(self):
        cme = (
            "SMB  10.0.0.5  445  DC01  [*] Windows (name:DC01) (domain:CORP) "
            "(signing:False) (SMBv1:True)\n"
            "SMB  10.0.0.6  445  WS01  [*] Windows (name:WS01) (domain:CORP) "
            "(signing:True) (SMBv1:False)\n")
        hosts = [f for f in self.server._parse_crackmapexec(cme, "t")
                 if isinstance(f, dict) and f.get("kind") == "host"]
        self.assertEqual({h["signing"] for h in hosts}, {False, True},
                         "distinct ips lost their verdicts to a false collision")

    # --- R7-B1: the shipped exec paragraph tells the truth about null-session ---
    def test_exec_paragraph_states_the_true_null_session_source(self):
        cme = ("SMB  10.0.0.5  445  DC01  [*] Windows (name:DC01) (domain:CORP) "
               "(signing:False) (SMBv1:True)\n")
        doc = _result("crackmapexec", "10.0.0.5",
                      self.server._parse_crackmapexec(cme, "10.0.0.5"))
        html = _write_one(self.server, doc)
        exec_para = re.search(r'<section class="exec">.*?</section>', html, re.S).group(0)
        self.assertIn("enum4linux", exec_para,
                      "exec paragraph does not name the real null-session source")
        # the two false claims R7-B1 named must be gone
        self.assertNotIn("null-session posture are asserted only from a crackmapexec",
                         html)
        self.assertNotIn("guest/empty-credential success was seen", html)

    def test_counts_are_not_claimed_to_be_lower_bounds(self):
        cme = ("SMB  10.0.0.5  445  DC01  [*] Windows (name:DC01) (domain:CORP) "
               "(signing:False) (SMBv1:True)\n")
        doc = _result("crackmapexec", "10.0.0.5",
                      self.server._parse_crackmapexec(cme, "10.0.0.5"))
        html = _write_one(self.server, doc)
        self.assertNotIn("counts above are lower bounds", html,
                         "the false 'lower bounds' claim is still shipped (RT-B1)")
        # Pin the exact honest phrasing, so a mutation to "upper bounds" or
        # "lower bounds" also fails, not only the one forbidden string
        # (R8-TEST-DISCLOSURE).
        self.assertIn("neither upper nor lower bounds", html,
                      "the disclosure no longer states the counts are neither bound")
        self.assertIn("ANY IP", html,
                      "the disclosure no longer states a hostile host can forge any IP")

    # --- RT-B1-XDOC: a forged row in one scan doc cannot overwrite another -----
    def test_a_forged_row_in_one_doc_cannot_overwrite_a_genuine_row_in_another(self):
        real = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC01  [*] Win (name:DC01) (domain:C) "
            "(signing:False) (SMBv1:True)\n", "10.0.0.5")
        forged = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC01  [*] Win (name:DC01) (domain:C) "
            "(signing:True) (SMBv1:False)\n", "10.0.0.9")
        # Both orders: the cross-doc conflict for ip 10.0.0.5 must withhold, so a
        # forged scan doc can neither assert 'required' nor blank a real verdict.
        for a, b in ((real, forged), (forged, real)):
            html = _write_docs(self.server,
                               [_result("crackmapexec", "t1", a),
                                _result("crackmapexec", "t2", b)])
            self.assertIn("verdict withheld", html,
                          "cross-doc conflict for one ip was not withheld (RT-B1-XDOC)")
            row = re.search(r'<tr><th scope="row">DC01</th>.*?</tr>', html, re.S).group(0)
            self.assertIn("<td>not observed</td>", row,
                          "a forged scan doc's verdict survived cross-doc aggregation")
            self.assertNotIn("<td>required</td>", row)
            self.assertNotIn("<td>not required</td>", row)

    def test_an_ambiguous_row_after_a_clean_not_observed_row_stays_marked(self):
        # A clean line with NO signing/SMBv1 tokens has both verdicts "not
        # observed" and ambiguous=False; an ambiguous row for the same ip also has
        # "not observed" verdicts. Testing only `prev` let the tuples compare
        # equal, dropping the ambiguity marker (RT10-1). Either side ambiguous
        # must withhold+mark.
        clean = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC01  [*] Windows (name:DC01) (domain:C)\n", "10.0.0.5")
        amb = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC01  [*] W (name:DC01) (name:X) (domain:C) "
            "(signing:True)\n", "10.0.0.9")
        self.assertTrue(clean[0].get("ambiguous") is False)
        self.assertTrue(amb[0].get("ambiguous") is True)
        # Order is the whole point (the bug only bites CLEAN-first), and the
        # file-reload path does NOT preserve list order, so render with a
        # CONTROLLED results order directly.
        for label, order in (("clean-first", [clean, amb]), ("amb-first", [amb, clean])):
            doc = {"schema_version": 1, "report_type": "adsmb", "scanner": "combined",
                   "source_type": "host", "target_ref": "x", "status": "success",
                   "metadata": {}, "results": [
                       _result("crackmapexec", "t1", order[0]),
                       _result("crackmapexec", "t2", order[1])]}
            html = self.server._render_report(doc)
            self.assertIn("verdict withheld", html,
                          f"[{label}] an ambiguous row was dropped by an "
                          "identical-verdict clean row (RT10-1)")

    def _render_docs(self, docs):
        return self.server._render_report({
            "schema_version": 1, "report_type": "adsmb", "scanner": "combined",
            "source_type": "host", "target_ref": "x", "status": "success",
            "metadata": {}, "results": docs})

    def test_a_clean_not_observed_row_does_not_suppress_a_real_weakness(self):
        # B1: "not observed" is absence of evidence, NOT a contrary verdict. A
        # clean token-free row for an ip must not withhold a genuine
        # signing:False/SMBv1:True weakness observed in another scan doc.
        weak = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC01  [*] W (name:DC01) (domain:C) "
            "(signing:False) (SMBv1:True)\n", "10.0.0.5")
        tokenless = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC01  [*] W (name:DC01) (domain:C)\n", "10.0.0.9")
        self.assertTrue(tokenless[0].get("signing") == "not observed")
        for label, order in (("weak-first", [weak, tokenless]),
                             ("tokenless-first", [tokenless, weak])):
            html = self._render_docs([_result("crackmapexec", "t1", order[0]),
                                      _result("crackmapexec", "t2", order[1])])
            row = re.search(r'<tr><th scope="row">DC01</th>.*?</tr>', html, re.S).group(0)
            self.assertIn("<td>not required</td>", row,
                          f"[{label}] a token-free row suppressed a real weakness (B1)")
            self.assertIn("<td>enabled</td>", row, f"[{label}] SMBv1 weakness lost")
            self.assertIn("T1557.001", html, f"[{label}] ATT&CK weakness dropped")
            self.assertNotIn("verdict withheld", row,
                             f"[{label}] absence wrongly marked a conflict")

    def test_a_true_conflict_still_withholds_only_the_conflicting_field(self):
        # The forgery defence still holds: two DEFINITE values that disagree
        # withhold that field (and mark the row), while a field they AGREE on
        # keeps its verdict.
        a = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC01  [*] W (name:DC01) (signing:False) (SMBv1:True)\n", "1")
        b = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC01  [*] W (name:DC01) (signing:True) (SMBv1:True)\n", "2")
        html = self._render_docs([_result("crackmapexec", "t1", a),
                                  _result("crackmapexec", "t2", b)])
        row = re.search(r'<tr><th scope="row">DC01</th>.*?</tr>', html, re.S).group(0)
        self.assertIn("verdict withheld", row, "a real signing conflict was not marked")
        # signing conflicts (withheld) but SMBv1 agrees True (kept "enabled")
        self.assertIn("<td>enabled</td>", row, "an agreed SMBv1 verdict was needlessly withheld")

    def test_a_parse_miss_transcript_is_not_hidden_by_another_structured_scan(self):
        # B2: a raw parse-miss card used to render only when NO structured host
        # existed anywhere, so one scan's structured row hid another's transcript.
        raw = self.server._parse_crackmapexec("UNPARSED-CME-TRANSCRIPT-XYZ", "10.0.0.5")
        struct = self.server._parse_crackmapexec(
            "SMB  10.0.0.9  445  WS  [*] W (name:WS) (signing:True) (SMBv1:False)\n", "10.0.0.9")
        self.assertTrue(raw[0].get("kind") == "raw")
        html = self._render_docs([_result("crackmapexec", "t1", raw),
                                  _result("crackmapexec", "t2", struct)])
        self.assertIn("UNPARSED-CME-TRANSCRIPT-XYZ", html,
                      "a captured parse-miss transcript was dropped when another scan parsed (B2)")

    def test_conflicting_password_policy_is_marked_not_silently_first_wins(self):
        # B3: two enum docs disagreeing on a policy field must not silently pick
        # one; the field reads "conflicting across scans — verify".
        weak = self.server._parse_enum4linux("[+] Minimum password length: 1\n", "10.0.0.5")
        strong = self.server._parse_enum4linux("[+] Minimum password length: 14\n", "10.0.0.9")
        for label, order in (("weak-first", [weak, strong]),
                             ("strong-first", [strong, weak])):
            html = self._render_docs([_result("enum4linux", "10.0.0.5", order[0]),
                                      _result("enum4linux", "10.0.0.9", order[1])])
            policy = re.search(r"Minimum password length</th>.*?</tr>", html, re.S).group(0)
            self.assertIn("conflicting across scans", policy,
                          f"[{label}] a policy disagreement was silently first-wins (B3)")
            self.assertNotIn(">1<", policy)
            self.assertNotIn(">14<", policy)

    def test_transcript_clip_lands_on_a_line_boundary(self):
        cap = self.server.MAX_ADSMB_TRANSCRIPT
        text = "a" * (cap - 5) + "\n" + "FORGED_PARTIAL_LINE_WITH_NO_NEWLINE"
        out = self.server._clip_adsmb_transcript(text)
        self.assertNotIn("FORGED", out,
                         "a truncated final line survived the transcript clip")
        self.assertTrue(out.endswith("\n"), "clip did not land on a line boundary")

    def test_an_agreed_weakness_survives_a_conflict_on_a_different_field(self):
        # codex-B1: three docs for one ip. signing conflicts (A=False, B=True) but
        # SMBv1 is agreed True by all three. The old pairwise merge marked the row
        # ambiguous on the signing conflict, then a third doc's "withhold all"
        # branch suppressed the AGREED SMBv1 weakness (tile 0, no T1210). Order-
        # independent accumulate must keep SMBv1 enabled while withholding signing.
        A = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC  [*] W (name:DC) (signing:False) (SMBv1:True)\n", "1")
        B = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC  [*] W (name:DC) (signing:True) (SMBv1:True)\n", "2")
        C = self.server._parse_crackmapexec(
            "SMB  10.0.0.5  445  DC  [*] W (name:DC) (signing:True) (SMBv1:True)\n", "3")
        import itertools
        for order in itertools.permutations([("d1", A), ("d2", B), ("d3", C)]):
            html = self._render_docs([_result("crackmapexec", t, f) for t, f in order])
            row = re.search(r'<tr><th scope="row">DC</th>.*?</tr>', html, re.S).group(0)
            names = [t for t, _ in order]
            self.assertIn("<td>enabled</td>", row,
                          f"{names}: an agreed SMBv1 weakness was suppressed by a signing conflict (codex-B1)")
            self.assertIn("T1210", html, f"{names}: SMBv1 ATT&CK technique dropped")
            self.assertIn("verdict withheld", row, f"{names}: the signing conflict was not marked")

    def test_a_malformed_host_line_in_a_mixed_transcript_is_surfaced(self):
        # codex-B2: one transcript, one malformed host line + one good line. The
        # malformed line (host prefix, no parseable tail) must surface as an
        # AMBIGUOUS host, not be silently dropped because another line parsed.
        transcript = (
            "SMB  10.0.0.5  445  LOST  [*] malformed-tail-with-no-name\n"
            "SMB  10.0.0.6  445  GOOD  [*] W (name:GOOD) (domain:C) "
            "(signing:True) (SMBv1:False)\n")
        hosts = {f.get("ip"): f for f in self.server._parse_crackmapexec(transcript, "t")
                 if isinstance(f, dict) and f.get("kind") == "host"}
        self.assertIn("10.0.0.5", hosts,
                      "a malformed host line was dropped when another line parsed (codex-B2)")
        self.assertIs(hosts["10.0.0.5"].get("ambiguous"), True,
                      "the malformed host line was not marked ambiguous")
        self.assertIn("10.0.0.6", hosts)
        self.assertIs(hosts["10.0.0.6"].get("ambiguous"), False)


def _write_one(server, doc):
    """Render one result doc through the SHIPPED write path and return the HTML."""
    return _write_docs(server, [doc])


def _write_docs(server, docs):
    """Render several result docs through the SHIPPED write path; return the HTML."""
    with tempfile.TemporaryDirectory() as root_text:
        root = Path(root_text)
        results, reports = root / "results", root / "reports"
        results.mkdir()
        for letter, doc in zip("ABDEFGHIJK", docs):
            (results / (letter * 32 + ".json")).write_text(
                json.dumps(doc), encoding="utf-8")
        with (
            patch.object(server, "RESULTS_ROOT", results),
            patch.object(server, "REPORTS_ROOT", reports, create=True),
            patch.object(server.secrets, "token_urlsafe", return_value="C" * 32),
        ):
            asyncio.run(server.internal_ad_report(""))
            return (reports / f"{'C' * 32}.html").read_text(encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
