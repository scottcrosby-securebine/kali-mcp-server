#!/usr/bin/env python3
"""Base-versus-head differential over every finding-producing parser (#27).

Three prior fixes to the redaction helpers each hit their target and silently
broke shipped behaviour, and a fully green suite hid all three, because every
redaction test asserted only that a secret was ABSENT -- never that legitimate
content SURVIVED. This runs one corpus through both module versions and
classifies in BOTH directions, per parser.

Deliberately NOT named test_*.py: `unittest discover -s tests` must not collect
it. Run it directly; the exit status is the gate.
"""

import argparse
import importlib.util
import itertools
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from server_test_support import load_server  # noqa: E402  (needs REPO on sys.path)

# The revision this change is measured against. Overridable, because a gate that
# hardcodes one commit silently compares against an ever-staler base as main moves.
DEFAULT_BASE = "b3ca7e1"


def _load(path, name):
    """Load one server copy under its own module name so both can coexist."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _xml(value):
    """Escape a probe value for an XML attribute without changing its shape."""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _lines(payload, prefix=""):
    """Re-emit a payload one line per record, for the line-oriented parsers."""
    return "\n".join(prefix + line for line in payload.splitlines())


# Each entry wraps the payload in that parser's REAL input format, in the
# fields scanner-controlled text actually reaches. Shapes follow the probes in
# tests/test_scanner_adapters.py so the two stay recognisably the same corpus.
# Neutral key names throughout: a key matching SECRET_KEY blanket-redacts its
# value and would measure the key rule rather than the value patterns.
EMBED = {
    "_parse_nmap_xml": lambda p: (
        '<nmaprun><host><ports><port portid="80" protocol="tcp"><state state="open"/>'
        '<service name="http" product="nginx" version="1.18"/>'
        f'<script id="probe" output="{_xml(p)}"/></port></ports></host></nmaprun>'),
    "_raw_text_parser": lambda p: p,
    "_parse_dnsrecon_json": lambda p: json.dumps(
        [{"arguments": "m"}, {"type": "A", "name": p, "address": "10.0.0.5"}]),
    "_parse_amass_text": lambda p: _lines(p),
    "_parse_subdomain_lines": lambda p: _lines(p),
    "_parse_whatweb_json": lambda p: json.dumps(
        [{"target": "t", "plugins": {"tech": {"k": p, "nested": [p]}}}]),
    "_parse_nikto_json": lambda p: json.dumps(
        {"vulnerabilities": [{"OSVDB": "3092", "msg": p, "url": p}]}),
    "_parse_ffuf_json": lambda p: json.dumps(
        {"results": [{"url": p, "status": 200, "length": 10, "words": 2}]}),
    "_parse_wafw00f_json": lambda p: json.dumps(
        [{"detected": True, "firewall": p, "manufacturer": p}]),
    "_parse_paths_text": lambda p: _lines(p, "/"),
    "_parse_sslscan_xml": lambda p: (
        f'<document><ssltest><cipher status="accepted" sslversion="TLSv1.2" '
        f'bits="128" cipher="{_xml(p)}"/></ssltest></document>'),
    "_parse_testssl_json": lambda p: json.dumps(
        [{"id": "probe", "severity": "HIGH", "finding": p}]),
    "_parse_sslyze_json": lambda p: json.dumps({"server_scan_results": [{"scan_result": {
        "tls_1_2_cipher_suites": {"result": {"accepted_cipher_suites": [{"cipher_suite": {"name": p}}]}}}}]}),
}

KEEP_HEADERS = ("Server: nginx/1.18.0", "Content-Type: text/html",
                "X-Frame-Options: DENY", "Location: /login")
HEADER_KEEPS = ("nginx/1.18.0", "text/html", "DENY", "/login")
PORTED = "https://portsafe.example:8443"
# Each terminator gets its own sample so the table names the one that broke.
TERMINATORS = {
    "slash": "/status", "query": "?a=1", "fragment": "#top", "doublequote": '"',
    "singlequote": "'", "comma": ",", "semicolon": ";", "paren": ")", "bracket": "]",
    "space": " next", "tab": "\tnext", "end-of-string": "", "backslash-n": "\\n",
}

# (name, payload, secrets that must NOT survive, legitimate values that MUST)
CORPUS = [
    # AMASS_ASSET fullmatches one bare token, so this is the ONLY corpus shape
    # amass's own format can carry -- without it that lane has no keep coverage
    # at all and would sit at two findings from the JWT samples.
    ("bare-asset-tokens", "corp.portsafe.example\n2001:db8::1",
     (), ("corp.portsafe.example", "2001:db8::1")),
    ("url-cred-orphan", "https://svc:PWLEAKA", ("PWLEAKA",), ()),
    # NO keep token, deliberately. An orphan-guard redaction truncates to
    # end-of-value BY DESIGN: once the closing anchor is gone there is no way to
    # know where the secret ends. So the email BELOW the orphan cannot survive
    # unless the password above it leaks, and asserting both is asserting a
    # state that no implementation can reach. On base the email "survived" only
    # because `PWLEAKB` leaked -- the pair was measuring the bug, not a
    # requirement. `whois-record` below is the control: an abuse address with no
    # orphan above it must still survive, and does in 12 of the 13 parsers --
    # `_parse_amass_text` is the exception and drops it for a FORMAT reason,
    # since AMASS_ASSET fullmatches one bare token and no multi-line record can
    # exist in amass output at all.
    ("url-cred-orphan-then-email",
     "https://svc:PWLEAKB\nRegistrar Abuse Contact Email: abuse@registrar.example",
     ("PWLEAKB",), ()),
    ("url-cred-complete", "https://svc:PWLEAKC@host.example/x", ("PWLEAKC",), ("host.example",)),
    ("ipv6-url-with-port", "https://[2001:db8::1]:8443/status", (), ("db8::1]:8443",)),
    ("jwt-orphan", "eyJhbGciOiJIUzI1NiJ9.PAYLOADLEAK", ("PAYLOADLEAK",), ()),
    ("jwt-complete", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKIn0.SIGLEAKA", ("SIGLEAKA",), ()),
    ("pem-pair-upper",
     "-----BEGIN PRIVATE KEY-----\nKEYBODYLEAKA\n-----END PRIVATE KEY-----\n" + KEEP_HEADERS[0],
     ("KEYBODYLEAKA",), (HEADER_KEEPS[0],)),
    ("pem-pair-lower",
     "-----begin private key-----\nkeybodyleakb\n-----end private key-----\n" + KEEP_HEADERS[0],
     ("keybodyleakb",), (HEADER_KEEPS[0],)),
    ("pem-unpaired",
     "-----BEGIN PRIVATE KEY-----\nKEYBODYLEAKC\n" + KEEP_HEADERS[0],
     ("KEYBODYLEAKC",), (HEADER_KEEPS[0],)),
    ("pem-after-keyword",
     "password: -----BEGIN PRIVATE KEY-----\nKEYBODYLEAKD\n-----END PRIVATE KEY-----\n" + KEEP_HEADERS[0],
     ("KEYBODYLEAKD",), (HEADER_KEEPS[0],)),
    ("signed-cookie-and-headers",
     "Set-Cookie: session=HDRPART.SIGLEAKB\n" + "\n".join(KEEP_HEADERS),
     ("SIGLEAKB",), HEADER_KEEPS),
    ("whois-record",
     "Registrar URL: https://www.registrar.example\n"
     "Registrar Abuse Contact Email: abuse@registrar.example\n"
     "Name Server: NS1.EXAMPLE.NET\nName Server: NS2.EXAMPLE.NET",
     (), ("www.registrar.example", "abuse@registrar.example", "NS1.EXAMPLE.NET", "NS2.EXAMPLE.NET")),
    ("nbtscan-name-table",
     "NetBIOS Name Table for Host 10.0.0.5\n"
     "Name             Service          Type\n"
     "WORKGROUP        <00>             GROUP\n"
     "FILESRV          <20>             UNIQUE",
     (), ("WORKGROUP", "FILESRV", "UNIQUE")),
    ("msfconsole-module-list",
     "Matching Modules\n"
     "   #  Name                              Rank    Description\n"
     "   0  auxiliary/scanner/smb/smb_version  normal  SMB Version Detection",
     (), ("auxiliary/scanner/smb/smb_version", "SMB Version Detection")),
    # The MAX_REDACT_CHARS cap itself puts the closing `@` out of reach, so the
    # cap is what orphans the anchor. The keep sits BEFORE the secret: anything
    # after an orphaned opener is cut by design, so a keep behind it would only
    # measure that design decision again.
    ("over-max-redact-chars",
     "PREFIXKEEP\nhttps://svc:LONGPWLEAK" + "P" * 9000 + "@host.example/x",
     ("LONGPWLEAK",), ("PREFIXKEEP",)),
]
CORPUS += [(f"ported-url-{label}", PORTED + tail, (), ("portsafe.example:8443",))
           for label, tail in TERMINATORS.items()]
# The corpus reported zero regressions on a revision that leaked in 152 shapes,
# because it carried no keyword-introduced URL and no bracketed userinfo. Both
# are here now. A fixed corpus only ever measures what someone thought to write
# down, which is why `sweep` below exists beside it.
CORPUS += [
    ("keyword-value-is-a-plain-url", "password: http://svc.example/cb?k=KWURLLEAK", ("KWURLLEAK",), ()),
    ("keyword-value-is-a-vault-url", "api_key: https://vault.example/s/KWVAULTLEAK", ("KWVAULTLEAK",), ()),
    ("keyword-value-is-a-credential-url", "token: https://svc:KWCREDLEAK@host.example/x", ("KWCREDLEAK",), ()),
    ("bracket-in-userinfo", "https://us[er:BRACKETLEAKA@host.example/x", ("BRACKETLEAKA",), ()),
    ("close-bracket-in-userinfo", "https://us]er:BRACKETLEAKB@host.example/x", ("BRACKETLEAKB",), ()),
]

# Every shape the sweep below builds. A secret that survives HEAD but not BASE is
# a regression whatever the combination, so this does not depend on anyone having
# imagined the combination first.
SWEEP_TOKEN = "ZQSWEEPZQ"
SWEEP_KEYWORDS = ("", "password: ", "api_key: ", "token: ", "authorization: ",
                  "secret=", "Set-Cookie: session=", "cookie: ")
SWEEP_BODIES = (
    f"http://svc.example/cb?k={SWEEP_TOKEN}", f"https://vault.example/s/{SWEEP_TOKEN}",
    f"https://svc:{SWEEP_TOKEN}@host/x", f"https://svc:{SWEEP_TOKEN}",
    f"https://us[er:{SWEEP_TOKEN}@host/x", f"https://us]er:{SWEEP_TOKEN}@host/x",
    f"ftp://u:{SWEEP_TOKEN}@h/x", f"eyJhbGciOiJIUzI1NiJ9.{SWEEP_TOKEN}",
    f"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.{SWEEP_TOKEN}",
    f"-----BEGIN PRIVATE KEY-----\n{SWEEP_TOKEN}",
    f"-----BEGIN PRIVATE KEY-----\n{SWEEP_TOKEN}\n-----END PRIVATE KEY-----",
    f"Bearer {SWEEP_TOKEN}", f"Basic {SWEEP_TOKEN}", f"ghp_{SWEEP_TOKEN}AAAAAAAAAAAAAAAAAAAA",
    f"?access_token={SWEEP_TOKEN}", SWEEP_TOKEN,
)
SWEEP_TAILS = ("", "\nName Server: NS1", " trailing text", "\n")

BUCKETS = {
    "LEAK CLOSED": "closed", "LEAK OPENED": "opened",
    "CONTENT PRESERVED": "presvd", "CONTENT DESTROYED": "destrd",
    "SECRET STILL PRESENT IN BOTH": "leak2", "KEEP STILL MISSING IN BOTH": "gone2",
}
REGRESSIONS = ("LEAK OPENED", "CONTENT DESTROYED")
# The two "IN BOTH" buckets are a standing defect neither version fixes, and
# they hit most parsers at once. Print them collapsed to one line per (sample,
# token) with the parser count; the per-parser detail is in --json.
COLLAPSED = ("SECRET STILL PRESENT IN BOTH", "KEEP STILL MISSING IN BOTH")


def _parsers(module):
    """Name -> callable(text) for every finding-producing parser in one copy."""
    bound = {name: getattr(module, name) for name in EMBED if name != "_raw_text_parser"}
    bound["_raw_text_parser"] = module._raw_text_parser("whois", "target.example")
    return bound


def run(base, head):
    base_parsers, head_parsers = _parsers(base), _parsers(head)
    rows = {name: {"findings_base": 0, "findings_head": 0, **{bucket: [] for bucket in BUCKETS}}
            for name in EMBED}
    for name, row in rows.items():
        for sample, payload, secrets, keeps in CORPUS:
            text = EMBED[name](payload)
            base_findings, head_findings = base_parsers[name](text), head_parsers[name](text)
            row["findings_base"] += len(base_findings)
            row["findings_head"] += len(head_findings)
            base_out, head_out = json.dumps(base_findings), json.dumps(head_findings)
            for token in secrets:
                in_base, in_head = token in base_out, token in head_out
                if in_base and not in_head:
                    row["LEAK CLOSED"].append((sample, token))
                elif in_head and not in_base:
                    row["LEAK OPENED"].append((sample, token))
                elif in_base and in_head:
                    row["SECRET STILL PRESENT IN BOTH"].append((sample, token))
            for token in keeps:
                in_base, in_head = token in base_out, token in head_out
                if in_head and not in_base:
                    row["CONTENT PRESERVED"].append((sample, token))
                elif in_base and not in_head:
                    row["CONTENT DESTROYED"].append((sample, token))
                elif not in_base and not in_head:
                    row["KEEP STILL MISSING IN BOTH"].append((sample, token))
    return rows


def sweep(base, head):
    """Every combination, not just the ones someone wrote down.

    The corpus above is a fixed list, so it can only catch a regression in a
    shape its author already imagined -- and the first attempt at this fix
    passed it while leaking in 152 combinations. This walks the product of
    keyword prefix, secret body and trailing text through the composed public
    path and reports any token BASE removed that HEAD leaves behind. It is the
    mechanical check for that whole class rather than for two instances of it.
    """
    def path(module, text):
        return module._clip(module._safe_scanner_value(text), module.MAX_EVIDENCE_CHARS)

    leaked = []
    for keyword, body, tail in itertools.product(SWEEP_KEYWORDS, SWEEP_BODIES, SWEEP_TAILS):
        text = keyword + body + tail
        if SWEEP_TOKEN not in path(base, text) and SWEEP_TOKEN in path(head, text):
            leaked.append((keyword, body, tail))
    total = len(SWEEP_KEYWORDS) * len(SWEEP_BODIES) * len(SWEEP_TAILS)
    print(f"\nSWEEP: {total} combinations, {len(leaked)} leak on head that base redacted")
    for keyword, body, tail in leaked[:20]:
        print(f"  {keyword!r} + {body!r} + {tail!r}")
    if len(leaked) > 20:
        print(f"  ... and {len(leaked) - 20} more")
    return leaked


def report(rows):
    width = max(len(name) for name in rows)
    header = f"{'parser'.ljust(width)}  base  head  " + "  ".join(
        label.rjust(6) for label in BUCKETS.values())
    print(header)
    print("-" * len(header))
    for name, row in sorted(rows.items()):
        print(f"{name.ljust(width)}  {row['findings_base']:>4}  {row['findings_head']:>4}  "
              + "  ".join(str(len(row[bucket])).rjust(6) for bucket in BUCKETS))
    print("\nlegend: base/head = findings produced over the whole corpus; "
          + ", ".join(f"{label}={bucket}" for bucket, label in BUCKETS.items()))

    for bucket in BUCKETS:
        hits = [(name, sample, token) for name, row in sorted(rows.items())
                for sample, token in row[bucket]]
        print(f"\n{bucket}: {len(hits)}")
        if bucket in COLLAPSED:
            collapsed = {}
            for name, sample, token in hits:
                collapsed.setdefault((sample, token), []).append(name)
            for (sample, token), names in collapsed.items():
                print(f"  {sample}  {token[:60]}  ({len(names)} parsers)")
        else:
            for name, sample, token in hits:
                print(f"  {name}  {sample}  {token[:60]}")

    empty = sorted(name for name, row in rows.items() if not row["findings_head"] or not row["findings_base"])
    if empty:
        print(f"\nPARSERS THAT PRODUCED NOTHING (the corpus did not exercise them): {empty}")
    regressions = sum(len(row[bucket]) for row in rows.values() for bucket in REGRESSIONS)
    print(f"\nsamples={len(CORPUS)} parsers={len(rows)} regressions={regressions} empty_parsers={len(empty)}")
    return 1 if regressions or empty else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", help="write the full classified result here")
    parser.add_argument("--base", default=DEFAULT_BASE,
                        help=f"revision to measure against (default {DEFAULT_BASE})")
    args = parser.parse_args()

    load_server()  # reuse the repo's FastMCP stub install; its module is discarded
    with tempfile.TemporaryDirectory() as tmp:
        base_path = Path(tmp) / "base_kali_pentest_server.py"
        base_path.write_bytes(subprocess.run(
            ["git", "show", f"{args.base}:kali_pentest_server.py"],
            cwd=REPO, check=True, stdout=subprocess.PIPE).stdout)
        base = _load(base_path, "kali_pentest_server_base")
    head = _load(REPO / "kali_pentest_server.py", "kali_pentest_server_head")
    print(f"base={args.base}  head={REPO / 'kali_pentest_server.py'}\n")

    rows = run(base, head)
    status = report(rows)
    leaked = sweep(base, head)
    status = status or (1 if leaked else 0)
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"base_commit": args.base, "exit_status": status,
             "sweep_leaks": leaked, "parsers": rows},
            indent=2, sort_keys=True), encoding="utf-8")
    return status


if __name__ == "__main__":
    sys.exit(main())
