# Field-reported fixes — parallel wave A

Spec and anchor for the fixes to nine issues reported from live container runs
on 2026-08-27 (#30-#38). This file is the doctrine anchor: it records the
user's decisions verbatim and the acceptance criteria every wave agent and
every review is judged against.

## Anchor — the user's own words

> "Can you use a multi-subagent building process using doctrine skills to
> attack multiple issues at one time as opposed to doing it serial?"

Decisions taken by the user before wave 1 opened:

- **D1 — #31 authorized to break the text-byte-unchanged invariant.**
  "Yes, break it — do #31 last." `run_command` may return `❌` where it
  previously returned `⚠️`. This is a deliberate, authorized reversal of the
  HARD invariant that capture waves 1-5 were built to honour. It ships last,
  in its own wave, in PR B, so it can be reverted independently.
- **D2 — enhancements are in scope.** "Both in": #32 and #35 ship alongside
  the correctness fixes, notwithstanding the standing only-true-bugs rule,
  because in both cases the natural caller invocation errors out.
- **D3 — two PRs.** PR A = wave 1 (the six independent tool fixes).
  PR B = wave 2 (renderer: #37, #38) + wave 3 (#31).

## Verification performed before wave 1

Every issue was re-verified against the working tree at `19982e9`. One did not
survive:

- **#33 primary claim is STALE.** It reports that `_parse_nmap_xml` emits
  findings only from NSE `<script>` elements and that `nmap_service_scan`
  captures 0 findings. The per-open-port INFO block was added in `89f8703`
  (P2 wave 4) and is present on `main`. A direct probe of `_parse_nmap_xml`
  against a 4-port `-sV` XML returns 3 findings carrying `product` and
  `version`, with the closed port correctly skipped. The reporter's live run
  used a container image built before wave 4 merged. **No fix is required for
  the primary claim.** Only #33's secondary item is in scope (see A2).

The remaining eight were confirmed. #37 and #38 were confirmed by executing
the renderer, not by reading it.

## Test seams (fixed before wave 1; do not invent others)

The repo's existing convention, unchanged:

- `unittest`, discovered by `python3 -m unittest discover -s tests`.
- Load the server through `tests/server_test_support.py`'s `load_server()`.
- Patch at the `run_command` / `execute_command` seam. Never spawn a real
  binary and never reach the network in a test.
- **Each wave agent writes its tests to its own new file,
  `tests/test_issue_<N>.py`.** No agent appends to an existing test file.
  This keeps the test-side merge surface at zero.
- Regressions found by a REVIEW rather than by an issue go in
  `tests/test_wave<N>_gate.py`, since they span several issues and belong to
  no single one.
- `tests/fixtures/legacy_tool_contract.json` MUST NOT change in wave 1 or
  wave 2. Wave 3 (#31) may change only what D1 authorizes.

## Wave 1 — six independent fixes (PR A)

Each lands in one function, hundreds of lines from the others.

### A1 — #30 `testssl_scan` argv order
`kali_pentest_server.py:2072`. Effective argv today is
`testssl --fast --severity HIGH host:443 --jsonfile /tmp/x.json`, and
testssl.sh aborts with `Fatal error: URI comes last`. The tool fails on every
target.

**Required:** the URI is the final argv element and `--jsonfile <path>`
precedes it. Capture behaviour, the scanner label `testssl`, the target_ref
`host:port`, and the parse function are unchanged.

**Acceptance:** a test asserts the built argv ends with `host:port` and
contains `--jsonfile` before it; capture still produces a normalized result.

### A2 — #33 secondary: `nmap_port_scan` bare target
`kali_pentest_server.py:1352`. Returns
`❌ Error: Port specification required` when `ports` is empty, while
`nmap_service_scan` and `nmap_comprehensive_scan` work from a bare target.

**Required:** an empty `ports` defaults to a sensible range consistent with
its siblings (`--top-ports=100`, matching `nmap_service_scan`) rather than
erroring. An explicit `ports` value keeps its current behaviour exactly.

**Acceptance:** a test asserts a bare target builds a valid command and does
not return an error string; an explicit port spec is unaffected.

**Out of scope:** `_parse_nmap_xml`. It is already correct.

### A3 — #34 `nuclei_scan` zero-template hard failure
`kali_pentest_server.py:1859`. A `severity` value that matches none of the
promoted templates makes nuclei exit FTL
(`no templates provided for scan`), and the tool returns `❌ Error:` with
nuclei's full ASCII banner embedded.

**Required:**
1. A selection yielding zero templates returns a clear, self-explanatory
   message naming the severity and the promoted-set size, not nuclei's FTL.
2. nuclei's ASCII banner is stripped from error output.
3. The nuclei config dir is pre-created so the
   `Could not read nuclei-ignore file` error stops.

Expanding the promoted template set is **out of scope** — that is #25.

**Acceptance:** tests cover a zero-template selection and assert the message
names the severity and the set size and contains no banner art.

### A4 — #36 `web_headers` scheme and port
`kali_pentest_server.py:1923`. A bare host is forced to `http://`, so an
HTTPS service is never audited; `host:port` sends HTTP to :443 and returns
400.

**Required:** a bare host resolves to the scheme its port implies, defaulting
to HTTPS rather than HTTP; `host:443` is treated as HTTPS; an explicit
`http://` or `https://` prefix is always honoured unchanged.

**Acceptance:** a table test covers bare host, `http://`, `https://`, IP,
`host:443`, and `host:8080`, asserting the URL curl receives for each.

### A5 — #35 trivy/syft `source_type` discoverability
`kali_pentest_server.py:190-191, 2514, 2539`. `source_type="image"` is
rejected and neither the docstring nor the error names the valid set.

**Required:** the error message lists the accepted values, for trivy and for
syft. Docstrings name them too. Docstrings stay **one line** — the MCP client
shows that line verbatim.

**Acceptance:** tests assert the rejection message contains every accepted
value for both tools.

**Note:** aliasing `image` to `registry` is NOT required. If an agent
proposes it, it must be justified against the ambiguity between a remote
registry ref and a mounted archive path.

### A6 — #32 `ffuf_scan`/`wfuzz_scan` FUZZ placeholder
`kali_pentest_server.py:1748, 1792`. Both reject a plain target; the sibling
`gobuster_scan`/`dirb_scan` accept one.

**Required:** a target with no `FUZZ` is treated as a host or base URL and
fuzzed at `<base>/FUZZ`, applying the same scheme defaulting the tool already
uses. An explicit `FUZZ` anywhere in the target keeps today's behaviour
exactly, including fuzzing a non-path position.

**Acceptance:** tests cover bare host, base URL with and without a trailing
slash, and an explicit-FUZZ target in a query-parameter position.

## Wave 2 — renderer (PR B)

Both land inside `_render_report` (`:586`), ~30 lines apart. One unit.

### B1 — #37 dedupe collapses distinct findings
`render_combined`'s `seen` set keys on
`(scanner, target, id)`. nikto reuses test id `013587` for every
missing-header result. **Confirmed by execution: 5 input findings render as 2
articles.**

**Required:** dedupe removes true duplicates without collapsing distinct
findings that share a scanner id.

**Acceptance:** the 5-finding nikto case renders 5 articles; a genuine exact
duplicate still collapses to 1.

### B2 — #38 trivy findings not normalized
`render_findings` builds evidence from every key, so nested dicts render as
Python reprs. **Confirmed by execution:** `CVSS` renders as
`{'ghsa': {'V3Score': 9.8, 'V3Vector': 'CVSS:3.0/AV:N'}}` and `Remediation`
reads `Not reported` while `FixedVersion: 2.2.4` sits in the same table.

**Required:** trivy findings are normalized before rendering. `FixedVersion`
reaches the remediation slot, `PrimaryURL`/`References` the reference slot,
and no nested value is ever rendered as a Python repr.

**Acceptance:** a rendered trivy finding contains no `{'` sequence; the
remediation slot names the fixed version; report size for a realistic
multi-CVE result drops materially.

**Size, measured.** On a 151-CVE fixture carrying `Description`, 22
`References`, `CVSS`, `DataSource`, `Layer` and `PkgIdentifier`:
520,715 bytes before, 390,823 after, **-24.9%**. At 40 CVEs, -12.6%. The drop
comes from `Layer`/`PkgIdentifier`/`CVSS`/`DataSource` no longer repr-dumping.
A thinner fixture omitting the nested keys shows a small INCREASE instead,
because the references paragraph and the advisory-source line add back what
promotion removed; the criterion is about realistic trivy output, which always
carries those nested keys. Pinned by
`tests/test_wave2_gate.py::ReportSizeTests`.

## Wave 3 — `run_command` status semantics (PR B)

### C1 — #31, under D1
`kali_pentest_server.py:328-331`. Non-zero exit returns
`⚠️ Scan completed with warnings`, unconditionally. Nothing returns `❌`. A
scan that never ran is indistinguishable from a clean one.

**Required:** a non-zero exit reports as a failure, and the normalized result
`status` reflects it so `generate_report` does not count a failed scan as
successful coverage.

**Authorized breakage (D1):** returned text changes for every failing tool.
Three tests pin the old banner and must be updated:
`tests/test_reports.py:184`, `tests/test_scanner_adapters.py:1147`,
`tests/test_scanner_adapters.py:1246`.

**Acceptance:** a non-zero exit yields a failure banner; exit 0 is unchanged
byte-for-byte; the three pinned tests are updated deliberately, not deleted;
`generate_report` classifies a failed stage as failed.

## Invariants that hold for every wave

1. Commands are argument lists. Never `shell=True`.
2. Every tool remains an `@mcp.tool()` async function returning `str`, with a
   one-line docstring.
3. Findings are credential-redacted before persist or render.
4. Capture is best-effort and must never fail a completed scan.
5. `tests/fixtures/legacy_tool_contract.json` does not change (waves 1-2).
6. No new binary dependency and nothing requiring raw sockets or root.
