# Spec — session-wide combined branded report

Status: draft for review. Branch `feat/combined-report`, stacked on
`feat/report-securebine-design` (PR #17).

## Goal

Let an operator run any series of the server's scan tools and then, on request,
get **one** self-contained HTML report — in the SecureBine design system —
covering every scan captured in the session. Today only `trivy`/`syft`/
`oletools` persist a reportable result, `generate_report` wraps exactly one
result, no tool lists what is available, and nothing combines results. This
closes that gap.

The originating confusion (a prior session concluding `generate_report` was
"non-functional / orphaned") was a discoverability failure, not a broken
renderer: the ref-producing tools were never run and no `list_results` existed.

## Control model (decided)

- **Capture is automatic and silent.** As scans run, each executed scan stores
  one normalized result to `/results`. **No report is emitted.** Nothing is
  "spit out" on scan.
- **Report is pull-only.** A report exists only when `generate_report` is
  called. No-ref = render **all** stored results. Explicit ref(s) still
  supported for a subset.
- **The store is the container session.** `/results` is tmpfs; results
  accumulate for the container lifetime. `list_results` exposes the store.

## Decisions (D1–D6)

**D1 — Capture strategy: preserve text, side-channel structured.**
Each tool runs **once**. Its structured output is directed to a temp file
under `/tmp` (nmap `-oX`, nuclei jsonl, sslscan/testssl/sslyze `--xml`/`--json`,
whatweb/wpscan/nikto/ffuf/wafw00f/subfinder/amass/dnsrecon/searchsploit/
theHarvester JSON). That file is parsed into the existing normalized findings
schema and persisted; the temp file is discarded. **The operator's existing
text return is unchanged** — contract-safe by construction (`return: str`
holds; the `NucleiScanText`/`WebAuditText` str-subclass pattern is the model).
Tools with no usable structured mode (whois, nbtscan, fierce, smb_enum,
responder, metasploit search/info) fall back to a **raw-text result** captured
verbatim.

**D2 — Auto-capture at the individual-tool level.** Every executed scan records
one result. The four aggregators (`quick_recon`/`full_recon`/`web_audit`/
`network_sweep`) `await` the tool functions, so they inherit capture from the
tools they call — no special-casing. Aggregators keep their existing behaviour,
including `full_recon`/`web_audit`'s own auto-`report=` line (unchanged).

**D3 — What gets stored.** Stored: ran-with-findings, ran-empty (proves
coverage — "TLS checked, clean"), and failed (timeout/unreachable, recorded as
a failed-status entry so a report shows the gap honestly). Skipped: rejected-
before-run (invalid target, `capability_missing`, validation error) — no scan
happened, nothing to store.

**D4 — Report is pull-only; store is visible.**
- `generate_report` no-ref → load all stored results, dedupe, render one report.
- `generate_report(ref)` / explicit ref(s) → subset (backward compatible).
- New `list_results` tool → `{id, tool, target, status, finding_count, time}`
  per stored result, so the client can see the store and pass a subset.
- No `clear_results` (container restart is the reset; explicit-ref covers
  subsets). Add later only if a real need appears.

**D5 — Report structure: aggregate summary + per-tool sections + exact-dedupe.**
Top: an executive summary over **all** findings — severity tiles, one severity
distribution, and a coverage list of every scan run + status. Below: per-tool
findings sections in scan order, with clear provenance. Tier-2 raw-text tools
appear as labelled, redacted raw-output cards. Dedupe is **exact** — same
(tool, target, finding id) collapses to one; no cross-tool semantic merging
(fragile). Renders through the #17 SecureBine `_render_report`; the expanded
multi-result layout derives from the `securebine-design` repo's
`comp-dashboard` archetype and component cards (source of record — tokens.css +
STANDARD.md are law), not ad-hoc styling. `_redact_scanner_data` runs on the
combined document, so attack-tool output (hydra/john/hashcat) is captured but
credential-redacted.

**D6 — Delivery.** Stacked on `feat/report-securebine-design` (#17). Own PR,
merges after #17. Report stays HTML-only.

## Coverage — all 46 tools, two tiers

- **Tier 1 (structured findings):** the majority — any tool with a
  machine-readable mode → normalized findings with severity.
- **Tier 2 (raw-text block):** whois, nbtscan, fierce, smb_enum, responder,
  metasploit search/info → captured and shown as a raw redacted card.
- **Excluded (not scanners):** `generate_report`, `list_results`.

"All tools supported" is the end state across the phases; representation tier
per tool is fixed above.

## Phasing

- **P1 — plumbing + already-structured tools.** Capture helper, `list_results`,
  no-ref combine-all + multi-result rendering, exact-dedupe. Wired for the four
  tools that already emit structured data: `nuclei`, `trivy`, `syft`,
  `oletools`. Exit: a real branded combined report works end to end.
- **P2+ — tool families in waves,** each independently shippable:
  nmap family → TLS family (sslscan/testssl/sslyze) → web
  (whatweb/nikto/wpscan/ffuf/gobuster/dirb/wafw00f) → DNS/recon
  (dns_enum/dns_recon/subfinder/amass/fierce/theHarvester) → the raw-text tail.

## Architecture

- **Normalized result document** — reuse the existing shape
  (`schema_version`, `scanner`, `source_type`, `target_ref`, `status`,
  `findings[]`, `checks[]`, `metadata`) and `_write_scanner_result` (O_EXCL
  opaque non-overwriting ids).
- **Capture helper** — a shared function each capturing tool calls after its
  run: parse the structured temp file (or wrap raw text) → normalized document
  → persist. Failed runs persist a failed-status document. In P1, `nuclei`'s
  direct path is wired to persist (today it only does so inside `web_audit`).
- **`generate_report`** — no-ref: enumerate `/results`, load, exact-dedupe,
  build one combined document (each finding tagged with its source scanner +
  target for the per-tool sections), render via the extended `_render_report`.
  Single/explicit-ref path preserved.
- **`_render_report`** — extended to render a combined document: aggregate
  summary block + per-scanner sections + raw-output cards, all in the SecureBine
  system. Single-result documents render as today (a combined doc with one
  scanner).
- **`list_results`** — enumerate `/results`, return the per-result metadata
  line. Not a scanner; not captured.

## Invariants preserved

Self-contained + scriptless report; CSP unchanged from #17 (`default-src
'none'`, `img-src data:` for logos only); all scanner strings HTML-escaped;
`_redact_scanner_data` applied; 200-line public bound on tool text output;
opaque non-overwriting ids; captured tools keep name/params/`str` return.

**Deliberate contract change (not a preserved invariant):** `list_results` is a
new tool, so the additions grow from four to five and the total from 46 to 47.
This is an intended, reviewed change — update `legacy_tool_contract.json`
(additions set), and the "42 preserved + four additions / 46 callable tools"
wording in README.md and CLAUDE.md to "five additions / 47", in the same commit
that adds the tool. The 42 preserved tools and their signatures are unchanged.
`generate_report` gains no-ref / multi-ref behaviour but keeps its signature
(`result_ref=""`, `format="html"`), so its contract entry is unchanged.

## Test seams

- Unit: capture helper writes a valid normalized document from a sample
  structured output; failed run → failed-status document; rejected run → no
  file written.
- Unit: `generate_report` no-ref combines N stored results, exact-dedupe
  collapses a duplicate, per-tool sections present, aggregate counts correct.
- Unit: `list_results` shape.
- Renderer: combined document → one report, SecureBine tokens present, zero
  embedded DOM elements, headings/escaping/redaction intact (extends
  `tests/test_reports.py` + `tests/test_report_browser.py`).
- Contract: `tests/fixtures/legacy_tool_contract.json` unchanged for existing
  tools; `list_results` added to the additions set.

## Out of scope

Persistent results DB (tmpfs session is enough); report history/comparison;
non-HTML output; Nessus or any tool not already in the 46; cross-tool semantic
finding merge; parsing the Tier-2 tail into findings (raw block unless a
specific tool later warrants it).

---

## P2 wave 1 — nmap family (addendum, anchor for the wave)

Scope: wire the six nmap tools to capture, per D1 (preserve text, side-channel
structured). NO change to any tool's human-readable str return.

Tools: nmap_scan, nmap_service_scan, nmap_vuln_scan, nmap_comprehensive_scan,
nmap_port_scan, nmap_script_scan.

Mechanism: a shared helper (e.g. `_run_nmap_with_capture(cmd, scanner, target,
timeout)`) that:
1. Adds `-oX <tmpfile>` to the command (XML to a temp file under /tmp; stdout
   stays the normal operator text). Uses a fresh temp path; cleans it up.
2. Runs via the existing `run_command` seam and returns its text UNCHANGED.
3. Parses the XML with stdlib `xml.etree.ElementTree` into normalized findings:
   each open port → one INFO finding {id: "port-<portid>-<proto>", Severity:
   "INFO", Title: "<portid>/<proto> <service> open", plus product/version/state
   fields}; each NSE `<script>` element → one finding {id: script id, Title:
   script id, Severity: "HIGH" if its output contains "VULNERABLE" else "INFO",
   evidence: the script output}. Redact via _redact_scanner_data.
4. Best-effort `_write_scanner_result` (swallow OSError; a persist failure must
   not fail the scan), scanner label = the specific tool name (e.g. "nmap" for
   nmap_scan; keep it stable and human-meaningful).

Invariants: arg-list command (no shell); the `-oX` path is server-generated, not
caller data; XML parse must not raise on malformed/empty output (guard and skip
to empty findings); no raw sockets/root; the 200-line public text bound and
opaque ids unchanged; findings feed the P1 combined report and list_results
unchanged.

Test seams (extend tests/test_scanner_adapters.py or test_reports.py): the
capture helper parses a sample nmap XML into the expected findings (ports +
a VULNERABLE script → HIGH); a malformed/empty XML yields zero findings and no
raise; the tool's text return is unchanged; a persist failure is swallowed.
Contract: nmap tool signatures unchanged (no fixture change; these are the 42
preserved tools).

Out of scope for this wave: the other tool families (separate waves), and
severity heuristics beyond the VULNERABLE-string rule.

---

## P2 wave 2 — TLS family (addendum, anchor for the wave)

Scope: wire the three TLS tools to capture, per D1 (preserve text, side-channel
structured). NO change to any tool's human-readable str return. Stacked on P2
wave 1 (nmap); reuse its patterns.

Tools: sslscan_scan, testssl_scan, sslyze_scan. Each has a distinct structured
format, so each gets its own small parser; a shared runner handles the
run→capture→persist plumbing (mirroring `_run_nmap_with_capture`).

Structured flags (add to the existing command; stdout text stays unchanged):
- sslscan: `--xml=<tmpfile>` (XML). Parse: weak protocol enabled (SSLv2/SSLv3/
  TLSv1.0/TLSv1.1 with enabled="1") -> finding Severity HIGH for SSLv2/SSLv3,
  MEDIUM for TLS1.0/1.1; accepted cipher with a weak token (RC4, 3DES, DES,
  NULL, EXPORT, MD5) -> HIGH; each accepted cipher otherwise -> INFO. id like
  "tls-proto-<ver>" / "tls-cipher-<name>".
- testssl: `--jsonfile <tmpfile>` (JSON array of {id, severity, finding, cve?}).
  testssl already grades severity — map its severity string (CRITICAL/HIGH/
  MEDIUM/LOW/INFO/OK/WARN) to our vocabulary (OK/INFO/WARN -> INFO), id = the
  testssl id, Title = id, evidence = finding, keep cve when present. Skip
  entries with severity OK/INFO if noisy is a concern — but P2 keeps all,
  mapping OK/INFO/WARN -> INFO.
- sslyze: `--json_out <tmpfile>` (JSON). Parse accepted cipher suites per TLS
  version from the server scan result; weak protocol/cipher -> same severity
  rule as sslscan; otherwise INFO. Guard the nested structure defensively.

Mechanism: a shared runner `_run_tls_with_capture(cmd, scanner, target, timeout,
parse_fn, out_flag)` (or per-tool wrappers) that: creates a server-generated
tmpfile under /tmp, appends the tool's structured-output flag pointing at it,
runs via `run_command` and returns the text the operator would have seen from
the same scan WITHOUT capture (see the wave-4 addendum: identical bytes, which
for a tool that announces its output file means that line is stripped before the
200-line bound), reads+parses the file
with parse_fn, best-effort `_write_scanner_result` (swallow OSError), cleans the
tmpfile in a finally. scanner label = the tool's own name ("sslscan"/"testssl"/
"sslyze"). Add all three labels to the single-ID generate_report allowlist.

Invariants (same as wave 1): arg-list command (no shell); the out path is
server-generated, not caller data; parsers NEVER raise into the tool (malformed/
empty/oversized -> zero findings); JSON parsing bounded and safe (no eval); XML
via stdlib ElementTree with the same DOCTYPE/ENTITY guard as _parse_nmap_xml
(reuse it or a shared guard); findings redacted via _redact_scanner_data before
persist; 200-line public text bound and opaque ids unchanged; the 42 preserved
tool signatures unchanged (NO fixture change).

Test seams (extend tests/test_scanner_adapters.py): each parser maps a
representative sample (sslscan XML with a weak protocol + RC4 cipher; testssl
JSON with HIGH+OK entries; sslyze JSON with a weak cipher) to the expected
severities; malformed/empty input -> zero findings, no raise; each tool's text
return is unchanged vs a run_command mock; a persist failure is swallowed; the
single-ID report accepts each new scanner.

Out of scope: other tool families (later waves); deep protocol/cert analysis
beyond the weak-protocol/weak-cipher/testssl-severity rules above.

---

## P2 wave 3 — web family (addendum, anchor for the wave)

Scope: wire the seven web tools to capture, per D1 (preserve text, side-channel
structured). NO change to any tool's human-readable str return. Stacked on wave
2; reuse `_run_with_capture`, `_safe_xml_root`, the severity helpers, and the
best-effort/never-raise discipline.

Tools + structured flag + parser mapping (each parser returns [] on bad input,
never raises; findings redacted; normalize to id/Title/Severity/evidence):
- whatweb_scan: `--log-json=<file>` (JSON array of {target, plugins:{name:..}}).
  Each detected plugin/technology -> INFO finding {id:"web-tech-<name>",
  Title:"<name> detected", evidence:brief}. Tech disclosure is informational.
- nikto_scan: `-Format json -o <file>` (JSON; vulnerabilities list). Each item
  -> finding {id: item id/OSVDB or "nikto-<n>", Title: msg, Severity: MEDIUM if
  it names a vuln/OSVDB else INFO, evidence: msg/url}.
- wpscan_scan: `--format json --output <file>` (JSON). Map wpscan findings:
  interesting_findings + version/plugin/theme vulnerabilities. Each vulnerability
  -> finding {id: title/ref, Title, Severity: HIGH if it carries a CVE/references
  else MEDIUM, evidence, cve when present}. Detected components without a vuln ->
  INFO.
- ffuf_scan: `-of json -o <file>` (JSON {results:[{url,status,length,..}]}). Each
  result -> INFO finding {id:"web-path-<status>-<url-tail>", Title:"<status>
  <url>", evidence: length/words}.
- wafw00f_scan: `-o <file> -f json` (JSON). WAF detection -> INFO finding
  {id:"waf-<name>", Title:"WAF detected: <name>"} or a single "no WAF detected"
  INFO when none.
- gobuster_scan: `-o <file>` (text; gobuster has no stable JSON for dir/vhost).
  Parse each result line -> INFO finding {id:"web-path-<path>", Title: line,
  evidence: line}. Tolerate the dns/vhost/dir line variants; unknown line -> skip.
- dirb_scan: `-o <file>` (text). Parse discovered-URL lines (e.g. "+ <url>
  (CODE:200|SIZE:..)") -> INFO finding {id:"web-path-<url>", Title:url,
  evidence:line}. Non-result lines skipped.

Mechanism: route each tool through `_run_with_capture(cmd, scanner, target,
timeout, out_args, parse_fn, suffix)` with scanner = the tool's own name
("whatweb"/"nikto"/"wpscan"/"ffuf"/"wafw00f"/"gobuster"/"dirb"). Text-output
tools (gobuster/dirb) get a text parser, not XML/JSON. Add all seven labels to
the single-ID generate_report allowlist. Keep each tool's validation
(incl. wordlist checks), command construction, and str return EXACTLY as-is
except routing through the runner and adding the output flag. Text output
byte-unchanged.

**CORRECTED after wave 4.** The "VERIFY" above was never discharged, and one of
these seven fails it: ffuf prints an "Output file" AND a "File format" line to
**stderr** whenever `-o` is set (`pkg/output/stdout.go:82-94,483-484`), and
`run_command` merges stderr. Writing to a file is not sufficient on its own; a
tool can also announce that it is doing so. ffuf is handled by the `announces`
mechanism in the wave-4 addendum below.

Invariants (same as prior waves): arg-list command (no shell); the out path is
server-generated, not caller data; parsers NEVER raise (bad input -> []);
JSON via stdlib json only (no eval), text parsing bounded; findings redacted
before persist; 200-line public text bound + opaque ids unchanged; the leading-
dash target guard and MAX_ARTIFACT_BYTES size cap in the shared runner apply;
the 42 preserved tool signatures unchanged (NO fixture change).

Test seams (extend tests/test_scanner_adapters.py): each parser maps a
representative sample to the expected findings/severity; malformed/empty/hostile
input -> [] no raise; the single-ID report accepts each new scanner. No real
binaries.

**CORRECTED after wave 4.** "text return unchanged vs a `run_command` mock" is
not a valid seam: the announcement strip and the 200-line bound both live
*inside* `run_command`, so mocking it asserts only that the runner passes a
string through. Text-equality tests mock `execute_command` and compare a
captured run against an unflagged one.

Out of scope: the DNS/recon family and the raw-text tail (later waves); deep
per-tool analysis beyond the mappings above.

---

## P2 wave 4 — DNS/recon family (addendum, anchor for the wave)

Scope: wire the three DNS/recon tools that emit a single structured file to
capture, per D1. Stacked on wave 3; reuse `_run_with_capture`, `_load_json`,
the never-raise discipline.

Tools + flag + parser (each returns [] on bad input, never raises; findings
redacted; normalize to id/Title/Severity/evidence — all INFO, these are
enumeration/disclosure results):
- dns_recon (dnsrecon): `-j <file>` (JSON array of {type,name,address,...}).
  Each record -> INFO {id:"dns-<type>-<name>", Title:"<type> <name> <address>",
  evidence}. Tolerate a top-level list or a dict wrapping a list.
- subfinder_scan: plain `-o <file>` (one host per line). Each line -> INFO
  {id:"subdomain-<host>", Title:host}. NOT `-oJ`: that flag sets `options.JSON`,
  which feeds the single `NewOutputWriter` used for *every* writer in
  `pkg/runner/enumerate.go`, stdout included, so it reformats the operator's
  text. Plain `-o` appends the file to the writer list and leaves stdout alone
  (`pkg/runner/runner.go:90` sets `outputs := []io.Writer{r.options.Output}`,
  which `options.go` points at `os.Stdout`; `runner.go:143-149` appends the file).
  No `evidence:source` field: plain output carries no source.
- amass_enum: NO structured-output flag, because none exists. The v3 `-json`
  flag was removed: v3.23.3 registers it at `cmd/amass/enum.go:154`, v4.2.0
  keeps only the unregistered `JSONOutput` struct field in that same file, and
  by v5.1.1 the CLI moved to `internal/enum/cli.go` where the dead field
  survives at line 79. `-oA` is registered (cli.go:132) but read nowhere in the
  enum package. Passing `-json` makes the flag parser reject it; amass catches
  the error itself and prints a hint plus the raw `flag provided but not
  defined: -json` to stderr via `color.Error`, then calls `os.Exit(1)`
  (`internal/enum/cli.go:349-376`; the flagset uses `flag.ContinueOnError` with
  `fs.SetOutput`, so the flag package's own usage text is buffered and shown
  only for `-h`). `run_command` merges stderr, so that reaches the operator's
  text — a guaranteed text-invariant violation on every call. amass v5 `enum` prints
  one asset per line under `<type>:` headers to stdout and keeps assets in its
  engine DB. Findings carry no `evidence` field: the printed line is a bare
  asset token with nothing else on it. (The printing loop is `printScope`,
  reporting the session's
  scoped assets rather than an enumeration result set.) Capture parses the
  tool's own text with `out_args=None`.
  (Separately, amass still fails under the hardened runtime per issue #15.)

No JSONL remains in this wave: subfinder's plain `-o` is one host per line and
amass v5 prints bare asset tokens under `<type>:` headers, so both are parsed as
plain text, line by line, a bad line skipped.

Mechanism: route the three tools through `_run_with_capture` with scanner labels
dns_recon/subfinder/amass. Keep each tool's validation, command construction and
str return EXACTLY as-is. dns_recon and subfinder pass out_args + suffix; amass
passes `out_args=None`, adding nothing to argv. Text output byte-unchanged. Add
the three labels to the single-ID generate_report allowlist.

Three mechanisms were added in this wave, all required to keep the
byte-unchanged and redaction invariants true rather than merely asserted. Only
the first is a `_run_with_capture` behaviour; the second lives in the parsers
and the third in `run_command`:

1. **No-flag mode (`out_args is None`).** For a tool with no per-run structured
   output, nothing is added to argv and parse_fn reads the tool's own text. Text
   equality is then true by construction. Note the text it parses has already
   been cut to the 200-line public bound, so assets past that line are not
   captured -- acceptable for best-effort capture, recorded here so it is not
   mistaken for a parser bug.
2. **Truncation-safe redaction.** Redaction must run before any slice that
   would cut a pattern's trailing anchor, but a hostile artifact can hand the
   regex engine megabytes, so values are bounded to `MAX_REDACT_CHARS` first.
   That bound is itself a truncation, and the ATTACKER chooses the distance to
   the anchor, so no bound is "far enough": a private-key body longer than the
   cap would keep its `-----BEGIN` and lose its `-----END`. Every kept field
   therefore goes through `_clip`, which slices and then redacts any secret
   opener left without its closer. THREE patterns need a trailing anchor and
   all three are covered: the private key needs its `-----END-----`, the URL
   credential its `@`, the JWT its signature segment. Each is matched at its
   LAST opener, since a value can hold a complete secret followed by a
   truncated one. `_safe_scanner_value(value)` is the single named
   bound-then-redact entry point; callers slice its result through `_clip`,
   never with a bare slice. This covers the `MAX_REDACT_CHARS` bound and each
   field's own cap with one rule, and applies to EVERY finding-producing parser,
   including the wave 1-3 and P1 parsers already on main; a structural test
   discovers parsers by introspection so a new one cannot be forgotten.

   Two traps the guard has to avoid, both found by review after it shipped:
   `scheme://host:8080` has the same shape as `scheme://user:pass@` up to the
   colon, so an unqualified guard redacts the port and everything after it --
   which also collapsed distinct findings, since the report dedupes on `id`.
   `URL_PORT_TAIL` distinguishes them. And a tail slice such as ffuf's
   `str(url)[-40:]` removes the OPENER, so such values are guarded before the
   slice, not after.

   Two more traps, both found only after the guard shipped. Orphan detection is
   LOCAL to each opener: one value can carry several secrets, and a closer
   belonging to a later opener must not vouch for an earlier one, so each
   opener is judged on the region up to the next opener of its own kind and the
   first orphan wins. And the bound reaches every nesting depth, so the guard
   must too: `_bounded_for_redaction` guards at the point of the cut and
   `_clip_finding` recurses into lists and dicts -- nuclei's `extracted-results`
   is a list of strings lifted straight out of the scanned target's response
   body, and it leaked a private key to the operator's text, the persisted
   result and the report when only top-level fields were guarded.

   The blank line above a stripped announcement is OPT-IN per tool
   (`announce_blank`), not automatic: sslyze writes its blank as part of the
   announcement, but dirb's `OUTPUT_FILE` line follows its banner's own
   trailing blank, and collapsing unconditionally ate that legitimate line.

   Field caps are named, not inline: `MAX_ID_CHARS` (512) must clear a full
   253-char FQDN plus a prefix or distinct findings merge; `MAX_EVIDENCE_CHARS`
   (8192) carries what the operator actually reads -- NSE script output and
   testssl findings are routinely multi-KB and were unbounded before capture.
3. **Capture-path stripping.** A tool may announce the structured file it was
   told to write (dnsrecon logs `Saving records to JSON file: <path>` at INFO to
   stderr and to `~/.config/dnsrecon/dnsrecon.log`; cli.py:1917-1918 registers
   both sinks, and `run_command` merges stderr). That line exists only because
   capture asked for it and it discloses a server-internal path, so `run_command`
   takes a `strip_containing` argument and drops matching lines BEFORE applying
   its 200-line bound -- doing it after would leave the
   `(truncated N additional lines)` counter one higher than an unflagged run,
   which is itself a byte difference. A tool may announce more than the path:
   ffuf prints an "Output file" line AND a "File format" line whenever `-o` is
   set, so `_run_with_capture` takes an `announces` tuple of additional markers
   and `strip_containing` takes a tuple of markers. An announcement can also
   carry its own blank line -- sslyze writes
   `'\n       Wrote JSON output to "<path>".\n'` -- so a blank line immediately
   above a dropped line is dropped with it. Upstream was checked at the pinned
   version for EVERY capturing tool: only dirb and dnsrecon (one path-bearing
   line), ffuf (two lines, the second without the path) and sslyze (blank plus
   path line) emit anything extra; nmap, nikto, whatweb, wafw00f, testssl,
   gobuster and subfinder emit nothing under their output flags.

   nikto is a standing trap: it treats `-o` as a PREFIX and appends `".$fmt"`
   unless the path already ends in it, so its capture suffix and its `-Format`
   value are coupled. A test pins them together.

Invariants (same as prior waves): arg-list command (no shell); server-generated
out path; parsers never raise (incl. JSON depth bomb via _load_json); stdlib
json only; findings redacted before persist; 200-line bound + opaque ids
unchanged; the shared runner's leading-dash guard + size cap apply; 42 preserved
tool signatures unchanged (NO fixture change).

Test seams (extend tests/test_scanner_adapters.py): each parser maps a
representative sample (dnsrecon JSON array; subfinder one host per line; amass
`<type>:`-headed bare tokens) to the expected INFO findings; malformed/empty/
hostile -> [] no raise; single-ID report accepts each new scanner. No real
binaries.

Mock at the RIGHT seam: a `run_command` mock cannot prove either text property,
because the strip and the 200-line bound both live inside `run_command`. The
byte-equality and truncation-counter tests mock `execute_command` and compare a
captured run against an unflagged one. Nothing here proves the pinned binary's
own stdout behaviour; that is established from upstream source at the pinned
version and recorded per tool above.

DEFERRED from this wave, with reasons (later increment):
- dns_enum: runs three separate commands (nslookup/dig/host) concatenated — no
  single structured output; needs a multi-source or text-parse approach.
- fierce: text-only output; belongs to the Tier-2 raw-text tail.
- theharvester_scan: `-f <name>` writes <name>.json/.xml (appends its own
  extension), which breaks the shared runner's exact-out-path model; needs a
  basename-then-read variant.

Out of scope: the raw-text tail and the three deferred tools above.

## P2 wave 5 — raw-text tail (addendum, anchor for the wave)

Scope: the LAST family and the last of the combined-report feature. Wire the
tools that emit only unstructured human-readable text (no per-run structured
output of any kind) to capture, per D1. Stacked on wave 4; reuse
`_run_with_capture`'s `out_args=None` mode, `_safe_scanner_value`/`_clip`, and
the never-raise discipline. Nothing new is invented.

Tools wired (scanner label = tool's capture label):
- whois_lookup (whois) — registration/ownership prose.
- nbtscan_scan (nbtscan) — NetBIOS name table.
- smb_enum (smbclient `-L`) — share listing.
- metasploit_search (msfconsole `-x "search …"`) — module list.
- metasploit_info (msfconsole `-x "info …"`) — module detail.
- fierce_scan (fierce) — DNS recon prose (DEFERRED from wave 4 as "the Tier-2
  raw-text tail"; this is that tail).

Excluded, with reason:
- responder_analyze — returns a STATIC help string and spawns NO subprocess.
  There is no scan output to capture. Wiring it would fabricate a finding from a
  constant. Left exactly as-is.

Mechanism: one shared parser factory `_raw_text_parser(scanner, target)` returns
a `parse_fn(text)` that emits AT MOST ONE INFO finding carrying the tool's own
(redacted, bounded) text as `evidence`:
  {id:"<scanner>-<target>", Severity:"INFO", Title:"<scanner> <target>",
   evidence:<redacted+bounded raw text>}
`evidence` is the tool's text INCLUDING `run_command`'s status banner, not the
body alone: the banner is what the hard-failure and no-substance guards below
read, and it carries the run's status into the report card.
No per-record parsing: these tools have no record structure worth the
fragility, and the operator value is the verbatim text captured into the
report. Each wired tool routes through `_run_with_capture(cmd, "<label>",
target, TIMEOUT_*, None, _raw_text_parser("<label>", target))`, keeping its
validation, command construction and str return EXACTLY as-is. Add the six
labels to the single-ID `generate_report` allowlist.

Why `out_args=None` makes text byte-unchanged here: in that mode
`_run_with_capture` calls `run_command(cmd, timeout=timeout)` with NO strip
args — identical to the bare tool — and only adds a best-effort
`_capture_findings` that swallows every exception. The returned text is
byte-identical to a no-capture run by construction. The one behavioural change
routing through the shared runner introduces is wave 4's leading-dash guard
(`target` beginning with `-` is rejected as arg injection), and it is now
OPT-OUT rather than unconditional. It is right for whois/nbtscan/smbclient/
fierce, whose target reaches argv as its own positional token, and a legitimate
domain or IP never begins with `-`. It is WRONG for the two metasploit tools:
their query is interpolated inside a single `msfconsole -x "search …; exit"`
token, so it never reaches argv as an option, and a leading dash there is
msfconsole's OWN search syntax (`search -t exploit ms17_010`, `info -h`).
Guarding it would delete working functionality to defend a boundary the query
does not cross, so `_run_with_capture` takes `guard_target: bool = True` and
those two callers pass False. A test pins both halves.

The guard reaches two of the 42 preserved combined operations, since
`quick_recon` calls `whois_lookup` and `network_sweep` calls `nbtscan_scan`.
Their text is byte-identical for every real target and differs only for a
leading-dash one, where the base built `nbtscan -x` and now returns the guard's
error instead. That is the intended hardening, not a regression, but it is a
byte change in a preserved tool and is recorded here rather than left implicit.

Redaction/bounding: `evidence`, `id` and `Title` all pass
`_safe_scanner_value` (bound-then-redact) then `_clip` — the wave-4 rule, so a
credential in whois/msf output is redacted before it reaches the persisted
result or the report, and a truncation cannot orphan a secret's trailing
anchor. Caps: `id` MAX_ID_CHARS, `Title` MAX_TITLE_CHARS, `evidence`
MAX_EVIDENCE_CHARS (8192) — the same fields and caps every other parser uses.
The evidence cut is MARKED (`… [truncated]`) rather than silent, because for
this family the text is the whole deliverable and a mid-line stop otherwise
reads as the tool having ended there. Truncation is measured at BOTH points it
can happen: `MAX_REDACT_CHARS` against the original text, and
`MAX_EVIDENCE_CHARS` against the redacted body — redaction GROWS as well as
shrinks (`token=x` -> `token=[REDACTED]`), so a body under the cap before
redaction can exceed it after.

This wave is the first to route WHOLE multi-line, attacker-controlled tool text
through the wave-4 redaction helpers, and that input class exposed a cluster of
PRE-EXISTING defects in them. Two helper fixes ship here; the rest were
attempted, regressed three times, and were deliberately cut. See "Redaction
hardening, deliberately NOT in this wave" below.

Shipped, both verified with zero regressions across three adversarial rounds:
1. **Case.** `PEM_OPENER`/`PEM_CLOSER` were case-sensitive while
   `SECRET_VALUE_PATTERNS`' own private-key pattern carried `(?i)`, so a
   lowercase `-----begin private key-----` with no END matched NEITHER and its
   body leaked. Both anchors are now case-insensitive.
2. **Order.** `SECRET_VALUE_PATTERNS` ran the keyword pattern before the
   private-key one. The keyword value is `[^\r\n]*`, so
   `password: -----BEGIN PRIVATE KEY-----KEY-----END PRIVATE KEY-----` was eaten
   as a keyword value before the key pattern could match it. The private-key
   pattern now runs FIRST.

A differential over all twelve finding-producing parsers measures this pair at:
**11 leaks closed, 0 opened**. The remaining leaks are pre-existing on main and
unchanged by this wave (they are #27).

Fix 1 has a COST, found by an independent reviewer whose corpus carried a shape
mine did not, and an earlier draft of this paragraph wrongly claimed "0
destroyed". A COMPLETE lowercase key pair followed by legitimate output now
loses that output:

    -----begin private key-----\nAAA\n-----end private key-----\nName Server: NS1

`_redact_scanner_data` consumes the pair and leaves its opener behind as the
`\1` of `\1[REDACTED]`; `PEM_OPENER`'s new `(?i)` then matches that surviving
lowercase opener, finds no closer after it, and truncates to end-of-value.

It is taken deliberately, for three reasons. The UPPERCASE twin of that input
already truncates identically on main, so this extends an existing behaviour
rather than inventing one, and RFC 7468 specifies uppercase, so the lowercase
form is non-standard. The alternative is leaving a real credential leak open: a
lowercase `-----begin private key-----` with no END is matched by NEITHER the
guard's anchors nor the full pattern, and its body reaches the operator, the
store and the report. Losing trailing text on a malformed key beats leaking a
well-formed one. The underlying over-redaction (for both cases) is #27's to
fix.

Known NOT covered, and deliberately left:
- The pattern set assumes a `key: value` or `key=value` shape, while `nbtscan`,
  `smbclient -L` and `msfconsole info` emit whitespace-aligned COLUMNS
  (`Password    hunter2`), which pass through untouched. Widening the keyword
  pattern to accept column alignment changes redaction for all five waves and
  risks eating legitimate table rows, so it is a decision to take deliberately,
  not a fix to slip into this wave. RAISED to the user.
- Everything under "Redaction hardening, deliberately NOT in this wave" below.
- `_clip` can exceed its cap by the length of the redaction placeholder, because
  `_redact_truncated_secret` appends `[REDACTED]` to an already-sliced string.
  Worst observed is 8202 against a 8192 cap. `_clip` is byte-identical to main,
  so this is pre-existing; recorded because this addendum claims the caps hold.
  Filed with #27.
- An orphan-guard redaction truncates to end-of-value BY DESIGN — once a
  secret's closing anchor is gone there is no way to know where the secret
  ends, so everything after the opener goes. It is marked with `[REDACTED]`,
  not `… [truncated]`, because it is a redaction rather than a size cut. The
  cases where that used to fire on well-formed content are fixed above; what
  remains fires only on a genuine orphan.
- The line-oriented parsers (`_parse_amass_text`, `_parse_subdomain_lines`)
  turn each line of their input into a "host" finding, so a multi-line key body
  pasted into subfinder/amass output is captured line by line as garbage
  subdomains. That is those parsers working as designed on garbage rather than
  a credential leak, it predates this wave, and guarding it would mean teaching
  them what a key body looks like. Left alone; noted so a future sweep does not
  re-file it as a leak.
`target` is redacted before it is embedded in `id`/`Title`. It is in the `id`
so the SINGLE-result renderer, which prints `id` as the article heading, names
the scan the card belongs to. It is NOT needed for dedupe: `render_combined`
already keys on `(scanner, target, id)`, matching D-level "same (tool, target,
finding id) collapses to one", so a scanner-only id could not have merged two
whois runs anyway. (An earlier draft of this addendum claimed it could; that
was wrong and the code comment carried the same error.) Two collision cases, both checked end to end (an earlier draft of this
paragraph named only the first and got its consequence wrong):
- A query longer than 494 chars clips `id` to a shared value (`MAX_ID_CHARS` is
  512, the longest prefix `metasploit_search-` is 18). This does NOT lose a
  result: the combined key is `(scanner, target_ref, id)` and `target_ref` is
  not clipped, so both still render. Every legitimate target clears the cap
  anyway — a 253-char FQDN plus the longest prefix is 271.
- Two targets that REDACT to the same string collapse `id` and `target_ref`
  together, and one result is then dropped. Verified for `password=alpha` vs
  `password=bravo`, `token: x` vs `token: y`, and `https://u:p1@h` vs
  `https://u:p2@h`. Reaching it needs the operator to scan two targets that
  differ only inside a credential, which is not a real workflow, and the fix
  (keying on an unredacted target) would defeat the redaction. Accepted.
- Related and accepted for the same reason: the raw `id` is derived from
  `(scanner, target)` and NOT from the scan's content, unlike every other
  parser, so re-running one tool against one target inside a single session
  keeps only the first result. The "Scans" and "Total findings" tiles then
  disagree, which is the only signal. A content digest in the `id` would fix it
  at the cost of an unreadable article heading; deferred rather than taken.

Hard-failure guard: the parser returns [] when the tool's text is empty, when
it begins with a hard-failure status marker (`❌` command error, `⏱️` timeout),
or when a `✅`/`⚠️` banner has NO body below it. `run_command` has FOUR
no-substance returns, not two — it also emits `✅ Command completed
successfully (no output)` and `❌ Command failed with exit code N` — and each of
those was persisting a card whose entire evidence was its own status line. A
banner WITH a body is a real result and is captured, including a non-zero exit
that still printed. This is a local guard for the raw parser only; the
repo-wide "failed scans persist status:success" item is unchanged and out of
scope.

Rendering: NO `_render_report` change, and no Tier-2 raw-output card. A raw
finding is a normal INFO finding; `render_findings`/`rows` already show its
`evidence` in the per-scanner section as a fully escaped table cell. Two
corrections to an earlier draft of this paragraph, both checked in source:
`render_findings` calls `rows(finding, None, None)`, so the renderer does NOT
truncate the value — the parser's own `MAX_EVIDENCE_CHARS` cap is the only
bound, which is why that cut is now marked rather than silent. And `tbody td`
carries `word-break:break-word` but no `white-space` rule, so HTML collapses
the body's newlines: a whois record reads as one wrapped paragraph and an
nbtscan or smbclient table loses its column structure.

That is a readability limit, not a correctness or invariant one, and the fix is
one `white-space:pre-wrap` declaration. It is DEFERRED rather than taken here
because `_render_report`'s styling is governed by the external
`securebine-design` source of record (tokens.css + STANDARD.md are law, per D5)
which is not readable from this repo, and changing the design system on our own
authority is exactly what D5 forbids. Raise it as a design change against that
repo.

Invariants (same as prior waves): arg-list command (no shell); parser never
raises; findings redacted before persist; 200-line bound + opaque ids
unchanged; leading-dash guard + size cap from the shared runner apply; 42
preserved tool signatures and one-line docstrings unchanged (NO fixture
change).

Test seams (extend tests/test_scanner_adapters.py): `_raw_text_parser` maps a
sample to one INFO finding with the text as evidence; empty/❌/⏱️ text -> [];
non-string -> []; a credential in the text is redacted in evidence/id/Title; a
>8192-char body is bounded and leaves no orphaned anchor; each wired tool
returns its text byte-unchanged (mock `execute_command`, compare against a
no-capture run) AND persists one finding; the single-ID report accepts each new
scanner label; responder_analyze is NOT wired (still the static string, no
capture). No real binaries.

### Redaction hardening, deliberately NOT in this wave

Three adversarial rounds found six more defects in the wave-4 redaction helpers.
Every fix attempted for them introduced a fresh regression in the SHIPPED waves,
so the work was cut out of wave 5 rather than shipped half-verified. It is
tracked as issue #27, with its own gate. The record, so the next
attempt starts from evidence rather than from scratch:

Confirmed defects still present (all pre-existing on main, none introduced or
worsened by this wave):
- **H1** A later unrelated `@` vouches for an orphaned URL credential, because
  the closer is searched for anywhere in the region while the full
  `URL_CREDENTIAL` pattern cannot match across a newline. A whois record carries
  an abuse-contact email in nearly every case, so this is reachable from
  ordinary output: `https://svc:PW\nabuse@registrar.tld` keeps `PW`.
- **H2** A keyword line eats a secret's OPENER (`[^\r\n]*` to end of line), so
  an UNPAIRED key body — no `-----END-----`, which a hostile server simply omits
  — leaks in full. Reordering the patterns does not fix it: the key pattern
  needs an END to fire at all.
- **H3** `URL_PORT_TAIL` accepts a port terminated only by `/ ? #` or
  end-of-string, so a legitimate `https://host:8443` followed by `" ' , ; ) ]`,
  whitespace, or a serialized `\n` is truncated along with the rest of the
  value. Every IPv6 URL is truncated too.

What was tried and why each attempt was reverted, so it is not retried blindly:
- Anchoring the URL/JWT closers at the region start fixes H1, but turns H3 from
  latent into constant, and needs the terminator set widened in the same change.
- Running the orphan guard BEFORE `_redact_scanner_data` fixes H2, but then the
  guard sees orphans that redaction was about to neutralize and amputates to
  end-of-value: an ordinary 2-segment signed cookie
  (`Set-Cookie: session=hdr.sig`) destroyed every header below it. That shape is
  the commonest evidence form in the web family.
- Treating a region that starts with the `[REDACTED]` placeholder as closed
  fixes the second-pass over-redaction that anchoring causes, but is itself a
  LEAK: tool output is attacker-controlled, so a hostile server prints the
  literal placeholder and an unpaired key survives that base redacts.
- Recording how far an accepted closer reaches (to stop a JWT's own payload
  segment, which is itself a valid opener, reading as an orphan) skips an opener
  that STARTS inside the accepted span but ends outside it, so a real orphan is
  never judged.
- Removing wave 4's per-opener locality bound survived a 200,000-case fuzz with
  no counterexample, and it preserves legitimate text the bound destroys, but it
  is only worth taking together with the rest.

The lesson that matters most for the retry: a fully green suite hid all of the
over-redaction regressions, because every redaction test asserted only that a
secret was ABSENT and never that legitimate content SURVIVED. Any future attempt
must carry a PAIRED table — this wave's `REDACTION_MUST_REMOVE` /
`REDACTION_MUST_KEEP` in tests/test_scanner_adapters.py is the shape — and a
base-versus-head differential over all twelve parsers measured in BOTH
directions.

This completes P2. After it lands the combined-report feature is feature-complete
across all wired families; the deferred DNS tools (dns_enum, theharvester), the
redaction hardening above, and PII decisions D1–D4 remain, tracked separately.
