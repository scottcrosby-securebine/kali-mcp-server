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
runs via `run_command` and RETURNS ITS TEXT UNCHANGED, reads+parses the file
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
byte-unchanged (flags write to a file, not stdout — VERIFY).

Invariants (same as prior waves): arg-list command (no shell); the out path is
server-generated, not caller data; parsers NEVER raise (bad input -> []);
JSON via stdlib json only (no eval), text parsing bounded; findings redacted
before persist; 200-line public text bound + opaque ids unchanged; the leading-
dash target guard and MAX_ARTIFACT_BYTES size cap in the shared runner apply;
the 42 preserved tool signatures unchanged (NO fixture change).

Test seams (extend tests/test_scanner_adapters.py): each parser maps a
representative sample to the expected findings/severity; malformed/empty/hostile
input -> [] no raise; each tool's text return unchanged vs a run_command mock;
the single-ID report accepts each new scanner. Mock run_command; no real binaries.

Out of scope: the DNS/recon family and the raw-text tail (later waves); deep
per-tool analysis beyond the mappings above.
