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
