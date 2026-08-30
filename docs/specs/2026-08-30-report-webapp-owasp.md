# P3a / #88 — Web-application findings report (OWASP/WSTG)

Phase 3a of the report-types stack. Built on the Phase-2 tip
`feat/report-risk-dossier`@`ef81fb0`. Standalone web-app report mapping web-scanner
findings to OWASP Top-10 (2021) + WSTG, per-endpoint, for app/dev teams.

## Settled decisions (Scott, 2026-08-30)
- **D1 tool surface:** new `@mcp.tool async def web_app_report(result_ref: str = "") -> str`.
  Filters captured results to the web-scanner subset, tags the envelope
  `report_type:"webapp"`, calls existing `_write_report`. One-line docstring.
- **D2 source:** renders over ALREADY-CAPTURED results in `RESULTS_ROOT` (mirrors
  `generate_report` no-ref path ~5150). Does NOT re-run scanners.
- **D3 capture:** build net-new structured capture for ALL THREE currently-text-only
  feeders — sqlmap, wpscan, wfuzz — wired through `_run_with_capture` like ffuf/nikto.
  (wfuzz overlaps ffuf dir-bust; built anyway per Scott.)
- **D4 mapping:** net-new static substring table `_OWASP_WSTG_RULES` of
  `(token, owasp_category, wstg_id)`, matched per-finding against lowercased
  Title/id/evidence, following the `_MACRO_ATTACK_SUBSTR` (~3966) OBSERVED-ONLY
  discipline. Never inferred from scanner name alone.

## Honesty rules (from #88 caveats + Scott O1 ruling 2026-08-30 — non-negotiable)
- A keyword classifier cannot tell a vulnerability from a defence being present
  ("XSS found" vs "X-XSS-Protection header present"), so it FLAGS, never confirms.
- The coverage grid reads "flagged for review" / "not flagged" — never
  "exercised" and never "secure".
- A keyword-mapped finding renders as a confirmed severity ONLY when a scanner
  that actively tests the weakness (nuclei/nikto/sqlmap/wpscan) produced it;
  every other mapped finding renders "requires manual confirmation".
- Findings a detection-only scan cannot prove (IDOR/A09) also render "requires
  manual confirmation".
- Dir-bust path Titles never classify (a filename is not evidence of a class);
  they own the discovered-content lane. Tokens match on WORD BOUNDARIES so a
  slug like wp-sqlite-db does not forge A03.
- Unmapped findings land in an "unmapped / manual review" bucket, never forced into a category.

## Web-scanner subset (feeders)
Structured-capture today: nikto, nuclei, whatweb, wafw00f, dirb, gobuster, ffuf.
Net-new this phase: sqlmap, wpscan, wfuzz.

## Normalized finding shape (existing envelope, do not change)
`{schema_version, scanner, source_type:"host", target_ref, status, findings[], metadata}`
finding = `{"id","Title","Severity","evidence",[remediation],[reference], ...}`

### New parsers (each: parse tool output -> list[finding], wire via _run_with_capture, add to render allowlist)
- **`_parse_sqlmap`**: from `sqlmap --batch --output-dir` / JSON log. Finding carries
  `param`, `dbms`, `technique`, `payload`/repro in evidence; Title = injection point;
  Severity HIGH. REQUIRED for the acceptance "sqlmap injection detail" criterion.
- **`_parse_wpscan`**: from `wpscan --format json`. Findings for vulnerable
  plugins/themes, WP version, user enum; Severity from wpscan's own vuln refs.
- **`_parse_wfuzz`**: from `wfuzz -f json` / `-o json`. Discovered-content hits;
  Severity INFO; Title/evidence = path + code/size. (dir-bust lane, like ffuf.)

## render_webapp(results) — new closure in _render_report, new branch above ~2236
Layout (mockup "WebProof OWASP" IA), reusing escaped/rows/flatten/chart/render_findings/
confidence_chip/slots + existing tokens/CSS:
1. OWASP Top-10 (2021) coverage grid — A01..A10, each: exercised/not-exercised, finding count.
2. Per-endpoint findings table: endpoint · OWASP cat · WSTG id · severity · tool-sourced evidence snippet.
3. sqlmap injection worked block: param -> DBMS -> technique -> repro (when a sqlmap finding present).
4. Discovered-content (dir-bust) section with risk flags (dirb/gobuster/ffuf/wfuzz).
5. Tech-stack / outdated-components (whatweb/wpscan).
6. Remediation grouped by OWASP category.
All attacker-controlled fields escaped via existing `escaped()`.

## Test seams (TDD, agreed before wave 1)
- `_parse_sqlmap` / `_parse_wpscan` / `_parse_wfuzz`: fixture text/json -> expected finding dicts.
- `_owasp_classify(finding)`: known token -> (category, wstg); unmapped -> manual-review; observed-only.
- `render_webapp` via `_render_report({report_type:"webapp", results:[...]})`: asserts OWASP grid,
  per-endpoint rows, sqlmap block present when sqlmap finding present, "not exercised" for empty categories,
  markup in fields stays escaped, no "secure" label ever emitted.
- `web_app_report`: aggregates stored web results, sets report_type, persists via _write_report.

## Acceptance (#88 + this spec)
- [ ] Findings grouped/mapped to OWASP Top-10 + WSTG (observed-only)
- [ ] Per-endpoint findings with tool-sourced evidence snippets
- [ ] sqlmap injection detail rendered when present
- [ ] Discovered-content (dir-bust) section with risk flags
- [ ] wpscan + wfuzz structured-captured (D3)
- [ ] Reuses the existing SecureBine report token system
- [ ] "not exercised" / "manual confirmation" honesty rules enforced; never "secure"
- [ ] All rendered attacker-controlled fields escaped
