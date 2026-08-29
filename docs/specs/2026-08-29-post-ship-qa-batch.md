# Post-ship QA issue batch — spec / anchor

Fixed point: `31dbb837e1a19d163cad32f26f54c0f324ae9826` (main, 2026-08-29).
Branch: `fix/post-ship-qa-batch`. Issue-ref resolution: `docs/agents/issue-tracker.md`.

## Scope decisions (verbatim, Scott, 2026-08-29)

- **Done 4 (closed with evidence):** #39, #40, #44, #45 reproduce as fixed in
  HEAD and shipped in v2.0.0 (filed before the release); closed with evidence
  comments this session.
- **#72/#73 REVISED (Scott D3):** originally slated to close as "already fixed",
  but their fix commits are ancestors of the v2.0.0 tag while the issues were
  filed AGAINST v2.0.0 reporting the failure — the code did not cure the runtime.
  Root cause of #72 is #82. Both are now code-fixed in Phase 2 (F8/F12), not closed.
- **Fix scope:** F1–F7 (Phase 1) + F8–F12 (Phase 2, folded per D3) under the
  doctrine gate, with runtime container verification.

Structural: all 7 fixes touch the single file `kali_pentest_server.py`, so
mutations serialize (doctrine's single-file rule). Fan-out is the phase gate
(matts-code-review Standards+Spec + codex red team + simplification), which is
non-mutating. One phase, one gate.

## Fixes (F1–F7)

Each: root cause, acceptance criterion (AC), test seam. ACs are drawn from the
issue bodies; the Spec reviewer resolves `#N` via the issue tracker.

- **F1 — #74 SECURITY (redaction under-match).** `_redact_scanner_data` /
  `SECRET_VALUE_PATTERNS` is keyword-anchored (`keyword[:=]value`). nikto emits
  `Uncommon header(s) '<name>' found, with contents: <value>` — the value sits
  away from any keyword+separator, so it leaks to direct output, the `/results`
  store, and the report. **AC:** a credential value echoed in nikto's
  `... '<name>' found, with contents: <value>` prose is redacted when `<name>`
  matches a secret keyword; the existing header redaction is unchanged. **Seam:**
  redaction unit test asserting the nikto-prose value is `[REDACTED]`.

- **F2 — #78 (redaction over-match).** The HTTP-Basic-auth pattern
  `(basic\s+)[A-Za-z0-9+/=]+` matches Metasploit's `Basic options:` →
  `Basic [REDACTED]:`. **AC:** `Basic options:` survives verbatim; real bare
  `Basic <b64>` credentials still redact (including short, all-lowercase, and
  sentence-final ones — red-team R3). **Approach:** keep the broad base64 run,
  add a negative lookahead so a run immediately followed by `:` (a label) is not
  matched. A base64-shaped English word followed by `;`/EOL stays redacted (the
  original pattern's pre-existing behavior, out of #78's colon-label scope).
  **Seam:** redaction table — `Basic options:` survives; short/lowercase/final
  bare Basic creds redact. Same function as F1 — one agent, together.

- **F3 — #75 (theHarvester google engine).** Wrapper defaults/remaps to `google`,
  which theHarvester 4.11.1 dropped → exit 1 before any work; `source` arg not
  honored for the default. **AC:** default to a supported source; `source=`
  selects the engine; a real nonzero failure still surfaces as `❌`. **Seam:**
  argv-build test — default source is not `google`; `source="crtsh"` produces
  `-b crtsh`.

- **F4 — #76 (amass unbounded).** No bounded `-timeout`, no partial output, so the
  call never returns within the client budget. **AC:** amass runs passive by
  default with a bounded `-timeout` inside the tool's own timeout tier; returns
  subdomains or a bounded empty result. **Seam:** argv-build test — passive mode
  and a bounded `-timeout` flag are present by default.

- **F5 — #77 (valid-negative exits mislabeled).** `run_command` /
  `_run_with_capture` map any nonzero exit to `❌ Scan failed`; wpscan exit 4
  (not-WordPress) and sslyze exit 1 (cert/policy verdict) are valid negatives.
  **AC:** these classify as success WITHOUT masking real failures; genuine
  failures still `❌`; no regression to legacy callers passing nothing.
  **Approach (revised after red-team R1/R2):** a bare exit-code allowlist is
  wrong — wpscan 4 is any "scan did not finish" and sslyze 1 is a verdict OR
  `ServerScanResultIncomplete` (both confirmed from upstream source). So a caller
  passes `success_markers` = (exit_code, required_substring) pairs; the nonzero
  exit is success only when the marker proving a real result is present — wpscan
  `"does not seem to be running WordPress"`, sslyze `"Compliance against TLS
  configuration"`. **Seam:** adapter test — exit-4-with-marker → ✅, exit-4
  without-marker → ❌; exit-1-with-banner → ✅, incomplete (no banner) → ❌;
  unmarked nonzero still ❌.

- **F6 — #13 (startup arch log).** Startup emits no runtime-arch line; two
  docstrings (hashcat, metasploit_search) still say "ARM64". **AC:** report
  architecture without hard-coding Apple Silicon (or omit the claim); do not
  present QEMU arm64 as physical macOS qualification; stdio MCP behavior and the
  42+5 contract preserved; a focused test if a message remains. **Seam:** test the
  arch-string helper returns the real `platform.machine()` and never a hard-coded
  "Apple Silicon".

- **F7 — #35 (trivy `image` alias).** Error/docstring already list accepted values
  (`_format_accepted`); the remaining half is that the intuitive `image` value is
  rejected. **AC:** `trivy_scan(source_type="image")` succeeds by aliasing to
  `registry` (remote ref); accepted-value listing preserved. **Seam:** test
  `source_type="image"` resolves to the registry path, not `_scanner_error`.

## Close-with-evidence (Done 6)

#39, #40 (EPSS/KEV, commit 260afbd), #44 (web scheme, fdc5fe9), #45 (hashcat
self-test + pocl, 6dc150a/5dbee82) — closed with evidence this session.
**#72/#73 are NOT here** — they were reported against v2.0.0 with the code fix
already in it (runtime ≠ code), so they are code-fixed in Phase 2 (F8/F12), not
closed as bookkeeping. See the revised note in Scope decisions.

## Gate

Native checks (project-documented): `python3 -m unittest discover -s tests`;
`python3 tests/redaction_differential.py` (read EXIT STATUS: 0 clean, 3 nothing
to measure, else fail); `scripts/mutation-check <base>` where a redaction/adapter
assertion is added. Designated review: `matts-code-review` (Standards + Spec,
this file as spec path, fixed point `31dbb83`). Red team: `codex:codex-rescue`.
Simplification once before the certifying passes. Exit: two consecutive clean
passes. Delivery: commit on `fix/post-ship-qa-batch`; **hold for "push it"**
before any push or PR (standing rule + repo dev→PR→deploy norm).

## Phase 2 fixes (F8-F12) — folded in per Scott D3 (2026-08-29)

- **F8 — #82 (fixes #72).** SSL tools built `f"{target}:{port}"` unconditionally,
  so a port-bearing target became `host:8099:443` -> sslscan usage -> false ✅.
  `_target_host_port(target, default)` parses host/port once with urlsplit (embedded
  port wins, scheme/userinfo dropped, IPv6 re-bracketed); applied to sslscan,
  sslyze, testssl. sslscan also treats a `Usage:` banner as a failure marker.
  **AC:** `host:8099` scans host:8099 (no triple colon); explicit+embedded port
  resolved once; #72 usage-banner-as-success gone. **Seam:** _target_host_port unit
  table + sslscan argv test.
- **F9 — #81.** whatweb/wafw00f/sslyze/nikto/sslscan exit 0 on a failed connection
  -> false ✅ persisted as coverage. `run_command` gains `failure_markers`: an exit-0
  output containing a connection-failure signature demotes to ❌. **AC:** a refused/
  unreachable scan reads ❌ and status=failed; a clean exit-0 stays ✅. **Seam:**
  failure-marker demotion test + whatweb/sslyze wrapper tests.
- **F10 — #80 SECURITY.** Scanner-controlled ANSI/OSC/CSI + C0/C1 bytes reached the
  terminal and the HTML report. `_strip_control_bytes` runs in `run_command` (after
  redaction, before classify/bound) and in `_escape_report_data`. **AC:** ESC/OSC/BEL
  removed from output and report; tab/newline preserved. **Seam:** control-byte strip
  tests on output + report escape.
- **F11 — #83.** `web_audit` TLS stage hand-sliced the host and returned the userinfo
  username for `https://user:pass@host/`. Now `urlsplit(target).hostname`. **AC:** the
  TLS stage scans the real host. **Seam:** web_audit userinfo-URL test (mocked subs).
- **F12 — #73.** `nmap_service_scan` gains `--host-timeout` (TIMEOUT_LONG-60s) so it
  self-bounds and emits partial output. **AC:** argv carries a bounded --host-timeout.
  **Seam:** nmap argv test.
- #84 = track-only (mcp/pydantic transport, likely upstream). Not fixed here.

Runtime verification (Scott): build the image and run the #80/#81/#82/#72/#73/#83
repros in-container before certifying.

## Backlog fold-in (Scott, 2026-08-29): #96 + #97

Folded into this branch after the F1-F12 gate exited; same security-hardening theme.

- **#96 — PEM redaction ReDoS (pre-existing).** The PEM private-key pattern in
  `SECRET_VALUE_PATTERNS` used an unbounded `[\s\S]*?` between BEGIN and END, O(n^2)
  on target-reflected content with many unpaired openers. **AC:** the pattern is
  bounded so redaction is linear (a real key body <=~13KB still redacts; a genuine
  paired key is unaffected). **Seam:** timing guard (8000 unpaired openers < 2.5s;
  verified to exceed it on the unbounded pattern) + a real-key-still-redacts test.
- **#97 — SSL wrappers missing the leading-dash guard.** `sslscan_scan`,
  `sslyze_scan`, `testssl_scan` called `validate_target` but not
  `_reject_option_like`, so a dash-flag target (`--xml=/tmp/x`) reached the tool as
  an extra argv (CWE-88, operator-supplied/low). **AC:** a target beginning with `-`
  is rejected with the standard guard error before argv construction; a normal
  target still reaches the tool. **Seam:** the three wrappers reject a dash target;
  a normal target still calls execute_command.
