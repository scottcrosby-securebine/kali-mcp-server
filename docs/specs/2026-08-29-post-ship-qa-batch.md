# Post-ship QA issue batch — spec / anchor

Fixed point: `31dbb837e1a19d163cad32f26f54c0f324ae9826` (main, 2026-08-29).
Branch: `fix/post-ship-qa-batch`. Issue-ref resolution: `docs/agents/issue-tracker.md`.

## Scope decisions (verbatim, Scott, 2026-08-29)

- **Done 6:** "Close with evidence" — #39, #40, #44, #45, #72, #73 reproduce as
  fixed in HEAD; post an evidence comment citing the fixing commit/lines on each,
  then close as completed.
- **Fix scope:** "5 defects + 2 remainders" — code-fix F1–F7 below under the
  doctrine gate. Closes every open issue this session.

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
  `Basic [REDACTED]:`. **AC:** `Basic options:` survives verbatim; real
  `Authorization: Basic <b64>` credentials still redact. **Seam:** redaction unit
  test asserting `Basic options:` survives and a real Basic token still redacts.
  Same function as F1 — one agent, done together; they pull opposite directions.

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
  **AC:** per-tool known-nonzero exit codes classify as success (wpscan 4, sslyze
  1); genuine failures still `❌`; no regression to legacy callers passing nothing.
  **Seam:** adapter test — a wpscan exit-4 result is not prefixed `❌ Scan failed`;
  an arbitrary nonzero from a tool with no allowlist still `❌`.

- **F6 — #13 (startup arch log).** Startup emits no runtime-arch line; two
  docstrings (hashcat 3338, metasploit_info 3393) still say "ARM64". **AC:** report
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
self-test + pocl, 6dc150a/5dbee82), #72 (sslscan passes target, HEAD), #73 (nmap
`--top-ports=100` default, HEAD). Comment cites the fix, then close as completed.

## Gate

Native checks (project-documented): `python3 -m unittest discover -s tests`;
`python3 tests/redaction_differential.py` (read EXIT STATUS: 0 clean, 3 nothing
to measure, else fail); `scripts/mutation-check <base>` where a redaction/adapter
assertion is added. Designated review: `matts-code-review` (Standards + Spec,
this file as spec path, fixed point `31dbb83`). Red team: `codex:codex-rescue`.
Simplification once before the certifying passes. Exit: two consecutive clean
passes. Delivery: commit on `fix/post-ship-qa-batch`; **hold for "push it"**
before any push or PR (standing rule + repo dev→PR→deploy norm).
