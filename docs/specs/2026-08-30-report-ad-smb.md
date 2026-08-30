# P3c / #90 — Internal AD/SMB assessment report

Phase 3c of the report-types stack. Built on the P3b tip
`feat/report-attack-surface`@`62decd6`. Standalone **internal AD/SMB posture**
report for internal IT / blue team — a domain nothing else in the toolkit's
reports covers. Mockup: "SMB Perimeter" (issue #90).

Fixed point (matts): `62decd621e120ed3e35400b6943971107bf05a1d`.

## Anchor (issue #90, verbatim acceptance)
- [ ] Per-host SMB posture table (signing/SMBv1/null-bind)
- [ ] Share inventory with access + sensitivity flags
- [ ] Users + password-policy summary
- [ ] Poisoning exposure marked observation-limited
- [ ] Reuses SecureBine token system

Issue framing (verbatim): "Build the host-posture table as the core (rides the
working tools); render the poisoning/relay section as observation-limited given
the responder stub." "The MITRE mapping is report-side analysis over tool
output (flag it)." "Engagement precondition: internal placement + a domain
credential — state as scope, not a tool gap."

## In-container data surface (red-teamed against docker/packages.lock)
Installed feeders: `enum4linux=0.9.1-0kali2` (legacy Perl, no JSON),
`smbclient=4.24.5` (`-L`), `crackmapexec=5.4.0-0kali7` (pre-netexec, no
`--json`), `responder=3.2.2.0` (runs nothing under cap-drop), `nbtscan=1.7.2`.
Native-JSON tools (enum4linux-ng, netexec/nxc) are NOT in the image; adopting
them is a Dockerfile/tool-swap, out of scope for this phase.

Asymmetry that drives the design: crackmapexec's host line has a **stable
trailing** `(name:..) (domain:..) (signing:True) (SMBv1:False)` format, so the
structure is parseable — but the same line also carries the target's own OS
banner verbatim, so it is NOT a trustworthy channel for a verdict about a
hostile host. Parse the structure, bound the claim (see the honesty rules).
enum4linux's multi-section banner output is fragile → best-effort
parse with raw-transcript fallback (the Metasploit-card `_msf_*` precedent).
crackmapexec 5.4.0 colorizes non-TTY output → control bytes are folded before
slicing (`_adsmb_lines`, which reuses the existing `_strip_control_bytes`
chokepoint), same trap the Metasploit card solved.

## Settled decisions (Scott, 2026-08-30)
- **D1 tool surface:** new `@mcp.tool async def internal_ad_report(result_ref: str = "") -> str`.
  Filters captured results to the AD/SMB subset `_ADSMB_SCANNERS`, keeps newest
  per (scanner, normalized target), tags the envelope `report_type:"adsmb"`,
  calls existing `_write_report`. One-line docstring. Mirrors `surface_report`
  exactly.
- **D2 source:** renders over ALREADY-CAPTURED results in `RESULTS_ROOT`. Does
  NOT re-run scanners. Same aggregator shape as `surface_report`/`web_app_report`.
- **D3 net-new capture (mirrors P3b's "wire the new parser at capture time"):**
  - **`_parse_crackmapexec`** (STRUCTURED SPINE): parse the CME smb host line —
    per-host OS, name, domain, `signing:` tri-state, `SMBv1:` tri-state. null-bind
    does NOT come from here: crackmapexec cannot supply it (see the honesty
    rules). Control bytes are folded per line and the text split on newline
    alone (`_adsmb_lines`) before any slice.
    Wired into `crackmapexec_scan` via `_run_with_capture` (replaces the current
    unpersisted `run_command`). Best-effort; parse-miss → raw-transcript card.
  - **`_parse_enum4linux`** (best-effort + fallback): shares (sharename · type ·
    comment · map OK/DENIED), users (from `user:[name] rid:[..]`), and password
    policy (min length / lockout / history / complexity). Wired into
    `enum4linux_scan` via `_run_with_capture`. Parse-miss → raw-transcript card.
  - **enum4linux capture change (Scott: "Add -P to capture"):** `enum4linux_scan`
    invocation becomes `-U -S -G -P` so the password-policy summary has real data.
    `-P` is one extra RPC, not the `-a` sweep the existing comment dropped for
    timeout; TIMEOUT_EXTRA_LONG unchanged. Update the scope comment.
  - **nbtscan / smbclient stay raw-transcript feeders** (already captured). NetBIOS
    names/roles surfaced from the nbtscan transcript, corroboration only.
  - **responder unchanged** — static advisory, runs nothing; source of the
    observation-limited poisoning section, not a parser.

## Honesty rules (non-negotiable, mirror #90 caveats + P3b posture)
- **Host posture is observed-only.** signing/SMBv1/null-bind asserted only
  from an observed crackmapexec line; a host with no CME observation is absent
  from the posture table, never rendered "secure".
- **The channel is partly target-controlled, and the report says so** (Scott,
  2026-08-31, ruling O1). crackmapexec writes the target's own negotiate
  response into the host line unsanitized (`smb.py`: `server_os =
  conn.getServerOS()`, interpolated into the log line), so a hostile host can
  put a newline in its banner and author a syntactically perfect host row for
  any IP. **No parser-side anchoring closes this; it is a property of the
  channel, not a bug in the parser.** Do not write a spec sentence claiming the
  target cannot forge a line — an earlier revision did, and it was false.
  What IS guaranteed, and is checkable:
  - Feeder text is normalized per line through `_strip_control_bytes` and split
    on newline ALONE (`_adsmb_lines`), so no substitution reaches across a line
    boundary and none of `str.splitlines()`' other separators (CR, VT, FF,
    FS/GS/RS, NEL, U+2028/9) acts as one.
  - A verdict is emitted ONLY for a line whose structure is unambiguous.
  - The rendered report BADGES the posture verdicts as parsed from tool text,
    states that a host can influence its own row, presents the counts as lower
    bounds, and tells the reader to treat a single row as a lead to confirm.
    ATT&CK entries say the same. The verdicts are not presented as clean
    observations.
  - The permanent fix is a feeder with real structured output (netexec /
    enum4linux-ng emit JSON). Recorded as the follow-on; out of this phase.
- **An AMBIGUOUS host line asserts NOTHING, and says so in the report.** A line
  is ambiguous when it carries more than one `(name:` or `[*]`, when its trailing
  group does not parse, or when it exceeds `MAX_CME_LINE` — the banner is
  unbounded and target-controlled, so the target would otherwise choose where a
  clip falls and leave a forged group legitimately end-anchored. Such a line
  still reports the host, built from the tool's own start-anchored prefix
  columns, with OS, domain and both flags reading "not observed" and a
  `conf-heuristic` "line ambiguous — verdict withheld" marker in its row.
  Honesty must not cost visibility, and a withheld verdict must not read like a
  host the tool simply did not flag.
- **The share table is target-controlled CONTENT, excluded from every other
  extractor.** All three of its columns come from the target, and the share NAME
  is the leftmost field, so a line-start anchor alone is satisfied by a share
  called `[+]x` (forged the password policy) or `user:[X]` (forged an enumerated
  user), and a comment carrying `//h/s Mapping: OK` forged an access verdict on
  a share that does not exist. The table region is excised before users, share
  mappings, policy and the session check are read.
- **Every posture verdict comes from an EXACT observed token, anchored to the
  tool's own structure, and is tri-state.** signing/SMBv1 come from ONE
  END-ANCHORED trailing group `(name:..) (domain:..) (signing:..) (SMBv1:..)`,
  read as a single pattern rather than four independent searches. Four searches
  are positional, not structural: when the real group omits the flags — which
  crackmapexec does — the last `(signing:..)` on the line is whatever the
  target-controlled banner put there. The host prefix is likewise anchored at
  line START, so a `SMB <ip> <port>` sequence quoted inside a non-SMB
  crackmapexec transcript cannot become a phantom host row. An absent
  token is `"not observed"`, never `False`: absence is not an observation, in
  either direction. Every consumer tests `is True` / `is False` — a truthiness
  test would silently read `"not observed"` as a verdict. Password-policy values
  are read only from enum4linux's own `[+]` policy lines, never from a
  whole-transcript search, because a share COMMENT is target-controlled text on
  that same transcript.
- **null-bind comes from enum4linux's session check, NOT crackmapexec.** Verified
  against the pinned image: crackmapexec 5.4.0 contains no `(Guest)` marker at
  all, and `connection.py` only reaches its auth-success sites after a
  successful `login()`, which cannot happen because `crackmapexec_scan` passes
  no credentials — so it emits no `[+] <domain>\<user>:` line on the shipped
  path and a parser for one is dead code. The real signal is
  `enum4linux.pl`'s `print_plus("Server <target> allows sessions using username
  '<u>', password '<p>'")`; an EMPTY username is the anonymous bind, matched
  whole against a `[+]` line outside the share table and joined to the posture
  row by host hint. No observation → "not observed", never "disabled".
- **Password policy** renders real values when `-P` returned them; a field the
  capture did not return reads "not observed", never "compliant".
- **Sensitive-share flag is a keyword heuristic, flagged as such** (memory:
  keyword-classifiers-flag-not-confirm). Names like ADMIN$, C$, IPC$, SYSVOL,
  NETLOGON, any name ending `$`, and content hints
  (backup/finance/hr/payroll/password(s)/secret/confidential) get a `conf-heuristic`
  "sensitive-name — verify" badge. The flag never asserts the share IS sensitive
  or exposed; ACLs beyond enum4linux's map OK/DENIED are not observed.
- **Poisoning / relay section is observation-limited.** responder runs nothing
  under cap-drop; the section renders LLMNR/NBT-NS/mDNS exposure as
  `conf-heuristic` "not actively assessed — requires elevated on-network
  capture", nothing asserted (theHarvester-gap precedent, P3b line ~2886).
- **ATT&CK mapping is report-side analysis (Scott: "Bounded flagged mapping").**
  A static rule table: each OBSERVED weakness (SMBv1 observed on, signing
  observed off, null-bind observed) → one ATT&CK technique id + a one-line
  note, under a `conf-heuristic` "report-side analysis" badge. No ordered
  attacker-path narrative; no technique emitted for an unobserved weakness. This
  is a mapping legend, not a synthesized "chain" — an acknowledged fidelity gap
  to the mockup's "chain" wording, ruled acceptable.
- **Engagement precondition is scope, not a tool gap.** A one-line page note:
  "requires internal placement + a domain credential", never rendered as a
  toolkit deficiency.

## Escaping / PII (non-negotiable, copy P3b chokepoint verbatim)
- `render_adsmb` defines a local `esc()` = `escaped(_mask_email(value))` — the
  ONE chokepoint. EVERY attacker-controlled cell (share name, comment, user
  host name, OS banner, domain, NetBIOS field) routes through `esc()`. User
  names take `_mask_email` + `list_items`, which escapes internally: `esc` there
  would escape a second time and render `a<b>` as entity garbage.
  Fixed enums (signing True/False, verdict strings) and numerics use plain
  `escaped()`. No cell reaches the template unescaped.
- `_strip_ansi` runs before any column slicing (both parsers + raw-card
  transcript), so CME colour codes can't smuggle bytes past the parser.
- Any regex over feeder text uses BOUNDED quantifiers (memory:
  wall-clock-perf-asserts-flake-on-ci); verify linearity with a scaling-ratio
  test, not wall-clock seconds.

## AD/SMB subset (feeders)
`_ADSMB_SCANNERS = ("crackmapexec", "enum4linux", "nbtscan", "smbclient")`.
Structured this phase: crackmapexec (`_parse_crackmapexec`), enum4linux
(`_parse_enum4linux`). Transcript corroboration: nbtscan, smbclient (both
already in RAW_TRANSCRIPT_SCANNERS). responder is advisory-only, not a feeder.

## Normalized finding shape (existing envelope, do not change)
`{schema_version, scanner, source_type, target_ref, status, findings[], metadata}`

## render_adsmb(result_docs) — new closure in `_render_report`, new dispatch branch
New `_ADSMB_TEMPLATE` (SMB Perimeter IA), reusing escaped/rows/list_items/chart
+ existing tokens/CSS/badges. Sections:
1. **Posture summary tiles** — hosts assessed, SMBv1-on count, signing-off count,
   null-bind count, shares flagged.
2. **Per-host SMB posture** table — host · IP · OS · domain · signing · SMBv1 ·
   null-bind (crackmapexec spine).
3. **Share inventory** — host · share · type · comment · map (OK/DENIED) ·
   sensitivity flag (heuristic badge).
4. **Users + password policy** — user list (count + names) + policy summary
   (min length / lockout / history / complexity), fields not returned → "not
   observed".
5. **NetBIOS roles** — nbtscan names/roles (corroboration, transcript-derived).
6. **Poisoning / relay exposure** — observation-limited (conf-heuristic).
7. **ATT&CK mapping** — bounded flagged legend (observed weakness → technique id).
8. **Remediation** — ranked from observed weaknesses (disable SMBv1, require
   signing, disable null-bind), each tied to its host(s). The LLMNR/NBT-NS item is
   deliberately domain-wide and names no host.
9. Provenance (scans this session) + tool versions + engagement-precondition note.
All attacker-controlled fields via `esc()`.

## Test seams (TDD, agreed before wave 1)
- `_parse_crackmapexec`: CME host-line fixture (incl. ANSI-coloured variant) →
  {host, os, domain, signing, smbv1}; ambiguous line → every forgeable field
  withheld but the host still reported; parse-miss text → raw fallback
  signalled. Control bytes folded per line (no mis-slice, no cross-line splice).
- `_parse_enum4linux`: fixture with users / shares / password-policy sections →
  structured dict; missing password-policy section → policy fields "not
  observed"; malformed → raw fallback signalled.
- `_sensitive_share` (heuristic): ADMIN$/SYSVOL/"finance" → flagged; a plain
  share → not flagged; flag is advisory (badge text asserts "verify").
- `render_adsmb` via `_render_report({report_type:"adsmb", results:[...]})`:
  asserts posture rows, share rows with flags, users + policy, poisoning section
  carries observation-limited badge, ATT&CK legend only lists OBSERVED
  weaknesses, emails masked, markup in share/user/comment fields stays escaped,
  no "secure"/"compliant"/"safe" label emitted, null-bind "not observed" when
  unobserved.
- `internal_ad_report`: aggregates stored AD/SMB results, sets report_type,
  persists via `_write_report`; empty store → informational message.
- Bounded-regex scaling test on the enum4linux/CME parsers (ratio, not seconds).

## Acceptance (#90) — mapped
- Per-host SMB posture table → §2 (crackmapexec spine).
- Share inventory + sensitivity flags → §3.
- Users + password-policy summary → §4 (enum4linux `-P`).
- Poisoning observation-limited → §6.
- Reuses SecureBine token system → REPORT_CSS tokens + badges, no new palette.
