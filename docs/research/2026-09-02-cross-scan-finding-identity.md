# Cross-scan finding identity for the re-test / delta attestation report (#91)

Research date: 2026-09-02. Two independent sourced engines (Claude deep-research
workflow + Codex live web search), primary-source verification throughout, two gate
loops (logic critique + red team each), all findings folded. Dossier:
`2026-09-02-cross-scan-finding-identity-worknotes.md`.

## Recommendation (BLUF)

Two findings, one of them decisive:

1. **The matching machinery is a solved, adoptable pattern.** Every shipping system
   builds finding identity from a per-scanner allowlist of stable fields hashed into
   a versioned fingerprint, run-varying data excluded by construction. Inline
   DefectDojo's *mechanism* (BSD-3, ~40 lines, no dependency), tune the fields
   stricter than DefectDojo ships them, and all ~41 parsers can produce trustworthy
   **NEW / UNCHANGED / UPDATED** deltas once each has a stable key.

2. **A positive "closed / remediated" verdict is structurally unattainable in this
   tool, at this layer.** Two gate loops proved it from two directions: the parsers
   discard the negative observation before the report-time diff ever sees it, and
   the container's mandatory `-sT -Pn` (no raw sockets) cannot distinguish a
   remediated service from a firewall added between scans — a REJECT rule forges an
   RST that nmap reports as "closed." No wording of a comparability gate closes this;
   it is a property of the pipeline and the container, not of the report.

Therefore the recommendation is **Option A**: build #91 as a report-time diff that
classifies NEW / UNCHANGED / UPDATED reliably and says **"not observed on re-test"**
— a bounded, cited, non-closure statement — in place of any FIXED/closed claim, with
a comparability gate that decides only whether even that much is sayable (else
UNKNOWN or the zero-yield bucket). This is exactly what the #91 spec already ruled
(D3: never claim "verified closed"); the research independently proved the ruling is
forced, not merely cautious.

That answers "can we get all 25?" honestly: **yes for the delta — all ~41 parsers
with a stable key participate in NEW/UNCHANGED/not-observed-on-re-test — and no for
closure — no parser at this layer can emit an attestation-grade "fixed."** The
column everyone wants is a "not observed on re-test" column, not a "closed" column.

Scott ruled Option A on 2026-09-02 ("the simplest solution is the honest one").
Option B (a real closure attestation) is parked — larger, capability-bearing,
container-capped. A Tier-2 enhancement layers an **AI-assisted follow-up** on the
honest core: per finding, a grounded next-step recommendation from the finding's
history plus security best practice, advisory and never a closure verdict (see
"Enhancement" below).

## Findings (ranked by confidence)

**C1 — Matching mechanism: per-scanner stable-field fingerprint (DefectDojo/SecObserve). [single-origin, primary-verified]**
`hash_code` = hash of `HASHCODE_FIELDS_PER_SCANNER[parser]` fields, constrained to
`HASHCODE_ALLOWED_FIELDS` (no byte size, timestamp, or list index — that exclusion
is the defense), `service` always appended. `gh api` on `settings.dist.py` confirms
the whitelist verbatim; ~132 hash-field / ~193 algorithm entries. One origin
(DefectDojo repo) confirmed three ways — proves the config is the norm, not that its
fields suit attestation (C2). https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/deduplication_algorithms/ ,
https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/settings/settings.dist.py

**C2 — DefectDojo validates the mechanism and is the negative example for attestation. [both engines, web; primary-verified]**
Shipped lists carry drift-prone `title`/`description`; source comments document
per-scanner repairs for ffuf, Dirsearch, Gobuster, WhatWeb, Naabu, Masscan, sqlmap,
Nettacker, httpx (changing sizes/versions/timestamps/payloads — our failure list);
issues #8100 and #12754 are real false-mitigation bugs (both now closed, `gh api`
verified). Take the mechanism, stricter fields.

**C3 — "Closed/fixed" cannot be inferred from absence; even the standards refuse to. [red team + both loops; SARIF/OpenVEX primary-verified]**
SARIF `baselineState=absent` is "present in baseline, absent now" — a comparison
state, explicitly not remediation; GitHub keeps such alerts reopenable. OpenVEX
makes `fixed` an asserted, evidence-backed status beside `under_investigation`
(≈ UNKNOWN), never derived from a vanishing finding.
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html (§3.27, primary-verified),
https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md (primary-verified)

**C4 — Positive-closure evidence is unavailable at this tool's diff layer and container. [both loop-2 seats; primary-verified against our code + nmap.org]**
The killer finding, from two independent angles:
- **Data path.** `retest_report(baseline_ref, result_ref)` diffs already-parsed
  finding dicts. The nmap parser keeps only `state=="open"` (verified,
  `kali_pentest_server.py:3641`); closed/filtered/host-up observations are discarded
  before the diff can use them. The evidence a closure claim needs is not in the
  artifact.
- **Container.** With mandatory `-sT -Pn`, no raw sockets (CLAUDE.md security model),
  a connect scan reads *closed* from an RST and *filtered* from silence. A REJECT
  firewall rule added between scans **forges an RST nmap reports as "closed"**
  (https://nmap.org/book/determining-firewall-rules.html, primary-verified); a DROP
  rule reads *filtered*. Both are indistinguishable from remediation, and under
  `-Pn` "host up" is only inferred from *another* open port, not the port under test.
- **Granularity.** Reachability of *an* observation (a TLS handshake succeeding)
  never proves the *specific negative probe* for a finding executed — sslscan/testssl
  enumerate ciphers by attempting each; a target that now rate-limits enumeration
  shows the weak cipher absent behind a green handshake. Per-probe evidence, which
  the pipeline does not carry, would be required.
Conclusion: at report-time-diff-of-dicts under this container, a positive closure
verdict is not obtainable. Use "not observed on re-test," never "fixed/closed."

**C5 — Identity excludes version; version is a state signal. [both engines, web]**
Trivy `Fingerprint` includes `PkgID` (with version), so it tracks an exact-artifact
observation, not the logical vuln. Logical key = `VulnerabilityID + PkgName +
normalized target`, version in evidence; a bump is UPDATED, not fixed+new.
https://github.com/aquasecurity/trivy/issues/9793

**C6 — Config-driven scales operationally; trustworthy-verdict authority does not scale without per-scanner verification. [both engines]**
DefectDojo's ~132/193 entries prove the registry scales; but field choice is
semantic, not syntactic, and must be fixtured per parser (repeated/reordered output,
benign banner/size/version change, one genuine change, partial scan, parser failure).

**C7 — Serialize framed, version the fingerprint; require parser_id and target-mode equality. [engine 2 + red team]**
Canonical sorted-key JSON + explicit null markers + SHA-256, prefixed `parser_id` +
`fingerprint_version`; dual-read migration on schema change. Two red-team clauses:
(a) fingerprints are `parser_id`-prefixed and the toolset has overlapping scanners
(three TLS tools; ffuf and wfuzz), so a **tool swap** between runs surfaces as a
spurious drop+new pair — matching requires `parser_id` equality, and tool
substitution is not a valid re-test; (b) for a **name-addressed** target key on the
name and gate single-origin, for an **IP-addressed** target key on the IP — else
C4's host-in-key fix reintroduces dnsrecon's IP-churn for CDN/rotating-DNS hosts.

**C8 — Tool-side: of ~19 parsers inventoried (~41 total), most already emit stable ids; ~4-6 are contaminated. [own source read; high conf on the subset]**
Stable: nmap scripts, amass/subdomain, whatweb, wafw00f, sqlmap, the TLS trio, nmap
ports (single-host). Contaminated: dnsrecon (IP), nikto (list-position fallback),
ffuf/wfuzz (status/code in key), wpscan (list position + version). The ~22
uninventoried parsers are unaudited — "all 41 participate" is gated behind finishing
this inventory.

## Verdict model (what the report may emit)

- **NEW** — fingerprint present now, absent in baseline (vetted parser).
- **UNCHANGED** — present in both (vetted parser).
- **UPDATED** — same identity, changed evidence (version/severity/banner).
- **NOT OBSERVED ON RE-TEST** — present in baseline, absent now, from a re-run that
  passed the comparability gate. A cited non-closure statement, never "fixed."
- **UNKNOWN / NOT RE-TESTED** — gate failed: scan errored/partial, scope narrowed,
  scanner-content version differs, asset-set shrank, or ordering wrong.
- **ZERO-YIELD** — baseline had findings, re-test parsed none: own bucket, asserts
  nothing (#91 spec ruling).
- Un-vetted parser → advisory only. Contaminated un-vetted (ffuf/wfuzz/wpscan/dnsrecon
  raw) emit false-NEW churn and must be normalized or labeled low-confidence — this
  is added noise the pure-exclusion cut avoided, not free coverage.

**Comparability gate** (decides only whether NOT-OBSERVED-ON-RE-TEST is sayable vs
UNKNOWN): same check ran with `parser_id` equality, exit success, ordering correct,
scanner-content version matches, scope comparable. Note the limit (red team): a host
that is up but now has all ports closed emits no findings and drops from the
responded-set, so full closure is indistinguishable from a host going dark → UNKNOWN.
The maximal remediation is the one this layer can least attest — an accepted ceiling,
not a bug to chase.

## Baseline persistence

Read path is resolved by the #91 spec (D1/D2): `retest_report` diffs at report time,
no new stored state; `baseline_ref` is an opaque same-session result id or a path
under the read-only `/artifacts` bind. Two open edges: the baseline artifact must
carry, per finding, `captured_at` + argv + exit/status + responded-asset-set +
scanner-content version, so pre-schema baselines can only ever produce UNKNOWN; and
the cross-engagement **write** path is unspecified — `/artifacts` is read-only and
`/results` is `--rm` tmpfs, so persisting a baseline for a later engagement is
operator-manual today.

## Adoptable OSS (none as a drop-in identity engine)

- **DefectDojo** (BSD-3): mechanism + shared field-map data; drop Django and the
  unframed hash.
- **SecObserve** (BSD-3, Python): lifecycle *wiring* reference — but its lifecycle
  "resolves absent-in-scope," i.e. it closes on absence, the exact behavior C3/C4
  forbid; borrow its indexing shape, not its resolution semantics or its hash.
- **Semgrep** `rule_match.py` (LGPL-2.1): code-finding key reference.
- **microsoft/sarif-tools** (MIT, pip): SARIF diff; skips equal-count appear/disappear.
- **github/codeql-action** `fingerprints.ts` (MIT): content-relative line hashing.
- **trivy-plugin-compare** (Apache-2.0): CVE-id sets only — unsafe as a sole engine.

Verdict: of those surveyed, no Python package safely solves identity for ~41
heterogeneous Kali tools. Build the small local registry; borrow per finding-type.

## Concrete design

1. `IDENTITY_FIELDS_PER_PARSER` + global `IDENTITY_ALLOWED_FIELDS` whitelist.
2. Normalization before hashing: lowercase host/scheme/protocol, strip URL
   query+fragment, port as int, sort set-valued fields, drop trailing dots, keep path
   case, explicit null markers; name-vs-IP keying per C7.
3. Fingerprint = SHA-256 of canonical sorted-key JSON, prefixed `parser_id` +
   `fingerprint_version`.
4. Verdict per the model above — no "fixed/closed" emitted at this layer.
5. Comparability gate as above; any miss → UNKNOWN.
6. Evidence (title, description, version, banner, size, timing) never hashed.

Ceilings to state in the report: human-mismapped parser still mis-identifies
(whitelist bounds, not eliminates); target-controlled fields can force a
change (→UNKNOWN) or a drop (→never a closure claim, which this layer doesn't make
anyway); severity-in-hash guards over-merge but adds re-score churn; full closure is
un-attestable here (gate ceiling above).

## The decision — RULED: Option A (Scott, 2026-09-02)

"Sometimes the simplest solution is the honest one." Build #91 as the honest,
non-closure diff.

- **Option A — CHOSEN. Report-time diff, "not observed on re-test," no closure
  claim.** This is #91 spec D1/D2/D3 as ruled, proven forced by C4. Cheapest, no
  parser changes, safe. Delivers reliable NEW/UNCHANGED/UPDATED across all vetted
  parsers and an honest non-closure column. Widens past 5 for the delta; a positive
  "fixed/closed" is simply not a thing this architecture emits, and the report says
  so plainly rather than manufacturing one.
- **Option B — PARKED.** A real closure attestation would require changing the
  parsers to emit negative observations and still be container-capped (`-sT -Pn`
  can't prove host-up when all-filtered). Revisit only if a contract demands a
  positive "remediated" statement that "not observed on re-test" cannot satisfy.

Build #91 on Option A: seed the delta with C8's already-stable parsers, grow
per-parser with fixtures, keep the verdict model's closure-free vocabulary.

## Enhancement — AI-assisted follow-up (context + best practice)

Scott's enhancement (2026-09-02): the honest verdict is the floor, not the ceiling.
Since the report truthfully declines to assert closure, an AI layer turns each
delta row into a grounded next step for the operator — closing the loop the tool
itself cannot.

- **What it does.** Per finding, given its cross-run history (first-seen,
  verdict trajectory, evidence deltas — all already in the stored results the diff
  consumes) plus its class (CVE / TLS weakness / open port / web path), produce a
  short advisory recommendation grounded in security-scanning best practice:
  - for **NOT OBSERVED ON RE-TEST** — how to actually establish closure the scan
    can't (authenticated re-check, second-scanner corroboration, manual verification),
    directly addressing C4's honest gap;
  - for **UNCHANGED / recurring** — remediation guidance and a root-cause prompt
    (e.g. a CVE reappearing every image rebuild is a process finding);
  - for **UNKNOWN / ZERO-YIELD** — what to re-run and why the last run proved nothing.
- **Grounding.** History (context) is the finding's trajectory across runs; best
  practice cites recognized frameworks (OWASP / NIST / CIS). The context already
  exists — this reads it, it does not invent state.
- **Guardrail (hard).** The AI output is ADVISORY and labeled as such. It never
  upgrades "not observed on re-test" into "fixed," never emits a verdict, and never
  puts a closure claim in target-controlled or model-generated prose. Keyword/AI
  layers flag and suggest; they do not confirm (repo doctrine). It sits beside the
  deterministic verdict, never inside it.
- **Laziest fit for a single-file MCP server.** The client consuming these tools is
  already an AI. The minimal version emits the structured per-finding history plus a
  best-practice hook and lets the calling model generate the follow-up — no model
  call baked into the server, no new dependency. A bounded in-server helper is a
  later step only if the follow-up must ship inside the artifact itself.
- **Tiering.** This is a Tier-2 enhancement layered on the Option-A core, not a
  prerequisite. The honest diff ships first and stands alone; the AI follow-up
  augments it.

## Conflicts

- Hash serialization: engine 1 (copy `compute_hash_code`) vs engine 2 (its unframed
  concat is boundary-ambiguous; use framed JSON). Resolved toward engine 2.

## Gaps & unknowns

- ~22 uninventoried parsers unaudited; "all 41" gated behind finishing C8.
- Cross-engagement baseline write-path is operator-manual (Baseline section).
- Faraday/PlexTrac/Dradis cross-scan internals largely unpublished.
- DefectDojo 132/193 counts are configured-key counts, directional.

## Divergence notes

Loop 2 raised a divergence flag (FIXED-seed evidence infeasibility). It is resolved,
not a re-aim: it drove the recommendation from "asymmetric FIXED" to "no closure
claim at this layer (Option A)," which is the #91 spec's own D3. The anchor holds;
the open A/B choice is surfaced to the user in "The decision."

## Method appendix

- Engines: Engine 1 = Claude deep-research workflow (`wf_a3530147-c66`); Engine 2 =
  Codex CLI, `web_search=true` verified, live searches confirmed. Blind, concurrent.
- Native checks: primary verification via `gh api`/`curl` of the DefectDojo whitelist
  and field maps, issues #8100/#12754, SARIF baselineState, OpenVEX status labels,
  nmap RST/closed behavior, and this tool's nmap `state=="open"`/`-Pn`; link check on
  all cited full URLs = 200. All passed.
- Designated review: logic critique filled the review slot (both loops).
- Red team: attacked the merged claim table + report (both loops); loop 1 = 4
  blocking, loop 2 = 2 blocking + clauses, all folded.
- Loops: 2 gate loops. Valve: 2 passes produced blocking findings (both converged on
  the C4 structural boundary). No clean-pass gate has yet run on THIS (Option-A)
  revision — recommended before build, or after the A/B decision.
- Deferred non-blocking: none outstanding.
- Worknotes/dossier + engine raws beside this file.
