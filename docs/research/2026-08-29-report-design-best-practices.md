# CASP-grade report redesign — best-practices research

Branch: `feat/report-risk-dossier`. Feeds report-epic waves 2/3 + #85. Method:
doctrine-research, two blind engines, merged claim table, 4 gate rounds to two
consecutive clean passes. Worknotes/dossier: `scratchpad/report-design-worknotes.md`.

## Recommendation (BLUF)

The boldness a CASP engineer and a security-company CEO both trust comes from
**structure and honesty, not decoration**. Redesign every report on one spine:
a **tier-split** — a bold, standalone one-page executive layer (hero risk score,
letter grades, traffic-light KRIs, and a page-one scope/coverage box) over
**austere, high-data-ink technical tiers**, with identical numbers across both
and only the chrome differing. Rank everything by the #86 contextual risk band
as the single sort axis. Render every chart as inline SVG/CSS (the scriptless
CSP stays — no recommended visual needs JS). The two moves that separate a
credible dossier from a scanner dump are epistemic: a per-finding **confidence
tier** that admits these are unauthenticated, detection-only findings, and a
page-one **scope box + TLP marking**. Both directly leverage work this repo
already has (the #86 risk model, the redaction pipeline).

## The direction (what to build)

**Tier-split, applied fractally.** The combined dossier opens with a dramatic
exec page; each single-scanner report opens with its own smaller verdict/grade
hero (TLS letter grade, macro verdict banner, risk band) then an austere body.
Bold where the CEO looks, rigorous where the engineer works, same numbers in
both places so a CISO never sees two values for one finding.

**Exec page (bold).** Hero contextual-risk score + band (with an inline
confidence qualifier), TLS/posture letter grade, 4–6 traffic-light KRI tiles,
top-3 risks, and a **scope/coverage box**: what was tested, what was not,
method = detection-only/unauthenticated, count of unvalidated findings, as-of
timestamp. That box is also the artifact a CEO actually acts on.

**Technical tiers (austere).** Four-block order — Exec → Remediation →
Findings → Appendices. Findings as a summary table first (sorted by risk band),
then a fixed per-finding block: id, title, severity + version-pinned CVSS,
CWE, affected asset, **confidence (confirmed / probable / potential-unvalidated)**,
business impact, reproduction, evidence, remediation, references.

## Findings by confidence

Tags: **[AGREE]** both engines, web-sourced · **[SE]** single-engine ·
**[PRIMARY]** authoritative primary source.

### Structure
- **F1 [AGREE]** Tiered/layered reporting is the named solution to the
  two-audience problem: a standalone ≤2-page exec summary, then a reproducible
  technical tier. (PTES; Bishop Fox; Wiz.)
- **F2 [AGREE]** Four-block order Exec → Remediation → Findings → Appendices;
  execs read top-down and stop early, engineers jump to findings.
- **F3 [AGREE]** Fixed per-finding block (uniform template) is what earns
  engineer trust and lets a manager scan severity down the left edge.
- **F4 [AGREE]** Scope/Methodology before findings (NIST SP 800-115) = credibility
  and PCI/regulatory acceptance and the liability boundary.
- **F5 [AGREE]** Findings summary table before per-finding detail, sorted by
  risk band, not scan order.

### Prioritization
- **F6 [AGREE]** Rank KEV → EPSS → CVSS, never CVSS alone; show all three. This
  is exactly what #86's contextual risk model already encodes.
- **F7 [design]** ONE sort axis: the #86 contextual risk score + band sorts the
  fix-first queue and CVE explorer. SLA windows and KEV→EPSS→CVSS are
  **within-band tiebreaks + per-finding badges, never a reorder.** One rank
  source per page.
- **F8 [PRIMARY]** KEV is a **binary override badge**, not a gradient — top
  priority regardless of EPSS/CVSS. (CISA KEV.)
- **F9 [PRIMARY]** EPSS is a **predicted probability of exploitation activity in
  the next 30 days** (population-relative percentile), not impact or
  environmental risk. Label the axis honestly; do not fold it silently into an
  absolute score. (FIRST EPSS.)
- **F10 [PRIMARY]** SLA framing: CISA **BOD 26-04** (issued 2026-06-10; revoked
  BOD 22-01 and 19-02) sets 3/14/60-day remediation tiers on a four-factor risk
  model (public exposure, known-exploited, automatable, technical impact). It
  **binds federal civilian agencies only** — in a private report present it as an
  external benchmark the customer *may* adopt, not an SLA the report imposes.
  Note: BOD 26-04's four factors are a *separate* concept from #86's four weights
  (exploit/exposure/reachability/asset_value); present them as "aligned with,"
  not identical.

### Visualization
- **F11 [AGREE]** Severity distribution = sorted/stacked bar with colorblind-safe
  **sequential-lightness** bands (≥30 CIELAB L delta, ≤6 categories), never a pie.
- **F12 [AGREE/PRIMARY]** Avoid pie, donut, gauge/dial, 3D, dual-axis, rainbow.
  (Few: the pie is "by far the least effective" quantitative graph; gauges waste
  space — 3–4 bullet graphs fit one gauge.)
- **F13 [AGREE/PRIMARY]** A 5×5 risk matrix is a **communication device only**;
  never compute priority by multiplying its ordinal cells (Cox 2008: matrices can
  misrank worse than random). Plot findings onto it by the #86-computed band.
- **F14 [AGREE/PRIMARY]** TLS report: SSL-Labs **letter grade as hero** + category
  sub-scores (protocol 30% / key-exchange 30% / cipher 40%) + grade-cap callouts
  (no TLS 1.3 → A−; no forward secrecy / RC4 / DH<2048 → B; POODLE → C;
  ROBOT/DROWN/Heartbleed → F).
- **F15 [SE]** Aggregate risk score displayed **with its drivers beside it** +
  color tiles (Tenable VPR / Wiz / Rapid7 pattern), marked "indicative," with the
  confidence qualifier and as-of timestamp.
- **F16 [AGREE]** Recon = asset inventory table + **host × port/service matrix**
  (colored cells) + exposure count tiles. Not a force-directed graph (needs JS,
  reads as noise).
- **F17 [PRIMARY]** CVSS severity bands (FIRST CVSS v3.1 spec): None 0.0 / Low
  0.1–3.9 / Medium 4.0–6.9 / High 7.0–8.9 / Critical 9.0–10.0. **Pin the CVSS
  version per finding** (v3.1 vs v4.0); ranges match but don't mix legends.
- **F18 [design]** Accessibility for scriptless SVG: `<title>`/`<desc>`,
  `role="img"`, `aria-label`, and a text-equivalent table (no JS = no tooltips,
  so every datum must also exist as text). Colorblind-safe palette is necessary,
  not sufficient.
- **F19 [design]** Print/PDF fidelity: `@media print`, `@page`,
  `break-inside: avoid` on finding blocks, a print-visible color legend (CEOs
  print these). Any trend/burndown is a pre-computed SVG polyline with a
  prominent as-of timestamp (static = generation-time only).
- **F20 [design]** Page-one **TLP/data-classification marking**: the report may
  contain sensitive target data, service banners, and IOCs; secret-shaped strings
  are handled by the existing redaction pipeline.

## Per-report-type blueprints (all six)

- **Combined dossier** — exec one-page dashboard (risk-posture indicator, top-3
  risks, KRI tiles with target + trend arrow, traffic-light row, decision block),
  then drill to each sub-report as an appendix.
- **Vuln/package (trivy, syft, nuclei)** — severity stat-tiles/stacked bar,
  top-vulnerable-packages/assets, package upgrade units (one work unit clears N
  CVEs), remediation table.
- **TLS/hardening (nikto, sslscan, testssl, sslyze)** — letter-grade hero,
  protocol/cipher matrix (green/red cells), cert-chain card, HSTS/headers, grade-cap
  callouts.
- **Recon/enumeration (nmap, whatweb, dns, subfinder, amass, whois…)** — asset
  inventory table, host × port/service matrix, exposure tiles.
- **Macro (olevba/msodde)** — verdict/risk banner (this report's exec-tier hero),
  auto-exec triggers (AutoOpen/AutoExec/Document_Open), suspicious-keyword table
  (keyword | description | count), extracted IOC list (URLs/IPs/exe — listed, not
  charted), decoded/deobfuscated macro source, MITRE ATT&CK tags
  (T1204.002 / T1059.001 / T1547). One small stacked count bar of the scan summary.
- **Metasploit search/info** — **strip the severity chrome entirely**: this is a
  catalog lookup, not a finding against a target. Reference-card per module (name,
  path, type, disclosure date, CVE/refs, targets, key options); module rank shown
  as a **neutral reliability badge** (Excellent/Great/Normal, Rapid7's own field),
  never severity; one-line disclaimer "catalog lookup, not an assessment of any
  target." Any severity coloring here is the specific dishonesty to avoid.

## Conflicts (kept, not silently resolved)

- **C1 Gauge vs bullet graph.** Both render scriptless. Lean **bullet graph /
  horizontal meter** over a dial gauge (Few: gauges waste space, mislead). The
  hero score is a big number + a bullet bar, not a dial.
- **C2 CVSS × EPSS quadrant.** FIRST warns multiplying a calibrated probability
  by an ordinal ("score laundering") is meaningless. If both are shown, plot the
  axes **independently**, never a multiplied score.

## Gaps & unknowns

- **G1 Viz sourcing leans on one school.** The "bars/bullets, avoid the rest"
  core traces largely to Stephen Few, counted across several claims. Cox, SSL
  Labs, the CVSS spec, and colorblind guidance diversify the edges. Defensible,
  not settled.
- **G2 Phase-2, out of this research's build scope:** delta-since-last-scan +
  retest diff (needs baseline history), remediation cost estimate and named
  ownership, and explicit PCI/SOC2/ISO control mapping (overlaps wave-2 M3
  CWE→ATT&CK/NIST). All legitimate, all later.
- **G3 CSP relaxation is not needed.** No recommended visual requires JS; the
  scriptless posture holds and is itself a CASP credibility signal. Relaxing the
  CSP for a JS chart library is available as an explicit option but buys nothing
  the static SVG approach lacks.

## Divergence note (user ruling)

The logic critique flagged that "bold" (the request) and the Few/Tufte austerity
the viz research converged on pull opposite ways. Put to Scott; ruling:
**tier-split — bold exec page, austere technical tiers.** That reconciliation is
now the spine of the direction above.

## Findings handed to the #86 wave-1 gate (out of this phase's scope)

The red team read the already-built wave-1 code; these belong to that build's own
gate, not this research:
- **W1** The Risk-model thesis prose overclaims: it leads with "unused/unreachable
  should not outrank exploited/internet-facing," but wave-1 hardwires
  reachability = asset_value = 1.0, so 42% of the weight is constant and that
  de-prioritization cannot occur yet. Disclosed two lines down (not false) but the
  headline example is unreachable. Reword the thesis to a phase-1-true one
  (exploit/exposure). *This is in the sample currently under review.*
- **W2** `_exploit_score` inverts on enrichment: a real low EPSS (0.02) scores
  below the unknown default 0.5, so enriching a genuinely low-risk CVE can rank it
  beneath an unenriched one. Documented-conservative; keep the flag visible.
- **W3** Spec bug: "unreachable CVSS-9.8 → Medium" is listed under wave-1
  acceptance criteria, but reachability is phase 2, so it is unmeetable in wave 1
  (the lowest a 9.8 reaches is 71/High).
- **W4** Teaching case 2 yields 95 (High ceiling), not the spec's "~96";
  `_exposure_for`'s `:\d{1,5}` false-positives on version-like targets (`app:8.0`).

## Method appendix

- **Engines.** Round 1: two blind engines on the same refined question — Engine 1
  a fan-out of three web agents (structure / dataviz / per-type), Engine 2 one
  independent web agent, whole question. Both are Claude general-purpose, so engine
  **model diversity was reduced** (codex refuses security tasks and has no web by
  default this session); both fetched real URLs, so agreements are two independent
  web fetches, not search-plus-recollection.
- **Gate.** doctrine-research three-part gate each round: native checks
  (citation/link + claim verification) + **designated-review slot = logic
  critique** + adversarial red team. 4 rounds. Round 1: 8 blocking (macro/metasploit
  coverage gap, "bold" divergence, 2 citation swaps, 4 epistemic gaps). Round 2:
  3 blocking (competing sort axis, hero-vs-honesty, federal-SLA overclaim). Rounds
  3 and 4: **two consecutive clean passes** (no blocking either seat; native
  carried). Valve reached 2, never fired.
- **Native checks that ran.** 16 citations fetched and claim-verified across two
  native rounds; all load-bearing sources OK. cisa.gov 403s automated fetch —
  BOD 26-04 confirmed via secondary sources (nucleussec, Tenable FAQ) and the
  now-"(Revoked)" title on CISA's own BOD 22-01 page.
- **Deferred non-blocking (not taken, would reset the gate):** minor phrasing on
  SLA-as-tiebreak, naming BOD's fourth factor in the legend, and adding the 19-02
  revocation mention; EPSS wording and the "austere" definition were folded at
  authoring.
- **Key sources.** PTES reporting; NIST SP 800-115; FIRST EPSS + CVSS v3.1/v4.0
  specs; CISA KEV + BOD 26-04; SSL Labs Server Rating Guide; Cox 2008 "What's
  Wrong with Risk Matrices?"; Stephen Few "Save the Pies for Dessert" / "Common
  Pitfalls in Dashboard Design"; oletools olevba; Rapid7 Metasploit exploit-ranking;
  Bishop Fox / Wiz / HackerOne report guidance.
