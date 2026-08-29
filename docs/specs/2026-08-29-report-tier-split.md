# Report redesign wave 2 — tier-split (spec)

Branch: `feat/report-risk-dossier` off `main`@`31dbb83`. Anchor: the research brief
`docs/research/2026-08-29-report-design-best-practices.md` (two clean passes) and
Scott's ruling **tier-split: bold exec, austere technical**. Scriptless, CSP
unchanged (inline CSS + inline SVG + data-URI only, no JS).

## Decomposition (phases, each its own doctrine gate)

- **P1 — Combined report: bold exec layer. THIS PHASE.** A standalone exec layer
  at the top of the combined report: scope/coverage box, a bold posture hero
  (aggregate contextual risk as a bullet graph + confidence qualifier), and
  traffic-light KRI tiles. Technical tiers below stay austere and unchanged.
- **P2 — Per-finding confidence + detection-only posture.** Derive a per-finding
  confidence tier (confirmed / probable / potential-unvalidated) from the signals,
  render it in the per-finding block and the scope box's "N unvalidated".
- **P3 — Per-type heroes.** Each single-scanner report leads with its own
  verdict/grade hero (TLS letter grade, macro verdict banner, risk band), austere
  body below. Metasploit strip-chrome reference card.
- **P4 — Mappings + evidence + SLA** (the old epic M3/M4/M5): CWE→ATT&CK/NIST,
  evidence blocks, auto SLA/benchmark from band.

## P1 acceptance criteria

- **A1 Scope/coverage box** at the top of the combined report (first section
  after the title block), rendering: the hosts/targets assessed (from the scan
  set), method = **detection-only, unauthenticated**, total findings, scan count,
  as-of date, and a **TLP:AMBER** handling marking. This is the CEO artifact and
  the honesty anchor (research RB2/RB4).
- **A2 Posture hero (bold).** An aggregate posture = the **maximum contextual risk
  score across all work units** (0 when none), with its band word, rendered as an
  inline-SVG **bullet graph** (qualitative bands + value bar + a target marker at
  40), carrying an inline confidence qualifier "indicative · detection-only". No
  dial gauge (research F12/CF1). When there are no scored units, the hero states
  "No scored findings" rather than a misleading 0.
- **A3 Traffic-light KRIs.** The exec tiles gain a severity traffic-light row
  (critical / high / medium counts as colored status dots), ≤6 signals, readable
  at a glance (research F15/dossier pattern).
- **A4 Numbers match.** The hero posture score and any severity counts equal what
  the technical tiers show — one value per fact across tiers (research FIX-D).
- **A5 Scriptless + a11y + print.** Bullet graph is inline SVG with `role="img"`
  + `aria-label` + a text equivalent; new blocks carry `break-inside: avoid` and
  a print-legible palette; CSP unchanged. Theme-aware via existing `--sev-*`/token
  system.
- **A6** Existing sections (fix-first queue, matrix, CVE explorer, hardening,
  appendix, methodology) are untouched in content and order; only the exec top is
  restructured. The old flat "Executive summary" tiles are absorbed into the new
  exec layer, not duplicated.

## Seams (P1)

- `_risk_bullet(score, band)` returns inline SVG (no JS); a unit test asserts it
  contains the score, an `aria-label`, and no `<script>`.
- `_posture(work_units)` returns (score, band); test: max across units; 0/empty →
  "No scored findings" path.
- render test: scope box present with "detection-only" + "TLP"; hero present with
  the posture band; severity traffic-light row present; the numbers match the
  severity section.

## Gate

Native (`unittest discover`; redaction differential; a new seam pinned by a
mutation-relevant assertion). Review: `matts-code-review` (Standards+Spec, fixed
point `31dbb83`, this spec). Red team: fresh-context adversarial. Simplification:
once. Visual: render a sample + publish artifact for review. Exit: two consecutive
clean passes. Delivery: commit on `feat/report-risk-dossier`; hold for "push it".

## Run state — see `-run-state.md` sidecar.
