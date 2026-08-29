# #86 Phase 1 + #85 — combined report → risk dossier (spec)

Branch: `feat/report-risk-dossier` off `main`@`31dbb83`. Issues: #86 (CASP-grade
maturation), #85 (bold render). Mockup reference: the "Risk Assessment Dossier"
in #86 (assessor's account); build faithfully to #86's section set on the
existing SecureBine token system.

## Scope — Phase 1 only (no new external data)

Everything computable from fields already in the findings document + the nmap
inventory + two static lookup tables. Phase 2 (reachability engine, asset
register, remediation.yaml, baseline/history) is OUT.

## Waves

- **Wave 1 — risk-reasoning core (M1 + M2-exposure + M7-honesty).** The report's
  thesis change: rank by contextual risk, show the auditable formula/weights,
  name which inputs were assumed. THIS wave.
- **Wave 2 — mappings + evidence (M3 + M4).** CWE→ATT&CK + CWE→NIST/CIS static
  tables rendered per finding + a control-mapping summary; per-finding evidence
  block + confidence-from-detection-method.
- **Wave 3 — workflow + scope block (M5-SLA + M7 full + #85 hero/cards).** Auto
  SLA/due-date from risk band; full scope/methodology/coverage block; #85's bold
  severity hero + top-3 fix cards.

## Wave 1 acceptance criteria

- **M1.** `_contextual_risk(finding, exposure_score)` returns
  `min(cvss_band, round(100*(0.30*exploit + 0.28*exposure + 0.24*reachability +
  0.18*asset_value)))`. Inputs 0..1:
  - `exploit`: KEV actively-exploited → 1.0; else EPSS probability; else 0.5
    (unknown → conservative), tagged.
  - `exposure`: from the nmap join (below).
  - `reachability`: unknown → 1.0 (conservative), finding tagged `assumed-reachable`.
  - `asset_value`: unknown → 1.0 (conservative), tagged `assumed-critical`.
  - `cvss_band`: the CVSS-derived ceiling so the contextual score never exceeds
    the raw CVSS band (a 9.8 caps the score's ceiling; context only lowers it).
  The Phase-1 teaching case must hold (exposure is the live lever; reachability/
  asset_value are constant this phase): an unexposed, internal CVSS-9.8 scores ~71
  (High), while an exploited, internet-facing CVSS-7.5 scores 95 (its High-band
  ceiling) — exposure and exploitation, not raw CVSS, set the order.
- **M2 exposure (half).** `_exposure_for(finding, inventory)` joins a CVE/web
  finding to the nmap open-port/service inventory built from the same document:
  a finding on a host/port that nmap saw open and externally reachable →
  exposure 1.0 `internet-facing`; a host with no open-port evidence → 0.5
  `exposure-unknown`; internal-only markers → lower. (Reachability half is Phase 2.)
- **M1 render.** Contextual risk is the primary sort key of the fix-first queue
  and the CVE explorer (replacing the severity/EPSS/KEV ordering). A **Risk model**
  section renders the formula, the four weights, and a per-report list of which
  inputs were defaulted-conservative (so every score is auditable).
- **M7 honesty (partial).** The existing "not by risk … not collected" note is
  replaced by one that names the model and the assumed inputs, keeping the
  honesty (reachability/asset assumed-conservative, verify).
- No new runtime dependency; inline CSS + existing tokens; theme-aware; the
  report stays self-contained and scriptless (CSP unchanged).

## Seams (wave 1)

- `_contextual_risk` unit table incl. the two teaching cases (9.8-unreachable →
  ~71/High; 7.5-exploited-facing → 95).
- `_exposure_for` join test (finding on an open nmap port → internet-facing;
  no inventory → unknown/0.5).
- render test: fix-first queue ordered by contextual risk; Risk-model section
  present with the weights; assumed-input list rendered.

## Gate

Native (`unittest discover -s tests`; redaction differential; mutation-check where
a scoring assertion is added). Review: `matts-code-review` (Standards+Spec, fixed
point `31dbb83`, this spec). Red team: fresh-context adversarial (codex refuses).
Visual: render a sample document to HTML and publish as an artifact for review
(UI verified visually, not by tests alone). Exit: two consecutive clean passes.
Delivery: commit on `feat/report-risk-dossier`; hold for "push it".

## Run state (orchestrator only) — see `-run-state.md` sidecar.
