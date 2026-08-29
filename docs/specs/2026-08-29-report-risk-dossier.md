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

- **M1.** `_contextual_risk(finding, exposure)` returns
  `min(cvss_band, round(100*(0.52*exploit + 0.48*exposure)))`. Phase 1 scores the
  two signals actually collected; reachability and asset_value are NOT in the
  Phase-1 score — they join the formula in Phase 2 (#86 M2). Inputs 0..1:
  - `exploit`: KEV actively-exploited → 1.0; else EPSS probability; else 0.5
    (unknown → conservative), tagged `exploit-unknown`.
  - `exposure`: from the nmap per-host join (below).
  - `cvss_band`: the CVSS-derived ceiling, one per severity band and set at the top
    of that band's word so a score never renders a band above its CVSS severity:
    Critical 100 / High 89 / Medium 69 / Low 39 / Info 14 / Unknown 69. When a
    finding carries no Severity label the band is derived from its CVSS score.
    CVSS caps the top; context only lowers from there.
  The Phase-1 teaching case must hold (exposure is the live lever): an unexposed,
  internal CVSS-9.8 (exploit 0.5, exposure 0.5) scores 50 (Medium), while an
  exploited, internet-facing CVSS-7.5 (exploit 1.0, exposure 1.0) scores 89 (its
  High-band ceiling) — exposure and exploitation, not raw CVSS, set the order.
- **M2 exposure (half).** `_exposure_for(finding, inventory)` joins a CVE/web
  finding to the set of hosts nmap saw with an open service, built from the same
  document: a finding whose host nmap saw open → exposure 1.0 `internet-facing`;
  a host with no open-port evidence → 0.5 `exposure-unknown`. `_host_of` extracts
  the bare host (scheme/path/userinfo/port stripped) for the join. (Reachability
  half is Phase 2.)
- **M1 render.** Contextual risk is the primary sort key of the fix-first queue
  and the CVE explorer (replacing the severity/EPSS/KEV ordering). A **Risk model**
  section renders the formula, the two Phase-1 weights, and states that
  reachability/asset_value join in Phase 2 (so every score is auditable).
- **M7 honesty (partial).** The existing "not by risk … not collected" note is
  replaced by one that names the model and states that reachability/asset_value
  are not scored this phase (Phase 2), keeping the honesty.
- No new runtime dependency; inline CSS + existing tokens; theme-aware; the
  report stays self-contained and scriptless (CSP unchanged).

## Seams (wave 1)

- `_contextual_risk` unit table incl. the two teaching cases (9.8-unexposed →
  50/Medium; 7.5-exploited-facing → 89/High) and the LOW→Low B3 regression.
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
