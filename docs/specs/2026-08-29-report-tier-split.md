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
- **P2 — Per-finding confidence + detection-only posture. THIS PHASE.** Derive a
  per-finding confidence tier and render it in the per-finding block and the scope
  box. Vocabulary (Scott, 2026-08-29): **Observed / Inferred / Heuristic** — the
  honest set for a detection-only, unauthenticated scan where nothing is
  exploit-validated. "Confirmed" is rejected: it reads as exploit-proven, which an
  unauthenticated remote scan cannot claim (honesty anchor RB2/RB4).
    - **Observed** — a scanner on the **Observed allowlist** actively confirmed the
      condition by probing the target: TLS negotiated (testssl/sslscan/sslyze), a
      resolved record (dns_recon), a fired nuclei template matched to a live response,
      a fact retrieved directly from the host (nbtscan/smbclient connect to it), or an nmap
      open-port finding. Observed is an ALLOWLIST, never a default (doctrine valve-4
      ruling): a scanner not on it never renders Observed.
    - **Inferred** — a CVE, or a **package/advisory scanner** (`_INFERENCE_SCANNERS`:
      trivy) attributing a vuln by installed version, not exploitation-validated. Any
      CVE-bearing finding, and every trivy finding (its GHSA/AVD advisories are
      version matches too, not live observations — red-team B-OVERCLAIM).
    - **Heuristic** — the **default**: a discovery/fingerprint guess (`web-path`,
      `web-tech`, `waf`, `subdomain`), a signature match (nikto, an nmap NSE vuln
      script), a local-DB lookup (metasploit), whois (a registry query on TCP 43 that never
      touches the host, red-team F1 — note dns_recon stays Observed because its finding IS the live record it resolved, whereas whois returns registry bookkeeping about the domain, red-team R9-N1), or **any scanner not on the Observed
      allowlist and not an inference scanner**. An unvetted or new scanner lands here,
      so it can never overclaim Observed.

## P2 acceptance criteria

- **PA1 Derivation (Observed is an ALLOWLIST).** `_confidence(finding, scanner="")`
  returns `(key, label)`, derived in that precedence: an **unwitnessed scanner**
  (`_UNWITNESSED_SCANNERS`: nikto, metasploit) → heuristic FIRST, before the CVE
  check, so a CVE named in a metasploit query is not read as a host attribution
  (red-team B1); else a **CVE** → inferred; else an **inference scanner**
  (`_INFERENCE_SCANNERS`: trivy) → inferred (its GHSA/AVD advisories are version
  matches, not live observations — red-team B-OVERCLAIM); else **nmap** split by
  finding shape (an open-port finding → observed, an NSE vuln-script hit → heuristic);
  else a scanner on the **Observed allowlist** (`_OBSERVED_SCANNERS`: testssl,
  sslscan, sslyze, nuclei, dns_recon, nbtscan, smbclient) → observed; else
  **heuristic (the default)**. The organizing principle, and the doctrine valve-4
  ruling (Scott, 2026-08-29): **Observed is an allowlist, never a default** — only a
  scanner vetted as a direct live-target confirmation renders Observed, so a new or
  unvetted scanner (and any discovery/signature/DB finding) defaults to heuristic and
  can never overclaim. This closes the overclaim CLASS (nikto, nmap-NSE, metasploit,
  trivy-GHSA were four instances of the same "unvetted scanner defaults to Observed"
  bug) rather than point-patching each. A conservative underclaim (a real observation
  rendered heuristic — e.g. a testssl-confirmed heartbleed carrying a CVE renders
  Inferred, or an smbclient bare string) is accepted; an overclaim is the failure the
  allowlist prevents. No new signal is invented; it reads fields the finding already carries, plus the scanner
  name the combined loop already holds. Callers that know the scanner (the combined
  per-scanner loop, the single-result path) compute the verdict and **stamp it on the
  finding under a private `_conf` key**. The stamp is read by `confidence_chip` and
  survives the redundant `_enrich_finding` re-copy inside the shared `render_findings`
  (which does `dict(finding)`, copying `_conf` forward), so a scanner-DEPENDENT verdict
  is not lost when a CVE-bearing finding is re-copied — the bug an `id()`-keyed side map
  hit once the unwitnessed override became CVE-reachable (red-team B1). `slots()` skips
  the `_conf` key so it never reaches the evidence table.
- **PA2 Per-finding render.** Every per-finding article (fix-first work units, CVE
  units, hardening, appendix, and the single-result path that shares
  `render_findings`) carries a confidence chip beside its severity, colour + word
  (never colour alone), theme-aware via existing tokens.
- **PA3 Scope-box disclosure.** The scope/coverage box gains one cell: the count of
  findings **not directly observed** (inferred + heuristic) out of the total — the
  honesty disclosure that stops a version-inferred CVE from reading as a confirmed
  breach.
- **PA4 Methodology.** The methodology / risk-model prose names the three tiers and
  what each means, so the label is auditable, not decorative.
- **PA5 Numbers match.** The scope-box not-observed count equals the number of
  findings whose confidence is inferred or heuristic (`_confidence` over the deduped
  finding set) — one value per fact (research FIX-D). NB it counts findings, not
  chips: a Trivy package upgrade unit renders one chip for its N CVE members, so
  chip-count and finding-count differ by design; the disclosure counts findings.
- **PA6 Scriptless + a11y + print + scope untouched.** CSP unchanged; chips are
  text + token colour with a print-legible palette and `break-inside` respected;
  every existing section keeps its content and order (A6 carried from P1).

### Seams (P2)

- `_confidence` teaching cases (inverted allowlist): a CVE finding → inferred; a
  trivy GHSA finding (no CVE) → inferred; a `testssl` finding → observed; a nuclei
  non-CVE finding → observed; an nmap open-port finding → observed while an nmap NSE
  vuln-script finding → heuristic; any nikto/metasploit finding → heuristic; an
  **unvetted/unknown scanner → heuristic** (never Observed); a metasploit query
  naming a CVE → heuristic (unwitnessed beats CVE, B1). A mutation-relevant assertion
  pins that an unvetted scanner defaults to heuristic, not observed.
- render test: a combined report of ungrouped findings (one article each) renders
  `Inferred`/`Observed`/`Heuristic` chips; the scope box's not-observed count equals
  `sum(_confidence(f) != observed)` over the finding set (PA5).
- **P3 — Per-type heroes.** Each single-scanner report leads with its own
  verdict/grade hero (TLS letter grade, macro verdict banner, risk band), austere
  body below. Metasploit strip-chrome reference card.

### P3a — TLS letter-grade hero (THIS SUB-PHASE)

The single-scanner TLS report (testssl/sslscan/sslyze) leads its exec summary with
a bold SSL-Labs-style **letter grade hero**, grade drivers, and a coverage qualifier.
Honesty anchor (carried from P2): the grade is a CEILING computed DOWNWARD from
weaknesses the scanner ACTUALLY OBSERVED; it never asserts a top grade on a scanner's
silence, and is never "A+".

- **QA1 Grade rubric (F14).** `_tls_grade(findings, scanner)` → `(grade, drivers,
  coverage)`, worst cap wins: catastrophic break (Heartbleed/ROBOT/DROWN/SSLv2) → **F**;
  SSLv3 / POODLE → **C**; a weak cipher (RC4/3DES/DES/NULL/EXPORT/MD5) or legacy
  TLS 1.0/1.1 → **B**; nothing observed → **A**. Grades read from the finding fields
  already captured across all three scanners: sslscan/sslyze use `tls-proto-*`/
  `tls-cipher-*` ids; testssl uses its own named ids (TLS1/TLS1_1 legacy protocols,
  RC4/SWEET32 weak ciphers, FREAK/LOGJAM/DROWN/heartbleed/POODLE named vulns) + `cve`.
  Only a coloured-severity finding caps (a testssl "not offered" OK row must not), and
  the fine testssl ids TLS1_2/TLS1_3 must not false-cap. A **CRITICAL-severity
  backstop** sends any weakness the specific caps did not name (a future testssl
  vuln, a NULL cipher, a critically-broken cert) to F, so an unrecognised critical
  never grades A; testssl weak-cipher LISTS (`cipherlist_*`) cap at B. The named-vuln
  allowlist covers testssl's vuln batch: renegotiation (`renego`, CVE-2009-3555) → F,
  CRIME/compression → C, BREACH/BEAST/LUCKY13 → B (Scott ruled allowlist over inversion at
  the valve-4 stop, 2026-08-29). No invented signal.
- **QA2 Coverage honesty.** The coverage note names the scanner and states the grade
  reflects only what was tested. testssl runs `--severity HIGH`, so its JSON never
  carries the LOW/MEDIUM tier (legacy TLS 1.0/1.1, SWEET32); it therefore CANNOT
  certify A and a clean testssl grade is **capped at B** with a coverage-limit driver
  (red-team R6-B1). sslscan/sslyze emit protocols/ciphers at any severity so a clean
  scan honestly grades A, but their note does NOT claim vuln coverage they did not
  perform. Never "A+" (HSTS + full assessment not verified).
- **QA3 Hero render.** A TLS report's exec summary opens with `.tls-hero`: the grade
  letter (colour-banded A green→F red via the existing `band-*` tokens), the grade
  drivers, and the coverage `meta` note. A non-TLS report shows no grade hero.
- **QA4 Scriptless + a11y + scope.** Inline HTML + token colour, CSP unchanged, the
  grade word/letter always present (never colour alone); every existing single-report
  section keeps content and order; the combined report is untouched.

### Seams (P3a)

- `_tls_grade` teaching cases: heartbleed/ROBOT/SSLv2 → F; SSLv3/POODLE → C; weak
  cipher / legacy TLS1.0-1.1 → B; clean → A + coverage note (no "A+"); worst-cap-wins
  (F beats B); sparse-scanner coverage note omits "named vulnerabilities".
- render test: a testssl report shows the `tls-hero` with the grade letter and the
  "ceiling on posture" qualifier; a nikto report shows no hero.
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
