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
### P3b — Macro verdict banner hero (THIS SUB-PHASE)

The single-scanner **macro** report (olevba/msodde) leads its exec summary with a
bold **verdict/risk banner hero**, the auto-exec triggers that earned the verdict,
observed MITRE ATT&CK technique tags, and a coverage qualifier. Honesty anchor
(carried from P2/P3a): the verdict is computed DOWNWARD from what STATIC analysis
ACTUALLY FLAGGED; olevba/msodde never execute the document, so the banner never
asserts detonation, and a clean scan means "no indicators found by static
analysis", never "safe" (RB2/RB4).

- **MA1 Verdict rubric (F14-analog).** `_macro_verdict(findings, scanner)` →
  `(verdict, vclass, drivers, attack_tags, coverage)`, worst tier wins.
  olevba analysis entries carry `type` (`AutoExec`/`Suspicious`/`IOC`/`Hex String`/
  `Base64 String`/`VBA obfuscated Strings`/…), `keyword`, `description`; msodde
  emits `type:"dde"`, `field` (the DDE command), `source`. Tiers:
    - **HIGH RISK** (`band-critical`) — an **auto-exec trigger** (olevba `type` ==
      `AutoExec`, or a `keyword` in the auto-run/close handler family — AutoOpen/
      AutoExec/AutoNew/AutoExit/Auto_Close, Document_Open/Document_Close/Document_New/
      Document_BeforeClose, Workbook_Open/Workbook_Close/Workbook_Activate/
      Workbook_BeforeClose, Window_Activate (close/activate handlers auto-execute too;
      the backstop no longer depends solely on olevba's type string, red-team NB4) —
      matched EXACTLY against the entry's own type/keyword,
      never as a substring of the free-text blob, so an "autoopen" token smuggled into a
      Base64 payload keyword or an IOC filename cannot mis-tier the verdict, red-team F1)
      **combined with** any DISTINCT concerning indicator
      (a Suspicious/IOC entry, OR an encoded/obfuscated payload label olevba emits under
      its own type — Base64 String/Hex String/Dridex string/VBA obfuscated Strings —
      red-team B1); OR any msodde `dde`/DDEAUTO finding (auto-executing DDE is the
      classic weaponised-document pattern). The verdict word is "HIGH RISK", never
      "MALICIOUS" (static analysis cannot prove intent).
    - **SUSPICIOUS** (`band-high`) — indicators present but not the HIGH-RISK
      combination: an auto-exec trigger (or several) alone, or concerning entries
      (Suspicious/IOC/payload labels) without an auto-exec trigger. Warrants manual
      review of the decoded macro.
    - **NO INDICATORS** (`band-low`) — no analysis findings. Phrased "No macro
      indicators flagged by static analysis" with the coverage caveat; never "clean"
      or "safe".
- **MA2 Drivers.** `drivers` lists the auto-exec triggers by keyword + description
  (the behaviours that earned the tier), bounded; for msodde the DDE command
  `field`. Empty drivers on the NO-INDICATORS tier render an explicit "none" line.
- **MA3 ATT&CK tags (observed-only).** Tags are derived from finding CONTENT, never
  hard-coded: any indicator ⇒ **T1204.002** (User Execution: Malicious File, the
  document is the lure); `powershell` ⇒ **T1059.001**; a command-interpreter token
  (`cmd.exe`/`cmd /`/`comspec`/`wscript.shell` substrings, or the keyword-exact VBA
  functions `shell`/`wscript`/`cscript`) ⇒ **T1059.003** — a bare `shell` substring is
  NOT used, since it collides with "powerSHELL"; a msodde `dde` finding ⇒ **T1559.002**
  (Inter-Process Communication: DDE); a GENUINE persistence write (`run key`/`runkey`/
  `runonce`/`startup folder`/`autostart`/`currentversion\run`) ⇒ **T1547.001**. A
  registry READ, "Runs when opened", or a bare AutoOpen hook is NOT persistence and MUST
  NOT tag T1547 (red-team N1). Technique/persistence tokens are matched on BEHAVIOURAL
  text (type + description + msodde `field` + a non-IOC keyword) — an IOC's raw URL/IP/
  path value never drives a tag, so `http://powershell-cdn.example` does not tag
  T1059.001 (red-team F3). No match beyond a present indicator ⇒ T1204.002 only.
  NO INDICATORS ⇒ no tags. Never tag a technique the scan did not evidence (P2 overclaim
  discipline).
- **MA4 Coverage honesty.** The note names the scanner and states the verdict
  reflects only STATIC pattern-matching of the document, that the macro was NOT
  executed, and that absence of indicators is not proof of safety. Never a
  definitive "malicious"/"benign" claim.
- **MA5 Hero render.** A macro report's exec summary opens with `.macro-hero`: the
  verdict word (colour-banded via existing `band-*` tokens), the drivers, the ATT&CK
  tag chips, and the coverage `meta` note. A non-macro report shows no verdict hero.
  The austere body (existing finding rows, evidence table) is unchanged, exactly as
  P3a left the TLS body.
- **MA6 Scriptless + a11y + scope.** Inline HTML + token colour, CSP unchanged, the
  verdict word always present (never colour alone); every existing single-report
  section keeps content and order; the combined report is untouched.

### Seams (P3b)

- `_macro_verdict` teaching cases: AutoOpen + Suspicious/IOC → HIGH RISK; msodde
  DDEAUTO → HIGH RISK; Suspicious-only (no auto-exec) → SUSPICIOUS; auto-exec alone
  → SUSPICIOUS; no findings → NO INDICATORS (+ coverage note, never "safe");
  worst-tier-wins.
- ATT&CK teaching cases: powershell keyword ⇒ T1059.001 present (not T1059.003 off the
  "shell" substring); msodde dde ⇒ T1559.002; a bare Suspicious entry ⇒ T1204.002 only;
  a registry READ ⇒ no T1547 (red-team N1); NO INDICATORS ⇒ no tags.
- indicator-set teaching cases: AutoOpen + an encoded-payload label (Base64/Hex/Dridex/
  VBA obfuscated) ⇒ HIGH RISK (red-team B1); two bare auto-run hooks, no payload ⇒
  SUSPICIOUS; a non-dict junk entry beside a lone AutoOpen ⇒ SUSPICIOUS, never HIGH RISK
  (red-team N2).
- render test: an olevba report shows the `macro-hero` with the verdict word and the
  "not executed" coverage qualifier; a nikto report shows no verdict hero; the macro
  body finding rows are unchanged.

### P3c — Metasploit reference card (THIS SUB-PHASE)

A `metasploit_search`/`metasploit_info` report is a CATALOG LOOKUP, not an assessment of
any target. It must **strip the severity chrome entirely** and render a per-module
reference card. Scope RULING (Scott, 2026-08-30): **Full parse** — this supersedes the
deliberate no-parse capture decision in `_raw_text_parser` for metasploit only, contained
by best-effort parsing with a raw-transcript fallback.

- **MC1 Parse (render-time, best-effort).** `_parse_msf_search(text)` reads the "Matching
  Modules" table by HEADER-COLUMN positions (robust to the optional Disclosure Date/Check
  columns) → a list of `{name, mtype, disclosure, rank, description}`; `_parse_msf_info(text)`
  reads the `Key: Value` header (Name/Module/Rank/Disclosed) + References + Available
  targets + Basic options → one `{name, module, mtype, rank, disclosed, platform, cves, refs,
  targets, options}`. `mtype` is derived from the module path prefix (exploit→Exploit,
  auxiliary→Auxiliary, post→Post, payload→Payload, encoder→Encoder, nop→NOP,
  evasion→Evasion). CVEs are extracted as `CVE-\d{4}-\d{3,7}` from refs/text. On ANY parse
  miss (no table / no header), return empty and the render FALLS BACK to the raw
  transcript — never a fabricated card. Parses the transcript from the finding `evidence`
  (already redacted at capture), so capture/redaction is untouched.
- **MC2 Strip severity chrome (ALWAYS).** A metasploit report renders NO per-finding
  Severity mark, NO detection-confidence chip, NO "Highest severity" tile, and NO Severity
  chart (the section says "Not applicable — catalog lookup") — whether the transcript
  parsed into cards OR fell back to raw, because a catalog lookup carries no target
  severity either way (Spec-axis R1-F1). On a parse miss the catalog banner still frames
  the report and the raw transcript renders in a NEUTRAL card (no severity/conf). Module **rank** (manual/low/average/
  normal/good/great/excellent — Rapid7's own reliability field) is shown as a NEUTRAL
  badge, never colour-mapped to severity. Any severity colouring here is the specific
  dishonesty to avoid.
- **MC3 Reference cards.** Each module renders a `.msf-card`: module name + path, type
  badge, disclosure date, neutral rank badge, CVE/reference list (inert text, never an
  `<a href>`), targets, and key option names. `metasploit_info` renders one detailed card;
  `metasploit_search` renders one compact card per matched module (bounded).
- **MC4 Catalog banner + disclaimer.** The exec summary opens with a `.msf-catalog` banner
  carrying the one-line disclaimer "Catalog lookup — a Metasploit module reference, NOT an
  assessment or finding against any target," plus the module count. Because MC2 removes the
  "Highest severity" tile, the tile row is rebuilt to NEUTRAL catalog tiles (Modules /
  Lookup / Assessment="Catalog, not a target scan" / Source). A non-metasploit report shows
  no catalog banner.
- **MC5 Scriptless + a11y + scope.** Inline HTML + token colour, CSP unchanged, the rank
  WORD always present (never colour alone); references stay inert text; the raw transcript
  remains available as the fallback body; the combined report is untouched.

### Seams (P3c)

- `_parse_msf_search` teaching cases: the minimal 3-column table (#/Name/Rank/Description)
  and the full 5-column table (+Disclosure Date/Check) both parse to the same module
  fields via header-column positions; a transcript with no "Matching Modules" table → [].
- `_parse_msf_info` teaching cases: Name/Module/Rank/Disclosed header parsed; CVEs pulled
  from References; targets + option names captured; a non-info transcript → {} / None.
- render tests: a metasploit report shows the `.msf-catalog` disclaimer + `.msf-card`(s),
  the rank as a neutral badge, and NO Severity mark / NO conf chip / NO severity chart; an
  unparseable metasploit transcript falls back to the raw text; a nikto report shows no
  catalog banner.

### P3d — Recon + vuln heroes (THIS SUB-PHASE)

Two single-scanner exec-summary heroes, each computed from findings already captured, each
mirroring the P3a/P3b/P3c add-a-hero pattern (the austere body is unchanged). Scope default
(concrete): recon exposure hero = **nmap**; vuln severity hero = **trivy + nuclei**. Other
recon tools (whatweb/dns/subfinder/amass) and syft (SBOM inventory) get their own heroes
later — their data shapes differ.

- **DA1 Recon exposure hero (nmap).** `_recon_exposure(findings)` → `(open_ports, services,
  versioned)`: `open_ports` = count of open-port findings (`state == "open"`); `services` =
  `{service: count}`; `versioned` = how many carry a product/version fingerprint. Exposure
  is counted from the PRE-DEDUP finding list: nmap findings carry no host id, so host-blind
  dedup would collapse N hosts with an identical open-port fingerprint to one and headline
  a multi-host scan as "1 open port" (red-team B1); the hero counts open host:port pairs
  across all hosts and notes when the findings table de-duplicates. The `.recon-hero` shows
  the open-port count, the exposed-service breakdown, and an honesty
  note: open ports are the reachable ATTACK SURFACE, and a TCP connect scan does NOT assess
  the services' security (RB2/RB4 — never implies vulnerability from exposure).
- **DA2 Vuln severity hero (trivy/nuclei).** `_vuln_summary(findings)` → `(severity_counts,
  total, top_packages)`: `severity_counts` over the coloured severities; `total` = their
  sum; `top_packages` = `[(pkg, finding_count), …]` desc from trivy `PkgName`, counting RAW coloured findings per package on the SAME basis as `total` so the headline and the package tally never disagree (red-team N1).
  The `.vuln-hero` shows the total, a scriptless STACKED severity bar (segments sized by
  count, coloured by the existing `--sev-*` tokens; each segment carries its severity+count in a
  `title`, and an always-present TEXT legend below the bar carries every severity+count
  visibly, never colour alone), and the top vulnerable packages. Qualifier "detection-only"
  (carried from P2): a version/advisory match, not exploit-validated. A clean scan (total 0)
  says so honestly, never "secure".
- **DA3 Render + gating.** Heroes fill the shared `{exec_hero}` slot (`tls_hero or
  macro_hero or msf_catalog or vuln_hero or recon_hero`); scanner sets are disjoint so at
  most one fires. `_RECON_SCANNERS = {nmap}`, `_VULN_SCANNERS = {trivy, nuclei}`. A scanner
  outside these shows no P3d hero. Unlike metasploit, the severity chrome is KEPT (a vuln
  report IS a target assessment; nmap findings are INFO).
- **DA4 Scriptless + a11y + scope.** Inline HTML + token colour, CSP unchanged, every count
  and severity present as TEXT (never colour alone); the combined report is untouched.

### Seams (P3d)

- `_recon_exposure`: 3 open ports over 2 services + 2 versioned → correct counts; a report
  with no open-port findings → (0, {}, 0); non-dict/closed findings ignored.
- `_vuln_summary`: mixed-severity trivy findings → correct severity_counts + total; two CVEs
  on one package → top_packages `[(pkg, 2)]`; a clean scan → ({}, 0, []); nuclei severity
  counted; non-coloured (INFO/UNKNOWN) not counted.
- render tests: an nmap report shows `.recon-hero` with the open-port count + the connect-
  scan honesty note; a trivy report shows `.vuln-hero` with the stacked bar + top packages;
  a nikto report shows neither; a clean trivy scan never says "secure".

- **P4 — Mappings + evidence + SLA** (the old epic M3/M4/M5): CWE→ATT&CK/NIST,
  evidence blocks, auto SLA/benchmark from band.

### P4 — Auto remediation SLA from band (THIS SUB-PHASE)

Scope RULING (concrete default): P4 ships **M5 — the auto remediation SLA/benchmark
from severity band** in the combined report's exec layer. **M3 (CWE→ATT&CK/NIST) is
DEFERRED**: findings do not currently carry a CWE id (only trivy has `CweIDs`, unsurfaced),
so a CWE mapping would be low-signal and needs CWE surfaced first. **M4 (evidence blocks)
is COVERED** by the existing per-finding evidence table (`slots()` + the Evidence section).

- **SLA1 Benchmark helper.** `_SLA_DAYS = {CRITICAL:15, HIGH:30, MEDIUM:90, LOW:180}` — a
  common severity-based vulnerability-management SLA pattern. No SLA for INFO/UNKNOWN. The
  window is an ILLUSTRATIVE policy TARGET, never a measured deadline or a compliance
  guarantee (RB2/RB4).
- **SLA2 Exec render.** The combined exec layer gains a `.sla` block: a table with one row
  per COLOURED severity that has REMEDIATION WORK UNITS (fix-queue items counted by their
  top severity, NOT every finding by `agg_severity`): a coloured hardening finding that
  never becomes a work unit must not get an SLA row, or the SLA would assert a remediation
  target in the same exec layer that says "No remediable findings" (red-team B1). Showing the severity, the
  open count, and the target window framed as a TARGET (e.g. "15-day target"); the block
  heading and the note both carry "illustrative benchmark" so a skimmed/screenshotted
  table is not read as a committed deadline (red-team N1). Window values come from
  `_remediation_sla` (single source of truth) and the note's window list is interpolated
  from it, so the prose cannot drift from the table (Standards F1/F2). Bands with no open
  findings are omitted (never invent an SLA for an empty tier). An honesty note states the
  windows are an illustrative benchmark for prioritisation, NOT a measured deadline or a
  compliance guarantee, and that KEV/regulatory due dates override.
- **SLA3 Honesty + a11y + scope.** Scriptless inline HTML, severity word always present
  (never colour alone, reuse `.sev sev-*`), CSP unchanged. Single-scanner reports are
  unchanged (the SLA lives in the combined exec layer where the aggregate bands are); the
  per-finding technical body is untouched.

### Seams (P4)

- `_remediation_sla` teaching cases: CRITICAL→15, HIGH→30, MEDIUM→90, LOW→180, INFO/UNKNOWN
  → None (no SLA row).
- render tests: a combined report with Critical+High findings shows the `.sla` table with
  "15 days"/"30 days" rows and the illustrative-benchmark honesty note (never "compliance"
  as a guarantee); a combined report with only INFO findings shows no SLA rows; the SLA
  never claims a measured deadline.

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
