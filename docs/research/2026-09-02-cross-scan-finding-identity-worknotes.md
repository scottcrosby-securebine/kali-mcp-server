# Worknotes — Cross-scan finding identity (dossier)

Report: docs/research/2026-09-02-cross-scan-finding-identity.md

## Anchor (verbatim, Scott)

**Decision this informs:** Keep #91's ~5-scanner opt-in cut, or adopt a more
scalable cross-scan finding-identity mechanism — and which one.

**Success criteria:** A grounded recommendation plus concrete design that
(1) never manufactures a false FIXED, (2) safely widens coverage well past 5
scanners, (3) fits a single-file Python MCP wrapper parsing ~41 Kali tools'
text/JSON/XML into finding dicts, under the container's constraints (`--rm`,
`/results` tmpfs, `/artifacts` read-only bind, no new heavy datastore).

**Scope bounds:** Verifiable mechanisms in real shipping tools/standards —
DefectDojo (hash_code / HASHCODE_FIELDS_PER_SCANNER, reimport), SARIF
fingerprints vs partialFingerprints, GitHub code-scanning alert identity,
Faraday, Dradis, PlexTrac, Nuclei/Trivy native ids. Current practice, no budget
limit. PLUS: survey other open-source GitHub projects (beyond the named ones)
that implement cross-scan finding identity / dedupe / re-test delta, and whether
any is usable as a dependency or reference implementation for this tool.

**Context of THIS tool:** single-file Python MCP server (kali_pentest_server.py)
shelling out to ~41 Kali binaries, parsing stdout into finding dicts
(id, Title, evidence, severity). Known failure mode to NOT reintroduce: parsers
put run-varying data (byte sizes, IPs, versions, LIST POSITION) into the finding
identity string, so a naive key manufactures false FIXED.

## Claim table

(empty — populated at merge)

## Gap ledger

(empty — populated after round 1)

## Divergence / settled rulings

(none yet)

---

## Run state — orchestrator only

- Loop: 2 complete (both seats converged on C4 structural boundary); report rewritten to Option A
- Clean-pass counter: 0
- Valve counter (never resets): 1 (loop 1 produced blocking)
- Engine 2 (codex): web_search=true confirmed in ~/.codex/config.toml — LIVE, sourced
- Round history: 2 gate loops. L1: 4 block (absence!=remediation). L2: LC 2 block + RT 2 block, all converging on C4 (positive-closure unattainable at diff layer + container). Report = Option A (not-observed-on-re-test, spec D3). A/B fork surfaced to Scott. No clean-pass gate yet on Option-A revision.

## Tool-side ground truth (independent, current main @ origin 12209f4)

Per-parser finding `id` construction (kali_pentest_server.py). S=stable identity,
C=contaminated with run-varying data, X=constant/transcript (excluded class):

| Parser | id format | Class | Note |
|---|---|---|---|
| _parse_nmap_xml ports (3648) | `port-{portid}-{proto}` | S* | *no host field -> multi-host collision; single-host OK |
| _nmap_script_finding (3564) | `{script_id}` | S | nmap NSE script name |
| generic transcript (3736) | `{scanner}-{label}` | X | RAW_TRANSCRIPT_SCANNERS, keyed {id,Title,Sev} |
| _parse_dnsrecon_json (3974) | `dns-{rtype}-{name or address}` | C | address=IP -> false FIXED |
| _parse_amass_text (4004) | `subdomain-{asset}` | S | asset name stable |
| _parse_subdomain_lines (4023) | `subdomain-{host}` | S | host stable |
| _parse_whatweb_json (4110) | `web-tech-{name}` | S | tech name |
| _parse_whois (4182) | `whois-registration` | X | constant per pair |
| _parse_nikto_json (4293) | `{osvdb} if named else nikto-{index}` | S/C | OSVDB stable; index fallback = POSITION |
| _parse_ffuf_json (4329) | `web-path-{status}-{url[-40:]}` | C | status in key + url tail |
| _parse_wafw00f_json (4352) | `waf-{waf}` / `waf-none` | S | |
| _parse_paths_text (4384) | `web-path-{token}` | S? | token = path |
| _parse_sqlmap (4420) | `sqlmap-{pname}-{place}` | S | param+place |
| _parse_wpscan (4468/4490) | `wpscan-{kind}-{name}-{index}` / `wpscan-core-{number}` | C | index=POSITION; core=version |
| _parse_wfuzz (4540) | `web-path-{code}-{url[-40:]}` | C | code in key |
| _parse_sslscan_xml (5462/5472) | `tls-proto-{label}` / `tls-cipher-{name}` | S | |
| _parse_testssl_json (5503) | testssl native `id` | S | testssl.sh stable id |
| _parse_sslyze_json (5544) | `tls-cipher-{name}` | S | |
| _parse_msf_search/info | transcript | X | excluded |

Reframe: the false-FIXED problem is NOT "25 scanners are unsafe." Most parsers
already emit a stable id. Contamination is concentrated in ~4-6 parsers:
dnsrecon (IP in key), nikto (index fallback), ffuf/wfuzz (status/code in key),
wpscan (index + version). Fixing identity = per-parser key selection +
normalization for that handful, not a 25-way audit from scratch.

## DefectDojo primary-source verification (gh api, raw settings.dist.py)

CONFIRMED (high conf, primary source): django-DefectDojo, 4919★, BSD-3-Clause.
The config exists exactly as engine 1 said:
- HASHCODE_ALLOWED_FIELDS = [title, cwe, cwes, vulnerability_ids, line, file_path,
  payload, component_name, component_version, description, endpoints,
  unique_id_from_tool, severity, vuln_id_from_tool, mitigation]  (verbatim match)
- HASH_CODE_FIELDS_ALWAYS = ["service"]
- HASHCODE_FIELDS_PER_SCANNER + DEDUPLICATION_ALGORITHM_PER_PARSER dicts present.
- Env override via DD_HASHCODE_FIELDS_PER_SCANNER (JSON).

CRITICAL NUANCE (my read of the actual shipped field lists — a red-team point):
DefectDojo's shipped per-scanner fields are tuned for IMPORT-DEDUP TOLERANCE,
not false-FIXED-proof attestation. They include DRIFT-PRONE rendering strings:
  Trivy Scan : [title, severity, vulnerability_ids, cwe, description]
  Wpscan     : [title, description, severity]
  Nuclei Scan: [title, cwe, severity, component_name]
title + description drift when a tool evolves or a target changes; DefectDojo's
own docs admit this weakens dedup, and their open bug cluster (#8100, #12754 —
"findings wrongfully marked Inactive/Mitigated", Trivy named) is precisely the
false-remediation failure our attestation must not have.
=> ADOPT THE MECHANISM (per-parser field allowlist + global whitelist + hash +
   asymmetric FIXED authority). DO NOT copy their field lists verbatim — pick
   STRICTER stable-only fields (native ids / CVE+pkg / template-id+location),
   keep title/description/version in EVIDENCE, never in identity.

## Engine 2 (codex) status
Job byqfbyh59 / thread 01a06264 is LIVE-SEARCHING the web (dozens of Searching:
lines in the forwarder log) — genuine second sourced engine, still running.
Merge deferred until it returns.

## Gate loop 1 — logic critique returned (10 findings + divergence flag)
Key blocking: (1) baseline PERSISTENCE across --rm/tmpfs/RO-artifacts unaddressed
in report — BUT #91 spec D1/D2 already answers it (opaque result id same-session,
or path under RO /artifacts cross-engagement). Fold in. (2) "every system same
way" overgeneralized — SARIF/GitHub use comparability/location, not field-hash;
soften. (3) "same protection" as full exclusion — soften to equiv-for-vetted +
bounded human-map surface. (5) inventory is ~19 of 41 — caveat C7, gate "all 41".
(6) C1 label circular — single-origin primary-verified. (7,8) SARIF + DD bugs NOW
primary-verified (bugs are CLOSED not open). (9) keep "of those surveyed". (4,10)
framing/labeling.
Primary-verified this loop: SARIF baselineState+Comprehensive in spec text; DD
#8100 + #12754 real (both CLOSED).
Red team: still running.

## Gate loop 2 — logic critique returned (5 findings, 2 blocking) + DIVERGENCE
F1 (block): C3 positive-evidence has NO data path — retest_report diffs already-
parsed dicts; nmap parser keeps only state=="open" (verified 3641), so port-closed/
host-up is discarded before the diff. "Demonstrated for ports" is FALSE.
F2 (block): under -sT -Pn no-raw-socket, "host proven up" unprovable in the all-
filtered case (the exact WAF false-FIXED scenario). RST-closed proves up; filtered
can't.
F3 (med): SecObserve resolves-on-absence (forbidden by C3) but only its hash is
caveated. F4/F5 (low): SecObserve taxonomy contradiction; "superset NEW/UNCHANGED"
doesn't net false-NEW churn.
DIVERGENCE FLAG: FIXED-seed evidence infeasibility. => positive-evidence FIXED is
largely UNATTAINABLE at the report-time-diff-of-dicts layer AND blocked by the
container. RESOLUTION PATH: this VALIDATES #91 spec D3 (already ruled: never claim
"verified closed"; say "not observed on re-test" + cite run + zero-yield bucket).
The fork = Option A (report-time diff, non-closure language, spec D3 — cheap, no
parser change) vs Option B (parsers emit negative observations for positive FIXED —
more work, container-limited). DECISION-GRADE for Scott.
Red team loop 2: still running.
Valve: 2.

## SETTLED (Scott, 2026-09-02)
- A/B fork RULED: Option A (report-time diff, "not observed on re-test", no closure
  claim; = #91 spec D1/D2/D3). Option B parked.
- Enhancement added (Tier-2): AI-assisted follow-up per finding — grounded in
  cross-run history (context) + security best practice (OWASP/NIST/CIS). ADVISORY
  only, never upgrades to a closure verdict. Laziest fit: server emits structured
  history + best-practice hook, calling AI client generates follow-up (no in-server
  model call, no dep).
- Report reflects both. Untracked/uncommitted pending Scott's commit call.
