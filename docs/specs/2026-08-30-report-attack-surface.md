# P3b / #89 — External attack-surface report (inventory-first)

Phase 3b of the report-types stack. Built on the P3a tip
`feat/report-webapp-owasp`@`60d6a28`. Standalone **inventory-first** report —
"everything of ours reachable from the internet" — a purpose the combined CVE/SCA
report and #86 dossier do not serve. Mockup: "Surface Atlas" (issue #89).

## Settled decisions (Scott, 2026-08-30)
- **D1 tool surface:** new `@mcp.tool async def surface_report(result_ref: str = "") -> str`.
  Filters captured results to the external-recon subset `_SURFACE_SCANNERS`, keeps
  newest per (scanner, normalized target), tags the envelope `report_type:"surface"`,
  calls existing `_write_report`. One-line docstring. Mirrors `web_app_report` exactly.
- **D2 source:** renders over ALREADY-CAPTURED results in `RESULTS_ROOT` (same
  path as `web_app_report`/`generate_report` no-ref). Does NOT re-run scanners.
- **D3 net-new capture (Scott chose "add whois + DNS-hygiene parsers" over derive+flag):**
  - **`_parse_whois`**: structured whois — registrar, nameservers, creation/expiry
    dates, status; abuse/registrant email **masked** via `_mask_email`. Wired into
    `whois_lookup` via `_run_with_capture` (replaces the current `_raw_text_parser`),
    following P3a's D3 "wire the new parser at capture time" precedent.
  - **DNS hygiene (SPF/DMARC/AXFR):** a `_dns_hygiene(records)` render-side derivation
    over the captured `dns_recon` (dnsrecon `-j`) records. SPF = apex TXT `v=spf1`;
    DMARC = `_dmarc` TXT `v=DMARC1`; AXFR = presence of zone-transfer records.
    Each renders present / absent / **flagged "not observed in this scan"** — a
    verdict is only asserted from an observed record, never inferred from silence.
    (Verify dnsrecon actually emits DMARC during impl; where a run's capture lacks
    a check, that one check flags the gap — the tile as a whole is structured, not
    degraded.)

## Honesty rules (inventory-first; non-negotiable, mirrors #89 caveats)
- **Inventory is observed-only.** A host/port/service row is asserted only from an
  nmap/whatweb capture; nothing is inferred.
- **Subdomain resolve/live split** is derived by joining subfinder/amass/dns_recon
  names against nmap/dns_recon A-records. A name with no observed A-record is
  "unresolved", never "dead"; a resolved name with no observed open port is
  "resolved, no observed live service", never "offline".
- **Dangling-CNAME / subdomain-takeover watch FLAGS, never confirms.** A CNAME
  whose target has no observed A-record is a *takeover candidate to verify* — the
  toolkit cannot confirm takeover (needs the provider fingerprint / external feed).
- **DNS/email hygiene** asserts present/absent only from observed records; an
  unqueried check reads "not observed", never "pass"/"secure".
- **OSINT footprint** renders as **counts + masked values** only. Emails are masked
  (`_mask_email`, e.g. `a***@example.com`). theharvester is non-functional (#75):
  its tile degrades to a flagged "feed unavailable" gap, per the issue's own model.
- Feed-dependent rows (breach-corpus overlap, takeover confirmation) are flagged
  in-page, never faked or hidden.

## PII / masking (issue caveat — non-negotiable)
- Emails MUST be masked before render (`_mask_email`), everywhere they appear
  (whois abuse contact, theharvester OSINT). Masking is applied in render AND the
  existing `_write_report` redaction still runs.
- OSINT harvest is an operator action in the MAIN session (PII output filter);
  `surface_report` only renders what was captured. This spec adds no subagent harvest.

## External-recon subset (feeders)
Structured capture today: nmap (`_parse_nmap_xml`), dns_recon (`_parse_dnsrecon_json`),
subfinder (`_parse_subdomain_lines`), amass (`_parse_amass_text`), whatweb
(`_parse_whatweb_json`). Changed this phase: whois → structured (`_parse_whois`).
`_SURFACE_SCANNERS = ("nmap","dns_recon","subfinder","amass","whatweb","whois")`.

## Normalized finding shape (existing envelope, do not change)
`{schema_version, scanner, source_type, target_ref, status, findings[], metadata}`

## render_surface(result_docs) — new closure in `_render_report`, new dispatch branch
New `_SURFACE_TEMPLATE` (Surface Atlas IA), reusing escaped/rows/flatten/chart/
list_items + existing tokens/CSS. Sections:
1. **Surface summary tiles** — hosts, open services, subdomains (resolved/live),
   hygiene flags, OSINT counts.
2. **Asset inventory** table — host · IP · ports · service · tech · exposure
   (nmap joined with whatweb per host).
3. **Exposed-services highlight** — risky open ports (`_RISKY_PORTS`: e.g. 21/23/
   3389/445/3306/5432/6379/9200/27017 …) called out.
4. **Subdomains** — resolve/live split + **dangling-CNAME takeover watch** (flagged).
5. **DNS / email hygiene** — SPF / DMARC / AXFR verdicts (`_dns_hygiene`).
6. **Registration** — whois registrar/NS/dates (masked email).
7. **OSINT footprint** — counts + masked emails; theharvester gap flagged.
8. Provenance (scans this session) + tool/feed versions.
All attacker-controlled fields escaped via existing `escaped()`.

## Test seams (TDD, agreed before wave 1)
- `_parse_whois`: fixture whois text → registrar/NS/dates dict; abuse email masked.
- `_mask_email`: `alice@example.com` → `a***@example.com`; non-email untouched;
  handles no-@ and short local-part safely.
- `_dns_hygiene`: dns_recon records fixture → SPF/DMARC/AXFR verdicts; missing check
  → "not observed" (never "pass").
- `render_surface` via `_render_report({report_type:"surface", results:[...]})`:
  asserts inventory rows, risky-port highlight, resolve/live split, takeover
  candidate FLAGGED (never "confirmed"), hygiene verdicts, emails masked in output,
  markup in fields stays escaped, no "secure"/"safe" label emitted.
- `surface_report`: aggregates stored external-recon results, sets report_type,
  persists via `_write_report`; empty → informational message.

## Acceptance (#89)
- [ ] Asset inventory keyed to nmap+whatweb, exposure per host
- [ ] Subdomain enumeration from subfinder (amass optional once #76 fixed)
- [ ] DNS/email hygiene (SPF/DMARC/zone-transfer)
- [ ] OSINT footprint as counts + masked values
- [ ] Feed-dependent rows flagged, not faked
- [ ] Reuses the existing SecureBine report token system
- [ ] All rendered attacker-controlled fields escaped; emails masked
