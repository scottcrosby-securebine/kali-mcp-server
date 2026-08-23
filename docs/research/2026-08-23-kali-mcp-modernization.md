# Kali MCP modernization research

## Recommendation

Modernize around a small, tested scanner core rather than installing Kali tool metapackages wholesale. Preserve the existing 42 MCP calls, but place every operation behind a stable profile, scope, intensity, and approval policy. Add first-class artifact assessment with Trivy, Syft and bounded oletools; use uro internally for authorized URL-set preprocessing; retain Nmap/Nuclei/WhatWeb/Nikto/TLS coverage with safer adapters; and evaluate WPProbe through overlap, feed, schema and two-architecture tests before approval.

The first implementation should not include authenticated web scanning, exploit execution, report comparison/history, high-rate raw scanning, GUI/daemon-heavy scanners, wireless, cloud assessment, VPN/proxy management, Docker-socket access, public OAST services, telemetry, or remote report hosting. Authenticated scanning, comparison/history, and exploit execution remain explicit later milestones. Exploit execution always requires an express natural-language request and can never auto-chain from discovery.

The existing 42 public names, parameter names, order, defaults, and semantic intent form the compatibility floor, not a permanent ceiling. Approved new capabilities may add versioned public calls after the tool-matrix gate; they must not rename, replace, or silently repurpose an existing call. Internal helpers such as `uro` do not expand the public catalog.

### Runtime profiles and launcher defaults

The host-side launcher must detect the host and default Linux to `linux-full` and Apple Silicon macOS to `mac-hardened`; `linux-hardened` is an explicit alternative. Intel Mac is unsupported. The server still verifies effective capabilities because a selected profile is not proof that Docker granted them.

- `mac-hardened`: arm64 image, bridge networking, non-root, all capabilities dropped, no raw/link-layer tools, read-only root plus bounded writable cache/tmp/report mounts.
- `linux-hardened`: amd64 or arm64 image with the same hardened execution boundary and bridge networking.
- `linux-full`: amd64 or arm64 image, native Linux host networking, non-root, all capabilities dropped except per-mode additions proven by experiments. “Full” increases authorized network visibility; it never implies intrusive authorization or automatic escalation.

**Evidence status:** launcher defaults and profile intent are settled user requirements. Docker networking facts are high-confidence official-source observations. Exact capability behavior is an explicit empirical unknown.

## Current Kali baseline

**Evidence status:** high-confidence official Kali observations for the release, branch and container facts; the release/build policy is derived. The selected new-tool list is single-engine gap-fill evidence and remains unapproved.

As of 2026-08-23, Kali 2026.2 (released 2026-06-29) is the latest named snapshot release. `kali-rolling` is a different clock: it is continuously updated, and Kali's official `kalilinux/kali-rolling` container is rebuilt weekly, contains no default tool metapackage, and publishes a multi-architecture manifest including `linux/amd64` and `linux/arm64`. Kali explicitly distinguishes installability checks from functional testing. ([Kali releases](https://www.kali.org/releases/), [Kali 2026.2](https://www.kali.org/blog/kali-linux-2026-2-release/), [Kali branches](https://www.kali.org/docs/general-use/kali-branches/), [official Kali containers](https://www.kali.org/docs/containers/official-kalilinux-docker-images/), [rolling tags](https://hub.docker.com/r/kalilinux/kali-rolling/tags))

The project should therefore develop against `kalilinux/kali-rolling`, resolve and test packages in CI, and release only a digest-pinned manifest with recorded per-platform package versions. Official image/package availability is not proof that every transitive asset runs correctly; amd64 and arm64 builds and smoke tests are mandatory.

Official release posts identify potentially relevant additions since the project was written: `evil-winrm-py` and `hexstrike-ai` in 2025.4; `SSTImap`, `WPProbe`, `XSStrike`, and `MetasploitMCP` in 2026.1; and `legba`, `oletools`, `uro`, and `tookie-osint` in 2026.2. These are **new to Kali**, not automatically suitable or new to this MCP. The individual assessment below is single-engine, primary-source gap-fill research; its policy dispositions are recommendations pending the matrix approval and runtime gates. ([Kali 2025.4](https://www.kali.org/blog/kali-linux-2025-4-release/), [Kali 2026.1](https://www.kali.org/blog/kali-linux-2026-1-release/), [Kali 2026.2](https://www.kali.org/blog/kali-linux-2026-2-release/))

| New Kali addition | Initial disposition | Basis and remaining proof |
|---|---|---|
| `evil-winrm-py` | Defer | Interactive authenticated remote shell with credential and upload/download handling; defer to the authenticated/post-exploitation milestone. ([Kali package](https://www.kali.org/tools/evil-winrm-py/), [upstream usage](https://github.com/adityatelange/evil-winrm-py/blob/main/docs/usage.md)) |
| `hexstrike-ai` | Exclude | A second autonomous MCP/API orchestration layer duplicates and can bypass this server's policy boundary; it advertises automated reconnaissance and exploitation. ([Kali package](https://www.kali.org/tools/hexstrike-ai/), [upstream](https://github.com/0x4m4/hexstrike-ai)) |
| `SSTImap` | Defer | Detection and exploitation are co-located, including command and shell behavior; defer to the explicitly gated active-web/exploit milestone. ([Kali package](https://www.kali.org/tools/sstimap/), [upstream](https://github.com/vladko312/SSTImap)) |
| `WPProbe` | Candidate after tests | Directly relevant to public WordPress CVE profiling and offers rate limits and JSON/CSV, but overlaps WPScan and needs safe-mode, feed-promotion, schema, and two-architecture tests. ([Kali package](https://www.kali.org/tools/wpprobe/), [upstream](https://github.com/Chocapikk/wpprobe)) |
| `XSStrike` | Defer | Payload, crawler, fuzzing, blind/OAST and self-update behavior needs the later active-web/DAST envelope; its `--json` option describes request-body parsing, not structured results. ([Kali package](https://www.kali.org/tools/xsstrike/), [upstream usage](https://github.com/s0md3v/XSStrike/wiki/Usage)) |
| `MetasploitMCP` | Exclude | A nested MCP/service duplicates the existing narrow Metasploit inspection calls and expands the policy-bypass and exploit surface. Retain typed local wrappers instead. ([Kali package](https://www.kali.org/tools/metasploitmcp/), [upstream guide](https://github.com/rapid7/metasploit-framework/blob/master/docs/metasploit-framework.wiki/How-to-use-Metasploit-MCP-Server.md)) |
| `legba` | Defer | Structured output and rate controls do not remove credential-spraying, account-lockout, arbitrary-command, API, and overlap risks with `hydra_attack`. ([Kali package](https://www.kali.org/tools/legba/), [upstream](https://github.com/evilsocket/legba)) |
| `oletools` | Include, bounded | Read-only offline Office/OLE artifact analysis fills a current gap and provides JSON modes. Limit the adapter to bounded analysis commands and never pass document passwords through MCP arguments. ([Kali package](https://www.kali.org/tools/oletools/), [upstream](https://github.com/decalage2/oletools)) |
| `uro` | Include internally | A no-network URL-list transformer can reduce duplicate requests before approved crawls. It is not a vulnerability scanner or a new public call; retain source inventory and filtering provenance. ([Kali package](https://www.kali.org/tools/uro/), [upstream](https://github.com/s0md3v/uro)) |
| `tookie-osint` | Exclude | Broad social-site enumeration, Selenium/Chromium and proxy features add third-party egress, privacy, image-size and out-of-scope proxy concerns while overlapping existing OSINT. ([Kali package](https://www.kali.org/tools/tookie-osint/), [upstream](https://github.com/Alfredredbird/tookie-osint)) |

Kali `arch: all/any` metadata is not runtime proof. Every included or deferred binary still needs pinned amd64/arm64 container builds and smoke tests, including Apple Silicon Docker Desktop where applicable.

## Findings

### Independently convergent findings

Evidence status for findings 1–3 is **high-confidence independent-agent convergence** on official upstream facts plus explicitly identified derived policy. Finding 4 is **medium confidence** because the default TLS adapter still needs fixtures and overlap comparison. Finding 5 is a **high-confidence derived scope recommendation** grounded in documented tool behavior and the user-approved boundary. Agent convergence is not counted as independent-source corroboration.

1. **Nmap remains the network foundation.** It supports unprivileged TCP connect scans, while raw-packet techniques require additional privilege. Preserve connect mode everywhere and qualify raw modes experimentally for Linux-full. ([Nmap scanning techniques](https://nmap.org/book/man-port-scanning-techniques.html), [Nmap miscellaneous options](https://nmap.org/book/man-misc-options.html))
2. **Nuclei is the principal live CVE/template scanner, but templates are executable policy.** Kali currently packages it with structured outputs and broad protocol/template support. Safe releases must pin or version templates, disable public cloud/OAST and dangerous template classes by default, and record template provenance. ([Kali Nuclei](https://www.kali.org/tools/nuclei/), [Nuclei running documentation](https://docs.projectdiscovery.io/opensource/nuclei/running))
3. **Trivy and Syft provide the portable source/image seam.** Trivy covers image archives, explicit remote-registry sources, filesystems, root filesystems and SBOMs; Syft creates reusable CycloneDX/SPDX inventory from explicit `registry`, `docker-archive`, `oci-archive`, `oci-dir`, `dir`, or `file` sources. The adapters must reject automatic runtime discovery and daemon-backed source schemes. Trivy registry scans must force remote-only resolution; archive scans use explicit input. ([Kali Trivy](https://www.kali.org/tools/trivy/), [Trivy image CLI](https://trivy.dev/docs/dev/docs/references/configuration/cli/trivy_image/), [Kali Syft](https://www.kali.org/tools/syft/), [Syft sources](https://github.com/anchore/syft/wiki/supported-sources))
4. **WhatWeb, bounded Nikto, and one primary deep TLS adapter round out the safe web baseline.** Scanner policies must limit request volume and exclude mutation, denial-of-service, external callback, and phone-home behavior. ([Kali WhatWeb](https://www.kali.org/tools/whatweb/), [Kali Nikto](https://www.kali.org/tools/nikto/), [Kali sslscan](https://www.kali.org/tools/sslscan/), [Kali testssl.sh](https://www.kali.org/tools/testssl.sh/))
5. **High-rate and deep DAST tools need later envelopes.** Masscan/Naabu, Wapiti, SQLmap, ZAP, NetExec, and exploitation frameworks add material rate, state, authentication, privilege, or payload risks. Existing compatible calls remain visible but automatic safe workflows must not invoke them. ([Kali Masscan](https://www.kali.org/tools/masscan/), [Kali Naabu](https://www.kali.org/tools/naabu/), [Kali Wapiti](https://www.kali.org/tools/wapiti/), [Kali SQLmap](https://www.kali.org/tools/sqlmap/), [Kali NetExec](https://www.kali.org/tools/netexec/))

### Candidate matrix

**Evidence status:** Nmap, Nuclei, WhatWeb, Nikto, TLS, Trivy, Syft, Masscan/Naabu and deferred DAST rows have independent-agent convergence but not necessarily independent sources. Gitleaks and enum4linux-ng are single-engine/unverified. ffuf and the default TLS adapter are contested. Profile cells are proposed policy pending runtime tests.

| Candidate | mac-hardened | linux-hardened | linux-full | Initial decision |
|---|---|---|---|---|
| Existing 42 calls | Stable catalog; capability/policy errors where unavailable | Stable catalog | Stable catalog | Preserve compatibility |
| Nmap | Connect mode | Connect mode | Connect plus qualified raw modes | Include |
| Nuclei | Safe pinned templates | Safe pinned templates | Same; intensity may be approved upward | Include |
| WhatWeb | Yes | Yes | Yes | Include |
| Nikto | Bounded safe tuning | Bounded safe tuning | Bounded safe tuning | Include |
| sslscan/testssl.sh | Yes | Yes | Yes | Include both existing calls; select one primary audit adapter |
| Trivy | Read-only mounts, archives, registry | Same | Same | Add |
| Syft | Read-only mounts, archives, registry | Same | Same | Add |
| WPProbe | Candidate safe mode | Candidate safe mode | Candidate safe mode | Add only after overlap/feed/schema/two-architecture tests |
| oletools | Bounded read-only artifact analysis | Same | Same | Add |
| uro | Internal preprocessing only | Same | Same | Add internally; no new public scan call |
| Gitleaks | Candidate | Candidate | Candidate | Add only after independent source review plus pinned package/binary, structured-output, read-only-mount and amd64/arm64 runtime proof |
| enum4linux-ng | Candidate | Candidate | Candidate | Unapproved pending independent source/package review, overlap fixtures against `enum4linux_scan` and the existing SMB calls, and pinned structured-output/runtime proof on amd64/arm64 |
| ffuf | Existing call, explicit rate limits | Same | Same | Preserve; exclude from automatic safe composition pending approval |
| Masscan/Naabu | Unavailable | Unavailable | Candidate after capability/rate experiments | Defer |
| Wapiti/ZAP | Deferred | Deferred | Deferred | Authenticated/deep DAST milestone |
| evil-winrm-py/SSTImap/XSStrike/legba | Deferred | Deferred | Deferred | Authenticated, active-web, exploit, or password-audit milestones |
| hexstrike-ai/MetasploitMCP/tookie-osint | Excluded | Excluded | Excluded | Duplicate policy boundary or out-of-scope egress/runtime surface |
| Exploit execution | Future availability depends on adapter tests | Same | Same | Defer; express request only, never auto-chain, profile/tool support empirical |

This matrix is a proposed policy, not empirical compatibility proof. Gitleaks remains unapproved pending independent source review plus pinned package/binary, structured-output, read-only-mount and amd64/arm64 runtime proof. enum4linux-ng is unapproved pending independent source/package review, overlap fixtures against `enum4linux_scan` and the existing SMB calls, and pinned structured-output/runtime proof on amd64/arm64.

## Existing 42-call compatibility and policy audit

**Evidence status:** high-confidence direct source observation for names, defaults and current commands; future authorization classes are derived policy. The audit is exhaustive, including `theharvester_scan`.

All 42 names, parameter names, order, and defaults remain visible. The current implementation has no profile, engagement, approval, capability, redaction, or structured-error layer; every external call returns truncated decorated text. The policy classification below is derived from the exact current command construction and must be enforced before composition.

| Class | Existing calls |
|---|---|
| Safe-active or passive candidates for bounded automatic use | `nmap_scan`, `nmap_service_scan`, bounded `nmap_port_scan`, `dns_enum`, bounded `dns_recon`, approved-provider `subfinder_scan`, passive `amass_enum`, low-aggression `whatweb_scan`, `wafw00f_scan`, scoped `web_headers`, `sslscan_scan`, `testssl_scan`, `sslyze_scan`, scoped `nbtscan_scan`, `searchsploit_search`, approved-provider `theharvester_scan`, `whois_lookup` |
| Explicit active approval; never automatic at current defaults | `nmap_vuln_scan`, `nmap_comprehensive_scan`, `fierce_scan`, `nikto_scan`, `wpscan_scan`, `dirb_scan`, `ffuf_scan`, `gobuster_scan`, `wfuzz_scan`, `nuclei_scan`, `enum4linux_scan`, `smb_enum` |
| Hard gate/manual or future policy adapter | `nmap_script_scan`, `sqlmap_scan`, `crackmapexec_scan`, `hydra_attack`, `john_crack`, `hashcat_crack`, `metasploit_search`, `metasploit_info` |
| Informational only | `responder_analyze` |
| Composite workflows requiring redesign before use | `quick_recon`, `full_recon`, `web_audit`, explicit-active `network_sweep` |

Key defects in the existing catalog are observed directly in the source. The 42 public definitions span [`nmap_scan`](../../kali_pentest_server.py#L82) through [`network_sweep`](../../kali_pentest_server.py#L792), with the four composites at lines 654–819:

- Target validation only trims and checks non-empty length ([`validate_target`, lines 70–77](../../kali_pentest_server.py#L70)) and cannot enforce an engagement.
- Arbitrary Nmap script, Nuclei template, Hydra service, John format, Hashcat mode, wordlist and file strings cross policy boundaries.
- Metasploit inputs are embedded in the framework's `-x` command language ([lines 604–621](../../kali_pentest_server.py#L604)) and need grammar-level validation even though the operating-system subprocess avoids a shell.
- [`run_command`, lines 36–60](../../kali_pentest_server.py#L36) logs early arguments and returns combined unredacted output, which can expose targets, paths, SQL POST data, hashes, usernames, tokens, and recovered credentials.
- [`web_headers`, lines 431–442](../../kali_pentest_server.py#L431) invokes `curl -L`, whose [location behavior](https://curl.se/docs/manpage.html#-L) can cross scope on redirects.
- The four composite workflows ([lines 654–819](../../kali_pentest_server.py#L654)) use fragile string heuristics, run stages without separate authorization, have no shared request/time budget, continue after string-form failures, and concatenate output already truncated by `run_command`.
- `crackmapexec_scan` must retain its public name/contract even if a verified NetExec adapter becomes the preferred backend; `responder_analyze` remains non-executing.

Compatibility preserves public signatures and semantic intent, not unsafe reachability, arbitrary host paths, exact emoji prose, or automatic escalation. New structured states include `unavailable`, `approval_required`, `out_of_scope`, and `capability_missing`.

Approval is a staged natural-language contract: **propose** one immutable operation describing scope, exclusions, profile, intensity, capabilities, expected egress and expiry; **approve** that exact proposal explicitly; then **apply** it without broadening or mutation. Any material change creates a new proposal and requires new approval. Discovery output is never approval, and no stage may grant Docker capabilities or trigger exploit execution by itself. This applies equally to the organization's systems and explicitly authorized customer white-hat engagements.

## Runtime security findings

**Evidence status:** high confidence for cited Docker and scanner behavior; the controls are derived engineering policy and require empirical gates.

Linux host networking shares the host network namespace and removes the container's separate network stack; published ports are ignored. Docker Desktop host networking is opt-in, layer-4 only, cannot access host interfaces directly, and is not equivalent to native Linux. The mac-hardened matrix therefore expresses expected bounded support pending Apple Silicon hardware tests, not network equivalence. ([Docker host networking](https://docs.docker.com/engine/network/drivers/host/), [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/networking-how-tos/))

No primary source establishes one exact Docker capability set for every Nmap mode. Linux-full must begin with all capabilities dropped and add only capabilities proven by a per-mode test matrix covering connect, SYN, UDP, discovery, OS detection, traceroute and NSE behavior. Record UID, capability sets, network mode and packet evidence. Untested modes remain unavailable. `--privileged` remains prohibited. ([Nmap privilege options](https://nmap.org/book/man-misc-options.html), [Docker run security options](https://docs.docker.com/reference/cli/docker/container/run))

A read-only root filesystem needs explicit, size-limited writable locations: isolated Trivy cache/output, Syft `/tmp` and output, controlled Nuclei template/config cache and results, and report artifacts. Cache initialization warnings or malformed structured results fail the scan even if a process exits zero. Scanner executables, libraries and installation locations are immutable runtime image content; writable mounts are limited to declared data, template/database cache, temporary and report paths and must never shadow binary locations. Runtime self-update of scanner binaries is prohibited.

Nuclei execution disables automatic update checks, Interactsh/OAST, cloud/dashboard upload, code, JavaScript, headless, file-access, fuzz/DAST, and workflow templates by default. Templates are promoted through a separate controlled update job with reviewed IDs/paths, protocol allowlists, recorded digest/version, rollback, and cache integrity. Signatures prove identity/integrity, not safety. ([Nuclei updates](https://docs.projectdiscovery.io/opensource/nuclei/running), [template signing](https://docs.projectdiscovery.io/templates/reference/template-signing), [Nuclei cloud controls](https://docs.projectdiscovery.io/cloud/free/advanced))

## Engagement scope choke point

**Evidence status:** high-priority derived engineering policy; enforcement feasibility must be proven per adapter.

Input filtering alone cannot contain scanners that follow redirects, resolve names again, discover targets, override Host/SNI, or execute nested workflows. The implementation requires one fail-closed broker used by every adapter and composite workflow:

1. Canonicalize URLs, IDNA hostnames, schemes, ports, IPv4, IPv6 and IPv4-mapped IPv6; reject ambiguous forms and userinfo tricks.
2. Apply immutable exclusions before allow rules, including special-use ranges unless explicitly authorized.
3. Validate complete CNAME chains and every A/AAAA result; mixed allowed/disallowed result sets fail closed.
4. Revalidate each redirect, retry, discovered target, workflow handoff and protocol upgrade immediately before connection.
5. Authorize dial address, URL host, HTTP Host and TLS SNI as a bound tuple; scanner/template overrides cannot escape it.
6. Treat SANs, hyperlinks, CNAMEs, discovered subdomains, ASN/CIDR expansions and scanner outputs as candidates requiring authorization, never implicit scope additions.
7. Deny a tool whose secondary connections cannot be mediated or constrained. Log canonical decisions without secrets.

These are proposed engineering controls derived from scanner and Docker behavior, not claims that scanner-native flags alone enforce the engagement.

Kali `all`/`any` package metadata is discovery evidence, not an amd64/arm64 guarantee. Every pinned binary, database, template, and browser/runtime asset must pass release builds and smoke tests on both architectures.

## Operational invariants

“Local-only” governs findings storage, rendering, telemetry and upload; it does not ban expressly authorized target traffic, registry pulls, passive-source queries, or controlled feed/template updates. Required egress is explicit in the approved proposal and report. Implicit scanner self-update and phone-home behavior is disabled, and opening a local report produces zero network requests.

Release-blocking CI uses only controlled local fixtures, test containers and synthetic registries. It never scans production or other Internet-hosted targets. Scanner binaries are installed only during the pinned image build and remain immutable at runtime; vulnerability databases and reviewed templates use separate controlled, versioned data-update paths.

No image, launcher, configuration, adapter or report may embed credentials, host-specific project paths, Docker-socket endpoints, or deployment-specific secrets. Paths and private-registry access are supplied at launch through explicit read-only mounts and runtime-mounted secrets, then redacted from logs and reports.

## Human-readable report model

**Evidence status:** high confidence for OWASP/FIRST content guidance; hostile-document controls are derived engineering policy.

Report generation is not automatic for ordinary tool calls. The server creates a report only when the user expressly requests one or when an explicitly approved, clearly detailed multi-tool workflow has a report as its declared output. Lightweight calls return their structured result without silently persisting an HTML report; the proposal states whether report generation will occur before approval.

OWASP recommends serving executive and technical readers and documenting objectives, scope, limitations, findings, evidence, severity and remediation. FIRST specifies that CVSS communicates vulnerability severity rather than organizational risk and that published scores need their vectors. ([OWASP reporting](https://owasp.org/www-project-web-security-testing-guide/v41/5-Reporting/README), [CVSS v4 specification](https://www.first.org/cvss/v4.0/specification-document))

The consolidated offline HTML should therefore contain:

1. Engagement, scope, exclusions, authorization reference, profile, capabilities, intensity, DNS and scan times.
2. Executive summary with accessible charts and equivalent tables.
3. Coverage and limitations, including unauthenticated status, skipped checks, failures, stale feeds and unsupported modes.
4. Prioritized findings with separate severity, detection confidence, validation state and exploitation context.
5. Source, image and live-target evidence sections with remediation and retest guidance.
6. Tool, binary, database, template, Kali base and artifact provenance.
7. Sanitized local artifact references by relative ID/hash rather than host path.

Secrets and credentials are redacted before any observation or evidence is persisted. Canonical JSON, raw-artifact references, logs and rendered reports must never contain registry credentials, authentication material, tokens, private keys, submitted passwords/hashes, or recovered credentials; redaction uses typed fields plus scanner-specific patterns and hostile fixtures, and failures are fail-closed rather than rendered.

HTML is derived from the redacted canonical normalized JSON and should be scriptless where practical. It contains inline assets only, makes no network requests, uses a `default-src 'none'` content-security policy, rejects network-capable and unsafe data URL schemes, escapes scanner-controlled content, bounds evidence size, constructs any unavoidable DOM from typed data, and never embeds raw scanner HTML. Embedded JSON must not sit in an executable script context. Relative artifact IDs are resolved beneath one output root with path-traversal tests. Browser tests must prove that opening the report produces zero requests. Charts must have equivalent tables.

## Normalization and correlation

**Evidence status:** medium-confidence proposed policy informed by the cited standards; fixture validation remains required.

The following is a proposed engineering policy, not a normative requirement established by SARIF or CycloneDX. Store immutable scanner observations before deriving findings. Each observation retains scanner/rule versions, target or artifact identity, location, native severity/confidence, evidence reference, time, and database/template provenance.

Correlation rules:

- An advisory namespace, ID, revision and status may cluster related evidence for presentation; it is not canonical finding identity and does not prove that an asset is affected. Preserve rejected/reserved/published/withdrawn state, ecosystem version semantics, aliases, affected ranges, fixes, advisory source and database snapshot.
- Source identity uses rule namespace plus repository-relative location/fingerprint.
- Image identity uses immutable digest, platform, package URL/ecosystem/name/version, advisory ID and occurrence/layer.
- Live identity uses engagement, canonical virtual host/origin, resolved address, protocol/port, rule and evidence discriminator.
- Cross-scanner observations merge only when asset identity, advisory identity and evidence class are compatible. CPE-to-purl/name mapping is evidence with confidence, never equality.
- Shared CWE/root cause without the same location or fix becomes a remediation cluster, not one finding.
- Source-to-image correlation requires build provenance; image-to-live correlation requires deployment provenance.
- Conflicting applicability remains contested until authoritative VEX/vendor or analyst evidence resolves it.
- CVSS severity, scanner confidence, validation, CISA KEV status, EPSS probability/date, public exploit evidence and business priority remain separate fields. ([SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html), [CycloneDX](https://cyclonedx.org/docs/1.7/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [EPSS](https://www.first.org/epss/))

## Conflicts

- **ffuf:** one engine recommends initial inclusion with strict rate/concurrency ceilings; the other recommends deferral because it is inherently request-amplifying. Preserve its existing MCP call but keep it out of automatic safe workflows until the user approves the final matrix.
- **TLS overlap:** sslscan and testssl.sh both add value. Preserve both existing calls, but use one primary adapter in consolidated audits to avoid duplicate findings.
- **Scanner marketing versus evidence:** upstream/Kali language may describe highly accurate or zero-false-positive behavior. Reports must still preserve detection confidence and validation state rather than repeating that as a guarantee.

## Gaps and unknowns

- Exact minimal Docker/file capabilities for each raw Nmap mode and future raw scanners require container experiments.
- Kali package labels do not prove complete amd64/arm64 runtime compatibility; release smoke tests must do that.
- Apple Silicon Docker Desktop behavior is documented at a platform level, but actual reachability, IPv6, custom DNS, bind-mount ownership and scanner behavior still need hardware validation.
- Structured output schemas need fixtures against the exact pinned versions and lossless parse-failure handling.
- No vulnerability-report-specific primary standard was found for self-contained HTML security; escaping, CSP, scriptless rendering, local assets, path confinement and accessibility are engineering requirements derived from broader OWASP guidance and require hostile-fixture/browser tests.
- Private-registry secret mounting and redaction require implementation threat modeling and integration tests.
- Report encryption/access control is unresolved; local-only storage does not itself guarantee confidentiality.
- Per-connection engagement enforcement for unmodified scanner subprocesses is unproven. Each adapter must demonstrate constrained DNS, redirects, discovered targets and secondary connections through scanner controls plus resolver/egress mediation; otherwise it remains unavailable. Input preflight alone is insufficient.
- Gitleaks has only single-engine Kali-package evidence. Approval requires an independent source review plus pinned package/binary, structured-output, read-only-mount and amd64/arm64 runtime proof.
- enum4linux-ng has only single-engine Kali-package evidence. It is unapproved pending independent source/package review, overlap fixtures against `enum4linux_scan` and the existing SMB calls, and pinned structured-output/runtime proof on amd64/arm64.

## Method

Two blind fresh-context research agents independently answered the same questions from official Kali, upstream scanner, OWASP, FIRST, CISA, CVE, SARIF and CycloneDX sources. Their agreement is recorded as independent-agent convergence, not independent-source corroboration. Targeted gap-fill waves then covered the current Kali baseline, all 42 existing calls, Docker/runtime constraints, daemonless image inputs, Nuclei trust, engagement enforcement, exact claim traceability, and the ten selected additions from Kali 2025.4–2026.2.

The doctrine gate designates the logic critique as its formal review slot and runs a separate adversarial red team. Rounds 1–8 and subsequent exit-gate rounds ran both reviews; early rounds found missing current-Kali evidence, incomplete 42-call coverage/status, platform and containment overclaims, weak claim traceability, missing new-tool dispositions, and omitted settled safety/reporting rules. Every blocking finding was verified against primary sources, local source, or the verbatim anchor before amendment. Round 6 was clean; later edits reset the consecutive-clean counter as required. The final exit still requires two consecutive clean full-gate passes over the unchanged report.

Native checks for the current report resolved every referenced repository path and line anchor, independently counted 42 unique `@mcp.tool()` definitions by AST and repository search, fetched all 68 unique report/dossier URLs, and rechecked edited factual claims against the cited page content. All returned HTTP 200 except the CISA KEV page, which returned HTTP 403 to command-line requests and was separately accessible through the web research tool. Parallel Kali requests initially rate-limited; sequential HTTP/1.1 retries returned HTTP 200. The repository's `CLAUDE.md` states that no test suite, linter or CI exists, and no documentation build or Markdown/link-lint command is configured, so no project-native prose gate could run.

Deferred non-blocking items are: decide report encryption/access control; resolve ffuf's initial status; choose the primary TLS adapter from fixtures; define the exact CSP style/image/font mechanism while retaining zero-request browser tests; clarify wire/schema compatibility in the implementation specification; and refine third-party-provider egress and non-executing Metasploit categories.

Gitleaks and enum4linux-ng are not deferred non-blocking items. They are unapproved implementation gates: Gitleaks requires independent source review plus pinned package/binary, structured-output, read-only-mount and amd64/arm64 runtime proof; enum4linux-ng requires independent source/package review, overlap fixtures against `enum4linux_scan` and the existing SMB calls, and pinned structured-output/runtime proof on amd64/arm64. All other empirical gaps listed above likewise remain release or implementation gates rather than deferred assertions.

The amended dossier containing the verbatim anchor, settled decisions, merged claim table, gap ledger, review history and counters is [`docs/research/2026-08-23-kali-mcp-modernization-worknotes.md`](2026-08-23-kali-mcp-modernization-worknotes.md).
