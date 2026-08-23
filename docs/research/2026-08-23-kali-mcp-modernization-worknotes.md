# Kali MCP modernization research dossier

## Anchor — verbatim user direction

### Decision this work informs

> "we need to get the latest version of Kali Linux for this MCP. In addition, we need to now support Linux."

> "it still needs to stay in a container and also be able to work on Mac"

> "Linux should default to Linux-full."

> "Just Docker. We don't need Intel Mac."

> "Yes, but I also think we need to work with the latest version of Cali and see if there are any additional tools that we can add to the tool calls because of the updated version."

> "We want to make the MCP server portable and usable by other people, so we don't want to embed any kind of credentials or anything like that into this. We want to be able to leverage it wherever we decide to deploy it. No hard-coded paths."

### Success criteria

> "Yes" [the existing 42 MCP tool names and parameters must remain backward compatible].

> "I like the Docker k image cont scanning. That would be kinda cool. The rest of what you're looking at is perfectly on point."

> "The reports will be read by people, not other computers. Mainly."

> "I would expand this to be able to put out the reports in HTML so that we can get proper graphs and formatting and stuff that's a lot easier to read than just an MD file."

> "No, only if I ask for it or it's a very detailed thing that very obviously needs a report."

> "Local only."

> "Anything it needs beyond this, it needs to explicitly ask me if I want to do it."

> "Should never make a change unless I expressly ask it to do it via natural language."

### Scope bounds

> "Wireless tools are effectively out of scope." [Accepted recommendation.]

> "VPNs are outside the scope of this."

> "I'm okay with deferring [authenticated scanning], but we don't want to lose it in the sauce, so make sure that we do document that that will be a future step."

> "The exploit module is a gated response, meaning the agent can never ever kick it off on its own unless I expressly ask it to do it."

> "sometimes we need to do white hat evaluation, so we need to use these tools to scan our customers' networks."

## Settled decisions from the Grill Me interview

- Docker only. Supported hosts/architectures: Linux amd64/arm64 and Apple Silicon macOS arm64; no Intel Mac or Podman.
- Host launcher selects Linux-full by default on Linux and mac-hardened on macOS; Linux-hardened is optional.
- Linux-full uses host networking, remains non-root, grants only specific capabilities, and never uses `--privileged`.
- One stable tool catalog is visible on every profile; unavailable tools return structured capability guidance.
- Existing 42 names and parameters remain compatible; exact response strings may evolve semantically.
- Authorization supports customer engagements, IPv4/IPv6, CIDRs, domains, URL boundaries, exclusions, expiration, intensity ceilings, and custom DNS.
- Scope/policy mutations use propose/approve/apply, local audit logging, and explicit natural-language approval. Docker capabilities cannot be self-granted.
- Safe intensity is default. Balanced, aggressive, and custom settings are transparent and explicitly approved.
- Reports are local-only, self-contained HTML for humans with JSON as an internal source; they are generated only by express request or as the declared output of an explicitly approved detailed workflow, and lightweight calls do not silently persist them.
- Reports never serve over HTTP, upload results, emit telemetry, or reveal secrets/recovered credentials.
- Project/artifact mounts are read-only and chosen at launch. No Docker socket or hard-coded host path.
- Private registry credentials may only arrive via runtime-mounted secrets and never via MCP arguments, logs, reports, or images.
- Runtime vulnerability data/templates may update and must be versioned in reports; scanner binaries are immutable release artifacts.
- Development tracks Kali rolling; releases pin the exact base digest and package versions and publish tested amd64/arm64 images with SBOM/provenance where supported.
- Unit, container smoke, and controlled local integration tests gate releases. Internet-hosted production scans are not release-blocking CI.
- Wireless, cloud assessment, VPN management, proxy support, and arbitrary host control are out of scope.
- Authenticated website scanning, report comparisons/history, and gated exploit execution are explicit later milestones. Exploit execution can never chain automatically from discovery.
- Historical documentation is archived; current docs are rewritten around the launcher, profiles, engagements, tools, reporting, security, development, and roadmap.
- Deliverables: doctrine research, repository specification, GitHub epic, and dependency-linked implementation tickets.

## Research questions

1. Which current Kali tools should be included, deferred, or excluded for the three runtime profiles?
2. What capability, architecture, privilege, interactivity, maintenance, and reporting constraints apply to each candidate?
3. What current best practices should govern local, human-readable HTML vulnerability reports assembled from heterogeneous scanners?
4. How should source, image, and live-target findings be normalized and correlated without overstating exploitability?

## Claim table

| Claim | Status | Evidence | Disposition |
|---|---|---|---|
| A small curated tool set is preferable to Kali metapackages | Derived recommendation from independently convergent observations; high confidence | https://www.kali.org/docs/general-use/metapackages/ and https://www.kali.org/tools/kali-meta/ show broad dependency bundles; `Dockerfile` lines 12–103 show the current curated installation | Adopt |
| Nmap supports a non-root connect-mode baseline and raw modes need additional privilege | Both engines agree | https://nmap.org/book/man-port-scanning-techniques.html and https://nmap.org/book/man-misc-options.html | Include all profiles; raw modes Linux-full only |
| Nuclei is current in Kali and supports structured output, rate limits, mutable templates, cloud/OAST features | Both engines agree | https://www.kali.org/tools/nuclei/ and https://docs.projectdiscovery.io/opensource/nuclei/running | Include with pinned safe templates; disable cloud/OAST/code/headless/fuzz defaults |
| Trivy can use explicitly constrained remote-image and archive inputs without a Docker socket | Both engines agree | https://www.kali.org/tools/trivy/ and the `--image-src`/`--input` options at https://trivy.dev/docs/dev/docs/references/configuration/cli/trivy_image/ | Include all profiles; reject runtime auto-detection |
| Syft provides reusable SBOM inventory and explicit daemonless registry/archive/directory/file inputs | Both engines agree | https://www.kali.org/tools/syft/ and source schemes at https://github.com/anchore/syft/wiki/supported-sources | Include all profiles; reject daemon schemes and auto-detection |
| WhatWeb and a bounded TLS adapter are low-complexity, container-suitable inventory tools | Both engines agree | https://www.kali.org/tools/whatweb/, https://www.kali.org/tools/sslscan/, https://www.kali.org/tools/testssl.sh/ | Include; choose one default deep TLS adapter while preserving existing calls |
| Nikto is useful but its tuning categories require a safe policy | Both engines agree | https://www.kali.org/tools/nikto/ | Preserve/include with bounded safe defaults |
| ffuf belongs in the initial curated expansion | Conflict | Engine 1: include with strict ceilings; engine 2: defer as inherently request-amplifying. https://www.kali.org/tools/ffuf/ | Preserve existing call; do not make it part of automatic safe workflows; final include/defer decision requires tool-matrix approval |
| enum4linux-ng may expand SMB enumeration after complete verification | Single-engine/unverified | https://www.kali.org/tools/enum4linux-ng/ | Unapproved pending independent source/package review, overlap fixtures against `enum4linux_scan` and the existing SMB calls, and pinned structured-output/runtime proof on amd64/arm64 |
| Gitleaks may become the dedicated secret scanner after complete verification | Single-engine/unverified | https://www.kali.org/tools/gitleaks/ | Unapproved pending independent source review plus pinned package/binary, structured-output, read-only-mount and amd64/arm64 runtime proof |
| Masscan/Naabu high-rate raw scanning should not be initial safe baseline | Both engines agree | https://www.kali.org/tools/masscan/, https://www.kali.org/tools/naabu/, https://github.com/robertdavidgraham/masscan | Defer behind scope/rate/capability validation |
| Wapiti, SQLmap, ZAP, NetExec, authenticated scanning, and exploitation need later gated milestones | Both engines agree | https://www.kali.org/tools/wapiti/, https://www.kali.org/tools/sqlmap/, https://www.kali.org/tools/netexec/, https://www.kali.org/tools/zaproxy/ | Defer; preserve existing compatible calls under policy gates |
| Reports need executive and technical layers, scope/limitations, evidence, remediation, and severity vectors | Both engines agree | https://owasp.org/www-project-web-security-testing-guide/v41/5-Reporting/README and https://www.first.org/cvss/v4.0/specification-document | Adopt |
| CVSS is severity rather than organizational risk; KEV and EPSS are separate prioritization context | Both engines agree | https://www.first.org/cvss/v4.0/specification-document, https://www.first.org/epss/, https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Adopt with source/date labels |
| Normalize immutable observations before correlation and preserve native provenance | Both engines agree (derived) | SARIF and CycloneDX identity/lifecycle models: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html and https://cyclonedx.org/docs/1.7/ | Adopt |
| Source-to-image and image-to-live correlations require explicit build/deployment provenance | Both engines agree (derived) | Same standards plus CVE record semantics: https://www.cve.org/CVERecord/UserGuide/ | Adopt; never infer from names/banners alone |
| HTML should be self-contained, local-only, escaped, CSP-restricted, and accessible | Both engines agree (engineering inference) | OWASP report/logging guidance supports content/redaction; no report-specific primary standard was found | Adopt and red-team implementation |
| Kali 2026.2 is the latest named snapshot as of 2026-08-23; rolling is continuous and its official container updates weekly | Observed, targeted gap-fill | https://www.kali.org/releases/, https://www.kali.org/docs/general-use/kali-branches/, https://www.kali.org/docs/containers/official-kalilinux-docker-images/ | Rolling development; digest-pinned releases |
| Official rolling image publishes amd64/arm64, but package runtime support remains empirical | Observed plus derived gate | https://hub.docker.com/r/kalilinux/kali-rolling/tags | Per-platform build/smoke matrix |
| All 42 calls, including `theharvester_scan`, require stable visibility but different authorization classes | Observed source audit plus derived policy; high confidence | `kali_pentest_server.py` lines 81–819 contain 42 `@mcp.tool()` definitions; exact signatures begin at lines 82, 98, 114, 125, 144, 157, 178, 205, 215, 225, 239, 251, 264, 281, 302, 317, 340, 356, 377, 392, 405, 431, 447, 459, 472, 486, 497, 507, 520, 525, 537, 556, 573, 594, 604, 614, 626, 642, 654, 691, 739 and 792 | Carry exhaustive policy into spec and fixtures |
| Existing composite workflows amplify authorization and lack shared budgets and typed provenance | Observed source audit; high confidence | `kali_pentest_server.py` `quick_recon` lines 654–688, `full_recon` 691–736, `web_audit` 739–789, and `network_sweep` 792–819; `run_command` truncation at 51–55 occurs before composition | Redesign all four before automatic use |
| Linux host networking removes separate network-stack isolation; Docker Desktop host networking is L4-only and non-equivalent | Observed | https://docs.docker.com/engine/network/drivers/host/ | Explicit profiles and hardware tests |
| Exact raw-mode capabilities cannot be fixed from upstream documentation | Unknown by source; empirical requirement | https://nmap.org/book/man-misc-options.html | Per-mode/platform experiments |
| Trivy and Syft must use explicit daemonless source modes | Observed inputs plus derived enforcement | https://trivy.dev/docs/dev/docs/references/configuration/cli/trivy_image/, https://github.com/anchore/syft/wiki/supported-sources | Reject automatic/daemon resolution |
| Nuclei template/update/OAST/cloud behavior needs a promoted execution policy | Observed plus derived policy | https://docs.projectdiscovery.io/opensource/nuclei/running, https://docs.projectdiscovery.io/templates/reference/template-signing, https://docs.projectdiscovery.io/cloud/free/advanced | Separate controlled updates; disable implicit services |
| Per-connection scope containment cannot be guaranteed by input validation alone | Derived from observed scanner behavior; medium-high confidence | `kali_pentest_server.py` `validate_target` lines 70–77, direct target handoffs at 88–95, 215–236, 356–374, 405–442 and 626–639; Nuclei behavior at https://docs.projectdiscovery.io/opensource/nuclei/running; curl redirects at https://curl.se/docs/manpage.html#-L | Prove enforcement per adapter or mark unavailable |
| Hostile local HTML needs scriptless/CSP/path/size/zero-egress controls | Derived policy | OWASP guidance; no dedicated standard found | Hostile-fixture and browser tests |
| Linux defaults to linux-full; Apple Silicon macOS defaults to mac-hardened; linux-hardened is optional | Settled user requirement, high confidence | Verbatim interview anchor; Docker behavior: https://docs.docker.com/engine/network/drivers/host/ | Host launcher plus effective-capability verification |
| Selected relevant tools were newly added across Kali 2025.4, 2026.1 and 2026.2 | Observed, single gap-fill engine; high confidence for release lists | https://www.kali.org/blog/kali-linux-2025-4-release/, https://www.kali.org/blog/kali-linux-2026-1-release/, https://www.kali.org/blog/kali-linux-2026-2-release/ | Individually assessed in report; policy remains subject to approval/runtime gates |
| Kali 2025.4 additions `evil-winrm-py` and `hexstrike-ai` do not belong in the initial curated MCP | Observed capabilities plus derived policy; single-engine, medium-high confidence | https://www.kali.org/tools/evil-winrm-py/, https://github.com/adityatelange/evil-winrm-py/blob/main/docs/usage.md, https://www.kali.org/tools/hexstrike-ai/, https://github.com/0x4m4/hexstrike-ai | Defer authenticated WinRM; exclude nested autonomous HexStrike MCP |
| Of the selected Kali 2026.1 additions, WPProbe is the only initial candidate | Observed capabilities plus derived policy; single-engine, medium confidence | https://www.kali.org/tools/wpprobe/, https://github.com/Chocapikk/wpprobe, https://www.kali.org/tools/sstimap/, https://github.com/vladko312/SSTImap, https://www.kali.org/tools/xsstrike/, https://github.com/s0md3v/XSStrike/wiki/Usage, https://www.kali.org/tools/metasploitmcp/ | Test bounded WPProbe; defer SSTImap/XSStrike; exclude nested MetasploitMCP |
| Selected Kali 2026.2 additions have materially different MCP fit | Observed capabilities plus derived policy; single-engine, medium confidence | https://www.kali.org/tools/legba/, https://github.com/evilsocket/legba, https://www.kali.org/tools/oletools/, https://github.com/decalage2/oletools, https://www.kali.org/tools/uro/, https://github.com/s0md3v/uro, https://www.kali.org/tools/tookie-osint/ | Defer Legba; include bounded oletools; include uro internally; exclude tookie-osint |
| Current source validation cannot enforce engagement scope | Observed, high confidence | `kali_pentest_server.py` `validate_target` lines 70–77 and composite handoffs at 654–819 | Build central policy boundary and adapter enforcement tests |
| Current logging/results can disclose sensitive arguments and scanner output | Observed plus disclosure-risk inference, high confidence | `kali_pentest_server.py` `run_command` lines 36–60; sensitive argv construction at 356–374 and 537–589 | Redact before persistence or presentation |
| Metasploit query/module inputs cross its own `-x` command grammar | Observed, high confidence | `kali_pentest_server.py` lines 604–621; `validate_target` lines 70–77 does not constrain framework grammar | Grammar allowlist; keep non-executing inspection gated |
| Redirects and composite workflow handoffs can escape or amplify initial authorization | Observed plus derived impact, high confidence | `kali_pentest_server.py` `web_headers` lines 431–442 and composites 654–819; https://curl.se/docs/manpage.html#-L | Per-boundary authorization and shared budgets |
| Read-only root requires declared writable cache/tmp/output mounts | Docker behavior observed; scanner paths/sizes empirical, medium confidence | https://docs.docker.com/reference/cli/docker/container/run/#read-only, https://docs.docker.com/reference/cli/docker/container/run/#tmpfs, https://trivy.dev/latest/docs/configuration/cache/, https://docs.projectdiscovery.io/opensource/nuclei/running, https://github.com/anchore/syft/wiki/Configuration | Test pinned scanner paths; use size-limited isolated mounts and initialization validation |
| Scope broker canonicalization, exclusion, DNS, redirect, Host/SNI and discovery rules | Derived engineering policy, medium confidence | Direct handoff/redirect behavior above plus https://docs.projectdiscovery.io/opensource/nuclei/running and https://curl.se/docs/manpage.html#-L | Prove each rule through adapter and egress tests |
| Correlation keys and merge rules are not normative SARIF/CycloneDX requirements | Derived engineering policy, medium confidence | https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html, https://cyclonedx.org/docs/1.7/ | Fixture validation and provenance-preserving implementation |
| Hostile HTML must constrain URLs, embedded data, DOM sinks, paths and evidence size | Derived engineering policy, medium confidence | OWASP report guidance plus red-team analysis | Prefer scriptless rendering; zero-request browser tests |
| The 42 existing calls are a compatibility floor, while approved additions may use new versioned names | Settled requirement interpreted against the request to add current Kali capabilities; high confidence | Verbatim anchor requires existing 42 compatibility and asks for additional tools | Preserve all 42 unchanged; add no public call without matrix approval |
| Authorization uses immutable propose/approve/apply stages | Settled user requirement; high confidence | Verbatim interview anchor and settled decisions | Any material change requires a new natural-language approval; never self-grant capabilities or exploit |
| Reports and their canonical inputs never persist secrets or recovered credentials | Settled user requirement plus derived fail-closed control; high confidence | Verbatim interview decisions; source disclosure risk at `kali_pentest_server.py` lines 36–60 and 356–589 | Redact before persistence/rendering; fail closed on redaction failure |
| Scanner binaries and installation paths remain immutable at runtime | Settled user requirement plus derived mount boundary; high confidence | Verbatim decision on immutable binaries; https://docs.docker.com/reference/cli/docker/container/run/#read-only | Writable mounts cannot shadow executables; feeds/templates use separate controlled data paths |
| Release CI never scans production or Internet-hosted targets | Settled user requirement; high confidence | Verbatim interview decision | Controlled local fixtures, containers and synthetic registries only |
| Future exploit availability is tool/profile-dependent, not inherently linux-full-only | Logic divergence resolved against anchor; high confidence | Verbatim anchor requires express request/no auto-chain but does not prescribe a profile | Defer support decisions to adapter tests; preserve universal approval invariant |
| HTML report generation occurs only by express request or as the declared output of an approved detailed workflow | Settled user requirement; high confidence | Verbatim success criterion: “only if I ask for it or it's a very detailed thing that very obviously needs a report”; settled decisions | Lightweight calls do not silently persist reports; proposal discloses report output before approval |

## Gap ledger

| Gap | What is missing | Already tried |
|---|---|---|
| Tool matrix | Final approval after empirical builds | Source research, full 42-call audit, and individual assessment of selected 2025.4–2026.2 additions complete; exact runtime proof awaits implementation experiments |
| Reporting model | Report encryption/access-control product decision | Content and hostile-HTML controls researched; no report-specific HTML standard found |
| Correlation rules | Fixture validation of proposed policy | Standards researched; bespoke correlation rules explicitly labeled engineering policy |
| Exact Docker capabilities | Per-binary proof, especially Nmap raw modes and future Masscan | Upstream docs establish privilege classes but not minimal Docker capability sets; requires experiments |
| Complete multi-architecture support | Runtime proof for every pinned package and transitive asset | Kali `all`/`any` metadata is insufficient; requires amd64/arm64 build and smoke tests |
| Docker Desktop reachability | Apple Silicon scanner reachability/custom-DNS/bind ownership behavior | Official platform behavior researched; hardware validation remains |
| ffuf initial status | Resolve include-vs-defer conflict | Both engines reviewed the same official Kali page and reached different risk judgments |
| HTML security profile | Report-specific primary standard | No dedicated standard found; current rules are engineering inferences from OWASP guidance |
| Subprocess egress containment | Proof that each scanner's secondary connections remain in engagement scope | Input filtering and scanner flags were reviewed and found insufficient; requires resolver/egress experiments per adapter |
| Gitleaks candidate status | Second independent source review plus pinned amd64/arm64 package, binary, structured-output and read-only-mount runtime proof | One research engine reviewed the official Kali package page and proposed it as a dedicated secret scanner; no second-engine confirmation or container smoke evidence was obtained |
| enum4linux-ng candidate status | Unapproved pending independent source/package review, overlap fixtures against `enum4linux_scan` and the existing SMB calls, and pinned structured-output/runtime proof on amd64/arm64 | One research engine reviewed the official Kali package page; no independent confirmation, overlap fixtures, or container smoke evidence was obtained |

## Settled reviewer rulings

- Do not reopen wireless, VPN, proxy, cloud-assessment, Intel Mac, Podman, Docker-socket, or telemetry scope.
- Do not propose embedding credentials or host-specific paths.
- Do not treat arbitrary exploit execution as part of the initial modernization implementation.
- Local-only means findings/reports do not upload and HTML makes zero requests; it does not forbid explicitly authorized target traffic, registry pulls, or controlled feed/template updates.

## Run state — orchestrator only

- Phase: research
- Round: 15
- Consecutive clean full-gate passes: 2
- Blocking-pass valve count: 12
- Native checks: round 5 resolved both research paths and all local line anchors; AST and repository grep independently found 42 unique MCP tools. The report/dossier expose 68 unique URLs: non-Kali links returned HTTP 200 except CISA KEV (HTTP 403 to curl, previously accessible through the web research tool); Kali's parallel fetches rate-limited, while sequential HTTP/1.1 retries returned HTTP 200 for the edited release/tool/document pages. `CLAUDE.md` confirms no test suite, linter, docs build, or CI is configured.
- Review history: round 1 logic critique and red team blocked on current Kali/tool/runtime/report gaps; round 2 blocked on missing `theharvester_scan`, incomplete evidence status and dossier drift; round 3 confirmed all 42 calls but blocked on profile/default omissions, incomplete claim auditability and unledgered subprocess containment.
- Round 4: red team clean; logic critique blocked on exact claim-to-source anchors and the lack of individual include/defer/exclude assessments for selected tools newly added in Kali 2025.4–2026.2. Doctrine loop-health valve paused the run at blocking count 4 pending user direction.
- Round 5 gap fill: tightened exact primary URLs and local source anchors; individually classified all ten selected Kali additions. Full native/logic/red-team gate pending.
- Round 5 full gate blocked: logic critique found premature linux-full-only exploit placement; red team found ambiguity between the 42-call compatibility floor and additions plus missing propose/approve/apply, local-CI, report-redaction and immutable-binary invariants. Verified against the anchor and corrected for round 6. Blocking-pass valve count is now 5.
- Round 6 full gate clean: native checks passed; logic critique and red team reported no blocking findings. Consecutive clean count is 1; report and claim table unchanged after the pass.
- Round 7 full gate blocked: red team clean; logic critique found the report-generation trigger absent from the reader-facing report/claim table. Added the exact request-or-approved-detailed-workflow rule; blocking count is now 6 and clean count reset to 0.
- Round 8 full gate blocked: red team clean; logic critique found the reader-facing Method appendix lacked loops, red-team count, native/unrun checks, deferred list and concrete dossier path. Added the complete audit trail; blocking count is now 7.
- Round 9 full gate blocked: red team clean; logic critique found unverified Gitleaks and enum4linux-ng claims were not individually represented in the gap ledger. Blocking count reached the doctrine valve at 8; paused for user direction before amendment.
- Round 10 gap fill: after user authorization to continue, added explicit Gitleaks and enum4linux-ng ledger entries with missing evidence and prior attempts; clarified content-level citation verification. Full gate pending.
- Round 10 full gate blocked: logic critique clean; red team found the Gitleaks matrix understated its ledgered approval prerequisites. Aligned the matrix, caveat and reader-facing gaps; blocking count is now 9.
- Round 11 full gate blocked: both reviews found stale short-form Gitleaks/enum4linux-ng claim-table dispositions, and red team found missing pinned-binary wording in the report matrix. Normalized every operative disposition to the full proof gate; blocking count is now 10.
- Round 12 full gate blocked: logic critique clean; red team found enum4linux-ng gap wording weakened structured-output and overlap-fixture requirements. Replaced every operative occurrence with one canonical full gate; blocking count is now 11.
- Round 13 full gate blocked: logic critique clean; red team found the Method deferred-list shorthand still reduced Gitleaks/enum4linux-ng proof gates and incorrectly called them non-blocking. Blocking count reached the doctrine valve at 12; paused for user direction before amendment.
- Round 14 gap fill: after user authorization to continue, removed Gitleaks/enum4linux-ng from the deferred non-blocking list and stated both full prerequisite sets as approval-blocking implementation gates. Full gate pending.
- Round 14 full gate clean: native checks, logic critique and red team produced no blocking or new non-blocking findings. Consecutive clean count is 1; report and claim table remain unchanged.
- Round 15 full gate clean: native checks, logic critique and red team again produced no blocking or non-blocking findings on the unchanged report. Consecutive clean count is 2; research exit gate achieved.
- Deferred non-blocking items: report encryption/access control decision; finer distinction for third-party egress authorization; exact CSP styling mechanism; Metasploit inspection category refinement.
