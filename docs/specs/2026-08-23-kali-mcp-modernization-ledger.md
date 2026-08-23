# Kali MCP modernization specification ledger

## Anchor

Audience: maintainers and implementation agents. After reading, they must be able to modernize the MCP without reopening settled product or security decisions, and verify each increment through the approved public testing seam.

The user requires current Kali, Docker-only Linux and Apple Silicon support, Linux defaulting to linux-full, compatibility for all existing 42 calls, portable configuration without embedded credentials or host paths, container and project assessment, local human-readable HTML reports, practical tests, and updated documentation. The user explicitly rejected the expanded approval API and generalized policy architecture as unnecessary complexity for this upgrade.

## Claim ledger

| Claim | Source |
|---|---|
| Latest named snapshot is Kali 2026.2; development uses rolling and releases pin a digest/packages | Research report, Current Kali baseline |
| Hosts are Linux amd64/arm64 and Apple Silicon arm64; defaults are linux-full and mac-hardened | Research report, Runtime profiles |
| Existing 42 signatures are the compatibility floor | Research report, Existing 42-call audit |
| Approved public additions are `trivy_scan`, `syft_sbom`, `oletools_scan`, and `generate_report`; uro remains internal | Simplified specification decision |
| Trivy and Syft use explicit daemonless inputs; Docker socket is prohibited | Research report, Findings and Operational invariants |
| Reports derive from redacted canonical JSON and make zero requests when opened | Research report, Human-readable report model |
| Scanner binaries are immutable; controlled feeds/templates are separately versioned | Research report, Runtime security and Operational invariants |
| Release CI uses controlled local fixtures, never production Internet targets | Research report, Operational invariants |
| Approved primary testing seam is MCP request → tool wrapper → command runner → returned string or optional report | User simplification direction, 2026-08-23 |
| Authenticated scanning, comparison/history, and new exploit tooling are later milestones; preserved exploit-related calls never auto-chain | Research report plus simplified specification decision |

## Run state — orchestrator only

- Phase: simplified specification
- Round: final
- Consecutive clean passes: 2
- Blocking-pass valve count: 8
- Prior draft retired by user direction: remove speculative approval APIs, generalized policy brokers, and schema-platform work. Clean-pass counters reset because the anchor changed materially.
- Initial lens review found blocking normative-contract and traceability gaps; the draft was expanded before the first full gate.
- Simplified round 1 review blocked only on stale ledger claims, string-return compatibility, release lock semantics, new call signatures, dangerous-call wording, and report triggers. All were corrected without expanding architecture.
- Simplified round 2 review found narrow API gaps: report invocation, client/harness responsibility, scanner option literals/mappings, mount roots, and validation behavior. Corrected with four small public calls and finite options.
- Simplified round 3 review found registry/path conflation, an undefined result store, missing charts, implicit Nuclei refresh behavior, a call-count typo, and an overstrong rebuild claim. Corrected with fixed roots/result IDs, controlled template updates, local charts, four-call contracts, and immutable version-verified release wording.
- Simplified round 4 review split: one reviewer clean; red team blocked on private-registry secret mechanics and Nuclei command hardening. Private authentication moved to follow-up work and Nuclei received fixed template/feature constraints and tests.
- User directed continuation after the round-4 checkpoint; next checkpoint re-arms at blocking count 8.
- Simplified round 5 split: red team clean; focused review found report/result applicability ambiguous. Limited stored result IDs and `generate_report` to the three new scanners, with direct reports for `full_recon`/`web_audit`; blocking count is now 5.
- Simplified round 6 split: focused review clean; red team found explicit website-CVE reporting was outside the narrowed report surface. Made `web_audit` the bounded Nuclei-backed website report path; blocking count is now 6.
- Simplified round 7 split: focused review clean; red team required deterministic Nuclei defaults/ceilings and detailed-workflow report returns. Added a pinned subset, fixed bounds, and summary-plus-report-path behavior; blocking count is now 7.
- Simplified round 8 split: focused review clean; red team found `web_audit` must be explicitly documented as the one bounded composite permitted to invoke Nuclei. Blocking count reached the checkpoint at 8; paused for user direction.
- After the checkpoint, the spec defined `web_audit` as that explicitly requested bounded exception, allowlisted Nuclei severities, clarified summary versus report evidence, and made the 42-plus-four documentation count explicit. Clean-pass verification resumed on this wording.
- The first resumed gate found one residual absolute composite statement; it was narrowed so only bounded `web_audit` may add an active operation, while aggressive, credential, and exploit operations remain prohibited from every automatic composite chain.
- The next gate clarified that preserved composites retain their existing bounded safe-active checks; the `web_audit` exception concerns adding a new active check and does not remove legacy composite behavior.
- Final unchanged wording passed two independent clean reviews. The specification exit gate is complete.
