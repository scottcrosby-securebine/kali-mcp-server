# Kali MCP modernization specification

## Problem Statement

The MCP was built around Apple Silicon and a mutable Kali rolling image. Linux is not a supported host profile, the image is not reproducibly released, scanner results are difficult to test and report, and the documentation reflects the original Mac-only workflow.

## Solution

Upgrade the existing Docker-based MCP without redesigning it. Preserve all 42 existing tool names and parameters, add Linux support, pin tested releases, add a small set of useful container and artifact scanners, produce optional local HTML reports, and add practical automated tests.

Linux defaults to `linux-full`. Apple Silicon macOS uses `mac-hardened` because Docker Desktop cannot provide the same network behavior as native Linux. An optional `linux-hardened` profile provides the reduced-capability configuration on Linux.

## User Stories

1. As a Linux user, I want the MCP to run on amd64 and arm64, so that it is not limited to Mac laptops.
2. As an Apple Silicon user, I want reduced-capability behavior, so that supported tools work through Docker Desktop.
3. As an existing client, I want all 42 current calls and parameters preserved, so that upgrading does not break my configuration.
4. As an operator, I want clear errors for tools unavailable on my profile, so that platform limitations are understandable.
5. As a developer, I want to scan a mounted project, image archive, or registry image without mounting the Docker socket.
6. As an analyst, I want requested or detailed scans to produce a readable local HTML report.
7. As a maintainer, I want automated tests and multi-architecture smoke checks, so that releases do not regress silently.
8. As a new user, I want current installation and usage documentation for Linux and macOS.

## Implementation Decisions

### Container and host profiles

- Continue using Docker only. Do not add Podman support.
- Develop from `kalilinux/kali-rolling`; build version-verified releases from an exact base-image digest and package-version lock. The immutable published image digest is the release identity; byte-for-byte future source rebuilds are not promised against moving rolling repositories.
- Publish and test `linux/amd64` and `linux/arm64` images.
- Add a host launcher that selects:
  - `linux-full` by default on Linux, using host networking and only the minimal capabilities proven necessary by tests;
  - `mac-hardened` on Apple Silicon, using bridge networking and no raw/link-layer operations;
  - `linux-hardened` when explicitly requested, matching the reduced-capability boundary on Linux.
- Run non-root with `no-new-privileges`; never use `--privileged`.
- Do not support Intel Mac.

### Existing tool compatibility

- Preserve the names, parameter names, order, and defaults of all existing 42 MCP calls.
- Preserve their string return contract. Normalization is internal and report-only; exact human-readable message text may improve.
- Keep ordinary TCP/connect-compatible tools available on every profile when Docker networking permits them.
- Return a consistent, readable `unavailable` or `capability_missing` error when a profile cannot run an operation.
- Existing exploitation and credential-attack calls remain callable only when directly requested. Add no new exploit calls or automatic exploit workflows, and never chain exploitation from discovery.
- Keep composite workflows from automatically invoking intrusive tools, except for the explicitly requested `web_audit` bounded vulnerability workflow defined below.

### New capabilities

- Add `trivy_scan(target_ref: str = "", source_type: str = "filesystem") -> str` for read-only filesystems, SBOMs, explicit image archives, and explicit public-registry images.
- Add `syft_sbom(target_ref: str = "", source_type: str = "dir", format: str = "cyclonedx-json") -> str` for explicit filesystems, directories, archives, and public-registry images.
- Add `oletools_scan(artifact_ref: str = "", analyzer: str = "olevba") -> str` for bounded read-only Office/OLE analysis.
- Resolve filesystem references only beneath launcher-selected mounts; reject absolute host paths and traversal. Registry source values are validated image references, not filesystem paths.
- Use fixed container roots: `/workspace` for project directories/files, `/artifacts` for archives and Office files, `/results` for redacted normalized scan data, `/reports` for HTML, and `/run/secrets` for runtime secrets. Host paths remain caller-selected.
- Accepted values are:
  - Trivy `source_type`: `filesystem`, `sbom`, `archive`, or `registry`, mapped respectively to filesystem, SBOM, explicit `--input`, or forced remote-image mode.
  - Syft `source_type`: `dir`, `file`, `docker-archive`, `oci-archive`, `oci-dir`, or `registry`, mapped to the same explicit Syft source scheme.
  - Syft `format`: `cyclonedx-json`, `spdx-json`, or `syft-json`.
  - oletools `analyzer`: `olevba` or `msodde`.
- Empty references and unsupported option values return readable validation-error strings without running a subprocess.
- Each successful scanner call stores redacted normalized JSON at `/results/<result-id>.json` without overwriting an existing result. Its human-readable string response includes the opaque `result-id`; launcher shutdown removes results unless the caller mounted a result directory.
- In this release, that result-store contract and `generate_report` apply only to `trivy_scan`, `syft_sbom`, and `oletools_scan`. `full_recon` and `web_audit` generate their HTML directly; arbitrary reports from other legacy calls are deferred.
- Use uro internally to deduplicate URL lists before an explicitly requested crawl; do not add it as a public scanner call.
- Do not mount the Docker socket or auto-discover Docker, Podman, or containerd runtimes.
- Defer WPProbe, Gitleaks, enum4linux-ng, authenticated scanning, high-rate scanners, and new exploit tooling until separate follow-up work proves their value and compatibility.
- Exclude nested autonomous MCP servers such as HexStrike AI and MetasploitMCP.

### Inputs, credentials, and safety

- Accept project and artifact locations through launcher-selected read-only mounts. Do not hard-code host paths.
- Initial registry scanning supports public registries only. Private authentication is follow-up work and may use runtime-mounted secrets only—never MCP arguments, images, logs, or reports.
- Disable scanner telemetry, result upload, public OAST callbacks, and implicit binary self-updates.
- Keep scanner binaries immutable inside the released image. Record database and template versions when they update.
- Keep the existing Nuclei call as the explicitly requested website-CVE scanner. Refresh templates only through a separate controlled update command that pins and records the template version/digest; normal scans never update templates implicitly.
- Preserve its signature but constrain `templates` to promoted IDs/paths below the managed template root. Fixed adapter configuration disables Interactsh/OAST, cloud upload, update checks, code, JavaScript, headless, file access, fuzz/DAST, and workflow templates.
- Allow only Nuclei severity values `info`, `low`, `medium`, `high`, `critical`, or a comma-separated subset of them; reject other values before execution.
- An empty `nuclei_scan.templates` value and `web_audit` select the pinned promoted HTTP CVE/vulnerability subset only—not every installed template. Both use a 10-request/second rate, concurrency 5, ten-minute timeout, and the existing 200-line public-output bound. That bound applies to the returned human-readable summary; complete findings within the execution limits remain available to `web_audit` for its report. Tests pin the subset manifest and disabled features.
- Define `web_audit` as an explicitly requested, bounded vulnerability workflow. Without changing its signature, it invokes the promoted Nuclei subset and includes those results in its in-memory normalized data and HTML report; no other composite gains permission to invoke active or intrusive tools automatically.
- The MCP client/harness is responsible for obtaining the user's explicit natural-language request before calling aggressive, credential, exploit-related, or other explicit-request-only tools. Existing composites may retain their bounded safe-active checks. No composite other than the declared bounded `web_audit` may add a new active check, no composite may automatically add an explicit-request-only operation, and no new exploit calls are introduced.

### Reports

- Report generation in this release covers the three new scanners through `generate_report` and the existing `full_recon` and `web_audit` detailed workflows. Website CVE reports use `web_audit`; other legacy-call reports are deferred.
- Every successful or partially successful `full_recon` and `web_audit` invocation writes exactly one HTML report and keeps returning a string containing its human-readable summary plus `report=/reports/<report-id>.html`. A total failure returns the readable failure string and writes no report. The launcher maps `/reports` to the caller-selected host output directory.
- Add `generate_report(result_ref: str = "", format: str = "html") -> str`. `result_ref` is validated as an exact opaque result ID, never a path; the call accepts only `html` and returns `/reports/<report-id>.html` as a string.
- Build a self-contained local HTML report from normalized scanner data.
- Include an executive summary, scope, limitations, findings, evidence, severity, remediation, skipped/failed checks, and tool/database/template versions.
- Include bounded local charts for severity, tool coverage, and scan status when the data supports them, with equivalent accessible tables.
- Escape scanner-controlled content, embed no raw scanner HTML, keep assets local, redact secrets before writing, and verify that opening the report makes no network requests.
- Do not add a report server, remote storage, history/comparison, or encryption in this release.

### Documentation and releases

- Rewrite current installation, launcher, profile, tool, report, development, and troubleshooting documentation.
- Document the catalog as 42 preserved calls plus four additions, rather than replacing the legacy count with an ambiguous total.
- Archive obsolete Mac-only instructions instead of presenting them as current guidance.
- Document authenticated scanning, report comparison/history, and explicitly gated exploit execution as future work.
- Publish an SBOM and build provenance where supported by the release infrastructure; record an explicit limitation otherwise.

## Testing Decisions

- Use one primary test seam: MCP request → tool wrapper → command runner → returned result or report.
- Unit-test host/profile selection, command construction, unavailable-profile behavior, credential redaction, report triggering, and report rendering.
- Add contract tests that pin all 42 existing names and parameter defaults.
- Pin their string return type and the four new call signatures in the same contract tests.
- Add scanner adapter fixtures for successful, failed, malformed, truncated, and secret-bearing output.
- Add command-construction tests for Nuclei template-root validation and every required disable setting.
- Verify `web_audit` includes bounded Nuclei observations and renders them through the same escaping and redaction path as other report data.
- Test the pinned web-template manifest, rate/concurrency/timeout ceilings, one-report-per-workflow rule, partial-result reports, total-failure behavior, and summary-plus-path string return.
- Build and smoke-test both architectures, verifying installed binaries, versions, non-root execution, and MCP tool discovery.
- Run controlled integration tests against local fixture containers, mounted fixture projects, OCI/image archives, and a local test registry.
- Test Linux networking and required capabilities by operation; unproven raw modes remain unavailable.
- Run Apple Silicon qualification for representative supported tools before publishing the macOS instructions.
- Verify installed packages against the release lock and record the published image digest; do not claim future rolling-repository rebuild identity.
- Never use production or public Internet targets in release-blocking CI.

## Out of Scope

- A new approval API, generalized authorization state machine, or comprehensive engagement-policy broker.
- Intel Mac, Podman, wireless assessment, cloud-provider assessment, VPN/proxy management, or arbitrary host control.
- Docker-socket access, remote report hosting, telemetry, public OAST, or automatic scanner-binary updates.
- Authenticated web scanning, report history/comparison, and new exploit execution in the initial release.
- Private-registry authentication; public registries, archives, and mounted filesystems remain supported.
- Automatic exploitation or automatic escalation from safe to aggressive scanning.

## Further Notes

- Kali 2026.2 is the latest named snapshot as of the research date; development continues to track rolling while releases remain pinned and tested.
- The supporting evidence and detailed future security recommendations remain in `docs/research/2026-08-23-kali-mcp-modernization.md`.
