# Operator and deployment guide

This guide is authoritative for the current Docker runtime. The server exposes 42 preserved MCP calls plus eight additions and returns strings over stdio.

## Supported hosts and build

The launcher supports Linux amd64/arm64 and Apple Silicon. Intel macOS and Windows are rejected. Build locally:

```bash
docker build -t kali-mcp-server:latest .
docker run --rm --security-opt=no-new-privileges \
  --entrypoint verify-kali-mcp-image kali-mcp-server:latest
```

That direct `docker run` invocation verifies the built image only. It is not an MCP runtime command; use `scripts/kali-mcp` for the full runtime policy.

The base image, Kali packages, source packages, Python packages, and promoted Nuclei templates are pinned. A later rebuild against Kali rolling is not guaranteed to reproduce a release image; when an image is published, its manifest digest is the release identity. The current workflow does not publish an image.

CI verifies both Linux architectures; the arm64 leg runs through QEMU. Physical Apple Silicon Docker Desktop qualification separately passed for the local arm64 image recorded in [`release-evidence/apple-silicon-darwin-arm64.json`](release-evidence/apple-silicon-darwin-arm64.json). That structured evidence predates the later private writable-home launcher change and must be refreshed against the current launcher before final release. It also does not publish or qualify a registry manifest: the multi-architecture release image, immutable registry digest, SBOM, and provenance remain Issue [#12](https://github.com/scottcrosby-securebine/kali-mcp-server/issues/12) work.

## Launcher profiles

Run `scripts/kali-mcp --help` for the complete CLI.

| Profile | Allowed host | Network | Capabilities |
|---|---|---|---|
| `linux-full` | Linux amd64/arm64 | host | all dropped |
| `linux-hardened` | Linux amd64/arm64 | bridge | all dropped |
| `mac-hardened` | Darwin arm64 | bridge | all dropped |

All profiles also set `no-new-privileges`, use a read-only root filesystem, run as UID 1000, and never mount the Docker socket. `/tmp` is a hardened scratch tmpfs. `/home/pentest` is a private writable tmpfs owned by UID/GID 1000 with mode `0700`, allowing tools to initialize per-user configuration without weakening the read-only image. No current operation has proved a need for an added capability.

The launcher recognizes Apple Silicon even when its Python process is translated by Rosetta. Physical Intel Macs remain unsupported.

Nmap uses unprivileged TCP connect scans and skips raw host discovery. SYN scans, ICMP/ARP discovery, broadcast NSE behavior, masscan, arp-scan, and netdiscover are unavailable. `hashcat_crack` is CPU-only and uses `--force`.

## Mount contract

| Launcher option | Container root | Access | Contents |
|---|---|---|---|
| `--workspace` | `/workspace` | read-only | projects, files, SBOMs, OCI directories, password inputs |
| `--artifacts` | `/artifacts` | read-only | Docker/OCI image archives and Office artifacts |
| `--results` | `/results` | writable | normalized scanner JSON |
| `--reports` | `/reports` | writable | self-contained HTML reports |
| `--secrets` | `/run/secrets` | read-only | reserved explicit secret files |

If `results` or `reports` is omitted, the launcher creates non-persistent tmpfs for that root. Persist output by providing separate existing host directories.

Persisted output directories must be writable by container UID 1000. On Linux, set ownership or a narrow ACL for that UID; do not default to world-writable directories. For operator-owned directories where changing ownership is acceptable:

```bash
sudo chown 1000:1000 results reports
```

Mount roles must not alias, nest, or overlap. Resolved paths containing commas, missing/non-directory paths, Unix sockets, and symlinks to sockets are rejected. Scanner paths must remain beneath the selected root after symlink resolution. Absolute paths, `..` escapes, and sibling-prefix tricks fail before command execution.

The added scanners accept mount-relative references. Legacy direct-only password calls instead need container-visible file paths such as `/workspace/hashes.txt` or `/workspace/wordlist.txt`.

Example:

```bash
mkdir -p workspace artifacts results reports
scripts/kali-mcp --image kali-mcp-server:latest \
  --workspace "$PWD/workspace" \
  --artifacts "$PWD/artifacts" \
  --results "$PWD/results" \
  --reports "$PWD/reports"
```

## Scanner and report workflows

### Mounted project or file

- `trivy_scan(target_ref, source_type)` accepts `filesystem` and `sbom` beneath `/workspace`.
- `syft_sbom(target_ref, source_type, format)` accepts `dir`, `file`, and `oci-dir` beneath `/workspace`.

Use mount-relative references such as `project`, `package-lock.json`, or `oci-layout`; do not use host paths.

### Image archives

Place archives beneath `/artifacts`.

- Trivy: `source_type="archive"` for an image archive.
- Syft: `source_type="docker-archive"` or `source_type="oci-archive"`.

### Credential-free public registry

Both Trivy and Syft accept `source_type="registry"` with an explicit image reference. References must be credential-free and cannot contain a URL scheme or user information. Private-registry authentication is not supported.

Syntax-only example: call `syft_sbom` with `target_ref="registry.example/authorized/image:tag"`, `source_type="registry"`, and `format="cyclonedx-json"`. The reserved `.example` name will not resolve; replace it with a real credential-free public image reference that you are authorized to inspect.

### Office artifact

`oletools_scan` accepts one regular file of at most 25 MiB beneath `/artifacts`. Choose `analyzer="olevba"` or `analyzer="msodde"`. An invalid or oversized artifact is rejected before execution and creates no result. Macro source is not persisted; normalized findings are redacted before storage.

### Website CVE scan

`nuclei_scan` uses only reviewed templates promoted in `nuclei-templates/manifest.json`. An empty `templates` value selects the promoted root; explicit template IDs or relative paths must resolve beneath that root. Default severities are `critical,high`; accepted unique values are `info`, `low`, `medium`, `high`, and `critical`. The fixed ceilings are 10 requests per second, concurrency 5, and 600 seconds. OAST, cloud upload, update checks, code, JavaScript, headless, file, fuzz/DAST, and workflow template types are disabled. Ordinary scans never update templates.

`web_audit` includes bounded Nuclei observations in its returned summary while retaining the complete redacted finding set for its report.

For a direct authorized website-CVE check, call `nuclei_scan` with a profile-reachable, explicitly authorized HTTP(S) target and optional promoted template IDs and severities. Syntax example: `target="https://authorized-target.invalid"`, `templates="CVE-2021-41773"`, `severity="high,critical"`; the reserved `.invalid` name will not resolve and must be replaced. A service on host `127.0.0.1` is reachable from the container only with Linux `linux-full`; hardened bridge profiles require a target reachable from their Docker network.

### Result and report lifecycle

Successful Trivy, Syft, and oletools calls write one normalized JSON document to `/results` and return an opaque result ID plus a finding count. Scanner failure, malformed/truncated output, or invalid structure creates no result.

Pass the exact opaque ID to `generate_report(result_ref, format="html")`. It accepts supported normalized results only and creates a non-overwriting HTML file beneath `/reports`. Reports are self-contained, scriptless, escaped and redacted; browser acceptance tests verify that rendering makes zero network requests.

`full_recon` and `web_audit` write exactly one workflow report after successful or partial execution and return their text summary plus `report=/reports/<id>.html`. The `web_audit` summary is bounded to 200 lines; `full_recon` retains its legacy concatenated output. If every attempted check fails, they return a failure string and write no report.

Supported Syft formats are `cyclonedx-json`, `spdx-json`, and `syft-json`. HTML is the only report format.

## Direct-only calls

The following preserved calls require an explicit client or harness request and are excluded from every automatic combined workflow:

- `nmap_script_scan`
- `sqlmap_scan`
- `crackmapexec_scan`
- `hydra_attack`
- `john_crack`
- `hashcat_crack`
- `metasploit_search`
- `metasploit_info`

This rule prevents automatic escalation from reconnaissance into credential testing, exploit research, or other higher-risk operations. It is not an authorization system; operators remain responsible for scope and approval.

## Errors and troubleshooting

| Response | Meaning | Action |
|---|---|---|
| `unsupported_platform` | Host OS/architecture is unsupported | Use Linux amd64/arm64 or Apple Silicon |
| `unavailable` | Profile is not allowed on this host | Use the host default or an allowed profile |
| `invalid_mount` | Mount is missing, malformed, overlapping, or uninspectable | Supply separate existing directories |
| `prohibited_socket` | A mount would expose a Unix socket | Remove the socket or choose another tree |
| output write error | `/results` or `/reports` is not writable by UID 1000 | Correct ownership or grant a narrow ACL |
| `capability_missing` | Operation requires intentionally unavailable raw/link-layer behavior | Use a supported TCP-connect operation |
| scanner `Error` | Invalid source, confined path, process failure, timeout, or malformed output | Correct input; no result is created on failure |

Useful checks:

```bash
scripts/kali-mcp --image kali-mcp-server:latest --dry-run
python3 -m unittest discover -s tests -v
docker run --rm --security-opt=no-new-privileges \
  --entrypoint verify-kali-mcp-image kali-mcp-server:latest
```

Host-side Python is a contributor convenience, not an equivalent deployment: it requires the MCP dependency and every invoked Kali binary on `PATH`, and it lacks the container runtime controls.

## Known image defects

- `amass_enum` currently reaches a Kali wrapper that attempts a privileged libpostal bootstrap. That conflicts with the supported non-root, no-new-privileges runtime and fails before Amass starts. Track the reproducible fix in [#15](https://github.com/scottcrosby-securebine/kali-mcp-server/issues/15).
- Multiple adapters reference a default or fallback wordlist path absent from the locked image. `ffuf_scan`, `gobuster_scan`, and `wfuzz_scan` are confirmed default failures; Hydra and Hashcat reach the same missing path when their preferred wordlist is unavailable. Track the complete adapter audit and image regression fix in [#14](https://github.com/scottcrosby-securebine/kali-mcp-server/issues/14).

These calls remain in the 42-call compatibility contract, but affected execution paths are not qualified as successful real scans. Do not describe registration or string-return coverage as successful real scans.

## Future work and explicit exclusions

Future work includes authenticated scanning, private-registry authentication, report comparison/history, and explicitly gated new exploit execution.

This release does not provide a generalized approval broker, Docker-socket access, remote report hosting, telemetry, public OAST, automatic tool updates, Intel Mac support, Podman support, wireless/cloud assessment, or automatic exploitation/escalation.

## Client configuration

See [MCP client integration](SETUP_DOCKER_MCP.md). Client-specific schemas and locations must be verified against that client's current official documentation.
