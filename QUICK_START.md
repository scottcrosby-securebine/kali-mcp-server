# Quick start

This path uses the repository launcher so the container receives the required security, network, and mount policy.

## 1. Build

Install Docker, clone the repository, then build the pinned image:

```bash
git clone https://github.com/scottcrosby-securebine/kali-mcp-server.git
cd kali-mcp-server
docker build -t kali-mcp-server:latest .
```

The supported launcher hosts are Linux amd64/arm64 and Apple Silicon. Intel macOS and Windows are not supported by the launcher. Physical Apple Silicon qualification is pending; QEMU Linux/arm64 CI is green but is not a macOS result.

## 2. Prepare optional mounts

```bash
mkdir -p workspace artifacts results reports
```

- Put project files, SBOMs, and OCI directories in `workspace`.
- Put Docker/OCI archives and Office files in `artifacts`.
- `results` and `reports` persist generated output.

On Linux, the persisted output directories must be writable by container UID 1000. Prefer assigning those two directories to UID 1000 or granting that UID a narrow ACL; do not make them world-writable. For example, when you own the directories and accept changing their ownership:

```bash
sudo chown 1000:1000 results reports
```

The optional `--secrets` mount is reserved for explicit read-only secret files. Authenticated workflows do not consume it yet.

Input mounts are read-only. Output mounts are writable. Omit `results` or `reports` to use non-persistent container tmpfs instead.

## 3. Inspect and run

```bash
scripts/kali-mcp \
  --image kali-mcp-server:latest \
  --workspace "$PWD/workspace" \
  --artifacts "$PWD/artifacts" \
  --results "$PWD/results" \
  --reports "$PWD/reports" \
  --dry-run
```

Remove `--dry-run` when the command is connected to an MCP client. Linux defaults to `linux-full`; Apple Silicon defaults to `mac-hardened`. Select Linux bridge isolation explicitly with `--profile linux-hardened`.

See [MCP client integration](SETUP_DOCKER_MCP.md) for configuring a client to invoke this command.

## 4. First local workflows

Use only authorized targets and inputs.

- Project SBOM: call `syft_sbom` with `target_ref="."`, `source_type="dir"`.
- Project vulnerabilities: call `trivy_scan` with `target_ref="."`, `source_type="filesystem"`.
- Archive SBOM: place `image.tar` in `artifacts`, then call `syft_sbom` with `target_ref="image.tar"`, `source_type="docker-archive"`.
- Office analysis: place a document in `artifacts`, then call `oletools_scan` with its relative path.
- Report: copy the opaque ID from a successful scanner response into `generate_report`.

Generated JSON appears under `results`; generated HTML appears under `reports` when those mounts are present.

Trivy may need its vulnerability database. Under a deliberately isolated/no-egress network it can return a controlled database-unavailable failure and create no result; that is distinct from a mount error.

## Troubleshooting

```bash
scripts/kali-mcp --help
scripts/kali-mcp --image kali-mcp-server:latest --dry-run
python3 -m unittest discover -s tests -v
```

- `unsupported_platform`: use Linux amd64/arm64 or Apple Silicon.
- `unavailable`: the requested profile does not match the host.
- `invalid_mount`: ensure the directory exists, does not overlap another mount role, and contains no Unix socket.
- Output write errors: ensure `results` and `reports` are writable by container UID 1000.
- `prohibited_socket`: remove sockets and socket aliases from the mounted tree.
- Scanner path errors: use a relative path beneath the appropriate mount, not `/tmp`, an absolute host path, or `..`.
- `capability_missing`: the requested raw/link-layer operation is intentionally unavailable.

For the complete source matrix and report behavior, use the [deployment guide](DEPLOYMENT_GUIDE.md).
