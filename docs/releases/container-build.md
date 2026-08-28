# Container build record

The release build uses the multi-architecture Kali rolling manifest
`sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1`.
The repository packages and source-built packages have separate version locks.
Builds fail when those exact versions are unavailable or do not match.
Kali does not publish `dirb`, `sslscan`, or `nbtscan` binaries for arm64. The
image therefore builds the exact Kali source-package versions for both
architectures after verifying their source checksums, preserving the same MCP
operations without substituting different tools.
The lock covers direct image requirements; the workflow's complete installed
package inventory records the resolved transitive closure. `requirements.txt`
is a developer compatibility manifest, while the image installs the locked
Kali Python packages.

The container workflow builds and smoke-tests `linux/amd64` and `linux/arm64`
separately. Each job records the resulting local image metadata and complete
installed-package inventory as workflow artifacts. A published image digest,
not a future rebuild against the moving Kali repository, is the durable release
identity.

The `linux/arm64` workflow runs through QEMU on a Linux runner. It proves the
arm64 image build, verifier, MCP discovery, and hermetic integration behavior;
it is distinct from Docker Desktop behavior on Apple hardware. Physical
Darwin/arm64 Docker Desktop qualification passed for the local arm64 image in
[`release-evidence/apple-silicon-darwin-arm64.json`](../../release-evidence/apple-silicon-darwin-arm64.json).
The evidence records its exact local image digest, daemon identity, Docker
Desktop platform, disabled Docker Offload state, and integration result.
It predates commit `ba00f3a`, which made `/home/pentest` privately writable and
added ownership, mode, and write checks to the integration gate, so it should be
refreshed when a maintainer next has Apple hardware. macOS qualification is a
best-effort tier and does not gate the release (see the README runtime model);
the Linux amd64/arm64 CI gate is the release gate.

Maintainers capture that evidence with the release qualification entry point:

```bash
scripts/qualify-apple-silicon \
  --image '<digest-qualified-image-reference>' \
  --image-digest 'sha256:<local-image-digest>' \
  --evidence release-evidence/apple-silicon-darwin-arm64.json
```

The script requires physical Darwin/arm64, the local Docker Desktop daemon,
Docker Offload stopped and unconfigured, and a digest-qualified image reference
matching `--image-digest`. This is a maintainer qualification command, not an
ordinary operator startup command.

The `build-and-smoke` CI job loads images locally and does not publish.
Publishing is a separate release-tag job (`publish` in `container.yml`) that
pushes the multi-architecture image to GHCR (private) with an immutable digest,
a signed OIDC provenance attestation, and an SBOM. The recorded Apple image
digest is evidence for a local qualification artifact, not a pullable registry
manifest; a pullable manifest exists only after a release tag is pushed
(Issue #12).

GHCR package visibility is a one-time settings invariant, not a per-run check.
A container package inherits its visibility from the owning repository on first
publication, so the first push from this private repository creates a **private**
package. The workflow does not assert visibility per run: there is no reliable
read of a private user-owned package's visibility from the workflow
`GITHUB_TOKEN`, and a check that fails closed on exactly the private packages it
should pass is worse than none. If the package already exists, confirm once in
the repository's package settings that its visibility is Private.

The supported launcher mounts `/home/pentest` as a private writable tmpfs owned
by UID/GID 1000 with mode `0700`. Release integration must retain the ownership,
mode, and write test because several preserved tools initialize configuration
or cache state beneath the runtime home.

For a local multi-architecture OCI artifact, run `docker buildx bake` with a
BuildKit builder that supports both target platforms. The configured output is
`dist/kali-mcp.oci.tar`; its digest is local build evidence, not a published
registry manifest digest.
