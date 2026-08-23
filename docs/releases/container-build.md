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

The current local-load workflow does not publish an image, SBOM, or signed
provenance attestation. Publishing and those release artifacts remain a release
qualification step; this limitation must remain visible until that step exists.

For a local multi-architecture OCI artifact, run `docker buildx bake` with a
BuildKit builder that supports both target platforms. The configured output is
`dist/kali-mcp.oci.tar`; its digest is local build evidence, not a published
registry manifest digest.
