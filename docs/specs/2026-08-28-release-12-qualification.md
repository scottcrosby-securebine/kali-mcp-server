# Release #12 qualification and publish — spec

Fixed point: `d907d78831dc5327a068f56e53fc26bf1b2526ad` (main, 2026-08-28).
Tracker: `docs/plans/2026-08-28-issue-execution-stack.md` row 24. Closes #12;
resolves blockers #62, #63, #64, #65, #66. Issue-ref resolution:
`docs/agents/issue-tracker.md`.

## Anchor — the four release-policy decisions (verbatim, Scott, 2026-08-28)

- **Registry (#62): "GHCR, private."** Push the image to
  `ghcr.io/scottcrosby-securebine/kali-mcp-server`, private visibility, with an
  immutable digest. Pulls need auth.
- **Signing (#63): "OIDC + attestation" — REVISED 2026-08-28 to "private, drop
  signed attestation."** GitHub artifact attestation for a **private** repo
  requires Enterprise Cloud, which conflicts with the private-registry decision
  on a non-EE plan, so the signed OIDC provenance step is dropped. The release
  grants only `packages: write` and publishes an SBOM attestation via
  `build-push-action` `sbom: true`. #12 AC5 is met by the immutable digest + the
  SBOM, not by signed provenance. If the account later moves to Enterprise
  Cloud, re-add `actions/attest-build-provenance` (+ `id-token: write`,
  `attestations: write`).
- **Evidence retention (#64 package-lock, #65 CapEff): "Commit to
  release-evidence/."** Per-release package and CapEff evidence lands durably in
  the git tree under `release-evidence/`, not only as an expiring CI artifact.
- **Apple Silicon (#66): "Explicit scope limitation."** Document Linux
  amd64/arm64 as qualified and macOS `mac-hardened` as best-effort with a manual
  `scripts/qualify-apple-silicon` run. No hardware gate blocks release. QEMU
  arm64 is not a Darwin substitute (CLAUDE.md).

## #12 acceptance criteria — where each lands

Note AC7 wording: the contract is **42 preserved + FIVE additions = 47** tools
(`tests/fixtures/legacy_tool_contract.json`). #12's "plus four additions", the
integration test's print strings, and the recorded evidence pre-date the 5th
addition (`list_results`) and are stale — corrected here per the combined-report
spec (`docs/specs/2026-08-26-combined-report.md`).

| AC | Verifiable here | On release CI (tag + push) |
|---|---|---|
| 1 all test suites | yes: unittest, redaction gate, mutation check | — |
| 2 published images vs package lock | local image vs lock | published digest verify |
| 3 Linux profile + recorded CapEff | CapEff evidence step (#65) | recorded in CI run |
| 4 Apple Silicon results + unsupported-op msgs | scope-limitation doc (#66) | — |
| 5 immutable digest + SBOM/provenance | pipeline wiring | executed on tag |
| 6 no socket/creds/hostpaths/telemetry/upload/implicit-update | grep + tests | — |
| 7 42 preserved + 5 additions (47) | contract fixture test | — |
| 8 docs match released image/launcher | docs review | — |

The publish/attest ACs (2 published-verify, 5 execute) complete only on a
release-tag CI run with a real GHCR token — not reproducible on this dev host.

## Build path (grounded in source, not assumption)

CI builds via `docker/build-push-action` (`build-and-smoke`), **not**
`docker-bake.hcl`. Bake's `type=oci` output is the local-dev path. The publish
job therefore extends the build-push-action path (`push: true`, `provenance`,
`sbom`), gated to release tags. Bake output is made overridable so a local push
is possible too (#62's literal anchor), but CI does not route through it.

## Phases

- **P1 — publish + SBOM + evidence pipeline.** `container.yml` (tag trigger,
  gated publish job to GHCR private, immutable digest, SBOM attestation via
  `sbom: true` (signed provenance dropped per the revised #63), scoped
  `packages: write` only, CapEff capture, per-release evidence commit),
  `docker-bake.hcl` (overridable output).
- **P2 — scope limitation + qualification closeout.** #66 docs (README,
  container-build record), the 4→5 additions print-string correction
  (integration test), local qualification run recorded, tracker row 24.

Designated review: `matts-code-review` (Standards + Spec, this file as spec
path). Red team: `codex:codex-rescue`. Delivery: commit on
`feat/release-12-qualification`; hold for "push it" before any push or PR
(standing user rule + kickoff).
