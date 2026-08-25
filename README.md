# Kali MCP Server

An MCP stdio server that preserves 42 Kali security calls and adds four bounded scanning and local-reporting calls. The supported runtime is the repository's Docker image launched through `scripts/kali-mcp` on Linux amd64/arm64 or Apple Silicon.

Use this software only on systems and data you own or are explicitly authorized to assess.

## Start here

- [Quick start](QUICK_START.md)
- [Operator and deployment guide](DEPLOYMENT_GUIDE.md)
- [MCP client integration](SETUP_DOCKER_MCP.md)
- [Reproducible container build](docs/releases/container-build.md)

Physical Apple Silicon Docker Desktop qualification passed for the recorded local arm64 image; see the [container build record](docs/releases/container-build.md). The structured evidence predates the latest launcher home-mount change, so the current launcher still needs refreshed Darwin evidence before final release. Linux/arm64 also has a separate QEMU-backed CI gate. The final multi-architecture image, registry digest, SBOM, and provenance are not published yet.

## Runtime model

The launcher selects a host-compatible profile and constructs Docker arguments without a shell. Every profile runs as UID 1000 with a read-only root filesystem, `no-new-privileges`, all capabilities dropped, and no Docker socket.

| Profile | Host | Network | Important limitation |
|---|---|---|---|
| `linux-full` | Linux amd64/arm64 | host | Default on Linux; still has no raw/link-layer capability |
| `linux-hardened` | Linux amd64/arm64 | bridge | More network isolation; no raw/link-layer capability |
| `mac-hardened` | Apple Silicon | bridge | Only supported macOS profile; recorded Docker Desktop qualification needs a current-launcher evidence refresh before release |

Nmap wrappers force unprivileged TCP connect scanning (`--unprivileged -sT -Pn`). Raw-socket tools such as masscan, arp-scan, and netdiscover are absent. Broadcast NSE requests fail closed with `capability_missing`.

## Catalog

The 42 preserved calls are:

`nmap_scan`, `nmap_service_scan`, `nmap_vuln_scan`, `nmap_comprehensive_scan`, `nmap_port_scan`, `nmap_script_scan`, `dns_enum`, `dns_recon`, `subfinder_scan`, `amass_enum`, `fierce_scan`, `nikto_scan`, `wpscan_scan`, `dirb_scan`, `ffuf_scan`, `gobuster_scan`, `wfuzz_scan`, `sqlmap_scan`, `whatweb_scan`, `wafw00f_scan`, `nuclei_scan`, `web_headers`, `sslscan_scan`, `testssl_scan`, `sslyze_scan`, `enum4linux_scan`, `nbtscan_scan`, `crackmapexec_scan`, `responder_analyze`, `smb_enum`, `hydra_attack`, `john_crack`, `hashcat_crack`, `searchsploit_search`, `metasploit_search`, `metasploit_info`, `theharvester_scan`, `whois_lookup`, `quick_recon`, `full_recon`, `web_audit`, and `network_sweep`.

The four additions are:

| Call | Purpose |
|---|---|
| `trivy_scan` | Scan a mounted filesystem, SBOM, image archive, or credential-free public-registry image |
| `syft_sbom` | Generate CycloneDX, SPDX, or Syft JSON from a mounted source, archive, OCI layout, or public registry |
| `oletools_scan` | Analyze one bounded Office artifact with `olevba` or `msodde` |
| `generate_report` | Render one normalized scanner result as self-contained local HTML |

The public contract, including names, parameter order/defaults, and string returns, is pinned in `tests/fixtures/legacy_tool_contract.json`.

## Safety boundary

Commands are passed to subprocesses as argument lists; do not introduce `shell=True`. Inputs for the added scanners are confined to fixed mounts. Results and reports use opaque, non-overwriting names and redact common credentials.

The following existing calls are direct-only: `nmap_script_scan`, `sqlmap_scan`, `crackmapexec_scan`, `hydra_attack`, `john_crack`, `hashcat_crack`, `metasploit_search`, and `metasploit_info`. Combined workflows never auto-chain them. A client or test harness must request them explicitly.

Authenticated scanning, private-registry authentication, report history/comparison, and new exploit execution are future work.

Preserved calls have known image-level defects pending release fixes: `amass_enum` is blocked by the Kali Amass wrapper's attempted privileged libpostal bootstrap ([#15](https://github.com/scottcrosby-securebine/kali-mcp-server/issues/15)), and the default wordlist paths used by `ffuf_scan`, `gobuster_scan`, and `wfuzz_scan` do not match the locked image ([#14](https://github.com/scottcrosby-securebine/kali-mcp-server/issues/14)). Hydra and Hashcat also share the missing path as a fallback when their preferred wordlist is unavailable; #14 tracks the full adapter audit. These MCP contracts remain present, but affected paths are not qualified as successful default operations.

## Development

```bash
python3 -m unittest discover -s tests -v
docker build -t kali-mcp-server:latest .
docker run --rm --security-opt=no-new-privileges \
  --entrypoint verify-kali-mcp-image kali-mcp-server:latest
```

The direct `docker run` command is a build verifier only. Use `scripts/kali-mcp` for the MCP runtime so the full security and mount policy is applied.

Container CI builds and runs the verifier and hermetic integration gate for `linux/amd64` and `linux/arm64`. See [CLAUDE.md](CLAUDE.md) for contributor invariants.

## License

[MIT](LICENSE)
