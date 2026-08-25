# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file MCP (Model Context Protocol) server preserving 42 Kali Linux calls and adding four bounded scanning/reporting calls. An MCP client calls the tools over stdio; the server invokes underlying Kali binaries and returns strings. MCP behavior lives in `kali_pentest_server.py`. Host-side Docker profile selection lives in `kali_mcp_launcher.py` and its `scripts/kali-mcp` entry point.

## Commands

```bash
# Build the image from pinned base and package inputs
docker build -t kali-mcp-server:latest .

# Inspect the hardened launcher command, then run it through an MCP client
scripts/kali-mcp --image kali-mcp-server:latest --dry-run

# Host startup is only a development convenience
python3 kali_pentest_server.py          # host: needs `pip install -r requirements.txt` + the Kali tools on PATH

# Run the native contract, adapter, report, launcher, and documentation tests
python3 -m unittest discover -s tests -v

# Verify a built image under the required NNP boundary
docker run --rm --security-opt=no-new-privileges \
  --entrypoint verify-kali-mcp-image kali-mcp-server:latest
```

Container CI builds `linux/amd64` and `linux/arm64`, runs the image verifier, and exercises the hermetic MCP/container integration seam. QEMU arm64 CI is not physical Apple Silicon qualification; do not publish a claim that Docker Desktop qualification is complete until real Darwin/arm64 evidence exists. `python3 kali_pentest_server.py` on the host needs the Python dependencies plus the Kali binaries on `PATH`; the container is the reliable environment.

## Architecture

Most legacy tools follow the same shape:

```
@mcp.tool()
async def some_scan(target: str = "", ...) -> str:
    target = validate_target(target)      # trim, reject empty / >500 chars
    if not target: return "❌ Error: ..."
    cmd = ["binary", "-flag", target]     # arg list, never a shell string
    return run_command(cmd, timeout=TIMEOUT_*)
```

Shared helpers in `kali_pentest_server.py` carry the cross-tool logic:

- `execute_command(cmd_list, timeout, ...)` — the only place `subprocess.run` is called. It always uses an **argument list** (no `shell=True`) and returns the structured process result. Both public-output and structured adapters use this seam.
- `run_command(cmd_list, timeout)` — the legacy text adapter. It calls `execute_command`, merges stdout+stderr, truncates to `MAX_OUTPUT_LINES` (200), and wraps the result in a status string (✅/⚠️/❌/⏱️).
- Structured scanner adapters may call `execute_command` through a scanner-specific helper when they must parse complete JSON/JSONL before applying the public 200-line bound. Timeout, start, failure, parsing, and redaction behavior stays centralized in that helper rather than the public tool wrapper.
- `validate_target(s)` — length/empty guard. Called by nearly every tool.
- `sanitize_input(s)` — `shlex.quote` wrapper. Present but rarely needed: because commands are passed as arg lists, shell metacharacters are already inert. Don't add `shell=True` and then reason about quoting — keep the list form.
- `capability_missing(operation, capability)` — stable readable response for an operation the active Docker profile cannot support. Return this before calling `run_command`.

Combined-operation tools (`quick_recon`, `full_recon`, `web_audit`, `network_sweep`) don't spawn subprocesses directly — they `await` the other tool functions and concatenate the formatted output. Timeouts are tiered constants (`TIMEOUT_SHORT`=60s … `TIMEOUT_EXTRA_LONG`=1800s); pick the tier by expected scan length.

Server entrypoint runs `mcp.run(transport='stdio')`. The tool's single-line docstring **is** the description the AI client sees, so keep it accurate and one line.

## Docker MCP security model (why the code looks the way it does)

The image runs as non-root user `pentest`. The launcher supplies `--security-opt=no-new-privileges`, `--cap-drop=ALL`, a read-only root filesystem, hardened tmpfs, fixed mount roles, and a host-compatible network profile. This drives real code decisions; do not bypass the launcher in operator guidance:

- All nmap tools use `-sT` (TCP connect) and `-Pn` (skip host-discovery ping). SYN scans (`-sS`), ICMP discovery, and ARP scans won't work. The Dockerfile deliberately `setcap -r`s nmap.
- Raw-socket tools (masscan, arp-scan, netdiscover) are intentionally absent from the image.
- `hashcat` runs CPU-only (`--force`).

## Adding or changing a tool

Match the existing pattern exactly: `@mcp.tool()` async fn, string defaults, one-line docstring, validate → build argument list → text or structured adapter, return `str`. Use `run_command` for legacy text output; use a shared structured helper only when complete machine-readable output must be parsed before bounding the public response. New tools must not need raw sockets or root, and their binary must be pinned in the container build. Update `tests/fixtures/legacy_tool_contract.json` deliberately, preserve the 42-versus-additions wording, update current docs, and run the native plus container gates.

## Agent skills

### Issue tracker

Issues and PRDs are tracked in GitHub Issues. External pull requests are not a triage surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Use `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository using root `CONTEXT.md` and `docs/adr/`. See `docs/agents/domain.md`.
