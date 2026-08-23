# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file MCP (Model Context Protocol) server exposing 42 Kali Linux security tools as MCP tools. An AI client (Warp, Claude Desktop) calls the tools; the server shells out to the underlying Kali binaries and returns formatted text. MCP tool behavior lives in `kali_pentest_server.py`. Host-side Docker profile selection lives in the small `kali_mcp_launcher.py` module and its `scripts/kali-mcp` entry point.

## Commands

```bash
# Build the image (15-30 min; downloads Kali packages + compiles Go tools)
docker build -t kali-mcp-server:latest .

# Run the server standalone (talks MCP over stdio; mainly for smoke-testing startup)
python3 kali_pentest_server.py          # host: needs `pip install -r requirements.txt` + the Kali tools on PATH
docker run --rm -i kali-mcp-server:latest   # container: has all tools

# Run the dependency-free launcher tests
python3 -m unittest discover -s tests -v

# Count the registered tools (no deps needed)
grep -c "@mcp.tool()" kali_pentest_server.py    # should match the "42 tools" claim
```

Container CI builds both supported architectures and runs the image verifier. Verify launcher changes with the unit suite; verify server/image changes by building and running the image verifier and exercising MCP initialization. `python3 kali_pentest_server.py` on the host needs `pip install -r requirements.txt` (the `mcp` package) plus the Kali binaries on PATH — the container is the reliable environment.

## Architecture

Every tool follows the same shape, so read one and you understand all 42:

```
@mcp.tool()
async def some_scan(target: str = "", ...) -> str:
    target = validate_target(target)      # trim, reject empty / >500 chars
    if not target: return "❌ Error: ..."
    cmd = ["binary", "-flag", target]     # arg list, never a shell string
    return run_command(cmd, timeout=TIMEOUT_*)
```

Three shared helpers in `kali_pentest_server.py` carry all the real logic:

- `run_command(cmd_list, timeout)` — the only place a subprocess runs. Uses `subprocess.run` with an **argument list** (no `shell=True`), merges stdout+stderr, truncates to `MAX_OUTPUT_LINES` (200), and wraps the result in a status string (✅/⚠️/❌/⏱️). All error handling (timeout, missing binary, exceptions) lives here, not in the tools.
- `validate_target(s)` — length/empty guard. Called by nearly every tool.
- `sanitize_input(s)` — `shlex.quote` wrapper. Present but rarely needed: because commands are passed as arg lists, shell metacharacters are already inert. Don't add `shell=True` and then reason about quoting — keep the list form.

Combined-operation tools (`quick_recon`, `full_recon`, `web_audit`, `network_sweep`) don't spawn subprocesses directly — they `await` the other tool functions and concatenate the formatted output. Timeouts are tiered constants (`TIMEOUT_SHORT`=60s … `TIMEOUT_EXTRA_LONG`=1800s); pick the tier by expected scan length.

Server entrypoint runs `mcp.run(transport='stdio')`. The tool's single-line docstring **is** the description the AI client sees, so keep it accurate and one line.

## Docker MCP security model (why the code looks the way it does)

The image runs as non-root user `pentest` under Docker MCP Gateway with `--security-opt no-new-privileges`, so **no raw sockets**. This drives real code decisions, don't undo them:

- All nmap tools use `-sT` (TCP connect) and `-Pn` (skip host-discovery ping). SYN scans (`-sS`), ICMP discovery, and ARP scans won't work. The Dockerfile deliberately `setcap -r`s nmap.
- Raw-socket tools (masscan, arp-scan, netdiscover) are intentionally absent from the image.
- `hashcat` runs CPU-only (`--force`) — the image targets ARM64/Apple Silicon, no GPU.

## Adding or changing a tool

Match the existing pattern exactly: `@mcp.tool()` async fn, params default to `""`, one-line docstring, validate → build arg list → `run_command`, return the string. New tools must not need raw sockets or root, and their binary must be installed in the `Dockerfile` (grouped by category). Update the README tool table and bump the "42 tools" count in the README and the startup log banner.

## Agent skills

### Issue tracker

Issues and PRDs are tracked in GitHub Issues. External pull requests are not a triage surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Use `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository using root `CONTEXT.md` and `docs/adr/`. See `docs/agents/domain.md`.
