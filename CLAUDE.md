# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file MCP (Model Context Protocol) server preserving 41 Kali Linux calls and adding nine bounded scanning/reporting calls. An MCP client calls the tools over stdio; the server invokes underlying Kali binaries and returns strings. MCP behavior lives in `kali_pentest_server.py`. Host-side Docker profile selection lives in `kali_mcp_launcher.py` and its `scripts/kali-mcp` entry point.

## Commands

```bash
# Build the image from pinned base and package inputs
docker build -t kali-mcp-server:latest .

# Inspect the hardened launcher command, then run it through an MCP client
scripts/kali-mcp --image kali-mcp-server:latest --dry-run

# Host startup is only a development convenience
python3 kali_pentest_server.py          # host: needs `pip install -r requirements.txt` + the Kali tools on PATH

# Run the native contract, adapter, report, launcher, registry, and browser tests
python3 -m unittest discover -s tests -v

# Redaction gate. NOT collected by unittest discover -- run it directly, and read
# the EXIT STATUS, not the last line of output (a launcher test prints a docker
# line after `OK`). Three states: 0 measured and clean; 3 NOTHING TO MEASURE,
# the base carries a byte-identical kali_pentest_server.py so the run is a pass
# that proves nothing; any other status a failure. 1 is the real verdict -- a
# leak opened, legitimate content destroyed, a parser the corpus never
# exercised, or a sweep combination the base redacted and HEAD does not. 2 is
# not a verdict at all: CPython exits 2 on a script it cannot open and argparse
# exits 2 on a bad flag, which is why "nothing to measure" is 3 and 2 fails.
# Pass --base after this branch merges.
python3 tests/redaction_differential.py [--base <rev>] [--json out.json]

# Mutation check: swap kali_pentest_server.py for the version at <base-rev>, run
# the tests matching <test-pattern> (default `test_scanner_adapters.py`) against
# it, and require a real ASSERTION failure -- 0 the mutation was caught, 1 the
# suite ran clean so those assertions pin nothing, 2 INCONCLUSIVE (nothing
# collected, or an error, neither of which proves anything either way), 3 the
# base is byte-identical to the working tree so nothing was mutated. Same 3 as
# the redaction gate above, and for the same reason: a run that measured nothing
# must not report either a pass or an accusation. Refuses to start while
# kali_pentest_server.py has uncommitted changes. Restores the tree on any exit.
scripts/mutation-check <base-rev> [test-pattern]

# Verify a built image under the required NNP boundary
docker run --rm --security-opt=no-new-privileges \
  --entrypoint verify-kali-mcp-image kali-mcp-server:latest

# Exercise the real MCP/container seam after building the requested platform image
python3 tests/integration/run_container_integration.py \
  --image kali-mcp-server:latest --platform linux/amd64

# Stage an explicitly reviewed, detection-only Nuclei template set
scripts/update-nuclei-templates --source /path/to/upstream \
  --destination /new/staging/directory --version UPSTREAM_VERSION \
  http/cves/example.yaml
```

`scripts/mutation-check` clears `__pycache__` around every swap, and anything else that swaps the source must too: a restore rewriting the same byte count inside one second reproduces the source mtime, so Python keeps running the MUTATED bytecode while the source reads clean.

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
- `run_command(cmd_list, timeout, strip_containing=(), strip_leading_blank=False)` — the legacy text adapter. It calls `execute_command`, merges stdout+stderr, drops any line containing one of the `strip_containing` markers (and, when `strip_leading_blank` is set, a blank line immediately above a dropped one, since an announcement can carry its own), truncates to `MAX_OUTPUT_LINES` (200), and wraps the result in a status string: `✅` on exit 0, `❌` on a non-zero exit or an execution error, `⏱️` on timeout. A non-zero exit is a FAILURE, not a warning — `run_command` emits no `⚠️` (#31). `_workflow_check` still recognises `⚠️` from other producers. `strip_containing` exists so capture can remove a tool's announcement of the output file capture itself requested (dnsrecon's "Saving records to JSON file", ffuf's "Output file"/"File format"); it must run **before** the 200-line bound, or the `(truncated N additional lines)` counter differs from an unflagged run. Legacy callers pass nothing and are unaffected.
- Structured scanner adapters may call `execute_command` through a scanner-specific helper when they must parse complete JSON/JSONL before applying the public 200-line bound. Timeout, start, failure, parsing, and redaction behavior stays centralized in that helper rather than the public tool wrapper.
- `validate_target(s)` — length/empty guard. Called by nearly every tool.
- `sanitize_input(s)` — `shlex.quote` wrapper. Present but rarely needed: because commands are passed as arg lists, shell metacharacters are already inert. Don't add `shell=True` and then reason about quoting — keep the list form.
- `capability_missing(operation, capability)` — stable readable response for an operation the active Docker profile cannot support. Return this before calling `run_command`.

Combined-operation tools (`quick_recon`, `full_recon`, `web_audit`, `network_sweep`) don't spawn subprocesses directly — they `await` the other tool functions and concatenate the formatted output. `full_recon` and `web_audit` also classify stage status and persist one report for successful or partial execution. Timeouts are tiered constants (`TIMEOUT_SHORT`=60s … `TIMEOUT_EXTRA_LONG`=1800s); pick the tier by expected scan length.

Template promotion is a controlled maintainer operation. It requires an existing source root, a fresh destination, an upstream version, and explicitly reviewed relative template paths; unsafe features and mutating request methods are rejected. Review the staged manifest before replacing the repository set.

Server entrypoint runs `mcp.run(transport='stdio')`. The tool's single-line docstring **is** the description the AI client sees, so keep it accurate and one line.

## Docker MCP security model (why the code looks the way it does)

The image runs as non-root user `pentest`. The launcher supplies `--security-opt=no-new-privileges`, `--cap-drop=ALL`, a read-only root filesystem, hardened tmpfs, fixed mount roles, and a host-compatible network profile. This drives real code decisions; do not bypass the launcher in operator guidance:

- All nmap tools use `-sT` (TCP connect) and `-Pn` (skip host-discovery ping). SYN scans (`-sS`), ICMP discovery, and ARP scans won't work. The Dockerfile deliberately `setcap -r`s nmap.
- Raw-socket tools (masscan, arp-scan, netdiscover) are intentionally absent from the image.
- `hashcat_crack` is removed: hashcat cannot run any OpenCL kernel on the current Kali PoCL stack (upstream regression, see #45). `john` covers CPU cracking.

## Adding or changing a tool

Match the existing pattern exactly: `@mcp.tool()` async fn, string defaults, one-line docstring, validate → build argument list → text or structured adapter, return `str`. Use `run_command` for legacy text output; use a shared structured helper only when complete machine-readable output must be parsed before bounding the public response. New tools must not need raw sockets or root, and their binary must be pinned in the container build. Update `tests/fixtures/legacy_tool_contract.json` deliberately, preserve the preserved-versus-additions wording, update current docs, and run the native plus container gates.

## Agent skills

### Issue tracker

Issues and PRDs are tracked in GitHub Issues. External pull requests are not a triage surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Use `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository using root `CONTEXT.md` and `docs/adr/`. See `docs/agents/domain.md`.
