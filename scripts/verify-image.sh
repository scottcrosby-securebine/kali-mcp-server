#!/bin/sh
set -eu

lock_files="${*:-/tmp/packages.lock /tmp/source-packages.lock}"

if [ "$(id -u)" -eq 0 ]; then
    echo "image must run as a non-root user" >&2
    exit 1
fi

if ! grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status; then
    echo "image smoke test requires no-new-privileges" >&2
    exit 1
fi

if getcap /usr/bin/nmap /usr/lib/nmap/nmap | grep -q '='; then
    echo "nmap executable must not retain file capabilities" >&2
    exit 1
fi

for lock_file in ${lock_files}; do
    while IFS='=' read -r package expected; do
        actual="$(dpkg-query -W -f='${Version}' "${package}")"
        if [ "${actual}" != "${expected}" ]; then
            echo "${package}: expected ${expected}, got ${actual}" >&2
            exit 1
        fi
    done < "${lock_file}"
done

required_binaries="python3 nmap dig dnsrecon dnsenum fierce whois nc nikto wpscan sqlmap dirb ffuf gobuster wfuzz whatweb wafw00f sslscan sslyze testssl enum4linux nbtscan smbclient crackmapexec responder hydra john hashcat searchsploit msfconsole nuclei theHarvester subfinder amass"

for binary in ${required_binaries}; do
    command -v "${binary}" >/dev/null 2>&1 || {
        echo "missing required binary: ${binary}" >&2
        exit 1
    }
done

python3 - <<'PY'
import json
import subprocess
import kali_pentest_server

tools = kali_pentest_server.mcp._tool_manager._tools
if len(tools) != 42:
    raise SystemExit(f"expected 42 MCP tools, found {len(tools)}")
print("verified 42 MCP tools")

request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "image-smoke", "version": "1"},
    },
}
process = subprocess.run(
    ["python3", "kali_pentest_server.py"],
    input=json.dumps(request) + "\n",
    text=True,
    capture_output=True,
    timeout=10,
    check=False,
)
responses = [json.loads(line) for line in process.stdout.splitlines() if line.strip().startswith("{")]
if not any(response.get("id") == 1 and "result" in response for response in responses):
    raise SystemExit(f"MCP initialize smoke failed: {process.stderr[-500:]}")
print("verified MCP stdio initialization")
PY
