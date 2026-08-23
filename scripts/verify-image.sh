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

required_binaries="python3 nmap dig dnsrecon dnsenum fierce whois nc nikto wpscan sqlmap dirb ffuf gobuster wfuzz whatweb wafw00f sslscan sslyze testssl enum4linux nbtscan smbclient crackmapexec responder hydra john hashcat searchsploit msfconsole nuclei theHarvester subfinder amass trivy syft olevba msodde uro"

for binary in ${required_binaries}; do
    command -v "${binary}" >/dev/null 2>&1 || {
        echo "missing required binary: ${binary}" >&2
        exit 1
    }
done

python3 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path("/usr/local/share/kali-mcp/nuclei-templates")
manifest_path = root / "manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("schema_version") != 1 or not manifest.get("upstream_version"):
    raise SystemExit("invalid pinned Nuclei template manifest")
for entry in manifest.get("templates", []):
    template = (root / "promoted" / entry["path"]).resolve(strict=True)
    if not template.is_relative_to((root / "promoted").resolve()):
        raise SystemExit(f"Nuclei template escapes promoted root: {entry['path']}")
    actual = hashlib.sha256(template.read_bytes()).hexdigest()
    if actual != entry["sha256"]:
        raise SystemExit(
            f"Nuclei template digest mismatch for {entry['path']}: "
            f"expected {entry['sha256']}, got {actual}"
        )
print(f"verified pinned Nuclei templates: {manifest['upstream_version']}")
PY

python3 - <<'PY'
import json
import subprocess
from pathlib import Path

contract_path = Path("/usr/local/share/kali-mcp/legacy_tool_contract.json")
try:
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    if contract.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    legacy_tools = contract["tools"]
    additions = contract["additions"]
    if not isinstance(legacy_tools, list) or not isinstance(additions, list):
        raise TypeError("tools and additions must be lists")
    expected_tools = legacy_tools + additions
    legacy_names = [tool["name"] for tool in legacy_tools]
    expected_names = [tool["name"] for tool in expected_tools]
    for tool in expected_tools:
        if not isinstance(tool["parameters"], list):
            raise TypeError(f"parameters for {tool['name']!r} must be a list")
        for parameter in tool["parameters"]:
            if "name" not in parameter or "default" not in parameter:
                raise ValueError(
                    f"parameter entries for {tool['name']!r} require name and default"
                )
except (OSError, TypeError, KeyError, json.JSONDecodeError, ValueError) as error:
    raise SystemExit(f"invalid legacy MCP contract at {contract_path}: {error}") from error

if len(legacy_names) != 42 or len(set(legacy_names)) != 42:
    raise SystemExit(
        "legacy MCP contract must contain exactly 42 uniquely named tools; "
        f"found {len(legacy_names)} entries and {len(set(legacy_names))} unique names"
    )
if len(expected_names) != len(set(expected_names)):
    raise SystemExit("legacy MCP contract tools and additions contain duplicate names")

initialize = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "image-smoke", "version": "1"},
    },
}
initialized = {
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
}
list_tools = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {},
}
process = subprocess.run(
    ["python3", "kali_pentest_server.py"],
    input="".join(
        json.dumps(message) + "\n"
        for message in (initialize, initialized, list_tools)
    ),
    text=True,
    capture_output=True,
    timeout=10,
    check=False,
)
try:
    responses = [
        json.loads(line)
        for line in process.stdout.splitlines()
        if line.strip().startswith("{")
    ]
except json.JSONDecodeError as error:
    raise SystemExit(f"MCP server emitted invalid JSON: {error}") from error

initialize_response = next(
    (response for response in responses if response.get("id") == 1), None
)
if not initialize_response or "result" not in initialize_response:
    detail = initialize_response or process.stderr[-500:] or "no response"
    raise SystemExit(f"MCP initialize smoke failed: {detail}")

tools_response = next(
    (response for response in responses if response.get("id") == 2), None
)
try:
    discovered_tools = tools_response["result"]["tools"]
    discovered_names = [tool["name"] for tool in discovered_tools]
except (TypeError, KeyError) as error:
    detail = tools_response or process.stderr[-500:] or "no response"
    raise SystemExit(f"MCP tools/list smoke failed: {detail}") from error

if discovered_names != expected_names:
    raise SystemExit(
        "MCP tools/list names do not match declared legacy tools and additions: "
        f"expected {expected_names!r}, got {discovered_names!r}"
    )

for expected_tool, discovered_tool in zip(expected_tools, discovered_tools):
    tool_name = expected_tool["name"]
    input_schema = discovered_tool.get("inputSchema")
    if not isinstance(input_schema, dict):
        raise SystemExit(f"MCP tool {tool_name!r} has no public inputSchema")
    properties = input_schema.get("properties")
    if not isinstance(properties, dict):
        raise SystemExit(f"MCP tool {tool_name!r} inputSchema has no properties object")

    expected_parameters = expected_tool["parameters"]
    expected_parameter_names = [parameter["name"] for parameter in expected_parameters]
    discovered_parameter_names = list(properties)
    if discovered_parameter_names != expected_parameter_names:
        raise SystemExit(
            f"MCP tool {tool_name!r} parameter order mismatch: "
            f"expected {expected_parameter_names!r}, got {discovered_parameter_names!r}"
        )
    for parameter in expected_parameters:
        parameter_name = parameter["name"]
        public_parameter = properties[parameter_name]
        if "default" not in public_parameter:
            raise SystemExit(
                f"MCP tool {tool_name!r} parameter {parameter_name!r} "
                "does not expose its default"
            )
        if public_parameter["default"] != parameter["default"]:
            raise SystemExit(
                f"MCP tool {tool_name!r} parameter {parameter_name!r} default mismatch: "
                f"expected {parameter['default']!r}, "
                f"got {public_parameter['default']!r}"
            )

print(
    f"verified MCP initialize and tools/list: "
    f"{len(legacy_names)} legacy tools, {len(additions)} declared additions"
)
PY
