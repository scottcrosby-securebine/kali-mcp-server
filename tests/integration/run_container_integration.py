#!/usr/bin/env python3
"""Hermetic release gate for the built Kali MCP container."""

from __future__ import annotations

import argparse
from collections import deque
from contextlib import contextmanager, ExitStack
import gzip
import hashlib
import io
import json
from pathlib import Path
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tarfile
from typing import NamedTuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
RESULT_ID = re.compile(r"result-id=([A-Za-z0-9_-]{32})")
REGISTRY_IMAGE = "registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"

sys.path.insert(0, str(ROOT))
from kali_mcp_launcher import build_docker_command


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, **kwargs)


def create_office_fixture(path: Path) -> None:
    """Create a harmless deterministic OOXML document without macros or links."""
    timestamp = (2020, 1, 1, 0, 0, 0)
    members = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>'
        ),
        "word/document.xml": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>Harmless local fixture</w:t></w:r></w:p></w:body></w:document>'
        ),
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, contents in members.items():
            info = zipfile.ZipInfo(name, timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, contents)


class OciPayloads(NamedTuple):
    config: bytes
    config_digest: str
    layer: bytes
    layer_digest: str
    manifest: bytes
    manifest_digest: str
    index: bytes


def create_oci_payloads(platform_name: str) -> OciPayloads:
    """Build deterministic OCI bytes shared by archive and registry fixtures."""
    architecture = platform_name.rsplit("/", 1)[1]
    layer_buffer = io.BytesIO()
    with tarfile.open(fileobj=layer_buffer, mode="w") as layer:
        members = {
            "fixture-marker.txt": b"kali-mcp deterministic local image fixture\n",
            "var/lib/dpkg/status": (FIXTURES / "image/dpkg-status").read_bytes(),
        }
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            layer.addfile(info, io.BytesIO(data))
    layer_bytes = gzip.compress(layer_buffer.getvalue(), mtime=0)
    config = json.dumps({
        "architecture": architecture, "os": "linux", "config": {},
        "rootfs": {"type": "layers", "diff_ids": [
            "sha256:" + hashlib.sha256(layer_buffer.getvalue()).hexdigest()
        ]},
    }, sort_keys=True, separators=(",", ":")).encode()

    def descriptor(media_type: str, payload: bytes) -> dict:
        return {
            "mediaType": media_type,
            "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }

    config_descriptor = descriptor("application/vnd.oci.image.config.v1+json", config)
    layer_descriptor = descriptor("application/vnd.oci.image.layer.v1.tar+gzip", layer_bytes)
    manifest = json.dumps({
        "schemaVersion": 2, "config": config_descriptor, "layers": [layer_descriptor]
    }, sort_keys=True, separators=(",", ":")).encode()
    manifest_descriptor = descriptor("application/vnd.oci.image.manifest.v1+json", manifest)
    manifest_descriptor["annotations"] = {"org.opencontainers.image.ref.name": "fixture:latest"}
    index = json.dumps({"schemaVersion": 2, "manifests": [manifest_descriptor]},
                       sort_keys=True, separators=(",", ":")).encode()
    return OciPayloads(
        config=config,
        config_digest=config_descriptor["digest"],
        layer=layer_bytes,
        layer_digest=layer_descriptor["digest"],
        manifest=manifest,
        manifest_digest=manifest_descriptor["digest"],
        index=index,
    )


def create_oci_archive(path: Path, platform_name: str) -> None:
    """Create a minimal deterministic OCI archive without a registry or builder plugin."""
    payloads = create_oci_payloads(platform_name)
    members = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": payloads.index,
        f"blobs/sha256/{payloads.config_digest.split(':')[1]}": payloads.config,
        f"blobs/sha256/{payloads.layer_digest.split(':')[1]}": payloads.layer,
        f"blobs/sha256/{payloads.manifest_digest.split(':')[1]}": payloads.manifest,
    }
    with tarfile.open(path, "w") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname or "", parsed.port


class RegistryHttpError(ValueError):
    """A non-success registry response that must not be retried or redirected."""


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


REGISTRY_OPENER = build_opener(_NoRedirects())


def _request(url: str, method: str, *, data: bytes | None, headers: dict, timeout: float):
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with REGISTRY_OPENER.open(request, timeout=timeout) as response:
            status = response.status
            response_headers = response.headers
            response.read()
    except HTTPError as error:
        error.read()
        raise RegistryHttpError(f"registry {method} {url} returned HTTP {error.code}") from error
    if not 200 <= status < 300:
        raise RegistryHttpError(f"registry {method} {url} returned HTTP {status}")
    return response_headers


def _same_origin_location(endpoint: str, location: str) -> str:
    resolved = urljoin(endpoint.rstrip("/") + "/", location)
    if _origin(resolved) != _origin(endpoint):
        raise ValueError(f"registry upload Location changed origin: {location!r}")
    return resolved


def _with_digest_query(url: str, digest: str) -> str:
    parsed = urlsplit(url)
    query = [(name, value) for name, value in parse_qsl(parsed.query, keep_blank_values=True)
             if name != "digest"]
    query.append(("digest", digest))
    return urlunsplit(parsed._replace(query=urlencode(query)))


def publish_oci_fixture(
    endpoint: str,
    payloads: OciPayloads,
    *,
    request_timeout: float = 2,
    readiness_timeout: float = 15,
) -> str:
    """Seed a loopback registry through the host-side OCI Distribution API."""
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise ValueError("registry endpoint must be an explicit http://127.0.0.1:<port> origin")
    deadline = time.monotonic() + readiness_timeout
    while True:
        try:
            _request(f"{endpoint}/v2/", "GET", data=None, headers={}, timeout=request_timeout)
            break
        except (URLError, TimeoutError, OSError) as error:
            if time.monotonic() >= deadline:
                raise ValueError(f"registry did not become ready at {endpoint}") from error
            time.sleep(0.1)

    upload_root = f"{endpoint}/v2/kali-mcp-fixture/blobs/uploads/"
    for payload, digest in (
        (payloads.config, payloads.config_digest),
        (payloads.layer, payloads.layer_digest),
    ):
        headers = _request(
            upload_root, "POST", data=b"", headers={"Content-Length": "0"}, timeout=request_timeout
        )
        location = headers.get("Location")
        if not location:
            raise ValueError("registry blob upload response omitted Location")
        upload_url = _with_digest_query(_same_origin_location(endpoint, location), digest)
        _request(
            upload_url,
            "PUT",
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
            timeout=request_timeout,
        )

    manifest_url = f"{endpoint}/v2/kali-mcp-fixture/manifests/latest"
    headers = _request(
        manifest_url,
        "PUT",
        data=payloads.manifest,
        headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"},
        timeout=request_timeout,
    )
    remote_digest = headers.get("Docker-Content-Digest")
    if remote_digest is None:
        remote_digest = _request(
            manifest_url,
            "HEAD",
            data=None,
            headers={"Accept": "application/vnd.oci.image.manifest.v1+json"},
            timeout=request_timeout,
        ).get("Docker-Content-Digest")
    if remote_digest != payloads.manifest_digest:
        raise ValueError(
            f"registry manifest digest mismatch: expected {payloads.manifest_digest}, got {remote_digest}"
        )
    return payloads.manifest_digest


@contextmanager
def temporary_fixture_image(platform_name: str, *, run_command=run):
    """Build a fixture image and always remove its tag on scope exit."""
    fixture_tag = f"kali-mcp-fixture:{uuid.uuid4().hex[:12]}"
    run_command([
        "docker", "build", "--platform", platform_name,
        "-t", fixture_tag, str(FIXTURES / "image"),
    ])
    try:
        yield fixture_tag
    finally:
        active_error = sys.exc_info()[1]
        try:
            run_command(["docker", "image", "rm", "-f", fixture_tag], capture_output=True)
        except Exception:
            if active_error is None:
                raise


class McpClient:
    def __init__(self, command: list[str]):
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.request_id = 0
        self.responses: queue.Queue = queue.Queue()
        self.stderr_lines: deque[str] = deque(maxlen=200)
        self.stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.stdout_thread.start()
        self.stderr_thread.start()

    def _read_stdout(self) -> None:
        if self.process.stdout is None:
            self.responses.put(RuntimeError("MCP stdout pipe is unavailable"))
            return
        try:
            for line in self.process.stdout:
                self.responses.put(json.loads(line))
        except (OSError, json.JSONDecodeError) as error:
            self.responses.put(error)

    def _read_stderr(self) -> None:
        if self.process.stderr is None:
            return
        for line in self.process.stderr:
            self.stderr_lines.append(line.rstrip())

    def request(self, method: str, params: dict) -> dict:
        self.request_id += 1
        payload = {"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params}
        if self.process.stdin is None:
            raise RuntimeError("MCP stdin pipe is unavailable")
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                response = self.responses.get(timeout=min(1, deadline - time.monotonic()))
            except queue.Empty:
                if self.process.poll() is not None:
                    break
                continue
            if isinstance(response, BaseException):
                raise RuntimeError(f"failed to read MCP response: {response}") from response
            if response.get("id") == self.request_id:
                if "error" in response:
                    raise AssertionError(f"MCP {method} failed: {response['error']}")
                return response["result"]
        stderr = "\n".join(self.stderr_lines)
        raise AssertionError(f"MCP {method} timed out or exited: {stderr[-4000:]}")

    def notify(self, method: str, params: dict) -> None:
        if self.process.stdin is None:
            raise RuntimeError("MCP stdin pipe is unavailable")
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
        self.process.stdin.flush()

    def call(self, name: str, arguments: dict) -> str:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        content = result.get("content")
        if not isinstance(content, list) or not content or content[0].get("type") != "text":
            raise AssertionError(f"MCP tool {name} did not return text content: {result}")
        text = content[0].get("text")
        if not isinstance(text, str):
            raise AssertionError(f"MCP tool {name} returned non-string text: {result}")
        return text

    def close(self) -> None:
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.stdout_thread.join(timeout=2)
        self.stderr_thread.join(timeout=2)


def docker_runtime_args(
    args, workspace: Path, artifacts: Path, results: Path, reports: Path, registry_name: str
) -> list[str]:
    command = build_docker_command(args.profile, args.image, {
        "workspace": str(workspace),
        "artifacts": str(artifacts),
        "results": str(results),
        "reports": str(reports),
    })
    expected_network = "--network=host" if args.profile == "linux-full" else "--network=bridge"
    if command.count(expected_network) != 1:
        raise AssertionError(
            f"launcher network contract changed: expected one {expected_network!r} in {command!r}"
        )
    command[command.index(expected_network)] = f"--network=container:{registry_name}"
    image_index = len(command) - 1
    if command[image_index] != args.image:
        raise AssertionError(f"launcher image position changed: {command!r}")
    command[image_index:image_index] = ["--platform", args.platform]
    return command


def with_entrypoint(command: list[str], entrypoint: str, entrypoint_args: list[str]) -> list[str]:
    image_index = len(command) - 1
    return command[:image_index] + ["--entrypoint", entrypoint, command[image_index]] + entrypoint_args


def create_image_archives(fixture_tag: str, platform_name: str, artifacts: Path) -> None:
    """Write Docker and OCI archive fixtures from deterministic local inputs."""
    docker_archive = artifacts / "fixture-docker.tar"
    with docker_archive.open("wb") as output:
        subprocess.run(["docker", "save", fixture_tag], check=True, stdout=output)
    create_oci_archive(artifacts / "fixture-oci.tar", platform_name)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def assert_success(text: str, operation: str) -> str:
    if not text.startswith("✅"):
        raise AssertionError(f"{operation} failed: {text}")
    match = RESULT_ID.search(text)
    if not match:
        raise AssertionError(f"{operation} omitted result-id: {text}")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    parser.add_argument("--profile", choices=("linux-full", "linux-hardened", "mac-hardened"), default="linux-full")
    args = parser.parse_args()

    if args.profile == "mac-hardened" and args.platform != "linux/arm64":
        parser.error("mac-hardened qualification requires linux/arm64")

    registry_name = f"kali-mcp-registry-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory(prefix="kali-mcp-integration-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        workspace = root / "workspace"
        artifacts = root / "artifacts"
        results = root / "results"
        reports = root / "reports"
        shutil.copytree(FIXTURES / "project", workspace)
        for directory in (artifacts, results, reports):
            directory.mkdir()
        results.chmod(0o777)
        reports.chmod(0o777)
        create_office_fixture(artifacts / "harmless.docx")

        run([
            "docker", "run", "-d", "--rm", "--name", registry_name,
            "-p", "127.0.0.1::5000", REGISTRY_IMAGE,
        ], capture_output=True)
        stack.callback(lambda: subprocess.run(
            ["docker", "rm", "-f", registry_name], capture_output=True, text=True
        ))
        fixture_tag = stack.enter_context(temporary_fixture_image(args.platform))
        create_image_archives(fixture_tag, args.platform, artifacts)
        port = run(
            ["docker", "port", registry_name, "5000/tcp"], capture_output=True
        ).stdout.strip().rsplit(":", 1)[1]
        endpoint = f"http://127.0.0.1:{port}"
        payloads = create_oci_payloads(args.platform)
        publish_oci_fixture(endpoint, payloads)
        registry_ref = "127.0.0.1:5000/kali-mcp-fixture:latest"
        run(["docker", "network", "disconnect", "bridge", registry_name])

        base = docker_runtime_args(args, workspace, artifacts, results, reports, registry_name)
        run(
            with_entrypoint(base, "sh", ["-ceu", """
                test "$(id -u)" = 1000
                test "$(awk '/NoNewPrivs/ {print $2}' /proc/self/status)" = 1
                test "$(awk '/CapEff/ {print $2}' /proc/self/status)" = 0000000000000000
                awk 'NR > 1 && $1 != "lo" {exit 1}' /proc/net/route
                awk '$NF != "lo" {exit 1}' /proc/net/ipv6_route
                ! touch /app/rootfs-must-be-read-only
                test "$(stat -c '%u:%g %a' /home/pentest)" = "1000:1000 700"
                touch /home/pentest/.runtime-write-test
                rm /home/pentest/.runtime-write-test
                test -w /results && test -w /reports
                test ! -w /workspace && test ! -w /artifacts
                /usr/lib/amass/amass -version >/dev/null
                ! /usr/bin/amass -version >/dev/null 2>&1
                grep -q '/usr/lib/amass/amass' /app/kali_pentest_server.py
            """]),
            capture_output=True,
        )
        print("PASS runtime: non-root, private writable home, NNP, cap-drop, read-only mounts, no non-loopback routes")
        print("PASS amass_enum reaches the hardened binary directly, bypassing the sudo wrapper (#15)")

        client = McpClient(base)
        stack.callback(client.close)
        initialized = client.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "container-integration", "version": "1"},
        })
        require(
            initialized.get("serverInfo", {}).get("name") == "kali-pentest-tools",
            f"unexpected MCP server identity: {initialized}",
        )
        client.notify("notifications/initialized", {})
        listed = client.request("tools/list", {}).get("tools")
        require(isinstance(listed, list), f"tools/list omitted tools: {listed}")
        contract = json.loads((ROOT / "tests/fixtures/legacy_tool_contract.json").read_text())
        expected = [item["name"] for item in contract["tools"] + contract["additions"]]
        actual = [item.get("name") for item in listed]
        require(actual == expected, f"tool contract drift: expected {expected}, got {actual}")
        # Counts come from the fixture, never a literal: a hardcoded total goes
        # stale the moment an addition lands and makes the gate print a false
        # statement about the contract it just verified.
        print(f"PASS MCP initialize/tools/list: {len(contract['tools'])} preserved "
              f"+ {len(contract['additions'])} additions")

        for tool_name in expected:
            default_result = client.call(tool_name, {})
            require(isinstance(default_result, str), f"{tool_name} default call was not text")
        print(f"PASS MCP tools/call: all {len(expected)} declared tools "
              "return text for default arguments")

        before_confined = set(results.iterdir())
        confined = client.call("syft_sbom", {"target_ref": "../escape", "source_type": "dir"})
        require("target_ref" in confined and "mount" in confined, f"path confinement failed: {confined}")
        require(set(results.iterdir()) == before_confined, "rejected path created a scanner result")
        print("PASS mounted scanner path confinement creates no result")

        project_result = assert_success(
            client.call("syft_sbom", {"target_ref": ".", "source_type": "dir"}),
            "Syft mounted project",
        )
        report = client.call("generate_report", {"result_ref": project_result, "format": "html"})
        report_path = re.search(r"/reports/([A-Za-z0-9_-]{32}\.html)", report)
        require(report_path is not None, f"report path omitted: {report}")
        require((reports / report_path.group(1)).is_file(), f"report file missing: {report}")
        print("PASS Syft project -> normalized result -> HTML report")

        assert_success(client.call("syft_sbom", {
            "target_ref": "fixture-docker.tar", "source_type": "docker-archive"
        }), "Syft Docker archive")
        assert_success(client.call("syft_sbom", {
            "target_ref": "fixture-oci.tar", "source_type": "oci-archive"
        }), "Syft OCI archive")
        print("PASS Syft deterministic Docker and OCI archives")

        office = client.call("oletools_scan", {"artifact_ref": "harmless.docx", "analyzer": "olevba"})
        assert_success(office, "oletools harmless Office artifact")
        print("PASS oletools harmless local Office artifact")

        registry = client.call("syft_sbom", {"target_ref": registry_ref, "source_type": "registry"})
        assert_success(registry, "Syft local registry")
        print("PASS Syft hermetic registry in isolated shared network namespace")

        nmap = client.call("nmap_scan", {"target": "127.0.0.1", "ports": "5000"})
        require("open" in nmap and "5000" in nmap, f"local TCP-connect scan failed: {nmap}")
        raw = client.call("nmap_script_scan", {
            "target": "127.0.0.1", "scripts": "broadcast", "ports": "5000"
        })
        require(
            raw.startswith("capability_missing:") and "raw/link-layer" in raw,
            f"raw/link-layer operation did not fail closed: {raw}",
        )
        print("PASS isolated loopback Nmap TCP connect; raw/link-layer operation unavailable")

        before_trivy = set(results.iterdir())
        trivy = client.call("trivy_scan", {"target_ref": ".", "source_type": "filesystem"})
        if trivy.startswith("✅"):
            assert_success(trivy, "Trivy mounted filesystem")
            print("PASS Trivy mounted filesystem with packaged database")
        else:
            lowered = trivy.lower()
            controlled_failure = lowered.startswith("❌ error: trivy failed:") and any(
                marker in lowered for marker in ("database", "db error", "download vulnerability db")
            )
            require(controlled_failure, f"unexpected Trivy failure: {trivy}")
            require(set(results.iterdir()) == before_trivy, "failed Trivy call created a result")
            print("PASS Trivy controlled database-unavailable failure creates no result")

    print(f"PASS container integration gate ({args.platform}, {args.profile})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
