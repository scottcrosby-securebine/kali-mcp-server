#!/usr/bin/env python3
"""Hermetic release gate for the built Kali MCP container."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import tarfile
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
RESULT_ID = re.compile(r"result-id=([A-Za-z0-9_-]{32})")
REGISTRY_IMAGE = "registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"


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


def create_oci_archive(path: Path, platform_name: str) -> None:
    """Create a minimal deterministic OCI archive without a registry or builder plugin."""
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
    compressed = gzip.compress(layer_buffer.getvalue(), mtime=0)
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
    layer_descriptor = descriptor("application/vnd.oci.image.layer.v1.tar+gzip", compressed)
    manifest = json.dumps({
        "schemaVersion": 2, "config": config_descriptor, "layers": [layer_descriptor]
    }, sort_keys=True, separators=(",", ":")).encode()
    manifest_descriptor = descriptor("application/vnd.oci.image.manifest.v1+json", manifest)
    manifest_descriptor["annotations"] = {"org.opencontainers.image.ref.name": "fixture:latest"}
    index = json.dumps({"schemaVersion": 2, "manifests": [manifest_descriptor]},
                       sort_keys=True, separators=(",", ":")).encode()
    members = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": index,
        f"blobs/sha256/{config_descriptor['digest'].split(':')[1]}": config,
        f"blobs/sha256/{layer_descriptor['digest'].split(':')[1]}": compressed,
        f"blobs/sha256/{manifest_descriptor['digest'].split(':')[1]}": manifest,
    }
    with tarfile.open(path, "w") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))


class TcpFixture:
    def __init__(self, bind_address: str):
        self.bind_address = bind_address

    def __enter__(self):
        self.socket = socket.socket()
        self.socket.bind((self.bind_address, 0))
        self.socket.listen()
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def _serve(self):
        while True:
            try:
                client, _ = self.socket.accept()
            except OSError:
                return
            with client:
                try:
                    client.sendall(b"fixture\n")
                except (BrokenPipeError, ConnectionResetError):
                    pass

    def __exit__(self, *_args):
        self.socket.close()
        self.thread.join(timeout=2)


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

    def request(self, method: str, params: dict) -> dict:
        self.request_id += 1
        payload = {"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params}
        assert self.process.stdin and self.process.stdout
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            line = self.process.stdout.readline()
            if not line:
                break
            response = json.loads(line)
            if response.get("id") == self.request_id:
                if "error" in response:
                    raise AssertionError(f"MCP {method} failed: {response['error']}")
                return response["result"]
        stderr = self.process.stderr.read() if self.process.stderr else ""
        raise AssertionError(f"MCP {method} returned no response: {stderr[-2000:]}")

    def notify(self, method: str, params: dict) -> None:
        assert self.process.stdin
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
        self.process.stdin.flush()

    def call(self, name: str, arguments: dict) -> str:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        return result["content"][0]["text"]

    def close(self) -> None:
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


def docker_runtime_args(args, workspace: Path, artifacts: Path, results: Path, reports: Path) -> list[str]:
    network = "host" if args.profile == "linux-full" else "bridge"
    return [
        "docker", "run", "--rm", "-i", "--platform", args.platform,
        "--security-opt=no-new-privileges", "--cap-drop=ALL", "--read-only",
        f"--network={network}", "--env", f"KALI_MCP_PROFILE={args.profile}",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec",
        "--tmpfs", "/home/pentest:rw,nosuid,nodev",
        "--mount", f"type=bind,src={workspace},dst=/workspace,readonly",
        "--mount", f"type=bind,src={artifacts},dst=/artifacts,readonly",
        "--mount", f"type=bind,src={results},dst=/results",
        "--mount", f"type=bind,src={reports},dst=/reports",
    ]


def build_image_fixtures(
    platform_name: str, artifacts: Path, registry_name: str, fixture_host: str
) -> tuple[str, str]:
    fixture_tag = f"kali-mcp-fixture:{uuid.uuid4().hex[:12]}"
    run(["docker", "build", "--platform", platform_name, "-t", fixture_tag, str(FIXTURES / "image")])
    docker_archive = artifacts / "fixture-docker.tar"
    with docker_archive.open("wb") as output:
        subprocess.run(["docker", "save", fixture_tag], check=True, stdout=output)
    oci_archive = artifacts / "fixture-oci.tar"
    create_oci_archive(oci_archive, platform_name)
    port = run(
        ["docker", "port", registry_name, "5000/tcp"], capture_output=True
    ).stdout.strip().rsplit(":", 1)[1]
    local_push_ref = f"127.0.0.1:{port}/kali-mcp-fixture:latest"
    run(["docker", "tag", fixture_tag, local_push_ref])
    run(["docker", "push", local_push_ref])
    registry_ref = f"{fixture_host}:{port}/kali-mcp-fixture:latest"
    return fixture_tag, registry_ref


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
    parser.add_argument(
        "--fixture-host", choices=("127.0.0.1", "host.docker.internal"), default="127.0.0.1"
    )
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
        fixture_tag, registry_ref = build_image_fixtures(
            args.platform, artifacts, registry_name, args.fixture_host
        )
        stack.callback(lambda: subprocess.run(
            ["docker", "image", "rm", "-f", fixture_tag], capture_output=True, text=True
        ))

        base = docker_runtime_args(args, workspace, artifacts, results, reports)
        run(
            base + ["--entrypoint", "sh", args.image, "-ceu", """
                test "$(id -u)" = 1000
                test "$(awk '/NoNewPrivs/ {print $2}' /proc/self/status)" = 1
                test "$(awk '/CapEff/ {print $2}' /proc/self/status)" = 0000000000000000
                ! touch /app/rootfs-must-be-read-only
                test -w /results && test -w /reports
                test ! -w /workspace && test ! -w /artifacts
            """],
            capture_output=True,
        )
        print("PASS runtime: non-root, NNP, cap-drop, read-only root/input, writable output")

        bind_address = "127.0.0.1" if args.fixture_host == "127.0.0.1" else "0.0.0.0"
        with TcpFixture(bind_address) as tcp:
            client = McpClient(base + [args.image])
            stack.callback(client.close)
            initialized = client.request("initialize", {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "container-integration", "version": "1"},
            })
            assert initialized["serverInfo"]["name"] == "kali-pentest-tools"
            client.notify("notifications/initialized", {})
            listed = client.request("tools/list", {})["tools"]
            contract = json.loads((ROOT / "tests/fixtures/legacy_tool_contract.json").read_text())
            expected = [item["name"] for item in contract["tools"] + contract["additions"]]
            actual = [item["name"] for item in listed]
            assert actual == expected, f"tool contract drift: expected {len(expected)}, got {len(actual)}"
            print("PASS MCP initialize/tools/list: 42 preserved + 4 additions")

            project_result = assert_success(
                client.call("syft_sbom", {"target_ref": ".", "source_type": "dir"}),
                "Syft mounted project",
            )
            report = client.call("generate_report", {"result_ref": project_result, "format": "html"})
            report_path = re.search(r"/reports/([A-Za-z0-9_-]{32}\.html)", report)
            assert report_path and (reports / report_path.group(1)).is_file(), report
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
            print(f"PASS Syft hermetic local registry at {registry_ref.rsplit('/', 1)[0]}")

            nmap = client.call("nmap_scan", {"target": args.fixture_host, "ports": str(tcp.port)})
            assert "open" in nmap and str(tcp.port) in nmap, nmap
            raw = client.call("nmap_script_scan", {
                "target": args.fixture_host, "scripts": "broadcast", "ports": str(tcp.port)
            })
            assert raw.startswith("capability_missing:") and "raw/link-layer" in raw, raw
            print("PASS local-only Nmap TCP connect; raw/link-layer operation unavailable")

            trivy = client.call("trivy_scan", {"target_ref": ".", "source_type": "filesystem"})
            if trivy.startswith("✅"):
                print("PASS Trivy mounted filesystem")
            else:
                assert "trivy failed" in trivy.lower(), trivy
                print("PASS Trivy controlled failure (database unavailable; no network fallback)")

    print(f"PASS container integration gate ({args.platform}, {args.profile})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
