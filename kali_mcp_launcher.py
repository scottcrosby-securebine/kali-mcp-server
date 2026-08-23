#!/usr/bin/env python3
"""Portable Docker launcher for the Kali MCP server."""

from __future__ import annotations

import argparse
import os
import platform
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


PROFILES = ("linux-full", "linux-hardened", "mac-hardened")
MOUNT_TARGETS = {
    "workspace": ("/workspace", True),
    "artifacts": ("/artifacts", True),
    "results": ("/results", False),
    "reports": ("/reports", False),
}


class LauncherError(ValueError):
    """A readable host, profile, or launcher-input error."""


@dataclass(frozen=True)
class Host:
    system: str
    architecture: str


def detect_host(system: str, machine: str) -> Host:
    """Normalize a supported Linux or Apple Silicon host."""
    system_name = system.strip().lower()
    machine_name = machine.strip().lower()
    architectures = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    architecture = architectures.get(machine_name)

    if system_name == "darwin" and architecture == "amd64":
        raise LauncherError("unsupported_platform: Intel macOS is not supported")
    if system_name == "darwin" and architecture == "arm64":
        return Host("darwin", architecture)
    if system_name == "linux" and architecture:
        return Host("linux", architecture)
    raise LauncherError(f"unsupported_platform: {system or 'unknown'} {machine or 'unknown'} is not supported")


def select_profile(host: Host, requested: str | None) -> str:
    """Choose the host default or validate an explicit profile."""
    profile = requested or ("linux-full" if host.system == "linux" else "mac-hardened")
    allowed = {"linux-full", "linux-hardened"} if host.system == "linux" else {"mac-hardened"}
    if profile not in allowed:
        raise LauncherError(f"unavailable: profile '{profile}' cannot run on {host.system}/{host.architecture}")
    return profile


def _mount_value(name: str, host_path: str) -> str:
    target, read_only = MOUNT_TARGETS[name]
    if "," in host_path:
        raise LauncherError(f"invalid_mount: {name} path cannot contain a comma")
    path = Path(host_path).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise LauncherError(f"invalid_mount: {name} directory does not exist: {host_path}") from error
    if not resolved.is_dir():
        raise LauncherError(f"invalid_mount: {name} must be a directory: {host_path}")
    suffix = ",readonly" if read_only else ""
    return f"type=bind,src={resolved},dst={target}{suffix}"


def build_docker_command(profile: str, image: str, mounts: Mapping[str, str]) -> list[str]:
    """Build Docker argv without invoking a shell."""
    if profile not in PROFILES:
        raise LauncherError(f"unavailable: unknown profile '{profile}'")
    if not image.strip() or image.startswith("-"):
        raise LauncherError("invalid_image: image must be a Docker image reference")
    unknown_mounts = set(mounts) - set(MOUNT_TARGETS)
    if unknown_mounts:
        raise LauncherError(f"invalid_mount: unknown mount '{sorted(unknown_mounts)[0]}'")

    network = "host" if profile == "linux-full" else "bridge"
    command = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--security-opt=no-new-privileges",
        "--cap-drop=ALL",
        "--read-only",
        f"--network={network}",
        "--env",
        f"KALI_MCP_PROFILE={profile}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec",
        "--tmpfs",
        "/home/pentest:rw,nosuid,nodev",
    ]

    for name in MOUNT_TARGETS:
        if name in mounts:
            command.extend(["--mount", _mount_value(name, mounts[name])])
        elif name in {"results", "reports"}:
            command.extend(["--tmpfs", f"/{name}:rw,nosuid,nodev,noexec"])

    command.append(image)
    return command


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Kali MCP container with the correct host profile")
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--image", default=os.environ.get("KALI_MCP_IMAGE", "kali-mcp-server:latest"))
    for name in MOUNT_TARGETS:
        parser.add_argument(f"--{name}", metavar="HOST_DIRECTORY")
    parser.add_argument("--dry-run", action="store_true", help="print Docker argv without running it")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    system: str | None = None,
    machine: str | None = None,
    exec_command: Callable[[list[str]], None] = lambda command: os.execvp(command[0], command),
) -> int:
    args = _parser().parse_args(argv)
    try:
        host = detect_host(system or platform.system(), machine or platform.machine())
        profile = select_profile(host, args.profile)
        mounts = {name: getattr(args, name) for name in MOUNT_TARGETS if getattr(args, name)}
        command = build_docker_command(profile, args.image, mounts)
    except LauncherError as error:
        print(str(error), file=sys.stderr)
        return 2

    if args.dry_run:
        print(shlex.join(command))
        return 0
    exec_command(command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
