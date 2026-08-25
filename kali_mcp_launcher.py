#!/usr/bin/env python3
"""Portable Docker launcher for the Kali MCP server."""

from __future__ import annotations

import argparse
import os
import platform
import shlex
import stat
import subprocess
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
    "secrets": ("/run/secrets", True),
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


def detect_current_host(system: str | None = None, machine: str | None = None) -> Host:
    """Detect the physical host, including Apple Silicon processes running under Rosetta."""
    system_name = system or platform.system()
    machine_name = machine or platform.machine()
    if machine is None and system_name.strip().lower() == "darwin" and machine_name.lower() in {"x86_64", "amd64"}:
        try:
            translated = subprocess.run(
                ["/usr/sbin/sysctl", "-in", "sysctl.proc_translated"],
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        else:
            if translated.returncode == 0 and translated.stdout.strip() == "1":
                machine_name = "arm64"
    return detect_host(system_name, machine_name)


def select_profile(host: Host, requested: str | None) -> str:
    """Choose the host default or validate an explicit profile."""
    profile = requested or ("linux-full" if host.system == "linux" else "mac-hardened")
    allowed = {"linux-full", "linux-hardened"} if host.system == "linux" else {"mac-hardened"}
    if profile not in allowed:
        raise LauncherError(f"unavailable: profile '{profile}' cannot run on {host.system}/{host.architecture}")
    return profile


def _resolve_mount(name: str, host_path: str) -> Path:
    path = Path(host_path).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise LauncherError(f"invalid_mount: {name} directory does not exist: {host_path}") from error
    if not resolved.is_dir():
        raise LauncherError(f"invalid_mount: {name} must be a directory: {host_path}")
    if "," in str(resolved):
        raise LauncherError(f"invalid_mount: {name} path cannot contain a comma")
    _reject_host_sockets(name, resolved)
    return resolved


def _mount_value(name: str, resolved: Path) -> str:
    target, read_only = MOUNT_TARGETS[name]
    suffix = ",readonly" if read_only else ""
    return f"type=bind,src={resolved},dst={target}{suffix}"


def _reject_host_sockets(name: str, root: Path) -> None:
    """Fail closed if a bind source would expose a host Unix socket."""
    def walk_error(error: OSError) -> None:
        raise LauncherError(f"invalid_mount: cannot inspect {name} directory: {error.filename}") from error

    for directory, subdirectories, filenames in os.walk(root, followlinks=False, onerror=walk_error):
        for entry in (*subdirectories, *filenames):
            candidate = Path(directory, entry)
            try:
                mode = candidate.stat().st_mode
            except OSError as error:
                raise LauncherError(f"invalid_mount: cannot inspect {name} path: {candidate}") from error
            if stat.S_ISSOCK(mode):
                raise LauncherError(f"prohibited_socket: {name} directory contains a host socket: {candidate}")


def _reject_overlapping_mounts(mounts: Mapping[str, Path]) -> None:
    """Prevent one host tree from gaining different access through an alias."""
    items = list(mounts.items())
    for index, (name, path) in enumerate(items):
        for other_name, other_path in items[index + 1:]:
            if path == other_path or path in other_path.parents or other_path in path.parents:
                raise LauncherError(
                    f"invalid_mount: {name} and {other_name} directories must not overlap"
                )


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
    resolved_mounts = {name: _resolve_mount(name, host_path) for name, host_path in mounts.items()}
    _reject_overlapping_mounts(resolved_mounts)

    command = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--security-opt=no-new-privileges",
        # No current MCP operation has demonstrated a need for an added
        # capability. linux-full gains native host networking, while raw
        # operations remain unavailable until a later test proves otherwise.
        "--cap-drop=ALL",
        "--read-only",
        f"--network={network}",
        "--env",
        f"KALI_MCP_PROFILE={profile}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec",
        "--tmpfs",
        "/home/pentest:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700",
    ]

    for name in MOUNT_TARGETS:
        if name in resolved_mounts:
            command.extend(["--mount", _mount_value(name, resolved_mounts[name])])
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
        host = detect_current_host(system, machine)
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
