import os
import tempfile
import unittest
from pathlib import Path

import kali_mcp_launcher as launcher


class HostProfileTests(unittest.TestCase):
    def test_linux_defaults_to_linux_full_on_supported_architectures(self):
        for machine in ("x86_64", "amd64", "aarch64", "arm64"):
            with self.subTest(machine=machine):
                host = launcher.detect_host("Linux", machine)
                self.assertEqual("linux-full", launcher.select_profile(host, None))

    def test_apple_silicon_defaults_to_mac_hardened(self):
        host = launcher.detect_host("Darwin", "arm64")
        self.assertEqual("mac-hardened", launcher.select_profile(host, None))

    def test_intel_mac_is_rejected_readably(self):
        with self.assertRaisesRegex(launcher.LauncherError, "unsupported_platform.*Intel macOS"):
            launcher.detect_host("Darwin", "x86_64")

    def test_profiles_cannot_be_forced_onto_incompatible_hosts(self):
        linux = launcher.detect_host("Linux", "x86_64")
        mac = launcher.detect_host("Darwin", "arm64")
        with self.assertRaisesRegex(launcher.LauncherError, "unavailable"):
            launcher.select_profile(linux, "mac-hardened")
        with self.assertRaisesRegex(launcher.LauncherError, "unavailable"):
            launcher.select_profile(mac, "linux-full")


class DockerArgumentTests(unittest.TestCase):
    def test_profile_networking_and_security_arguments(self):
        cases = {
            "linux-full": "host",
            "linux-hardened": "bridge",
            "mac-hardened": "bridge",
        }
        for profile, network in cases.items():
            with self.subTest(profile=profile):
                args = launcher.build_docker_command(profile, "kali-mcp-server:test", {})
                self.assertIn(f"--network={network}", args)
                self.assertIn("--security-opt=no-new-privileges", args)
                self.assertIn("--cap-drop=ALL", args)
                self.assertIn("--read-only", args)
                self.assertIn(f"KALI_MCP_PROFILE={profile}", args)
                self.assertNotIn("--privileged", args)
                self.assertFalse(any("docker.sock" in arg for arg in args))
                self.assertFalse(any(arg.startswith("--cap-add") for arg in args))

    def test_input_mounts_are_read_only_and_outputs_are_writable(self):
        with tempfile.TemporaryDirectory(prefix="kali mcp ") as root:
            paths = {
                "workspace": root,
                "artifacts": root,
                "results": root,
                "reports": root,
                "secrets": root,
            }
            args = launcher.build_docker_command("linux-full", "kali-mcp-server:test", paths)
            mounts = [args[index + 1] for index, value in enumerate(args) if value == "--mount"]
            resolved = str(Path(root).resolve())
            self.assertIn(f"type=bind,src={resolved},dst=/workspace,readonly", mounts)
            self.assertIn(f"type=bind,src={resolved},dst=/artifacts,readonly", mounts)
            self.assertIn(f"type=bind,src={resolved},dst=/results", mounts)
            self.assertIn(f"type=bind,src={resolved},dst=/reports", mounts)
            self.assertIn(f"type=bind,src={resolved},dst=/run/secrets,readonly", mounts)

    def test_missing_mount_and_unsafe_image_fail_readably(self):
        with self.assertRaisesRegex(launcher.LauncherError, "invalid_mount"):
            launcher.build_docker_command("linux-full", "kali-mcp-server:test", {"workspace": "/does/not/exist"})
        with self.assertRaisesRegex(launcher.LauncherError, "invalid_image"):
            launcher.build_docker_command("linux-full", "--privileged", {})

    def test_ephemeral_output_mounts_are_used_when_not_persisted(self):
        args = launcher.build_docker_command("linux-full", "kali-mcp-server:test", {})
        tmpfs = [args[index + 1] for index, value in enumerate(args) if value == "--tmpfs"]
        self.assertTrue(any(value.startswith("/results:") for value in tmpfs))
        self.assertTrue(any(value.startswith("/reports:") for value in tmpfs))


class CliTests(unittest.TestCase):
    def test_dry_run_does_not_execute_docker(self):
        result = launcher.main(
            ["--dry-run", "--image", "kali-mcp-server:test"],
            system="Linux",
            machine="x86_64",
            exec_command=lambda _args: self.fail("dry-run executed Docker"),
        )
        self.assertEqual(0, result)


if __name__ == "__main__":
    unittest.main()
