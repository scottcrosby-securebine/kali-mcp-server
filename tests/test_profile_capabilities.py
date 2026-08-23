import asyncio
import os
import sys
import types
import unittest
from unittest.mock import patch

fake_fastmcp = types.ModuleType("mcp.server.fastmcp")


class FakeFastMCP:
    def __init__(self, _name):
        pass

    def tool(self):
        return lambda function: function


fake_fastmcp.FastMCP = FakeFastMCP
sys.modules.setdefault("mcp", types.ModuleType("mcp"))
sys.modules.setdefault("mcp.server", types.ModuleType("mcp.server"))
sys.modules.setdefault("mcp.server.fastmcp", fake_fastmcp)

import kali_pentest_server as server


class ProfileCapabilityTests(unittest.TestCase):
    def test_broadcast_nse_category_fails_before_command_execution(self):
        for profile in ("linux-full", "linux-hardened", "mac-hardened"):
            with (
                self.subTest(profile=profile),
                patch.dict(os.environ, {"KALI_MCP_PROFILE": profile}),
                patch.object(server, "run_command") as run_command,
            ):
                result = asyncio.run(server.nmap_script_scan("192.0.2.1", "safe,broadcast"))
                self.assertEqual(
                    f"capability_missing: nmap_script_scan requires raw/link-layer networking in profile '{profile}'",
                    result,
                )
                run_command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
