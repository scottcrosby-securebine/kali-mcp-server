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
    def test_responder_is_readably_unavailable_in_every_current_profile(self):
        for profile in ("linux-full", "linux-hardened", "mac-hardened"):
            with self.subTest(profile=profile), patch.dict(os.environ, {"KALI_MCP_PROFILE": profile}):
                result = asyncio.run(server.responder_analyze())
                self.assertTrue(result.startswith("unavailable:"))
                self.assertIn("responder_analyze", result)
                self.assertIn(profile, result)
                self.assertIn("raw/link-layer", result)


if __name__ == "__main__":
    unittest.main()
