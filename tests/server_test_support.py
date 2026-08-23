"""Dependency-free test support for importing the MCP server."""

import importlib
import sys
import types


class FakeFastMCP:
    """Small FastMCP stand-in that records decorated tool functions in order."""

    instances = []

    def __init__(self, name):
        self.name = name
        self.tools = []
        self.__class__.instances.append(self)

    def tool(self):
        def register(function):
            self.tools.append(function)
            return function

        return register

    def run(self, transport="stdio"):
        self.transport = transport


def load_server():
    """Import a fresh server module with FastMCP replaced by the recorder."""
    FakeFastMCP.instances.clear()
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_fastmcp.FastMCP = FakeFastMCP
    fake_server = types.ModuleType("mcp.server")
    fake_server.fastmcp = fake_fastmcp
    fake_mcp = types.ModuleType("mcp")
    fake_mcp.server = fake_server
    sys.modules.update(
        {
            "mcp": fake_mcp,
            "mcp.server": fake_server,
            "mcp.server.fastmcp": fake_fastmcp,
        }
    )
    sys.modules.pop("kali_pentest_server", None)
    module = importlib.import_module("kali_pentest_server")
    return module, FakeFastMCP.instances[-1]
