import ast
import asyncio
from contextlib import ExitStack
import inspect
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from server_test_support import load_server


TESTS_DIR = Path(__file__).resolve().parent
SERVER_PATH = TESTS_DIR.parent / "kali_pentest_server.py"
CONTRACT_PATH = TESTS_DIR / "fixtures" / "legacy_tool_contract.json"


class LegacyToolContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.server, cls.mcp = load_server()

    def test_fixture_is_a_static_unique_42_tool_inventory(self):
        self.assertEqual(1, self.contract["schema_version"])
        self.assertEqual(
            {"schema_version", "tools", "additions", "composites", "never_auto_chain"},
            set(self.contract),
        )
        names = [tool["name"] for tool in self.contract["tools"]]
        self.assertEqual(42, len(names))
        self.assertEqual(42, len(set(names)))
        for tool in self.contract["tools"] + self.contract["additions"]:
            self.assertEqual({"name", "parameters", "return"}, set(tool))
            self.assertEqual("str", tool["return"])
            for parameter in tool["parameters"]:
                self.assertEqual({"name", "default"}, set(parameter))
                self.assertIsInstance(parameter["default"], str)

    def test_every_declared_signature_matches_exactly(self):
        for expected in self.contract["tools"] + self.contract["additions"]:
            with self.subTest(tool=expected["name"]):
                function = getattr(self.server, expected["name"])
                signature = inspect.signature(function)
                actual_parameters = [
                    {"name": parameter.name, "default": parameter.default}
                    for parameter in signature.parameters.values()
                ]
                self.assertEqual(expected["parameters"], actual_parameters)
                self.assertIs(str, signature.return_annotation)

    def test_registration_preserves_ordered_inventory(self):
        expected = [
            tool["name"]
            for tool in self.contract["tools"] + self.contract["additions"]
        ]
        self.assertEqual(expected, [function.__name__ for function in self.mcp.tools])
        self.assertEqual(
            [getattr(self.server, name) for name in expected],
            self.mcp.tools,
            "registered tools must be the module's current callables",
        )

    def test_default_invocation_returns_string_without_subprocess(self):
        with patch.object(self.server, "run_command") as run_command:
            for expected in self.contract["tools"] + self.contract["additions"]:
                with self.subTest(tool=expected["name"]):
                    result = asyncio.run(getattr(self.server, expected["name"])())
                    self.assertIsInstance(result, str)
            run_command.assert_not_called()

    def test_composite_call_graph_matches_contract_and_excludes_explicit_only(self):
        module = ast.parse(SERVER_PATH.read_text(encoding="utf-8"))
        definitions = {
            node.name: node
            for node in module.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        public_names = {
            tool["name"]
            for tool in self.contract["tools"] + self.contract["additions"]
        }
        explicit_only = set(self.contract["never_auto_chain"])

        for function_name, definition in definitions.items():
            direct_explicit_calls = {
                node.func.id
                for node in ast.walk(definition)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in explicit_only
                and node.func.id != function_name
            }
            self.assertEqual(
                set(),
                direct_explicit_calls,
                f"{function_name} must not auto-chain explicit-only tools",
            )

        direct_calls = {
            function_name: {
                node.func.id
                for node in ast.walk(definition)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in definitions
            }
            for function_name, definition in definitions.items()
        }
        actual = {}
        for tool_name in public_names:
            boundaries = set()
            visited = set()
            pending = [tool_name]
            while pending:
                function_name = pending.pop()
                if function_name in visited:
                    continue
                visited.add(function_name)
                for called in direct_calls[function_name]:
                    if called in public_names and called != tool_name:
                        boundaries.add(called)
                    elif called not in public_names:
                        pending.append(called)
            if tool_name in self.contract["composites"]:
                self.assertNotIn(
                    "run_command",
                    visited,
                    f"{tool_name} must delegate through public tool wrappers",
                )
            if boundaries:
                actual[tool_name] = boundaries
        expected = {
            composite: set(calls)
            for composite, calls in self.contract["composites"].items()
        }
        self.assertEqual(expected, actual)

    def _run_composite(self, composite, target, expected_calls):
        call_log = []
        with ExitStack() as stack:
            run_command = stack.enter_context(patch.object(self.server, "run_command"))
            public_tools = [
                tool["name"]
                for tool in self.contract["tools"] + self.contract["additions"]
                if tool["name"] != composite
            ]
            for dependency in public_tools:
                replacement = AsyncMock(
                    side_effect=lambda *args, _name=dependency: (
                        call_log.append((_name, args)) or _name
                    )
                )
                stack.enter_context(patch.object(self.server, dependency, replacement))
            result = asyncio.run(getattr(self.server, composite)(target))
        self.assertIsInstance(result, str)
        self.assertEqual(expected_calls, call_log)
        run_command.assert_not_called()

    def test_composites_preserve_exact_runtime_order_arguments_and_conditions(self):
        cases = (
            (
                "quick_recon",
                "example.test",
                [
                    ("nmap_scan", ("example.test",)),
                    ("whatweb_scan", ("example.test", "1")),
                    ("whois_lookup", ("example.test",)),
                ],
            ),
            (
                "quick_recon",
                "192.0.2.1",
                [
                    ("nmap_scan", ("192.0.2.1",)),
                    ("whatweb_scan", ("192.0.2.1", "1")),
                ],
            ),
            (
                "full_recon",
                "example.test",
                [
                    ("nmap_service_scan", ("example.test",)),
                    ("dns_enum", ("example.test",)),
                    ("subfinder_scan", ("example.test",)),
                    ("whatweb_scan", ("example.test", "3")),
                    ("sslscan_scan", ("example.test",)),
                ],
            ),
            (
                "full_recon",
                "192.0.2.1",
                [
                    ("nmap_service_scan", ("192.0.2.1",)),
                    ("whatweb_scan", ("192.0.2.1", "3")),
                    ("sslscan_scan", ("192.0.2.1",)),
                ],
            ),
            (
                "web_audit",
                "https://example.test/path",
                [
                    ("whatweb_scan", ("https://example.test/path", "3")),
                    ("wafw00f_scan", ("https://example.test/path",)),
                    ("web_headers", ("https://example.test/path",)),
                    ("nikto_scan", ("https://example.test/path",)),
                    ("nuclei_scan", ("https://example.test/path",)),
                    ("sslscan_scan", ("example.test",)),
                ],
            ),
            (
                "web_audit",
                "example.test",
                [
                    ("whatweb_scan", ("http://example.test", "3")),
                    ("wafw00f_scan", ("http://example.test",)),
                    ("web_headers", ("http://example.test",)),
                    ("nikto_scan", ("http://example.test",)),
                    ("nuclei_scan", ("http://example.test",)),
                ],
            ),
            (
                "network_sweep",
                "192.0.2.0/24",
                [
                    ("nmap_scan", ("192.0.2.0/24",)),
                    ("nbtscan_scan", ("192.0.2.0/24",)),
                ],
            ),
        )
        for composite, target, expected in cases:
            with self.subTest(composite=composite, target=target):
                self._run_composite(composite, target, expected)

    def test_invalid_composite_targets_never_chain(self):
        for composite in self.contract["composites"]:
            with self.subTest(composite=composite):
                self._run_composite(composite, "", [])

    def test_explicit_only_tools_remain_directly_callable(self):
        cases = {
            "nmap_script_scan": ("192.0.2.1", "safe"),
            "sqlmap_scan": ("https://example.test/?id=1",),
            "crackmapexec_scan": ("192.0.2.1",),
            "hydra_attack": ("192.0.2.1", "ssh", "tester"),
            "john_crack": ("/workspace/hashes.txt",),
            "hashcat_crack": ("/workspace/hashes.txt",),
            "metasploit_search": ("CVE-2021-44228",),
            "metasploit_info": ("exploit/test/module",),
        }
        self.assertEqual(set(self.contract["never_auto_chain"]), set(cases))
        for name, arguments in cases.items():
            with (
                self.subTest(tool=name),
                patch.object(self.server.os.path, "exists", return_value=True),
                patch.object(
                    self.server,
                    "run_command",
                    return_value="direct-call-ok",
                ) as run_command,
            ):
                result = asyncio.run(getattr(self.server, name)(*arguments))
                self.assertEqual("direct-call-ok", result)
                run_command.assert_called()


if __name__ == "__main__":
    unittest.main()
