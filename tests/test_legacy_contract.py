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
        for tool in self.contract["tools"]:
            self.assertEqual({"name", "parameters", "return"}, set(tool))
            self.assertEqual("str", tool["return"])
            for parameter in tool["parameters"]:
                self.assertEqual({"name", "default"}, set(parameter))
                self.assertIsInstance(parameter["default"], str)

    def test_every_legacy_signature_matches_exactly(self):
        for expected in self.contract["tools"]:
            with self.subTest(tool=expected["name"]):
                function = getattr(self.server, expected["name"])
                signature = inspect.signature(function)
                actual_parameters = [
                    {"name": parameter.name, "default": parameter.default}
                    for parameter in signature.parameters.values()
                ]
                self.assertEqual(expected["parameters"], actual_parameters)
                self.assertIs(str, signature.return_annotation)

    def test_registration_preserves_ordered_legacy_inventory(self):
        expected = [tool["name"] for tool in self.contract["tools"]]
        registered = [function.__name__ for function in self.mcp.tools]
        self.assertEqual(expected + self.contract["additions"], registered)

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
        legacy_names = {tool["name"] for tool in self.contract["tools"]}
        actual = {}
        for composite in self.contract["composites"]:
            calls = []
            for node in ast.walk(definitions[composite]):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in legacy_names and node.func.id != composite:
                        calls.append((node.lineno, node.func.id))
            actual[composite] = [name for _line, name in sorted(calls)]
        self.assertEqual(self.contract["composites"], actual)
        chained = {name for calls in actual.values() for name in calls}
        self.assertTrue(chained.isdisjoint(self.contract["never_auto_chain"]))

        explicit_only = set(self.contract["never_auto_chain"])
        public_names = legacy_names | {
            tool["name"] for tool in self.contract["additions"]
        }
        module_functions = set(definitions)
        module_aliases = {}
        for statement in module.body:
            if (
                isinstance(statement, (ast.Assign, ast.AnnAssign))
                and isinstance(statement.value, ast.Name)
                and statement.value.id in module_functions
            ):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        module_aliases[target.id] = statement.value.id
        call_graph = {}
        explicit_references = {}
        for function_name, definition in definitions.items():
            called_names = set()
            referenced_explicit = set()
            for node in ast.walk(definition):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        called_names.add(module_aliases.get(node.func.id, node.func.id))
                    elif isinstance(node.func, ast.Attribute):
                        called_names.add(node.func.attr)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    if node.id in explicit_only and node.id != function_name:
                        referenced_explicit.add(node.id)
                elif isinstance(node, ast.Attribute) and node.attr in explicit_only:
                    if node.attr != function_name:
                        referenced_explicit.add(node.attr)
                elif isinstance(node, ast.Constant) and node.value in explicit_only:
                    referenced_explicit.add(node.value)
            call_graph[function_name] = called_names & module_functions
            explicit_references[function_name] = referenced_explicit

        for tool_name in public_names - explicit_only:
            reachable = set()
            pending = [tool_name]
            while pending:
                function_name = pending.pop()
                if function_name in reachable:
                    continue
                reachable.add(function_name)
                pending.extend(call_graph.get(function_name, set()) - reachable)
            chained_explicit_tools = set().union(
                *(explicit_references.get(function_name, set()) for function_name in reachable)
            )
            self.assertEqual(
                set(),
                chained_explicit_tools,
                f"{tool_name} must not auto-chain explicit-only tools",
            )

    def _run_composite(self, composite, target, expected_calls):
        call_log = []
        with ExitStack() as stack:
            public_tools = [
                tool["name"]
                for tool in self.contract["tools"] + self.contract["additions"]
                if tool["name"] != composite
            ]
            for dependency in public_tools:
                replacement = AsyncMock(
                    side_effect=lambda *args, _name=dependency: call_log.append((_name, args)) or _name
                )
                stack.enter_context(patch.object(self.server, dependency, replacement))
            result = asyncio.run(getattr(self.server, composite)(target))
        self.assertIsInstance(result, str)
        self.assertEqual(expected_calls, call_log)

    def test_composites_preserve_exact_runtime_order_arguments_and_conditions(self):
        cases = (
            ("quick_recon", "example.test", [
                ("nmap_scan", ("example.test",)),
                ("whatweb_scan", ("example.test", "1")),
                ("whois_lookup", ("example.test",)),
            ]),
            ("quick_recon", "192.0.2.1", [
                ("nmap_scan", ("192.0.2.1",)),
                ("whatweb_scan", ("192.0.2.1", "1")),
            ]),
            ("full_recon", "example.test", [
                ("nmap_service_scan", ("example.test",)),
                ("dns_enum", ("example.test",)),
                ("subfinder_scan", ("example.test",)),
                ("whatweb_scan", ("example.test", "3")),
                ("sslscan_scan", ("example.test",)),
            ]),
            ("full_recon", "192.0.2.1", [
                ("nmap_service_scan", ("192.0.2.1",)),
                ("whatweb_scan", ("192.0.2.1", "3")),
                ("sslscan_scan", ("192.0.2.1",)),
            ]),
            ("web_audit", "https://example.test/path", [
                ("whatweb_scan", ("https://example.test/path", "3")),
                ("wafw00f_scan", ("https://example.test/path",)),
                ("web_headers", ("https://example.test/path",)),
                ("nikto_scan", ("https://example.test/path",)),
                ("sslscan_scan", ("example.test",)),
            ]),
            ("web_audit", "example.test", [
                ("whatweb_scan", ("http://example.test", "3")),
                ("wafw00f_scan", ("http://example.test",)),
                ("web_headers", ("http://example.test",)),
                ("nikto_scan", ("http://example.test",)),
            ]),
            ("network_sweep", "192.0.2.0/24", [
                ("nmap_scan", ("192.0.2.0/24",)),
                ("nbtscan_scan", ("192.0.2.0/24",)),
            ]),
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
                patch.object(self.server, "run_command", return_value="direct-call-ok") as run_command,
            ):
                result = asyncio.run(getattr(self.server, name)(*arguments))
                self.assertEqual("direct-call-ok", result)
                run_command.assert_called()


if __name__ == "__main__":
    unittest.main()
