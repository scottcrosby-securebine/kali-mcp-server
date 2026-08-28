"""#51: a depth-bomb result file must be skipped, not crash both callers.

`_load_normalized_results` decoded with `json.loads` under an except tuple of
(OSError, UnicodeError, ValueError, json.JSONDecodeError). A deeply nested
document raises RecursionError, which is none of those, so it escaped and took
down `list_results` and the no-ref `generate_report` with it. `_load_json` has
caught RecursionError all along; the loader now uses it.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server

# Deep enough to exhaust the interpreter's stack in json's recursive decoder,
# small enough to stay far under MAX_ARTIFACT_BYTES so the size guard above
# cannot be what rejects it. Proven by the control test below.
DEPTH = 200_000
DEPTH_BOMB = "[" * DEPTH + "]" * DEPTH


class DepthBombResultsAreSkipped(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def _load(self, results):
        # A RecursionError escaping here is the defect itself, and an ERROR is
        # exactly what `scripts/mutation-check` refuses to accept as proof that
        # an assertion pins anything. Convert it to a FAILURE so the mutation
        # gate can certify this test against a base revision that still has the
        # bug (the #27 R8-B2 lesson: absence must fail, never error).
        with patch.object(self.server, "RESULTS_ROOT", Path(results)):
            try:
                return self.server._load_normalized_results()
            except RecursionError:
                self.fail(
                    "_load_normalized_results raised RecursionError instead of "
                    "skipping the undecodable file"
                )

    def _valid_document(self):
        return {
            "schema_version": 1,
            "scanner": "whatweb",
            "target": "example.test",
            "findings": [{"id": "x", "severity": "Info", "evidence": "e"}],
        }

    def test_a_depth_bomb_does_not_take_the_loader_down(self):
        with tempfile.TemporaryDirectory() as results:
            (Path(results) / "bomb.json").write_text(DEPTH_BOMB, encoding="utf-8")
            # Before the fix this raised RecursionError out of the loader.
            self.assertEqual([], self._load(results))

    def test_a_valid_result_beside_a_depth_bomb_still_loads(self):
        # The failure mode that matters to a user: one poisoned file must not
        # cost them every other captured result.
        with tempfile.TemporaryDirectory() as results:
            (Path(results) / "bomb.json").write_text(DEPTH_BOMB, encoding="utf-8")
            (Path(results) / "good.json").write_text(
                json.dumps(self._valid_document()), encoding="utf-8"
            )
            entries = self._load(results)
            self.assertEqual(["good"], [entry[0] for entry in entries])

    def test_the_bomb_is_rejected_by_the_decoder_not_the_size_guard(self):
        # Control. If the file were merely oversized, the fix would be untested
        # and this suite would pass for the wrong reason.
        self.assertLess(len(DEPTH_BOMB.encode()), self.server.MAX_ARTIFACT_BYTES)
        with self.assertRaises(RecursionError):
            json.loads(DEPTH_BOMB)


if __name__ == "__main__":
    unittest.main()
