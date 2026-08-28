"""#47: a spawned tool must not inherit the server's stdin.

Under stdio transport fd 0 is the MCP read pipe. A tool that prompts drains the
frames the server is waiting on, the server sees EOF, and the session ends with
a clean exit 0 mid-run. `execute_command` is the only place a subprocess is
spawned, so one guard there covers every tool.

The first test is deliberately end-to-end rather than a mock: it puts real bytes
on the driver's fd 0 and asserts a child cannot read them. A mock asserting
`stdin=DEVNULL` was passed would pass just as happily against a `subprocess.run`
that ignored the argument.
"""
import os
import subprocess
import sys
import textwrap
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Loads the server the way every other suite does, runs one command through the
# public seam, and reports what the child managed to read from fd 0.
DRIVER = textwrap.dedent(
    """
    import sys
    sys.path.insert(0, {tests!r})
    from server_test_support import load_server
    server, _ = load_server()
    result = server.execute_command([{cmd!r}], timeout=10)
    sys.stdout.write("CHILD_READ:" + repr(result.stdout))
    """
)


def _run_driver(cmd, stdin_bytes):
    """Run the driver with stdin_bytes sitting on its fd 0."""
    script = DRIVER.format(tests=os.path.join(REPO, "tests"), cmd=cmd)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        input=stdin_bytes,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO,
    )
    for line in completed.stdout.splitlines():
        if line.startswith("CHILD_READ:"):
            return line[len("CHILD_READ:"):]
    raise AssertionError(
        f"driver produced no verdict.\nstdout={completed.stdout!r}\n"
        f"stderr={completed.stderr!r}"
    )


class SpawnedToolsCannotReachTheServersStdin(unittest.TestCase):
    def test_a_child_reading_stdin_gets_eof_not_the_servers_frames(self):
        # `cat` stands in for any tool that reads fd 0 when it finds one open.
        # Without the guard it echoes whatever the server's peer sent, which is
        # both a leak of protocol traffic into tool output and the theft that
        # ends the session.
        child_read = _run_driver("cat", "MCP_FRAME_THE_SERVER_NEEDED\n")
        self.assertEqual(
            "''",
            child_read,
            "the child read the driver's stdin, so fd 0 is still inherited",
        )

    def test_a_child_does_not_block_on_a_pipe_nobody_closes(self):
        # The hang half of the same defect, and a different failure mode from
        # the test above: an inherited pipe that stays OPEN never reaches EOF,
        # so the tool waits for input that will never come. Feeding the driver
        # an already-closed stdin cannot detect this -- it reads EOF either way
        # -- so the pipe is held open for the life of the child.
        script = DRIVER.format(tests=os.path.join(REPO, "tests"), cmd="cat")
        child = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=REPO,
        )
        # NOT communicate(): it closes stdin immediately, which hands the child
        # the EOF this test exists to withhold. The write end stays open until
        # the driver has exited.
        try:
            child.wait(timeout=60)
        except subprocess.TimeoutExpired:
            child.kill()
            self.fail(
                "the driver never returned: the child inherited an open fd 0 "
                "and blocked waiting for input that was never coming"
            )
        finally:
            stdout = child.stdout.read()
            stderr = child.stderr.read()
            child.stdin.close()
            child.stdout.close()
            child.stderr.close()
        self.assertIn("CHILD_READ:''", stdout, f"stderr={stderr!r}")


class TheInputTextPathStillDelivers(unittest.TestCase):
    """The guard must not break the one caller that does feed a child."""

    def test_input_text_still_reaches_the_child(self):
        sys.path.insert(0, os.path.join(REPO, "tests"))
        from server_test_support import load_server

        server, _ = load_server()
        result = server.execute_command(["cat"], timeout=10, input_text="fed\n")
        self.assertEqual("fed\n", result.stdout)

    def test_passing_both_input_and_a_stdin_handle_is_rejected_by_subprocess(self):
        # Why the guard is conditional rather than unconditional: these two
        # arguments cannot both be given, so a flat `stdin=DEVNULL` would break
        # the msfconsole/resource-script caller.
        with self.assertRaises(ValueError):
            subprocess.run(
                ["cat"],
                capture_output=True,
                text=True,
                input="x",
                stdin=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    unittest.main()
