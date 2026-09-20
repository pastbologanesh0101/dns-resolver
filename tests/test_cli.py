"""Tests for the resolve.py CLI, run as a subprocess against the toy
server so they exercise argument parsing and output formatting exactly
as a real user would invoke them.
"""

import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from server import ToyDNSServer, load_zone  # noqa: E402

ZONE_PATH = os.path.join(REPO_ROOT, "zones", "example.json")
RESOLVE_PY = os.path.join(REPO_ROOT, "resolve.py")


class CliTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        zone = load_zone(ZONE_PATH)
        cls.server = ToyDNSServer(zone, host="127.0.0.1", port=0)
        cls.server.start()
        cls.port = cls.server.port

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, RESOLVE_PY, *args],
            capture_output=True, text=True, timeout=10,
        )


class TestShortFlag(CliTestCase):
    def test_short_flag_prints_only_the_value(self):
        result = self._run("example.com", "--server", f"127.0.0.1:{self.port}", "--short")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "93.184.216.34")

    def test_short_flag_prints_one_line_per_answer(self):
        result = self._run("toylab.dev", "--server", f"127.0.0.1:{self.port}", "--short")
        self.assertEqual(result.returncode, 0)
        values = sorted(result.stdout.strip().splitlines())
        self.assertEqual(values, ["10.0.0.1", "10.0.0.2"])

    def test_without_short_flag_prints_formatted_columns(self):
        result = self._run("example.com", "--server", f"127.0.0.1:{self.port}")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Resolved example.com", result.stdout)


class TestInvalidServerArg(CliTestCase):
    def test_malformed_server_port_exits_cleanly_with_message(self):
        result = self._run("example.com", "--server", "127.0.0.1:notaport")
        self.assertEqual(result.returncode, 3)
        self.assertIn("invalid --server value", result.stderr)


if __name__ == "__main__":
    unittest.main()
