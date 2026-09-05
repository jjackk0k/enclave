"""Menu logic (menuops): health checks against the mock server, ssh command
construction for the lane script, launch-command building for the REPL and
the menu, and spawn error paths. The tkinter window itself (menu.py) needs a
display - here we only prove it imports headless."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spark_code import config, menuops

from tests.mock_server import MockSparkServer


class TestHealthAndModel(unittest.TestCase):
    def test_health_ok_against_mock(self):
        with MockSparkServer() as srv:
            # /health isn't a mock route: a 404 still proves HTTP answers
            ok, detail = self._health(srv.base_url)
            self.assertFalse(ok)  # 404 = lane answers but route unknown
            self.assertIn("404", detail)

    def _health(self, base):
        with mock.patch.object(config, "BASE_URL", base):
            return menuops.health()

    def test_health_down_is_honest(self):
        ok, detail = self._health("http://127.0.0.1:9")
        self.assertFalse(ok)
        self.assertIn("unreachable", detail)

    def test_current_model(self):
        with MockSparkServer() as srv:
            with mock.patch.object(config, "BASE_URL", srv.base_url):
                self.assertEqual(menuops.current_model(), "mock-heretic-27b")
        with mock.patch.object(config, "BASE_URL", "http://127.0.0.1:9"):
            self.assertIsNone(menuops.current_model())


class TestLaneSsh(unittest.TestCase):
    def test_command_shape(self):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return type("P", (), {"returncode": 0, "stdout": "a.gguf\nb.gguf\n",
                                  "stderr": ""})()

        with mock.patch.object(menuops.subprocess, "run", fake_run):
            ok, names, raw = menuops.lane_list()
        self.assertTrue(ok)
        self.assertEqual(names, ["a.gguf", "b.gguf"])
        cmd = captured["cmd"]
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("BatchMode=yes", cmd)
        self.assertIn(config.SSH_TARGET, cmd)
        self.assertIn("lane-models.sh list", cmd[-1])

    def test_ssh_failure_is_honest(self):
        with mock.patch.object(menuops.subprocess, "run",
                               side_effect=OSError("ssh.exe missing")):
            ok, out = menuops.lane_ssh(["status"])
        self.assertFalse(ok)
        self.assertIn("ssh failed", out)


class TestLaunchCommands(unittest.TestCase):
    def test_repl_cmd_default_uses_python_module(self):
        with mock.patch.object(menuops, "REPL_EXE",
                               Path("Z:/nope/spark-code.exe")):
            cmd = menuops.launch_repl_cmd()
        self.assertEqual(cmd[-2:], ["-m", "spark_code"])
        self.assertNotIn("--resume-last", cmd)
        self.assertTrue(cmd[0].lower().endswith("python.exe"))

    def test_repl_cmd_prefers_built_exe(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "spark-code.exe"
            exe.write_bytes(b"MZ")
            with mock.patch.object(menuops, "REPL_EXE", exe):
                cmd = menuops.launch_repl_cmd(resume_last=True)
        self.assertEqual(cmd, [str(exe), "--resume-last"])

    def test_pythonw_swaps_to_console_python(self):
        exe = sys.executable
        with mock.patch.object(sys, "executable",
                               exe.replace("python.exe", "pythonw.exe")):
            self.assertTrue(menuops.python_for_console().lower().endswith("python.exe"))

    def test_spawn_repl_error_is_honest(self):
        with mock.patch.object(menuops.subprocess, "Popen",
                               side_effect=OSError("no console")):
            ok, msg = menuops.spawn_repl("C:/x")
        self.assertFalse(ok)
        self.assertIn("launch failed", msg)

    def test_spawn_menu_detached(self):
        seen = {}

        def fake_popen(cmd, **kw):
            seen["cmd"] = cmd
            return mock.Mock()

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(menuops, "MENU_EXE", Path(tmp) / "none.exe"), \
                    mock.patch.object(menuops.subprocess, "Popen", fake_popen):
                ok, msg = menuops.spawn_menu_detached()
        self.assertTrue(ok, msg)
        self.assertEqual(seen["cmd"][-2:], ["-m", "spark_code.menu"])

    def test_menu_module_imports_headless(self):
        import spark_code.menu  # tkinter import must not need a display
        self.assertTrue(hasattr(spark_code.menu, "MenuApp"))


if __name__ == "__main__":
    unittest.main()
