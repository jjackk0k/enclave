"""Docker self-sufficiency for the 1-click START (opsmenu.ensure_docker):
probe the engine -> launch Docker Desktop when down -> bounded wait for
readiness, with honest states (up / started / starting-timeout / down /
missing / error), never a raise into start_hunt, and the START message
carrying the docker verdict. Every spawn is an injected fake — the suite
never touches a real docker; the one win32 test pins the new spawns to the
windowless (no-console-flash) contract through the REAL hidden helpers."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spark_code import menuops, opsmenu

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
DESKTOP = r"C:\Program Files\Docker\Docker\Docker Desktop.exe"
CLI = r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"


def _run_result(stdout="", stderr="", returncode=0):
    return type("R", (), {"stdout": stdout, "stderr": stderr, "returncode": returncode})()


class _Clock:
    """Fake monotonic clock: sleeper() advances time by the real poll
    interval, so a 120s bounded wait runs instantly while the elapsed
    seconds reported stay honest."""

    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += s


def _no_spawn(cmd, **kw):
    raise AssertionError(f"nothing may spawn here: {cmd}")


class TestEnsureDocker(unittest.TestCase):
    def setUp(self):
        self._saved = opsmenu._DOCKER_LAST
        opsmenu._DOCKER_LAST = None

    def tearDown(self):
        opsmenu._DOCKER_LAST = self._saved

    def test_engine_already_up_spawns_nothing(self):
        calls = []

        def runner(cmd, **kw):
            calls.append(list(cmd))
            return _run_result(stdout="Server Version: 27.3.1", returncode=0)

        state, detail = opsmenu.ensure_docker(runner=runner, popen=_no_spawn)
        self.assertEqual(state, "up")
        self.assertIn("already", detail)
        self.assertEqual(calls, [["docker", "info"]],
                         "the only cost of an up engine is one probe")
        self.assertEqual(opsmenu._DOCKER_LAST, (state, detail),
                         "the verdict is remembered for the STATE rail")

    def test_down_launches_desktop_and_waits_for_ready(self):
        launched = []
        probes = {"n": 0}

        def runner(cmd, **kw):
            probes["n"] += 1
            if probes["n"] <= 2:
                return _run_result(stderr="error during connect: pipe not found",
                                   returncode=1)
            return _run_result(stdout="Server Version: 27.3.1", returncode=0)

        def popen(cmd, **kw):
            launched.append(list(cmd))
            return mock.Mock(pid=9999)

        clock = _Clock()
        state, detail = opsmenu.ensure_docker(
            runner=runner, popen=popen, desktop_finder=lambda: DESKTOP,
            which=lambda name: CLI, sleeper=clock.sleep, clock=clock.monotonic)
        self.assertEqual(state, "started")
        self.assertIn("engine ready after 3s", detail,
                      "one poll interval of waiting, honestly counted")
        self.assertEqual(launched, [[DESKTOP]],
                         "Docker Desktop is launched exactly once, by its exe path")

    def test_starting_timeout_is_honest_never_a_lied_green(self):
        def runner(cmd, **kw):
            return _run_result(stderr="error during connect: pipe not found",
                               returncode=1)

        popen = mock.Mock(return_value=mock.Mock(pid=1))
        clock = _Clock()
        state, detail = opsmenu.ensure_docker(
            wait_s=9.0, poll_s=3.0, runner=runner, popen=popen,
            desktop_finder=lambda: DESKTOP, which=lambda name: CLI,
            sleeper=clock.sleep, clock=clock.monotonic)
        self.assertEqual(state, "starting-timeout")
        self.assertIn("did not answer within 9s", detail)
        self.assertIn("last probe", detail, "the timeout carries its evidence")
        popen.assert_called_once_with([DESKTOP])
        self.assertEqual(clock.t, 9.0, "the wait is bounded, not indefinite")

    def test_missing_when_no_cli_and_no_desktop(self):
        def runner(cmd, **kw):
            raise FileNotFoundError("docker")

        state, detail = opsmenu.ensure_docker(
            runner=runner, popen=_no_spawn,
            desktop_finder=lambda: None, which=lambda name: None)
        self.assertEqual(state, "missing")
        self.assertIn("degrades", detail)
        self.assertIn("no docker CLI", detail)

    def test_down_when_cli_exists_but_no_desktop_to_launch(self):
        def runner(cmd, **kw):
            return _run_result(stderr="Cannot connect to the Docker daemon",
                               returncode=1)

        state, detail = opsmenu.ensure_docker(
            runner=runner, popen=_no_spawn,
            desktop_finder=lambda: None, which=lambda name: "/usr/bin/docker")
        self.assertEqual(state, "down")
        self.assertIn("no Docker Desktop.exe", detail)

    def test_desktop_launch_failure_is_an_error_state_never_raised(self):
        def runner(cmd, **kw):
            return _run_result(stderr="pipe not found", returncode=1)

        def popen(cmd, **kw):
            raise OSError("winerror 740: elevation required")

        state, detail = opsmenu.ensure_docker(
            runner=runner, popen=popen, desktop_finder=lambda: DESKTOP,
            which=lambda name: CLI)
        self.assertEqual(state, "error")
        self.assertIn("OSError", detail)

    def test_ensure_never_raises_even_when_a_check_explodes(self):
        def runner(cmd, **kw):
            return _run_result(stderr="pipe not found", returncode=1)

        def boom():
            raise OSError("registry hive on fire")

        state, detail = opsmenu.ensure_docker(
            runner=runner, popen=_no_spawn, desktop_finder=boom,
            which=lambda name: CLI)
        self.assertEqual(state, "error")
        self.assertIn("docker ensure failed", detail)

    def test_cli_falls_back_to_the_desktop_install_sibling(self):
        """A console started before the Desktop install lacks the CLI on PATH;
        the engine probe then rides the docker.exe next to Docker Desktop."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        desktop = Path(tmp.name) / "Docker" / "Docker Desktop.exe"
        sibling = desktop.parent / "resources" / "bin" / "docker.exe"
        sibling.parent.mkdir(parents=True)
        sibling.write_text("")
        probed = []
        outcomes = [_run_result(stderr="pipe not found", returncode=1),
                    _run_result(stdout="Server Version: 27.3.1", returncode=0)]

        def runner(cmd, **kw):
            probed.append(list(cmd))
            return outcomes.pop(0) if outcomes else _run_result(stdout="Server")

        clock = _Clock()
        state, _ = opsmenu.ensure_docker(
            runner=runner, popen=mock.Mock(return_value=mock.Mock(pid=1)),
            desktop_finder=lambda: str(desktop), which=lambda name: None,
            sleeper=clock.sleep, clock=clock.monotonic)
        self.assertEqual(state, "started")
        self.assertEqual(probed[0][0], "docker",
                         "the first probe has no better CLI than PATH")
        self.assertEqual(probed[-1][0], str(sibling),
                         "the readiness polls ride the Desktop install's own CLI")


class TestDockerStatusLine(unittest.TestCase):
    def setUp(self):
        self._saved = opsmenu._DOCKER_LAST
        opsmenu._DOCKER_LAST = None

    def tearDown(self):
        opsmenu._DOCKER_LAST = self._saved

    def test_up(self):
        state, detail = opsmenu.docker_status(
            runner=lambda cmd, **kw: _run_result(stdout="Server Version: 27"),
            which=lambda name: CLI, desktop_finder=lambda: DESKTOP)
        self.assertEqual(state, "up")

    def test_down_plain(self):
        state, detail = opsmenu.docker_status(
            runner=lambda cmd, **kw: _run_result(stderr="pipe not found", returncode=1),
            which=lambda name: CLI, desktop_finder=lambda: DESKTOP)
        self.assertEqual(state, "down")
        self.assertIn("engine not answering", detail)

    def test_down_explains_the_last_ensure_verdict(self):
        opsmenu._DOCKER_LAST = ("starting-timeout", "engine did not answer within 120s")
        state, detail = opsmenu.docker_status(
            runner=lambda cmd, **kw: _run_result(stderr="pipe not found", returncode=1),
            which=lambda name: CLI, desktop_finder=lambda: DESKTOP)
        self.assertEqual(state, "down")
        self.assertIn("starting-timeout", detail,
                      "the card says WHY the engine is down right now")

    def test_missing(self):
        state, detail = opsmenu.docker_status(
            runner=_no_spawn, which=lambda name: None, desktop_finder=lambda: None)
        self.assertEqual(state, "missing")
        self.assertIn("degrades", detail)


class TestStartHuntCarriesDocker(unittest.TestCase):
    """start_hunt: ensure_docker() runs BEFORE the loop spawns, its verdict
    rides the start message, and a degraded docker NEVER blocks the start."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hunt = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _start(self, ensure_ret, order=None):
        class FakeProc:
            pid = 4321

        def fake_popen(cmd, **kw):
            if order is not None:
                order.append("spawn")
            return FakeProc()

        def fake_ensure():
            if order is not None:
                order.append("ensure")
            return ensure_ret

        with mock.patch.object(opsmenu, "HUNTLOOP", self.hunt / "huntloop.mjs") as loop, \
                mock.patch.object(opsmenu, "find_node", return_value="node"), \
                mock.patch.object(opsmenu, "lane_status",
                                  return_value=("up", "lane up (health 200, model=rvn.gguf)")), \
                mock.patch.object(opsmenu, "ensure_docker", side_effect=fake_ensure), \
                mock.patch.object(opsmenu.menuops, "current_model", return_value="rvn.gguf"):
            loop.write_text("// loop")
            return opsmenu.start_hunt(self.hunt, popen=fake_popen)

    def test_message_reports_docker_started(self):
        ok, msg = self._start(("started", "engine ready after 41s"))
        self.assertTrue(ok, msg)
        self.assertIn("hunt started (pid 4321) — docker: started, engine ready after 41s", msg)

    def test_message_notes_docker_missing_but_still_starts(self):
        ok, msg = self._start(("missing", "no docker CLI on PATH and no Docker Desktop.exe "
                                          "— vm-verification degrades (transcript-only), honestly"))
        self.assertTrue(ok, "docker absence degrades, it never blocks a start")
        self.assertIn("NOTE: docker missing", msg)
        self.assertIn("degrades", msg)
        self.assertEqual((self.hunt / "hunt.pid").read_text(), "4321",
                         "the hunt really did start")

    def test_message_notes_a_starting_timeout(self):
        ok, msg = self._start(("starting-timeout", "engine did not answer within 120s"))
        self.assertTrue(ok, msg)
        self.assertIn("NOTE: docker starting-timeout", msg)

    def test_ensure_runs_before_the_loop_spawns(self):
        order = []
        ok, _ = self._start(("up", "engine already running"), order=order)
        self.assertTrue(ok)
        self.assertEqual(order, ["ensure", "spawn"])


@unittest.skipUnless(sys.platform == "win32", "CREATE_NO_WINDOW is a win32 posture")
class TestDockerSpawnsHidden(unittest.TestCase):
    """The new docker spawns ride the flash-fix contract: driven through the
    REAL menuops helpers with subprocess patched, every spawn must carry
    CREATE_NO_WINDOW and a detached stdin."""

    def test_probe_and_desktop_launch_are_windowless(self):
        calls = []
        outcomes = [_run_result(stderr="pipe not found", returncode=1),
                    _run_result(stdout="Server Version: 27", returncode=0)]

        def fake_run(cmd, **kw):
            calls.append(("run", list(map(str, cmd)), kw))
            return outcomes.pop(0) if outcomes else _run_result(stdout="Server")

        def fake_popen(cmd, **kw):
            calls.append(("popen", list(map(str, cmd)), kw))
            return mock.Mock(pid=4242)

        clock = _Clock()
        with mock.patch.object(subprocess, "run", fake_run), \
                mock.patch.object(subprocess, "Popen", fake_popen):
            state, _ = opsmenu.ensure_docker(
                desktop_finder=lambda: DESKTOP, which=lambda name: CLI,
                sleeper=clock.sleep, clock=clock.monotonic)
        self.assertEqual(state, "started")
        popens = [c for c in calls if c[0] == "popen"]
        self.assertEqual(len(popens), 1)
        self.assertIn("Docker Desktop.exe", popens[0][1][0])
        for kind, cmd, kw in calls:
            flags = kw.get("creationflags", 0)
            self.assertTrue(flags & CREATE_NO_WINDOW,
                            f"{kind} spawn lacks CREATE_NO_WINDOW: {cmd} ({flags:#x})")
            self.assertEqual(kw.get("stdin"), subprocess.DEVNULL,
                             f"{kind} spawn inherits a console stdin: {cmd}")


if __name__ == "__main__":
    unittest.main()
