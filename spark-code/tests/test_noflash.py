"""The console-window-flash regression pin (Jack's bug report): under a
WINDOWED parent (pythonw / frozen spark-menu.exe) every console child would
allocate a visible console window. One refresh tick spawned three of them
(ssh, tasklist, powershell). This test monkeypatches subprocess.run/Popen,
drives one refresh tick + tunnel start + hunt start/stop + a ghost check,
and asserts every spawn carries CREATE_NO_WINDOW (win32) — with the ONE
documented exception: spawn_repl's REPL console, which is visible ON PURPOSE
(CREATE_NEW_CONSOLE is its requirement)."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spark_code import menuops, opsmenu
from spark_code.tunnel import TunnelManager

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010)


class _SpawnNet:
    """Records every subprocess.run / subprocess.Popen call."""

    def __init__(self):
        self.calls = []
        self._run_outcomes = []
        self._real_run = subprocess.run
        self._real_popen = subprocess.Popen
        self.popen_communicate = None  # (stdout, stderr) the fake long-lived child "produced"
        self._popen_outcomes = []      # per-spawn (stdout, stderr), queued in spawn order

    def queue_run_stdout(self, *stdouts):
        self._run_outcomes.extend(stdouts)

    def queue_popen_communicate(self, *pairs):
        self._popen_outcomes.extend(pairs)

    def fake_run(self, cmd, **kw):
        self.calls.append(("run", list(map(str, cmd)) if not isinstance(cmd, str) else cmd, kw))
        out = self._run_outcomes.pop(0) if self._run_outcomes else ""
        return type("R", (), {"stdout": out, "stderr": "", "returncode": 0})()

    def fake_popen(self, cmd, **kw):
        self.calls.append(("popen", list(map(str, cmd)), kw))
        m = mock.Mock(pid=31337, poll=lambda: None, wait=lambda timeout=None: 0)
        if self._popen_outcomes:
            outcome = self._popen_outcomes.pop(0)
            m.communicate = lambda timeout=None: outcome
        elif self.popen_communicate is not None:
            m.communicate = lambda timeout=None: self.popen_communicate
        return m

    def __enter__(self):
        self._p1 = mock.patch.object(subprocess, "run", self.fake_run)
        self._p2 = mock.patch.object(subprocess, "Popen", self.fake_popen)
        self._p1.start()
        self._p2.start()
        return self

    def __exit__(self, *exc):
        self._p2.stop()
        self._p1.stop()

    def assert_all_hidden(self, testcase):
        for kind, cmd, kw in self.calls:
            flags = kw.get("creationflags", 0)
            testcase.assertTrue(
                flags & CREATE_NO_WINDOW,
                f"{kind} spawn lacks CREATE_NO_WINDOW: {cmd} (creationflags={flags:#x})")
            testcase.assertEqual(kw.get("stdin"), subprocess.DEVNULL,
                                 f"{kind} spawn inherits a console stdin: {cmd}")


@unittest.skipUnless(sys.platform == "win32", "CREATE_NO_WINDOW is a win32 posture")
class TestNoConsoleFlashes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hunt = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_refresh_tick_spawns_are_all_windowless(self):
        """One tick = lane status (ssh) + pipeline probe (tasklist + powershell)."""
        with _SpawnNet() as net:
            net.queue_run_stdout("[lane-models] health=000000 model=none")
            ok, out = menuops.lane_ssh(["status"])
            self.assertTrue(ok)
            (self.hunt / "hunt.pid").write_text("4242")
            net.queue_run_stdout('"tasklist.exe","4242"', "node ...\\huntloop.mjs --dir ...")
            state, _ = opsmenu.pipeline_status(self.hunt)
            self.assertEqual(state, "running")
            net.assert_all_hidden(self)
        cmds = [c[1][0] for c in net.calls]
        self.assertTrue(any("ssh" in c for c in cmds))
        self.assertTrue(any("tasklist" in c for c in cmds))
        self.assertTrue(any("powershell" in c for c in cmds))

    def test_tunnel_start_is_windowless(self):
        with _SpawnNet() as net:
            net.queue_run_stdout("0")  # the keeper probe: not running
            tm = TunnelManager()
            with mock.patch("spark_code.tunnel.endpoint_up",
                            side_effect=[False, True]):
                status = tm.ensure(wait_s=3)
            self.assertEqual(status, "started")
            kinds = [c[0] for c in net.calls]
            self.assertEqual(kinds, ["run", "popen"], "probe the keeper, then spawn it — nothing else")
            keeper_cmd = net.calls[1][1]
            self.assertTrue(any("tunnel-keeper.ps1" in str(a) for a in keeper_cmd),
                            "CONNECT launches the self-healing keeper, never a one-shot ssh")
            net.assert_all_hidden(self)

    def test_tunnel_keeper_already_running_spawns_nothing(self):
        with _SpawnNet() as net:
            net.queue_run_stdout("1")  # the keeper probe: already alive
            tm = TunnelManager()
            with mock.patch("spark_code.tunnel.endpoint_up",
                            side_effect=[False, True]):
                status = tm.ensure(wait_s=3)
            self.assertEqual(status, "started")
            self.assertEqual([c[0] for c in net.calls], ["run"], "a live keeper is reused — no duplicate spawn")
            net.assert_all_hidden(self)

    def test_hunt_start_and_stop_are_windowless(self):
        loop = self.hunt / "huntloop.mjs"
        loop.write_text("// loop")
        with _SpawnNet() as net:
            with mock.patch.object(opsmenu, "HUNTLOOP", loop), \
                    mock.patch.object(opsmenu, "find_node", return_value="node"), \
                    mock.patch.object(opsmenu, "lane_status", return_value=("down", "lane down / training")), \
                    mock.patch.object(opsmenu.menuops, "current_model", return_value=None):
                ok, msg = opsmenu.start_hunt(self.hunt)
            self.assertTrue(ok, msg)
            # stop: pid alive, cmdline matches, stays alive through grace -> taskkill
            net.queue_run_stdout('"tasklist.exe","31337"',
                                 "node huntloop.mjs",
                                 '"tasklist.exe","31337"',
                                 "node huntloop.mjs",
                                 '"tasklist.exe","31337"',
                                 "node huntloop.mjs",
                                 "")  # taskkill
            ok, msg = opsmenu.stop_hunt(self.hunt, grace_s=0.01)
            self.assertTrue(ok, msg)
            self.assertTrue(any("taskkill" in c[1][0] for c in net.calls))
            net.assert_all_hidden(self)

    def test_ghost_check_spawns_nothing(self):
        """The ghost gate is pure sockets — zero subprocess by design."""
        with _SpawnNet() as net:
            doc = {"eng": {"ghost.mode": "required",
                           "ghost.chain": "socks5://10.0.0.1:1080"}}
            import json
            p = self.hunt / "settings.json"
            p.write_text(json.dumps(doc))

            def fake_dial(host, port, dhost, dport, timeout=8.0, **kw):
                if str(dhost).endswith(".invalid"):
                    return False, "refused: host unreachable", None
                return True, "CONNECT ok", mock.Mock(close=lambda: None)

            r = opsmenu.ghost_preflight(
                p, env={},
                dialer=fake_dial,
                direct_fetch=lambda url, timeout=8.0: (True, "203.0.113.10"),
                chain_fetch=lambda chain, url, timeout=10.0, **kw: (True, "135.136.21.33"))
            self.assertTrue(r["ok"], r)
            self.assertEqual(net.calls, [], "the ghost gate must not spawn subprocesses")

    def test_spawn_repl_is_the_one_documented_visible_exception(self):
        """The REPL console is user-facing ON PURPOSE — pinned as _NEW_CONSOLE
        so a future cleanup can't 'fix' it into an invisible window either."""
        with _SpawnNet() as net:
            with mock.patch.object(menuops, "REPL_EXE", Path("Z:/nope/spark-code.exe")):
                ok, _ = menuops.spawn_repl("C:/x")
            self.assertTrue(ok)
            self.assertEqual(len(net.calls), 1)
            flags = net.calls[0][2].get("creationflags", 0)
            self.assertTrue(flags & NEW_CONSOLE,
                            "spawn_repl must keep its intentional visible console")
            self.assertFalse(flags & CREATE_NO_WINDOW,
                             "the REPL must NOT be hidden — it is the user's window")

    def test_build_poc_spawn_is_windowless(self):
        """BUILD PoC spawns node+pocforge — a 20-minute child; it must carry
        the same no-console-flash posture as the hunt child."""
        ev = self.hunt / "evidence" / "pixiv_x" / "cve-x"
        ev.mkdir(parents=True)
        forge = self.hunt / "pocforge.mjs"
        forge.write_text("// forge")
        with _SpawnNet() as net:
            net.popen_communicate = ('{"ok":true,"verdictClass":"poc-unproven","reason":"x"}\n', "")
            with mock.patch.object(opsmenu, "POCFORGE", forge), \
                    mock.patch.object(opsmenu, "find_node", return_value="node"):
                ok, msg, result = opsmenu.build_poc(ev, self.hunt)
            self.assertTrue(ok, msg)
            self.assertEqual(result["verdictClass"], "poc-unproven")
            net.assert_all_hidden(self)
        self.assertTrue(any("pocforge" in " ".join(c[1]) for c in net.calls),
                        "the forge child actually spawned")

    def test_verify_finding_pause_forge_resume_is_windowless(self):
        """VERIFY pauses a running hunt (tasklist+powershell probes), spawns
        the forge child, then resumes — every spawn hidden, the hunt resumed."""
        (self.hunt / "hunt.pid").write_text("4242")
        ev = self.hunt / "evidence" / "pixiv_x" / "cve-x"
        ev.mkdir(parents=True)
        forge = self.hunt / "pocforge.mjs"
        forge.write_text("// forge")
        with _SpawnNet() as net:
            # pipeline_status runs TWICE (verify_finding's check + pause_hunt's
            # own): each is tasklist + powershell
            net.queue_run_stdout('"tasklist.exe","4242"', "node ...\\huntloop.mjs --dir ...",
                                 '"tasklist.exe","4242"', "node ...\\huntloop.mjs --dir ...")
            net.popen_communicate = ('{"ok":true,"verdictClass":"poc-verified","proof":{"host":"h"}}\n', "")
            with mock.patch.object(opsmenu, "POCFORGE", forge), \
                    mock.patch.object(opsmenu, "find_node", return_value="node"):
                ok, msg, result = opsmenu.verify_finding(ev, self.hunt)
            self.assertTrue(ok, msg)
            self.assertEqual(result["verdictClass"], "poc-verified")
            net.assert_all_hidden(self)
        self.assertFalse((self.hunt / "PAUSE").exists(), "the hunt was resumed after the forge")
        self.assertFalse((self.hunt / "pocforge.lock").exists(), "the forge lock was released")

    def test_forge_all_batch_spawns_are_windowless(self):
        """FORGE ALL pauses the hunt ONCE (tasklist+powershell probes), then
        every forge child spawns through build_poc (popen_hidden) — the batch
        adds NO new direct subprocess path, and every spawn stays hidden."""
        import json
        (self.hunt / "hunt.pid").write_text("4242")
        ev_hi = self.hunt / "evidence" / "acme_x" / "cve-high"
        ev_crit = self.hunt / "evidence" / "acme_x" / "cve-crit"
        ev_hi.mkdir(parents=True)
        ev_crit.mkdir(parents=True)
        forge = self.hunt / "pocforge.mjs"
        forge.write_text("// forge")
        (self.hunt / "findings.jsonl").write_text(
            json.dumps({"opp": "acme", "finding": "A", "sev": "high", "verdict": "verified",
                        "verified": True, "evidenceDir": str(ev_hi), "ts": "t1"}) + "\n" +
            json.dumps({"opp": "acme", "finding": "B", "sev": "critical", "verdict": "verified",
                        "verified": True, "evidenceDir": str(ev_crit), "ts": "t2"}) + "\n",
            encoding="utf-8")
        with _SpawnNet() as net:
            # pipeline_status runs TWICE (forge_all's check + pause_hunt's own)
            net.queue_run_stdout('"tasklist.exe","4242"', "node ...\\huntloop.mjs --dir ...",
                                 '"tasklist.exe","4242"', "node ...\\huntloop.mjs --dir ...")
            # forge order is critical first: ev_crit (unproven), then ev_hi (verified)
            net.queue_popen_communicate(
                ('{"ok":true,"verdictClass":"poc-unproven","reason":"x"}\n', ""),
                ('{"ok":true,"verdictClass":"poc-verified","proof":{"host":"h"}}\n', ""))
            with mock.patch.object(opsmenu, "POCFORGE", forge), \
                    mock.patch.object(opsmenu, "find_node", return_value="node"):
                summary = opsmenu.forge_all(self.hunt)
            net.assert_all_hidden(self)
        popens = [c for c in net.calls if c[0] == "popen"]
        self.assertEqual(len(popens), 2)
        self.assertTrue(all("pocforge" in " ".join(c[1]) for c in popens),
                        "the ONLY popen spawns in a batch are forge children (build_poc's path)")
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["poc_unproven"], 1)
        self.assertEqual(summary["poc_verified"], [str(ev_hi)])
        self.assertTrue(summary["paused_by_us"])
        self.assertFalse((self.hunt / "PAUSE").exists(), "the hunt was resumed after the batch")
        self.assertFalse((self.hunt / "FORGE_ALL_LOCK").exists(), "the batch lock was released")
        self.assertFalse((self.hunt / "pocforge.lock").exists(), "the forge lock was released")


if __name__ == "__main__":
    unittest.main()
