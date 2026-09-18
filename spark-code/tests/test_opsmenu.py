"""Ops-console logic (opsmenu): the state machine (pipeline_status), START/STOP
with mocked spawn/kill (cmdline-checked kills only), the lane-status parsing
('lane down / training' as a first-class state), events.jsonl parsing (bad
lines skipped, never invented), the stage-board projection, verified gating
counters, and cleanup as a VERIFIED state (clean only from a real
verified-clean event)."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spark_code import opsmenu


def _run_result(stdout="", returncode=0):
    return type("R", (), {"stdout": stdout, "stderr": "", "returncode": returncode})()


class TestLaneAndBrain(unittest.TestCase):
    def test_lane_down_is_first_class_not_an_error(self):
        with mock.patch.object(opsmenu.menuops, "lane_ssh",
                               return_value=(True, "[lane-models] health=000000 model=none")):
            state, detail = opsmenu.lane_status()
        self.assertEqual(state, "down")
        self.assertIn("training", detail)

    def test_lane_up_and_unknown(self):
        with mock.patch.object(opsmenu.menuops, "lane_ssh",
                               return_value=(True, "[lane-models] health=200 model=rvn.gguf")):
            self.assertEqual(opsmenu.lane_status()[0], "up")
        with mock.patch.object(opsmenu.menuops, "lane_ssh",
                               return_value=(False, "ssh failed: timeout")):
            self.assertEqual(opsmenu.lane_status()[0], "unknown")

    def test_brain_waits_honestly_when_lane_down(self):
        with mock.patch.object(opsmenu.menuops, "health",
                               return_value=(False, "unreachable (URLError)")):
            state, detail = opsmenu.brain_status()
        self.assertEqual(state, "waiting")
        self.assertIn("nothing is invented", detail)


class TestStartStop(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hunt = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_start_writes_pid_and_refuses_double_start(self):
        class FakeProc:
            pid = 4321

        seen = {}

        def fake_popen(cmd, **kw):
            seen["cmd"] = cmd
            seen["env"] = kw.get("env")
            return FakeProc()

        with mock.patch.object(opsmenu, "HUNTLOOP", Path(self.tmp.name) / "huntloop.mjs") as loop, \
                mock.patch.object(opsmenu, "find_node", return_value="node"), \
                mock.patch.object(opsmenu, "lane_status", return_value=("down", "lane down / training (model=none)")), \
                mock.patch.object(opsmenu, "ensure_docker", return_value=("up", "engine already running")), \
                mock.patch.object(opsmenu.menuops, "current_model", return_value=None):
            loop.write_text("// loop")
            ok, msg = opsmenu.start_hunt(self.hunt, popen=fake_popen)
        self.assertTrue(ok, msg)
        self.assertIn("4321", msg)
        self.assertIn("lane down / training", msg, "lane down is reported, not hidden")
        self.assertIn("docker: up", msg, "the docker verdict rides the start message")
        self.assertEqual((self.hunt / "hunt.pid").read_text(), "4321")
        self.assertIn("--dir", seen["cmd"])
        self.assertEqual(seen["env"]["VARVEL_BRAIN_PROVIDER"], "openai-compatible")
        self.assertTrue(seen["env"]["VARVEL_BRAIN_BASE_URL"].endswith("/v1"))
        # A second start while the pid is a live hunt process refuses.
        with mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_hunt_process", return_value=True):
            ok2, msg2 = opsmenu.start_hunt(self.hunt, popen=fake_popen)
        self.assertFalse(ok2)
        self.assertIn("already", msg2)

    def test_start_refuses_without_node(self):
        with mock.patch.object(opsmenu, "HUNTLOOP", Path(self.tmp.name) / "x.mjs") as loop, \
                mock.patch.object(opsmenu, "find_node", return_value=None):
            loop.write_text("//")
            ok, msg = opsmenu.start_hunt(self.hunt)
        self.assertFalse(ok)
        self.assertIn("node", msg)

    def test_stop_graceful_via_stop_file(self):
        (self.hunt / "hunt.pid").write_text("777")
        calls = {"alive": 0}

        def alive_then_dead(pid, runner=None):
            calls["alive"] += 1
            return calls["alive"] < 2  # alive once, gone after the STOP file

        with mock.patch.object(opsmenu, "pid_alive", side_effect=alive_then_dead), \
                mock.patch.object(opsmenu, "is_hunt_process", return_value=True):
            ok, msg = opsmenu.stop_hunt(self.hunt)
        self.assertTrue(ok, msg)
        self.assertIn("gracefully", msg)
        self.assertTrue((self.hunt / "STOP").exists())
        self.assertFalse((self.hunt / "hunt.pid").exists())

    def test_stop_kills_only_when_cmdline_says_huntloop(self):
        (self.hunt / "hunt.pid").write_text("888")
        killed = []

        def fake_runner(cmd, **kw):
            killed.append(list(cmd))
            return _run_result("")

        with mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_hunt_process", return_value=False):
            ok, msg = opsmenu.stop_hunt(self.hunt, grace_s=0.01, runner=fake_runner)
        self.assertFalse(ok)
        self.assertIn("refusing to kill a stranger", msg)
        self.assertFalse(any(c and c[0] == "taskkill" for c in killed),
                         "no taskkill when the cmdline does not match")

    def test_stop_hard_kill_after_grace_still_cmdline_checked(self):
        (self.hunt / "hunt.pid").write_text("999")
        killed = []

        def fake_runner(cmd, **kw):
            killed.append(list(cmd))
            return _run_result("")

        with mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_hunt_process", return_value=True):
            ok, msg = opsmenu.stop_hunt(self.hunt, grace_s=0.01, runner=fake_runner)
        self.assertTrue(ok, msg)
        self.assertIn("cmdline-checked", msg)
        self.assertTrue(any(c[:1] == ["taskkill"] and "999" in c for c in killed))

    def test_pause_resume_files(self):
        (self.hunt / "hunt.pid").write_text("555")
        with mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_hunt_process", return_value=True):
            ok, _ = opsmenu.pause_hunt(self.hunt)
            self.assertTrue(ok)
            self.assertEqual(opsmenu.pipeline_status(self.hunt)[0], "paused")
            ok, _ = opsmenu.resume_hunt(self.hunt)
            self.assertTrue(ok)
            self.assertEqual(opsmenu.pipeline_status(self.hunt)[0], "running")


class TestEventsAndBoard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hunt = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, events):
        lines = []
        for ev in events:
            lines.append(ev if isinstance(ev, str) else json.dumps(ev))
        (self.hunt / "events.jsonl").write_text("\n".join(lines) + "\n")

    def test_bad_lines_are_skipped_never_invented(self):
        self._write([
            '{"type":"loop","state":"started"',
            {"type": "loop", "state": "started"},
            "not json at all",
            ["a", "list"],
        ])
        events = opsmenu.read_events(self.hunt)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["state"], "started")

    def test_board_projects_stages_and_resets_on_new_opportunity(self):
        self._write([
            {"ts": "t1", "type": "stage", "stage": "watch", "state": "done"},
            {"ts": "t2", "type": "opportunity", "state": "start", "opp": "acme"},
            {"ts": "t3", "type": "stage", "stage": "intake", "state": "active", "opp": "acme"},
            {"ts": "t4", "type": "stage", "stage": "intake", "state": "done", "opp": "acme"},
            {"ts": "t5", "type": "stage", "stage": "testing", "state": "failed", "opp": "acme", "msg": "replay mismatch"},
            {"ts": "t6", "type": "opportunity", "state": "start", "opp": "globex"},
        ])
        b = opsmenu.board(opsmenu.read_events(self.hunt))
        self.assertEqual(b["stages"]["intake"]["state"], "idle",
                         "a new opportunity resets the stage row")
        self.assertEqual(b["stages"]["watch"]["state"], "idle")
        self.assertEqual(b["last_ts"], "t6")

    def test_verified_gating_counters_come_from_counter_events(self):
        self._write([
            {"ts": "t1", "type": "counters", "data": {"seen": 2, "tested": 1, "verified": 0, "unverified": 1, "drafted": 0}},
            {"ts": "t2", "type": "counters", "data": {"seen": 2, "tested": 2, "verified": 1, "unverified": 1, "drafted": 1}},
        ])
        b = opsmenu.board(opsmenu.read_events(self.hunt))
        self.assertEqual(b["counters"]["verified"], 1)
        self.assertEqual(b["counters"]["unverified"], 1)
        self.assertEqual(b["counters"]["drafted"], 1)

    def test_clean_only_from_a_real_verified_clean_event(self):
        self._write([{"ts": "t1", "type": "loop", "state": "started"}])
        b = opsmenu.board(opsmenu.read_events(self.hunt))
        self.assertIsNone(b["clean"], "no cleanup event = no clean claim")
        self._write([
            {"ts": "t1", "type": "cleanup", "state": "residue-found", "detail": "leftover named"},
        ])
        b = opsmenu.board(opsmenu.read_events(self.hunt))
        self.assertIs(b["clean"], False)
        self._write([
            {"ts": "t1", "type": "cleanup", "state": "verified-clean", "detail": "no residue"},
        ])
        b = opsmenu.board(opsmenu.read_events(self.hunt))
        self.assertIs(b["clean"], True)

    def test_vm_and_brain_states_surface(self):
        self._write([
            {"ts": "t1", "type": "vm", "state": "active", "provider": {"name": "docker"}},
            {"ts": "t2", "type": "brain", "state": "waiting", "msg": "lane down"},
        ])
        b = opsmenu.board(opsmenu.read_events(self.hunt))
        self.assertEqual(b["vm"], {"state": "active", "provider": "docker"})
        self.assertEqual(b["brain"], "waiting")

    def test_last_run_survives_the_opportunity_reset(self):
        # an idle card must still say something TRUE after the per-opportunity reset
        self._write([
            {"ts": "t1", "type": "stage", "stage": "recon", "state": "done",
             "msg": "recon done — 0 brain candidate(s)"},
            {"ts": "t2", "type": "opportunity", "state": "start", "opp": "acme"},
        ])
        b = opsmenu.board(opsmenu.read_events(self.hunt))
        self.assertEqual(b["stages"]["recon"]["state"], "idle", "the new opportunity resets the live stage")
        self.assertEqual(b["last_run"]["recon"]["msg"], "recon done — 0 brain candidate(s)",
                         "last_run keeps the stage's last real result across the reset")
        self.assertIsNone(b["last_run"]["testing"], "a stage that never ran says so, never invents")

    def test_stage_vocabulary_matches_the_loop(self):
        # The board's stages must stay EXACTLY huntloop.mjs's STAGES.
        src = (opsmenu.VARVEL / "tools" / "huntloop.mjs").read_text(encoding="utf-8")
        m = __import__("re").search(r"export const STAGES = \[([^\]]+)\]", src)
        self.assertIsNotNone(m, "huntloop.mjs STAGES not found")
        loop_stages = [s.strip().strip("'\"") for s in m.group(1).split(",")]
        self.assertEqual(opsmenu.STAGES, loop_stages)

    def test_menu_module_still_imports_headless(self):
        import spark_code.menu  # noqa: F401
        import spark_code.opsmenu  # noqa: F401


class _FakePocProc:
    """A scripted forge child: communicate() answers (stdout, stderr) or raises."""

    def __init__(self, out, pid=5311):
        self.pid = pid
        self._out = out
        self.killed = False
        self.returncode = 0

    def communicate(self, timeout=None):
        if isinstance(self._out, Exception):
            raise self._out
        return self._out, ""

    def kill(self):
        self.killed = True


class TestPocForge(unittest.TestCase):
    """The BUILD PoC logic: candidates from the ledger (read-only), the
    windowless forge spawn with an honest bounded wait, the one-at-a-time lock,
    and the JSON-verdict parse. All spawns injected — never a real child."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hunt = Path(self.tmp.name)
        self.evdir = self.hunt / "evidence" / "pixiv_new-program_in_x" / "cve-x"
        self.evdir.mkdir(parents=True)
        self.forge = self.hunt / "pocforge.mjs"
        self.forge.write_text("// forge")

    def tearDown(self):
        self.tmp.cleanup()

    def _findings(self, *lines):
        (self.hunt / "findings.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _forge_patches(self):
        return mock.patch.object(opsmenu, "POCFORGE", self.forge), \
            mock.patch.object(opsmenu, "find_node", return_value="node")

    def test_poc_candidates_lists_verified_with_evidence_only(self):
        other = self.hunt / "evidence" / "valve_y" / "cve-y"
        other.mkdir(parents=True)
        (self.evdir / "poc-result.json").write_text(
            json.dumps({"verdictClass": "poc-verified", "at": "2026-09-12T10:00:00Z"}), encoding="utf-8")
        self._findings(
            json.dumps({"opp": "pixiv", "finding": "CVE-x jquery", "verified": True,
                        "evidenceDir": str(self.evdir), "ts": "t1"}),
            '{"opp":"bad","verified":true,"evidenceDir":null}',               # no dir
            json.dumps({"opp": "gone", "finding": "x", "verified": True,
                        "evidenceDir": str(self.hunt / "nope")}),             # missing dir
            json.dumps({"opp": "unv", "finding": "x", "verified": False,
                        "evidenceDir": str(other)}),                          # not verified
            "not json at all",                                                # torn line — skipped
            json.dumps({"opp": "valve", "finding": "CVE-y jquery", "verified": True,
                        "evidenceDir": str(other), "ts": "t2"}),
        )
        cands = opsmenu.poc_candidates(self.hunt)
        self.assertEqual(len(cands), 2)
        self.assertEqual(cands[0]["opp"], "pixiv")
        self.assertEqual(cands[0]["poc"], "poc-verified", "a forged finding shows its verdict")
        self.assertEqual(cands[1]["opp"], "valve")
        self.assertIsNone(cands[1]["poc"])

    def test_pocforge_cmd_shape(self):
        p1, p2 = self._forge_patches()
        with p1, p2:
            cmd = opsmenu.pocforge_cmd(self.evdir, self.hunt)
        self.assertEqual(cmd[0], "node")
        self.assertIn("pocforge.mjs", cmd[1])
        self.assertIn("--finding", cmd)
        self.assertIn(str(self.evdir), cmd)
        self.assertIn("--dir", cmd)

    def test_build_poc_defaults_the_model_from_the_lane(self):
        # Regression 2026-09-12: model=None left VARVEL_BRAIN_MODEL unset and the
        # forge's brain REFUSED ('needs a model id') — check-defect before any probe.
        seen = {}

        def fake_popen(cmd, **kw):
            seen["env"] = kw.get("env")
            return _FakePocProc('{"ok":true,"verdictClass":"poc-unproven"}\n')

        p1, p2 = self._forge_patches()
        with p1, p2, mock.patch.object(opsmenu.menuops, "current_model",
                                       return_value="Qwen3.8-27B-GGUF"):
            ok, msg, result = opsmenu.build_poc(self.evdir, self.hunt, popen=fake_popen)
        self.assertTrue(ok, msg)
        self.assertEqual(seen["env"]["VARVEL_BRAIN_MODEL"], "Qwen3.8-27B-GGUF",
                         "an unpassed model resolves from the lane, exactly like START HUNT")

    def test_build_poc_happy_path_parses_the_verdict_line(self):
        seen = {}

        def fake_popen(cmd, **kw):
            seen["cmd"] = cmd
            seen["kw"] = kw
            return _FakePocProc('progress noise\n{"ok":true,"verdictClass":"poc-verified",'
                                '"proof":{"host":"sensei.pixiv.net"}}\n')

        p1, p2 = self._forge_patches()
        with p1, p2:
            ok, msg, result = opsmenu.build_poc(self.evdir, self.hunt, popen=fake_popen)
        self.assertTrue(ok, msg)
        self.assertIn("DEMONSTRATED", msg)
        self.assertEqual(result["verdictClass"], "poc-verified")
        self.assertIn("--finding", seen["cmd"])
        self.assertEqual(seen["kw"]["stdout"], subprocess.PIPE, "stdout is captured for the verdict line")
        self.assertFalse((self.hunt / "pocforge.lock").exists(), "the lock is released after the run")

    def test_build_poc_timeout_is_an_honest_kill_never_a_lied_verdict(self):
        proc = _FakePocProc(subprocess.TimeoutExpired(cmd="x", timeout=1))
        p1, p2 = self._forge_patches()
        with p1, p2:
            ok, msg, result = opsmenu.build_poc(self.evdir, self.hunt, timeout_s=1,
                                                popen=lambda *a, **k: proc)
        self.assertFalse(ok)
        self.assertIn("did not finish", msg)
        self.assertIn("UNPROVEN", msg)
        self.assertTrue(proc.killed, "a timed-out forge is killed, not abandoned")
        self.assertEqual(result, {})
        self.assertFalse((self.hunt / "pocforge.lock").exists())

    def test_build_poc_refuses_a_second_forge_while_one_is_active(self):
        (self.hunt / "pocforge.lock").write_text("999")
        p1, p2 = self._forge_patches()
        with p1, p2, \
                mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_pocforge_process", return_value=True):
            def forbidden_popen(*a, **k):
                raise AssertionError("a second forge must never spawn")
            ok, msg, result = opsmenu.build_poc(self.evdir, self.hunt, popen=forbidden_popen)
        self.assertFalse(ok)
        self.assertIn("REFUSED", msg)
        self.assertIn("one at a time", msg)
        self.assertTrue((self.hunt / "pocforge.lock").exists(), "the live lock is left alone")

    def test_build_poc_cleans_a_stale_lock_and_runs(self):
        (self.hunt / "pocforge.lock").write_text("999")
        p1, p2 = self._forge_patches()
        with p1, p2, \
                mock.patch.object(opsmenu, "pid_alive", return_value=False):
            ok, msg, result = opsmenu.build_poc(
                self.evdir, self.hunt,
                popen=lambda *a, **k: _FakePocProc('{"ok":true,"verdictClass":"poc-unproven",'
                                                   '"reason":"attempts exhausted"}\n'))
        self.assertTrue(ok, msg)
        self.assertEqual(result["verdictClass"], "poc-unproven")
        self.assertFalse((self.hunt / "pocforge.lock").exists())

    def test_build_poc_without_a_verdict_line_assumes_nothing(self):
        p1, p2 = self._forge_patches()
        with p1, p2:
            ok, msg, result = opsmenu.build_poc(
                self.evdir, self.hunt,
                popen=lambda *a, **k: _FakePocProc("garbage\nmore garbage\n"))
        self.assertFalse(ok)
        self.assertIn("no JSON verdict line", msg)
        self.assertEqual(result, {})

    def test_build_poc_missing_evidence_dir_is_an_honest_refusal(self):
        p1, p2 = self._forge_patches()
        with p1, p2:
            ok, msg, _ = opsmenu.build_poc(self.hunt / "absent", self.hunt)
        self.assertFalse(ok)
        self.assertIn("evidence dir not found", msg)


class TestFindingsIndex(unittest.TestCase):
    """The FINDINGS section's row model: every ledger finding with severity +
    verdict badges, forgeable/reportable affordances with HONEST disabled
    reasons, sorted POC-DEMONSTRATED first (proven winners pin to the top),
    then verified → unproven → unverified (newest first within each band)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hunt = Path(self.tmp.name)
        self.outbox = self.hunt / "outbox"
        self.outbox.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _evdir(self, name, on_disk=True, poc=None):
        ev = self.hunt / "evidence" / "opp_x" / name
        if on_disk:
            ev.mkdir(parents=True)
            if poc:
                (ev / "poc-result.json").write_text(
                    json.dumps({"verdictClass": poc, "at": "2026-09-12T10:00:00Z"}), encoding="utf-8")
        return ev

    def _draft(self, name, evdir):
        p = self.outbox / name
        p.write_text(f"<!-- VARVEL huntloop draft — HUMAN REVIEW ONLY. Verdict: VERIFIED "
                     f"(replay-verification PASSED). Evidence bundle: {evdir} -->\n\n# x\n",
                     encoding="utf-8")
        return p

    def _ledger(self, *lines):
        (self.hunt / "findings.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _line(self, opp, finding, verdict, ev, ts, sev="medium", **extra):
        rec = {"opp": opp, "finding": finding, "sev": sev, "verdict": verdict,
               "verified": verdict == "verified", "evidenceDir": str(ev), "ts": ts}
        rec.update(extra)  # grade / submittable / readiness — the loop's own honesty fields
        return json.dumps(rec)

    def test_rows_badges_sort_and_affordances(self):
        # THE 2026-09-18 HONESTY FIX: a replay-passed finding is FIRM (an offline
        # re-derivation of the recorded fingerprint), and only a DEMONSTRATED PoC — or the
        # report gate's own ready over a non-self-referential target re-probe — is
        # SUBMITTABLE. There is no VERIFIED badge any more: the board used to show 61 of them
        # over version→CVE matches that no program accepts.
        ev_a = self._evdir("cve-a", poc="poc-verified")     # POC-DEMONSTRATED
        ev_b = self._evdir("cve-b")                          # FIRM (offline replay)
        ev_c = self._evdir("cve-c")                          # UNPROVEN
        ev_d = self._evdir("cve-d")                          # UNVERIFIED
        ev_gone = self._evdir("cve-gone", on_disk=False)     # FIRM, dir missing
        ev_sub = self._evdir("cve-sub")                      # SUBMITTABLE (report gate ready)
        ev_legacy = self._evdir("cve-legacy")                 # legacy line: verdict only
        self._draft("pixiv-cve-a.md", ev_a)
        self._draft("pixiv-cve-b.md", ev_b)
        self._ledger(
            self._line("pixiv", "finding A", "verified", ev_a, "2026-09-12T01:00:00Z",
                       grade="poc-demonstrated", submittable=True),
            self._line("pixiv", "finding SUB", "verified", ev_sub, "2026-09-12T06:00:00Z",
                       grade="firm", submittable=True, readiness="ready",
                       oracleKind="target-repro"),
            self._line("pixiv", "finding B", "verified", ev_b, "2026-09-12T03:00:00Z", grade="firm"),
            self._line("pixiv", "finding C", "unproven", ev_c, "2026-09-12T02:00:00Z"),
            self._line("pixiv", "finding D", "unverified", ev_d, "2026-09-12T04:00:00Z"),
            self._line("pixiv", "finding GONE", "verified", ev_gone, "2026-09-12T05:00:00Z", grade="firm"),
            self._line("pixiv", "LEGACY", "verified", ev_legacy, "2026-09-12T07:00:00Z"),
            "not json at all",                               # torn line — skipped
            self._line("pixiv", "finding B OLD", "verified", ev_b, "2026-09-12T00:00:00Z", grade="firm"),
        )
        rows = opsmenu.findings_index(self.hunt)
        # dedupe: latest ledger line per evidence dir wins (B OLD is the last B line,
        # and the row carries ITS ts — t0 — so it sorts after GONE's t5)
        self.assertEqual(len(rows), 7)
        # sort: POC-DEMONSTRATED, then SUBMITTABLE, then the FIRM band (newest first),
        # then unproven → unverified
        self.assertEqual([r["finding"] for r in rows],
                         ["finding A", "finding SUB", "LEGACY", "finding GONE",
                          "finding B OLD", "finding C", "finding D"])
        self.assertEqual([r["badge"] for r in rows],
                         ["POC-DEMONSTRATED", "SUBMITTABLE", "FIRM", "FIRM", "FIRM",
                          "UNPROVEN", "UNVERIFIED"])
        by_name = {r["finding"]: r for r in rows}
        a = by_name["finding A"]
        self.assertTrue(a["forgeable"])
        self.assertTrue(a["reportable"])
        self.assertTrue(a["draft_path"].endswith("pixiv-cve-a.md"))
        self.assertEqual(a["poc"], "poc-verified")
        # The new honesty fields are on the row (the UI reads them), and a LEGACY line —
        # written before the grade existed — can never come back as VERIFIED.
        self.assertEqual(a["grade"], "poc-demonstrated")
        self.assertIs(a["submittable"], True)
        sub = by_name["finding SUB"]
        self.assertEqual(sub["badge"], "SUBMITTABLE")
        self.assertEqual(sub["oracle_kind"], "target-repro")
        self.assertEqual(by_name["LEGACY"]["badge"], "FIRM")
        self.assertIs(by_name["LEGACY"]["submittable"], False)
        self.assertIsNone(by_name["LEGACY"]["grade"])
        gone = by_name["finding GONE"]
        self.assertFalse(gone["forgeable"])
        self.assertIn("missing from disk", gone["forge_reason"])
        self.assertFalse(gone["reportable"])
        self.assertIn("no outbox draft names this evidence bundle", gone["report_reason"])
        c = by_name["finding C"]
        self.assertFalse(c["forgeable"])
        self.assertIn("replay-VERIFIED", c["forge_reason"])
        self.assertIn("unproven", c["forge_reason"])
        self.assertFalse(c["reportable"])
        self.assertIn("report stage only drafts replay-VERIFIED", c["report_reason"])
        d = by_name["finding D"]
        self.assertEqual(d["sev"], "medium")
        self.assertFalse(d["reportable"])
        self.assertIn("unverified claim is not a draft", d["report_reason"])

    def test_empty_and_unreadable_ledger_is_an_honest_empty_list(self):
        self.assertEqual(opsmenu.findings_index(self.hunt), [])


class TestVerifyFinding(unittest.TestCase):
    """The VERIFY orchestration's pause/resume contract: pauses ONLY a running
    hunt, resumes ONLY when this call paused (never the operator's pause),
    and the resume fires after success AND error (try/finally)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hunt = Path(self.tmp.name)
        self.ev = self.hunt / "evidence" / "opp_x" / "cve-x"
        self.ev.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, state=("running", "hunt active"), pause_ret=(True, "PAUSE written"),
             build_side=None, build_ret=(True, "ok", {"verdictClass": "poc-verified"})):
        calls = []
        notes = []

        def fake_pause(hunt_dir, reason=""):
            calls.append("pause")
            return pause_ret

        def fake_resume(hunt_dir):
            calls.append("resume")
            return True, "resumed"

        def fake_build(evidence_dir, **kw):
            calls.append("forge")
            if build_side is not None:
                raise build_side
            return build_ret

        with mock.patch.object(opsmenu, "pipeline_status", return_value=state), \
                mock.patch.object(opsmenu, "pause_hunt", side_effect=fake_pause), \
                mock.patch.object(opsmenu, "resume_hunt", side_effect=fake_resume), \
                mock.patch.object(opsmenu, "build_poc", side_effect=fake_build):
            try:
                out = opsmenu.verify_finding(self.ev, self.hunt, note=notes.append)
            except Exception as exc:
                out = exc
        return calls, notes, out

    def test_pauses_a_running_hunt_and_resumes_after_success(self):
        calls, notes, out = self._run()
        self.assertEqual(calls, ["pause", "forge", "resume"])
        self.assertIn("hunt paused for the forge — capacity to the finding", notes)
        self.assertEqual(notes[-1], "hunt resumed after the forge")
        self.assertEqual(out[2]["verdictClass"], "poc-verified")

    def test_resumes_after_an_error_too(self):
        calls, notes, out = self._run(build_side=RuntimeError("forge died mid-run"))
        self.assertEqual(calls, ["pause", "forge", "resume"], "the resume rides try/finally")
        self.assertIsInstance(out, RuntimeError)
        self.assertEqual(notes[-1], "hunt resumed after the forge")

    def test_operator_paused_hunt_stays_paused(self):
        calls, notes, out = self._run(state=("paused", "hunt paused (pid 1)"))
        self.assertEqual(calls, ["forge"], "never pauses what is already paused — and NEVER resumes the operator's pause")
        self.assertTrue(any("STAYS paused" in n for n in notes))
        self.assertEqual(out[0], True)

    def test_stopped_hunt_is_never_paused(self):
        calls, notes, _ = self._run(state=("stopped", "no hunt on record"))
        self.assertEqual(calls, ["forge"])
        self.assertTrue(any("nothing to pause" in n for n in notes))

    def test_a_failed_pause_is_named_and_never_resumed(self):
        calls, notes, _ = self._run(pause_ret=(False, "cannot pause — the hunt is stopped"))
        self.assertEqual(calls, ["pause", "forge"], "we did not pause it, so we never resume it")
        self.assertTrue(any("could not pause" in n for n in notes))

    def test_pause_false_goes_straight_to_the_forge(self):
        with mock.patch.object(opsmenu, "pipeline_status") as ps, \
                mock.patch.object(opsmenu, "build_poc", return_value=(True, "ok", {})) as bp:
            ok, msg, _ = opsmenu.verify_finding(self.ev, self.hunt, pause=False)
        ps.assert_not_called()
        bp.assert_called_once()
        self.assertTrue(ok)


class TestForgeAll(unittest.TestCase):
    """The FORGE ALL batch: queue order (severity band → newest within), never
    re-forging a proven finding, the pause-ONCE/resume-ONCE contract (incl.
    the error path), the operator-pause hands-off, FORGE_STOP cancelling
    BETWEEN runs (file removed, cancelled: yes), a failing row recorded as
    'error' while the batch continues, the loud refusals, and the
    FORGE_ALL_LOCK lifecycle. build_poc is ALWAYS an injected fake — never a
    real forge child, never a real subprocess."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hunt = Path(self.tmp.name)
        self.ledger = []

    def tearDown(self):
        self.tmp.cleanup()

    def _finding(self, opp, name, sev, ts, verdict="verified", poc=None, on_disk=True):
        ev = self.hunt / "evidence" / opp / name
        if on_disk:
            ev.mkdir(parents=True, exist_ok=True)
            if poc:
                (ev / "poc-result.json").write_text(
                    json.dumps({"verdictClass": poc}), encoding="utf-8")
        self.ledger.append(json.dumps({
            "opp": opp, "finding": f"{name} title", "sev": sev, "verdict": verdict,
            "verified": verdict == "verified", "evidenceDir": str(ev), "ts": ts}))
        return ev

    def _write_ledger(self):
        (self.hunt / "findings.jsonl").write_text(
            "\n".join(self.ledger) + ("\n" if self.ledger else ""), encoding="utf-8")

    def _run(self, state=("stopped", "no hunt on record"), build=None,
             pause_ret=(True, "PAUSE written"), **kw):
        """Drive forge_all with the pipeline + the forge injected. Returns
        (summary, order, pauses, resumes, notes) — `order` records the exact
        interleaving of pause/forge/resume so the once-only contract is pinned."""
        order, pauses, resumes, notes = [], [], [], []

        def fake_pause(hunt_dir, reason=""):
            order.append("pause")
            pauses.append(reason)
            return pause_ret

        def fake_resume(hunt_dir):
            order.append("resume")
            resumes.append(1)
            return True, "PAUSE lifted"

        def fake_build(evidence_dir, **bkw):
            order.append("forge")
            if build is not None:
                return build(evidence_dir, **bkw)
            return True, "forge verdict: poc-unproven — attempts exhausted", \
                {"verdictClass": "poc-unproven"}

        with mock.patch.object(opsmenu, "pipeline_status", return_value=state), \
                mock.patch.object(opsmenu, "pause_hunt", side_effect=fake_pause), \
                mock.patch.object(opsmenu, "resume_hunt", side_effect=fake_resume), \
                mock.patch.object(opsmenu, "build_poc", side_effect=fake_build):
            summary = opsmenu.forge_all(self.hunt, note=notes.append, **kw)
        return summary, order, pauses, resumes, notes

    def _standard_ledger(self):
        ev_low = self._finding("acme", "cve-low", "low", "2026-09-12T01:00:00Z")
        ev_crit_old = self._finding("acme", "cve-crit-old", "critical", "2026-09-12T02:00:00Z")
        ev_high = self._finding("acme", "cve-high", "high", "2026-09-12T03:00:00Z")
        ev_crit_new = self._finding("acme", "cve-crit-new", "CRITICAL", "2026-09-12T04:00:00Z")
        ev_med = self._finding("acme", "cve-med", "medium", "2026-09-12T05:00:00Z")
        ev_proven = self._finding("acme", "cve-proven", "critical", "2026-09-12T06:00:00Z",
                                  poc="poc-verified")
        # never queued: an unverified finding, and a verified one whose dir is gone
        self._finding("acme", "cve-unv", "critical", "2026-09-12T07:00:00Z", verdict="unverified")
        self._finding("acme", "cve-gone", "critical", "2026-09-12T08:00:00Z", on_disk=False)
        self._write_ledger()
        return [str(ev_crit_new), str(ev_crit_old), str(ev_high), str(ev_med), str(ev_low)]

    def test_queue_order_severity_band_then_newest_and_proven_skipped(self):
        self._standard_ledger()
        summary, order, _, _, notes = self._run()
        self.assertEqual(order, ["forge"] * 5, "exactly the 5 forgeable, unproven rows")
        # the build order is derivable from the progress lines (start line per forge)
        started = [n for n in notes if n.startswith("forge ")]
        self.assertEqual(len(started), 5)
        self.assertIn("cve-crit-new", started[0], "critical band first, newest within")
        self.assertIn("cve-crit-old", started[1])
        self.assertIn("cve-high", started[2])
        self.assertIn("cve-med", started[3])
        self.assertIn("cve-low", started[4])
        self.assertIn("1/5", started[0])
        self.assertIn("5/5", started[4])
        self.assertEqual(summary["skipped_already_proven"], 1,
                         "the poc-verified row is counted, never re-forged")
        self.assertEqual(summary["total"], 5)
        self.assertEqual(sum(1 for n in notes if n == "→ poc-unproven"), 5)
        self.assertIn("FORGE ALL done: 0 poc-verified, 5 unproven, 0 defects/errors, "
                      "cancelled: no", notes)
        self.assertFalse((self.hunt / "FORGE_ALL_LOCK").exists(),
                         "the batch lock is cleaned after the run")
        self.assertEqual(summary["refused"], None)

    def test_limit_caps_the_queue_for_a_top_n_run(self):
        self._standard_ledger()
        summary, order, _, _, notes = self._run(limit=2)
        self.assertEqual(order, ["forge", "forge"])
        self.assertEqual(summary["total"], 2)
        started = [n for n in notes if n.startswith("forge ")]
        self.assertIn("cve-crit-new", started[0])
        self.assertIn("cve-crit-old", started[1])
        self.assertEqual(summary["skipped_already_proven"], 1,
                         "the proven row is still counted honestly outside the cap")

    def test_pause_once_resume_once_for_the_whole_batch(self):
        self._standard_ledger()
        summary, order, pauses, resumes, notes = self._run(
            state=("running", "hunt active (pid 1)"))
        self.assertEqual(order, ["pause"] + ["forge"] * 5 + ["resume"],
                         "ONE pause at the start, ONE resume at the end — never per finding")
        self.assertEqual(len(pauses), 1)
        self.assertIn("FORGE ALL", pauses[0], "the PAUSE names the batch, not a phantom click")
        self.assertTrue(summary["paused_by_us"])
        self.assertIn("hunt paused for the batch — capacity to the findings", notes)
        self.assertEqual(notes[-1], "hunt resumed after the batch")

    def test_error_path_still_resumes_once_and_cleans_the_lock(self):
        self._standard_ledger()

        def boom(*a, **k):
            raise KeyboardInterrupt()  # a cancel-level interruption, not a row error

        order, resumes = [], []
        with mock.patch.object(opsmenu, "pipeline_status", return_value=("running", "hunt active")), \
                mock.patch.object(opsmenu, "pause_hunt",
                                  side_effect=lambda *a, **k: (order.append("pause"), (True, "ok"))[1]), \
                mock.patch.object(opsmenu, "resume_hunt",
                                  side_effect=lambda *a, **k: (order.append("resume"), resumes.append(1), (True, "ok"))[2]), \
                mock.patch.object(opsmenu, "build_poc", side_effect=boom):
            with self.assertRaises(KeyboardInterrupt):
                opsmenu.forge_all(self.hunt)
        self.assertEqual(order, ["pause", "resume"],
                         "the resume rides try/finally — an interrupted batch never orphans the pause")
        self.assertEqual(len(resumes), 1)
        self.assertFalse((self.hunt / "FORGE_ALL_LOCK").exists(),
                         "the batch lock is cleaned even on the error path")

    def test_operator_paused_hunt_is_never_touched(self):
        self._standard_ledger()
        summary, order, pauses, resumes, notes = self._run(
            state=("paused", "hunt paused (pid 1)"))
        self.assertEqual(order, ["forge"] * 5,
                         "never pauses what is already paused — and NEVER resumes the operator's pause")
        self.assertEqual(pauses, [])
        self.assertEqual(resumes, [])
        self.assertFalse(summary["paused_by_us"])
        self.assertTrue(any("STAYS paused" in n for n in notes))

    def test_forge_stop_cancels_between_runs_and_is_removed(self):
        self._standard_ledger()
        stop = self.hunt / "FORGE_STOP"
        seen = []

        def build(evidence_dir, **k):
            seen.append(str(evidence_dir))
            stop.write_text("operator asked to stop\n")  # lands DURING run 1
            return True, "ok", {"verdictClass": "poc-unproven"}

        summary, order, _, _, notes = self._run(build=build)
        self.assertEqual(len(seen), 1, "the cancel lands BETWEEN runs — run 1 finished, run 2 never starts")
        self.assertTrue(summary["cancelled"])
        self.assertFalse(stop.exists(), "the stop file is removed when honored")
        self.assertTrue(any("FORGE STOP honored" in n for n in notes))
        self.assertIn("FORGE ALL done: 0 poc-verified, 1 unproven, 0 defects/errors, "
                      "cancelled: yes", notes)

    def test_a_failing_row_is_recorded_and_the_batch_continues(self):
        ev_a = self._finding("acme", "cve-a", "critical", "2026-09-12T01:00:00Z")
        ev_b = self._finding("acme", "cve-b", "high", "2026-09-12T02:00:00Z")
        ev_c = self._finding("acme", "cve-c", "medium", "2026-09-12T03:00:00Z")
        self._write_ledger()

        def build(evidence_dir, **k):
            if str(evidence_dir) == str(ev_b):
                return False, "REFUSED — a PoC forge is already running", {}
            if str(evidence_dir) == str(ev_c):
                raise RuntimeError("the impossible happened")  # build_poc's contract broken
            return True, "ok", {"verdictClass": "poc-unproven"}

        summary, order, _, _, notes = self._run(build=build)
        self.assertEqual(order, ["forge"] * 3, "one bad row never kills the batch")
        self.assertEqual(summary["errors"], 2, "the ok-False row AND the raising row are honest errors")
        self.assertEqual(summary["poc_unproven"], 1)
        self.assertTrue(any("→ error: REFUSED" in n for n in notes))
        self.assertTrue(any("→ error: RuntimeError" in n for n in notes))

    def test_summary_shape_and_counts(self):
        ev_a = self._finding("acme", "cve-a", "critical", "2026-09-12T01:00:00Z")
        ev_b = self._finding("acme", "cve-b", "high", "2026-09-12T02:00:00Z")
        ev_c = self._finding("acme", "cve-c", "medium", "2026-09-12T03:00:00Z")
        self._finding("acme", "cve-proven", "low", "2026-09-12T04:00:00Z", poc="poc-verified")
        self._write_ledger()

        def build(evidence_dir, **k):
            if str(evidence_dir) == str(ev_a):
                return True, "PoC DEMONSTRATED", {"verdictClass": "poc-verified"}
            if str(evidence_dir) == str(ev_b):
                return True, "forge verdict: check-defect", {"verdictClass": "check-defect"}
            return True, "forge verdict: poc-unproven", {"verdictClass": "poc-unproven"}

        summary, _, _, _, notes = self._run(build=build)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["poc_verified"], [str(ev_a)],
                         "proven rows are listed by their evidence dir")
        self.assertEqual(summary["poc_unproven"], 1)
        self.assertEqual(summary["check_defect"], 1)
        self.assertEqual(summary["errors"], 0)
        self.assertEqual(summary["skipped_already_proven"], 1)
        self.assertFalse(summary["cancelled"])
        self.assertFalse(summary["paused_by_us"])
        self.assertIsNone(summary["refused"])
        self.assertGreaterEqual(summary["duration_s"], 0.0)
        self.assertIn("FORGE ALL done: 1 poc-verified, 1 unproven, 1 defects/errors, "
                      "cancelled: no", notes)
        self.assertIn("→ poc-verified", notes)

    def test_refuses_loudly_while_a_single_forge_is_active(self):
        self._standard_ledger()
        (self.hunt / "pocforge.lock").write_text("999")
        notes = []

        def forbidden(*a, **k):
            raise AssertionError("no forge may spawn while the refusal stands")

        with mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_pocforge_process", return_value=True), \
                mock.patch.object(opsmenu, "build_poc", side_effect=forbidden):
            summary = opsmenu.forge_all(self.hunt, note=notes.append)
        self.assertIn("one at a time", summary["refused"])
        self.assertEqual(summary["total"], 0)
        self.assertTrue(any("REFUSED" in n for n in notes))
        self.assertFalse((self.hunt / "FORGE_ALL_LOCK").exists(),
                         "a refused batch never takes the batch lock")
        self.assertTrue((self.hunt / "pocforge.lock").exists(), "the live forge lock is left alone")

    def test_refuses_loudly_while_another_batch_is_active(self):
        self._standard_ledger()
        (self.hunt / "FORGE_ALL_LOCK").write_text("888")
        with mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_forge_all_process", return_value=True), \
                mock.patch.object(opsmenu, "build_poc",
                                  side_effect=AssertionError("must never forge")):
            summary = opsmenu.forge_all(self.hunt)
        self.assertIn("already running", summary["refused"])
        self.assertEqual(summary["total"], 0)
        self.assertTrue((self.hunt / "FORGE_ALL_LOCK").exists(),
                        "the live batch's lock is left alone")

    def test_a_stale_batch_lock_is_cleaned_and_the_run_proceeds(self):
        self._standard_ledger()
        (self.hunt / "FORGE_ALL_LOCK").write_text("888")
        with mock.patch.object(opsmenu, "pid_alive", return_value=False):
            # the guard itself reports the cleanup, loudly — never obeyed blindly
            active, detail = opsmenu.forge_all_active(self.hunt)
            self.assertFalse(active)
            self.assertIn("stale forge-all lock", detail)
            # and a fresh batch re-takes the lock, runs, and releases it
            summary, order, _, _, _ = self._run()
        self.assertEqual(order, ["forge"] * 5)
        self.assertIsNone(summary["refused"])
        self.assertFalse((self.hunt / "FORGE_ALL_LOCK").exists(),
                         "the batch's own lock is cleaned in the finally")

    def test_empty_queue_is_honest(self):
        self._write_ledger()  # no findings at all
        summary, order, _, _, notes = self._run()
        self.assertEqual(order, [])
        self.assertEqual(summary["total"], 0)
        self.assertTrue(any("no findings in the ledger yet" in n for n in notes))
        # every forgeable finding already proven: said plainly, zero forged
        self._finding("acme", "cve-proven", "high", "t1", poc="poc-verified")
        self._write_ledger()
        summary2, order2, _, _, notes2 = self._run()
        self.assertEqual(order2, [])
        self.assertEqual(summary2["skipped_already_proven"], 1)
        self.assertTrue(any("already poc-verified" in n for n in notes2))

    def test_pause_false_goes_straight_to_the_queue(self):
        self._standard_ledger()
        with mock.patch.object(opsmenu, "pipeline_status") as ps, \
                mock.patch.object(opsmenu, "build_poc",
                                  return_value=(True, "ok", {"verdictClass": "poc-unproven"})):
            summary = opsmenu.forge_all(self.hunt, pause=False)
        ps.assert_not_called()
        self.assertFalse(summary["paused_by_us"])
        self.assertEqual(summary["total"], 5)


class TestForgePathUnity(unittest.TestCase):
    """The consistency pin (the operator's observation: 'hunt still active
    during the forge' via the OPS button): BOTH forge entry points — the OPS
    BUILD PoC picker and the FINDINGS VERIFY button — ride the SAME
    pause→forge→auto-resume contract. menu.py is a tkinter shell (never
    instantiated headless), so this is a SOURCE pin — the same doctrine as
    varvel's never-submits static scan."""

    SRC = None

    @classmethod
    def setUpClass(cls):
        cls.SRC = (Path(opsmenu.__file__).parent / "menu.py").read_text(encoding="utf-8")

    def _body(self, name):
        i = self.SRC.index(f"def {name}(")
        j = self.SRC.index("\n    def ", i + 1)
        return self.SRC[i:j]

    def test_no_entry_point_calls_build_poc_directly(self):
        self.assertNotIn(
            "opsmenu.build_poc(", self.SRC,
            "every console forge rides verify_finding (pause→forge→resume) — "
            "build_poc is verify_finding's internal, never a button's direct call")

    def test_the_shared_kickoff_calls_verify_finding(self):
        self.assertIn("opsmenu.verify_finding(", self._body("_forge_begin"))

    def test_both_entry_points_ride_the_shared_kickoff(self):
        self.assertIn("self._forge_begin(", self._body("_poc_run"),
                      "the OPS BUILD PoC picker rides the shared contract")
        self.assertIn("self._forge_begin(", self._body("_verify_run"),
                      "the FINDINGS VERIFY button rides the shared contract")

    def test_the_one_at_a_time_guard_is_structural(self):
        body = self._body("_forge_begin")
        self.assertIn("if self._poc_busy:", body,
                      "the busy guard lives IN the shared kickoff — the two "
                      "buttons can never double-pause or fight, by construction")
        self.assertIn("return False", body)


class TestForgeAllWiring(unittest.TestCase):
    """The FORGE ALL button's wiring in menu.py, pinned at SOURCE level (the
    tkinter shell is never instantiated headless — TestForgePathUnity's
    doctrine). The behavior itself is tested live in TestForgeAll; these pins
    keep the shell honest: the batch rides the SAME _poc_busy guard, progress
    rides the app stream, STOP BATCH writes FORGE_STOP, and the winners'
    badges get their POC PASS emphasis."""

    SRC = None

    @classmethod
    def setUpClass(cls):
        cls.SRC = (Path(opsmenu.__file__).parent / "menu.py").read_text(encoding="utf-8")

    def _body(self, name):
        i = self.SRC.index(f"def {name}(")
        j = self.SRC.index("\n    def ", i + 1)
        return self.SRC[i:j]

    def test_the_button_lives_in_the_findings_header_and_dispatches(self):
        head = self._body("_build_findings_tab")
        self.assertIn("FORGE ALL", head)
        self.assertIn("self._forge_all_click", head)
        click = self._body("_forge_all_click")
        self.assertIn("_forge_all_begin", click)
        self.assertIn("_forge_all_stop", click,
                      "the same button is the batch's start AND its honest cancel")

    def test_the_batch_rides_the_shared_busy_guard(self):
        body = self._body("_forge_all_begin")
        self.assertIn("if self._poc_busy:", body,
                      "a single forge blocks a batch; a batch holds the guard — one lane, structurally")
        self.assertIn("self._poc_busy = True", body)
        self.assertIn("self._batch_running = True", body)

    def test_the_batch_calls_forge_all_in_a_daemon_thread_on_the_app_stream(self):
        body = self._body("_forge_all_begin")
        self.assertIn("opsmenu.forge_all(", body,
                      "the button never forges directly — opsmenu.forge_all owns the batch")
        self.assertIn("threading.Thread", body)
        self.assertIn('("app", t)', body, "progress lines ride the app stream")
        self.assertIn("poc-row-done", body,
                      "each landed verdict queues a findings refresh so badges flip live")

    def test_poc_row_done_and_batch_done_are_drained(self):
        body = self._body("_drain")
        self.assertIn("poc-row-done", body)
        self.assertIn("batch-done", body)
        self.assertIn("_forge_all_finish", body)

    def test_stop_batch_writes_forge_stop_and_says_after_current(self):
        body = self._body("_forge_all_stop")
        self.assertIn("opsmenu.FORGE_STOP_FILE", body)
        self.assertIn("after the current finding", body,
                      "the cancel is honestly labelled — it lands BETWEEN runs, never mid-forge")

    def test_finish_releases_the_guard_and_repaints(self):
        body = self._body("_forge_all_finish")
        self.assertIn("self._poc_busy = False", body)
        self.assertIn("self._batch_running = False", body)
        self.assertIn("_findings_refresh", body)
        self.assertIn("refused", body, "a loud refusal (forge active / batch active) surfaces")

    def test_poc_pass_badge_emphasis_and_header_score_line(self):
        self.assertIn("POC PASS ✓", self._body("_findings_row"),
                      "a poc-verified row wears the strongest emphasis")
        refresh = self._body("_findings_refresh")
        # The score line names the grades honestly (2026-09-18): a replay alone is `firm`,
        # and there is no "verified" claim anywhere — only a demonstrated PoC is submittable.
        self.assertIn("PoC demonstrated", refresh)
        self.assertIn("firm (not confirmed)", refresh)
        # No VERIFIED badge exists any more (note: "UNVERIFIED" is a different badge and
        # legitimately contains the word — the quoted badge literal is what must be gone).
        self.assertNotIn('"VERIFIED"', refresh)
        self.assertIn("POC-DEMONSTRATED", refresh,
                      "the header score line is computed from the real rows")


if __name__ == "__main__":
    unittest.main()