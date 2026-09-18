"""Ghost pre-flight gate + chat tab logic (opsmenu): the gate's three checks
(pass and fail each), exit-pin enforcement, the mid-hunt drop that PAUSES the
hunt, chat send/recv against the mock lane server, the profit-first chat
block, context-meter math, and stats-bar formatting. All network is injected
— the suite never dials out."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spark_code import opsmenu
from spark_code.client import SparkClient

from tests.mock_server import MockSparkServer


SETTINGS = {
    "tripcom": {
        "ghost.mode": "required",
        "ghost.chain": "socks5://10.64.0.1:1080",
        "ghost.expectExit": "135.136.21.33",
        "ghost.pinStrict": True,
    },
    "plain": {"stealth.profile": "paranoid"},
}


def _settings_file(tmp, doc):
    p = Path(tmp) / "settings.json"
    p.write_text(json.dumps(doc))
    return p


def _dial_ok(host, port, dhost, dport, timeout=8.0, **kw):
    if str(dhost).endswith(".invalid"):
        return False, "proxy CONNECT refused: host unreachable", None
    return True, f"CONNECT {dhost}:{dport} ok (remote DNS)", _FakeSock()


class _FakeSock:
    def close(self):
        pass


def _direct(ip):
    return lambda url, timeout=8.0: (True, ip)


def _chain(ip):
    return lambda chain, url, timeout=10.0, **kw: (True, ip)


class TestGhostConfig(unittest.TestCase):
    def test_reads_first_required_engagement(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _settings_file(tmp, SETTINGS)
            cfg, src = opsmenu.ghost_config(path, env={})
        self.assertEqual(src, "tripcom")
        self.assertEqual(cfg["chain"], "socks5://10.64.0.1:1080")
        self.assertEqual(cfg["expectExit"], "135.136.21.33")
        self.assertTrue(cfg["pinStrict"])

    def test_env_named_engagement_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = dict(SETTINGS)
            doc["chosen"] = {"ghost.mode": "on", "ghost.chain": "socks5://127.0.0.1:9050"}
            path = _settings_file(tmp, doc)
            cfg, src = opsmenu.ghost_config(path, env={"VARVEL_ENGAGEMENT": "chosen"})
        self.assertEqual(src, "chosen")
        self.assertEqual(cfg["chain"], "socks5://127.0.0.1:9050")

    def test_no_chain_is_an_honest_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _settings_file(tmp, {"plain": {"stealth.profile": "paranoid"}})
            cfg, reason = opsmenu.ghost_config(path, env={})
        self.assertIsNone(cfg)
        self.assertIn("ghost.chain", reason)
        r = opsmenu.ghost_preflight(path, env={})
        self.assertFalse(r["ok"])
        self.assertTrue(any("arm a ghost chain" in x for x in r["remediation"]))


class TestGhostPreflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = _settings_file(self.tmp.name, {
            "eng": {"ghost.mode": "required", "ghost.chain": "socks5://10.0.0.1:1080"}})

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, **over):
        kw = {"settings_path": self.path, "env": {}, "dialer": _dial_ok,
              "direct_fetch": _direct("203.0.113.10"), "chain_fetch": _chain("135.136.21.33")}
        kw.update(over)
        return opsmenu.ghost_preflight(**kw)

    def test_full_pass_green(self):
        r = self._run()
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["checks"]["exit"]["origin"], "203.0.113.10")
        self.assertEqual(r["checks"]["exit"]["exit"], "135.136.21.33")
        self.assertTrue(r["checks"]["dns"]["ok"])
        self.assertEqual(r["remediation"], [])
        # no pin: the gate passes on dial + identity-diff + DNS, and SAYS so
        self.assertEqual(r["checks"]["pin"]["ok"], True)
        self.assertIn("identity-diff mode", r["checks"]["pin"]["detail"])

    def test_pin_set_and_matching_exit_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            pinned = _settings_file(tmp, {"eng": {
                "ghost.mode": "required", "ghost.chain": "socks5://10.0.0.1:1080",
                "ghost.expectExit": "135.136.21.33", "ghost.pinStrict": True}})
            r = opsmenu.ghost_preflight(pinned, env={}, dialer=_dial_ok,
                                        direct_fetch=_direct("203.0.113.10"),
                                        chain_fetch=_chain("135.136.21.33"))
        self.assertTrue(r["ok"], r)
        self.assertIn("== pinned expectExit", r["checks"]["pin"]["detail"])

    def test_dial_failure_blocks_with_remediation(self):
        def bad_dial(host, port, dhost, dport, timeout=8.0, **kw):
            return False, f"dial {host}:{port} failed: TimeoutError", None
        r = self._run(dialer=bad_dial)
        self.assertFalse(r["ok"])
        self.assertFalse(r["checks"]["dial"]["ok"])
        self.assertTrue(any("not dialable" in x for x in r["remediation"]))

    def test_exposed_when_origin_equals_exit(self):
        r = self._run(chain_fetch=_chain("203.0.113.10"))
        self.assertFalse(r["ok"])
        self.assertFalse(r["checks"]["exit"]["ok"])
        self.assertTrue(any("EXPOSED" in x for x in r["remediation"]))

    def test_dns_canary_connected_fails(self):
        def leaky_dial(host, port, dhost, dport, timeout=8.0, **kw):
            return True, "CONNECT ok", _FakeSock()  # even .invalid 'connects'
        r = self._run(dialer=leaky_dial)
        self.assertFalse(r["ok"])
        self.assertFalse(r["checks"]["dns"]["ok"])
        self.assertTrue(any("DNS-leak" in x for x in r["remediation"]))

    def test_chain_echo_failure_blocks(self):
        def bad_chain(chain, url, timeout=10.0, **kw):
            return False, "proxy CONNECT refused: host unreachable"
        r = self._run(chain_fetch=bad_chain)
        self.assertFalse(r["ok"])
        self.assertTrue(any("chain IP echo failed" in x for x in r["remediation"]))

    def test_exit_pin_strict_and_unpinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            strict = _settings_file(tmp, {"eng": {
                "ghost.mode": "required", "ghost.chain": "socks5://10.0.0.1:1080",
                "ghost.expectExit": "135.136.21.33", "ghost.pinStrict": True}})
            r = opsmenu.ghost_preflight(strict, env={}, dialer=_dial_ok,
                                        direct_fetch=_direct("203.0.113.10"),
                                        chain_fetch=_chain("198.51.100.9"))
            self.assertFalse(r["ok"], "pinStrict mismatch refuses")
            self.assertTrue(any("pinStrict" in x for x in r["remediation"]))
            loose = _settings_file(tmp, {"eng": {
                "ghost.mode": "required", "ghost.chain": "socks5://10.0.0.1:1080",
                "ghost.expectExit": "135.136.21.33"}})
            r2 = opsmenu.ghost_preflight(loose, env={}, dialer=_dial_ok,
                                         direct_fetch=_direct("203.0.113.10"),
                                         chain_fetch=_chain("198.51.100.9"))
            self.assertTrue(r2["ok"], "unpinned mismatch is a loud warning, still green")
            self.assertIn("loud warning", r2["checks"]["pin"]["detail"])


class TestGhostWatchTick(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hunt = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_running(self):
        (self.hunt / "hunt.pid").write_text("4242")

    def test_drop_pauses_the_hunt_loud(self):
        self._make_running()
        with mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_hunt_process", return_value=True):
            # a SINGLE failed tick is a blip: loud, degraded, NO pause
            state, detail = opsmenu.ghost_watch_tick(
                self.hunt, checker=lambda: {"ok": False, "remediation": ["exit exposed"]})
            self.assertEqual(state, "degraded")
            self.assertIn("exit exposed", detail)
            self.assertFalse((self.hunt / "PAUSE").exists(), "one blip never pauses the hunt")
            # the SECOND consecutive failure is a proven drop: PAUSE, loud
            state, detail = opsmenu.ghost_watch_tick(
                self.hunt, checker=lambda: {"ok": False, "remediation": ["exit exposed"]})
        self.assertEqual(state, "dropped")
        self.assertIn("GHOST DROPPED", detail)
        self.assertIn("exit exposed", detail)
        self.assertTrue((self.hunt / "PAUSE").exists(), "the hunt is PAUSED, not left exposed")
        self.assertIn("ghost watchdog", (self.hunt / "PAUSE").read_text(),
                      "the PAUSE file names the watchdog, not a phantom console click")

    def test_success_resets_the_streak(self):
        self._make_running()
        with mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_hunt_process", return_value=True):
            fail = lambda: {"ok": False, "remediation": ["blip"]}
            good = lambda: {"ok": True}
            self.assertEqual(opsmenu.ghost_watch_tick(self.hunt, checker=fail)[0], "degraded")
            self.assertEqual(opsmenu.ghost_watch_tick(self.hunt, checker=good)[0], "ok")
            # the recovery cleared the streak: the next failure counts from 1 again
            self.assertEqual(opsmenu.ghost_watch_tick(self.hunt, checker=fail)[0], "degraded")
            self.assertFalse((self.hunt / "PAUSE").exists())

    def test_ok_and_not_running(self):
        self._make_running()
        with mock.patch.object(opsmenu, "pid_alive", return_value=True), \
                mock.patch.object(opsmenu, "is_hunt_process", return_value=True):
            state, _ = opsmenu.ghost_watch_tick(self.hunt, checker=lambda: {"ok": True})
        self.assertEqual(state, "ok")
        self.assertFalse((self.hunt / "PAUSE").exists())
        state, _ = opsmenu.ghost_watch_tick(self.hunt, checker=lambda: {"ok": False})
        self.assertEqual(state, "not-running")


class TestChatLogic(unittest.TestCase):
    def test_send_recv_against_mock_and_usage_recorded(self):
        with MockSparkServer() as srv:
            srv.scripts.append({"deltas": ["hello ", "operator"],
                                "usage": {"prompt_tokens": 128, "completion_tokens": 9}})
            client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
            state = opsmenu.ChatState()
            seen = []
            ok, reply = opsmenu.chat_send(state, client, "ping", on_delta=seen.append)
        self.assertTrue(ok, reply)
        self.assertEqual(reply, "hello operator")
        self.assertEqual("".join(seen), "hello operator")
        self.assertEqual([m["role"] for m in state.messages], ["user", "assistant"])
        self.assertEqual(state.last_prompt_tokens, 128)
        self.assertGreater(state.last_tok_s, 0)

    def test_thinking_toggle_reaches_the_wire(self):
        with MockSparkServer() as srv:
            srv.scripts.append({"deltas": ["ok"], "usage": None})
            client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
            state = opsmenu.ChatState()
            state.thinking = False
            ok, _ = opsmenu.chat_send(state, client, "no thinking please")
        self.assertTrue(ok)
        body = srv.requests[0]
        self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})

    def test_tunnel_down_is_honest_not_raised(self):
        client = SparkClient(base_url="http://127.0.0.1:9", model="x")
        client.retry_backoff = ()
        state = opsmenu.ChatState()
        ok, msg = opsmenu.chat_send(state, client, "anything")
        self.assertFalse(ok)
        self.assertIn("TunnelDownError", msg)
        self.assertEqual(len(state.messages), 1, "the user turn stays for an honest retry")

    def test_profit_first_chat_block(self):
        ok, reason = opsmenu.chat_gate("running")
        self.assertFalse(ok)
        self.assertIn("all model capacity to the hunt", reason)
        self.assertTrue(opsmenu.chat_gate("paused")[0])
        self.assertTrue(opsmenu.chat_gate("stopped")[0])


class TestContextMeterAndStats(unittest.TestCase):
    def test_meter_math_estimate_then_real(self):
        state = opsmenu.ChatState()
        state.messages = [{"role": "user", "content": "x" * 400}]  # ~100 tok estimate
        used, limit, pct = state.context_meter(limit=262144)
        self.assertEqual(used, 100)
        self.assertEqual(limit, 262144)
        self.assertEqual(pct, round(100 / 262144 * 100, 1))
        state.last_prompt_tokens = 5000  # the server's REAL count wins
        used, _, pct = state.context_meter(limit=262144)
        self.assertEqual(used, 5000)
        self.assertEqual(pct, round(5000 / 262144 * 100, 1))

    def test_lane_activity_and_stats_fields(self):
        self.assertEqual(opsmenu.lane_activity("running", "up"), "hunt")
        self.assertEqual(opsmenu.lane_activity("paused", "up"), "paused")
        self.assertEqual(opsmenu.lane_activity("stopped", "down"), "training")
        self.assertEqual(opsmenu.lane_activity("stopped", "up"), "idle")
        self.assertEqual(opsmenu.lane_activity("stopped", "unknown"), "down")
        f = opsmenu.stats_fields("rvn-q4", 21.37, "idle", "standard")
        self.assertEqual(f["model"], "rvn-q4")
        self.assertEqual(f["tok_s"], "21.4 tok/s")
        self.assertEqual(f["activity"], "idle")
        f2 = opsmenu.stats_fields(None, 0.0, "training", "fast")
        self.assertEqual(f2["model"], "—")
        self.assertEqual(f2["tok_s"], "— tok/s")


if __name__ == "__main__":
    unittest.main()


class TestStreamMerge(unittest.TestCase):
    """Bug repro: a transient console line (VERIFY GHOST progress) vanished on
    the next refresh tick because the pane rebuilt from the file alone."""

    @staticmethod
    def _fmt(ev):
        if ev.get("type") == "stage":
            return (ev.get("state", "dim"), f"{ev.get('stage')} {ev.get('state')}")
        return None

    def test_transient_survives_the_refresh_tick(self):
        events_t0 = [
            {"type": "stage", "stage": "watch", "state": "done"},
            {"type": "stage", "stage": "intake", "state": "done"},
        ]
        transients = [("app", "ghost: waiting — verifying chain (dial · exit · dns)…")]
        lines_t0 = opsmenu.build_stream(events_t0, transients, self._fmt)
        texts0 = [t for _, t in lines_t0]
        self.assertIn("ghost: waiting — verifying chain (dial · exit · dns)…", texts0)

        # the next tick: a new file event arrives, the pane re-renders — the
        # transient must STILL be rendered (pre-fix it was wiped here).
        events_t1 = events_t0 + [{"type": "stage", "stage": "scope-check", "state": "done"}]
        lines_t1 = opsmenu.build_stream(events_t1, transients, self._fmt)
        texts1 = [t for _, t in lines_t1]
        self.assertIn("ghost: waiting — verifying chain (dial · exit · dns)…", texts1,
                      "transient vanished on refresh — the bug Jack reported")
        self.assertEqual(texts1[:3], ["watch done", "intake done", "scope-check done"],
                         "file events keep their order, transients after")
        self.assertEqual(texts1[-1], "ghost: waiting — verifying chain (dial · exit · dns)…")

    def test_transients_are_capped_oldest_dropped(self):
        many = [("dim", f"line {i}") for i in range(opsmenu.TRANSIENT_CAP + 50)]
        lines = opsmenu.build_stream([], many, self._fmt)
        self.assertEqual(len(lines), opsmenu.TRANSIENT_CAP)
        self.assertEqual(lines[0][1], "line 50", "the oldest transients drop first")
        self.assertEqual(lines[-1][1], f"line {opsmenu.TRANSIENT_CAP + 49}")

    def test_formatter_nones_are_skipped(self):
        events = [{"type": "counters", "data": {}}, {"type": "stage", "stage": "watch", "state": "done"}]
        lines = opsmenu.build_stream(events, [], self._fmt)
        self.assertEqual(len(lines), 1)


class TestGhostLoopEvents(unittest.TestCase):
    """The loop's own ghost verdict reaches the board projection (the console's
    GHOST card shows 'chain in use by loop' once the hunt is running)."""

    def test_ghost_event_projects(self):
        events = [
            {"ts": "t1", "type": "ghost", "state": "in-use", "chain": "socks5://10.64.0.1:1080",
             "msg": "ghost chain VERIFIED by the loop's own dial"},
        ]
        b = opsmenu.board(events)
        self.assertEqual(b["ghost"]["state"], "in-use")
        self.assertEqual(b["ghost"]["chain"], "socks5://10.64.0.1:1080")

    def test_ghost_down_and_off_project(self):
        b = opsmenu.board([{"ts": "t1", "type": "ghost", "state": "down",
                            "msg": "GHOST CHAIN DOWN — the loop refuses to start"}])
        self.assertEqual(b["ghost"]["state"], "down")
        b2 = opsmenu.board([{"ts": "t1", "type": "ghost", "state": "off", "msg": "no chain"}])
        self.assertEqual(b2["ghost"]["state"], "off")
        b3 = opsmenu.board([])
        self.assertIsNone(b3["ghost"], "no ghost event = no claim")
