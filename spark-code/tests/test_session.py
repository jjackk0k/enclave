"""Session persistence tests: JSONL round-trip, compaction/clear replay,
usage totals, listing, resume-by-prefix, torn-line tolerance."""

import tempfile
import unittest
from pathlib import Path

from spark_code.session import SessionStore


class TestSessionStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SessionStore(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip(self):
        s = self.store.create(cwd=r"C:\proj", model="mock-model")
        s.add_message("user", "hello")
        s.add_message("assistant", "hi there")
        s.add_usage(100, 20)
        s.add_message("user", "second")

        loaded = self.store.load(s.id)
        self.assertEqual(loaded.id, s.id)
        self.assertEqual([m["content"] for m in loaded.messages],
                         ["hello", "hi there", "second"])
        self.assertEqual(loaded.meta["model"], "mock-model")
        self.assertEqual(loaded.total_prompt_tokens, 100)
        self.assertEqual(loaded.total_completion_tokens, 20)

    def test_compact_replay(self):
        s = self.store.create(cwd="c", model="m")
        for i in range(6):
            s.add_message("user", f"u{i}")
        kept = s.messages[-2:]
        s.apply_compact("SUMMARY", kept)
        s.add_message("user", "after")

        loaded = self.store.load(s.id)
        self.assertEqual(loaded.messages[0]["content"], "SUMMARY")
        self.assertEqual([m["content"] for m in loaded.messages[1:]],
                         ["u4", "u5", "after"])

    def test_clear_replay(self):
        s = self.store.create(cwd="c", model="m")
        s.add_message("user", "gone")
        s.clear()
        s.add_message("user", "fresh")
        loaded = self.store.load(s.id)
        self.assertEqual([m["content"] for m in loaded.messages], ["fresh"])

    def test_list_and_latest(self):
        a = self.store.create(cwd="a", model="m")
        b = self.store.create(cwd="b", model="m")
        import time as _time
        _time.sleep(0.05)  # guarantee distinct mtimes on any filesystem
        b.add_message("user", "newer activity")
        infos = self.store.list()
        self.assertEqual(len(infos), 2)
        self.assertEqual(self.store.latest_id(), b.id)

    def test_resume_by_unique_prefix(self):
        s = self.store.create(cwd="c", model="m")
        s.add_message("user", "x")
        loaded = self.store.load(s.id[:12])  # date-hour prefix
        self.assertEqual(loaded.id, s.id)

    def test_missing_session_raises(self):
        with self.assertRaises(KeyError):
            self.store.load("nope-0000")

    def test_torn_final_line_skipped(self):
        s = self.store.create(cwd="c", model="m")
        s.add_message("user", "good")
        with s.path.open("a", encoding="utf-8") as fh:
            fh.write('{"t": "msg", "role": "user", "con')  # hard kill mid-write
        loaded = self.store.load(s.id)
        self.assertEqual(len(loaded.messages), 1)

    def test_todos_replay_and_clear(self):
        s = self.store.create(cwd="c", model="m")
        s.set_todos([{"content": "one", "status": "in_progress"}])
        s.set_todos([{"content": "one", "status": "done"}])
        loaded = self.store.load(s.id)
        self.assertEqual(loaded.todos, [{"content": "one", "status": "done"}])
        s.clear()
        self.assertEqual(s.todos, [])
        loaded = self.store.load(s.id)
        self.assertEqual(loaded.todos, [])

    def test_last_ctx_used_tracks_usage_and_resets(self):
        s = self.store.create(cwd="c", model="m")
        self.assertEqual(s.last_ctx_used, 0)
        s.add_message("user", "x")
        s.add_usage(1000, 50)
        self.assertEqual(s.last_ctx_used, 1050)
        loaded = self.store.load(s.id)
        self.assertEqual(loaded.last_ctx_used, 1050)  # real count survives resume
        s.apply_compact("SUMMARY", [])
        self.assertEqual(s.last_ctx_used, 0)          # unknown until next stream
        loaded = self.store.load(s.id)
        self.assertEqual(loaded.last_ctx_used, 0)

    def test_effort_persists_and_survives_resume(self):
        """The owner's chosen tier (fast/standard/reasoning) must be restored on
        reopen - previously it was never persisted and silently reset to default."""
        s = self.store.create(cwd="c", model="m")
        # fresh log has no effort yet -> meta absent, not a bogus value
        loaded0 = self.store.load(s.id)
        self.assertNotIn("effort", loaded0.meta)
        s.set_effort("reasoning")
        self.assertEqual(s.meta.get("effort"), "reasoning")
        # last write wins if the owner switches tiers mid-session
        s.set_effort("fast")
        loaded = self.store.load(s.id)
        self.assertEqual(loaded.meta.get("effort"), "fast")
        # and it is NOT wiped by a context clear (like todos, it's session state)
        s.clear()
        loaded2 = self.store.load(s.id)
        self.assertEqual(loaded2.meta.get("effort"), "fast")

    def test_pings_survive_resume(self):
        """Scheduled reminders must round-trip through the log. Previously load()
        read 'ping' events but dropped them - they never reached the Session."""
        s = self.store.create(cwd="c", model="m")
        import time as _time
        now = int(_time.time())
        items = [
            {"id": "p1", "kind": "once", "message": "check build",
             "due_ts": float(now + 60), "interval_s": 0},
            {"id": "e1", "kind": "every", "message": "standup",
             "due_ts": float(now + 300), "interval_s": 300},
        ]
        s.set_pings(items)
        self.assertEqual(s.pings, items)          # live state set
        loaded = self.store.load(s.id)
        self.assertEqual(loaded.pings, items)     # the actual bug: was [] before fix
        # updating to a shorter list also round-trips (cancel path)
        s.set_pings([items[0]])
        loaded2 = self.store.load(s.id)
        self.assertEqual(len(loaded2.pings), 1)
        self.assertEqual(loaded2.pings[0]["id"], "p1")

    def test_effort_and_pings_independent_of_clear(self):
        s = self.store.create(cwd="c", model="m")
        import time as _time
        now = int(_time.time())
        s.set_effort("standard")
        s.set_pings([{"id": "x", "kind": "once", "message": "hi",
                      "due_ts": float(now + 10), "interval_s": 0}])
        s.clear()   # wipes messages+todos, must NOT wipe effort/pings
        loaded = self.store.load(s.id)
        self.assertEqual(loaded.meta.get("effort"), "standard")
        self.assertEqual(len(loaded.pings), 1)


if __name__ == "__main__":
    unittest.main()
