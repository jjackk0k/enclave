"""read_image tool: honest refusals (missing file, bad extension, too big,
text-only endpoint), base64 data-URL attachment when vision is supported,
optional Pillow downscale, the client-side capability probe (models flag or
1x1-png POST, cached once per session), and a full agent-loop roundtrip
where the image lands in the next request as multipart content."""

import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spark_code import tools
from spark_code.agent import Agent
from spark_code.client import SparkClient
from spark_code.session import SessionStore
from spark_code.tools import ToolExecutor
from spark_code.ui import UI

from tests.mock_server import MockSparkServer

PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
    "AAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def make_image(tmp, name="shot.png", raw=PNG_1X1):
    p = Path(tmp) / name
    p.write_bytes(raw)
    return p


class TestReadImageRefusals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ex = ToolExecutor(cwd=self.tmp.name, approve=lambda a, s, d: True)
        self.ex.vision_probe = lambda: True

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_file_refused(self):
        r = self.ex.execute("read_image", {"path": "nope.png"})
        self.assertFalse(r.ok)
        self.assertIn("Not a file", r.text)

    def test_bad_extension_refused(self):
        (Path(self.tmp.name) / "notes.txt").write_text("hi", encoding="utf-8")
        r = self.ex.execute("read_image", {"path": "notes.txt"})
        self.assertFalse(r.ok)
        self.assertIn("not a supported image", r.text)

    def test_too_big_refused(self):
        big = Path(self.tmp.name) / "big.png"
        big.write_bytes(b"\x89PNG" + b"0" * 100)
        with mock.patch.object(tools, "IMAGE_MAX_BYTES", 10):
            r = self.ex.execute("read_image", {"path": "big.png"})
        self.assertFalse(r.ok)
        self.assertIn("cap", r.text)

    def test_text_only_endpoint_is_honest_never_dumps_base64(self):
        make_image(self.tmp.name)
        self.ex.vision_probe = lambda: False
        r = self.ex.execute("read_image", {"path": "shot.png"})
        self.assertFalse(r.ok)
        self.assertIn("not supported by the serving endpoint", r.text)
        self.assertNotIn("base64", r.text)
        self.assertIsNone(r.data)  # nothing attached

    def test_no_probe_wired_means_unsupported(self):
        make_image(self.tmp.name)
        self.ex.vision_probe = None
        r = self.ex.execute("read_image", {"path": "shot.png"})
        self.assertFalse(r.ok)


class TestReadImageAttach(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ex = ToolExecutor(cwd=self.tmp.name, approve=lambda a, s, d: True)
        self.ex.vision_probe = lambda: True

    def tearDown(self):
        self.tmp.cleanup()

    def test_small_image_attached_as_data_url(self):
        make_image(self.tmp.name)
        r = self.ex.execute("read_image", {"path": "shot.png"})
        self.assertTrue(r.ok, r.text)
        self.assertIn("image attached", r.text)
        url = r.data["image_dataurl"]
        self.assertTrue(url.startswith("data:image/png;base64,"))
        self.assertEqual(base64.b64decode(url.split(",", 1)[1]), PNG_1X1)

    def test_pil_downscale_when_needed(self):
        Image = tools._pil()
        if Image is None:
            self.skipTest("Pillow not importable in this runtime")
        big = Path(self.tmp.name) / "big.png"
        Image.new("RGB", (2000, 1000), (200, 30, 30)).save(big)
        r = self.ex.execute("read_image", {"path": "big.png"})
        self.assertTrue(r.ok, r.text)
        self.assertIn("downscaled 2000x1000 -> 1568x784", r.text)
        sent = base64.b64decode(r.data["image_dataurl"].split(",", 1)[1])
        im = Image.open(io.BytesIO(sent))
        self.assertEqual(im.size, (1568, 784))

    def test_no_pil_sends_raw_with_note(self):
        make_image(self.tmp.name)
        with mock.patch.object(tools, "_pil", lambda: None):
            r = self.ex.execute("read_image", {"path": "shot.png"})
        self.assertTrue(r.ok)
        self.assertIn("sent raw", r.text)
        self.assertIsNotNone(r.data["image_dataurl"])  # never silently dropped


class TestVisionProbe(unittest.TestCase):
    def test_modalities_flag_wins_no_probe_needed(self):
        with MockSparkServer() as srv:
            client = SparkClient(base_url=srv.base_url, model="m")
            with mock.patch.object(client, "_get_json", return_value={
                    "data": [{"id": "m", "modalities": {"input": ["text", "image"]}}]}):
                self.assertTrue(client.supports_vision())
                self.assertTrue(client.supports_vision())  # cached
            self.assertEqual(srv.requests, [])  # no probe POST at all

    def test_probe_400_means_text_only_cached(self):
        with MockSparkServer() as srv:
            srv.scripts.append({"error_code": 400,
                                "error": {"message": "this model does not support images"}})
            client = SparkClient(base_url=srv.base_url, model="m")
            with mock.patch.object(client, "_get_json", return_value={"data": []}):
                self.assertFalse(client.supports_vision())
                self.assertFalse(client.supports_vision())  # cached verdict
            self.assertEqual(len(srv.requests), 1)  # probed exactly once

    def test_probe_200_means_vision(self):
        with MockSparkServer() as srv:
            srv.scripts.append({"raw_json": {"choices": [
                {"message": {"role": "assistant", "content": "ok"}}]}})
            client = SparkClient(base_url=srv.base_url, model="m")
            with mock.patch.object(client, "_get_json", return_value={"data": []}):
                self.assertTrue(client.supports_vision())
            body = srv.requests[-1]
            parts = body["messages"][0]["content"]
            self.assertEqual(parts[0]["type"], "image_url")
            self.assertTrue(parts[0]["image_url"]["url"].startswith("data:image/png;base64,"))

    def test_probe_failure_means_unsupported(self):
        client = SparkClient(base_url="http://127.0.0.1:9", model="m")
        with mock.patch.object(client, "_get_json", side_effect=Exception("down")):
            self.assertFalse(client.supports_vision())


class TestReadImageRoundtrip(unittest.TestCase):
    def test_image_lands_in_next_request_as_multipart(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            make_image(tmp)
            srv.scripts.append({
                "deltas": ['```tool\n{"tool": "read_image", "args": {"path": "shot.png"}}\n```'],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            })
            srv.scripts.append({
                "deltas": ["The image shows a single pixel."],
                "usage": {"prompt_tokens": 30, "completion_tokens": 8},
            })
            store = SessionStore(Path(tmp) / "sessions")
            session = store.create(cwd=tmp, model="mock-heretic-27b")
            client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
            executor = ToolExecutor(cwd=tmp, approve=lambda a, s, d: True)
            executor.vision_probe = lambda: True
            ui = UI(yolo=True, color=False)
            agent = Agent(client, session, executor, ui)
            with contextlib.redirect_stdout(io.StringIO()):
                stats = agent.run_turn("what is in shot.png?")
            self.assertEqual(stats.tool_steps, 1)
            # history carries multipart content: text results + the image
            tool_msg = next(m for m in session.messages
                            if isinstance(m["content"], list))
            kinds = [p["type"] for p in tool_msg["content"]]
            self.assertEqual(kinds, ["text", "image_url"])
            # and the next request really contained the image
            next_body = srv.requests[-1]
            last = next_body["messages"][-1]["content"]
            self.assertEqual(last[-1]["type"], "image_url")
            self.assertTrue(last[-1]["image_url"]["url"].startswith("data:image/png;base64,"))
            # session reload keeps the multipart shape
            loaded = session.store.load(session.id)
            self.assertIsInstance(
                next(m for m in loaded.messages if m["role"] == "user"
                     and isinstance(m["content"], list))["content"], list)

    def test_compact_helpers_tolerate_image_messages(self):
        from spark_code import compact
        msgs = [{"role": "user", "content": "look at this"},
                {"role": "user", "content": [
                    {"type": "text", "text": "<tool_results>x</tool_results>"},
                    {"type": "image_url", "image_url": {"url": "data:..."}}]},
                {"role": "assistant", "content": "a pixel."},
                {"role": "user", "content": "thanks"}]
        req = compact.build_compaction_request(msgs)
        self.assertIn("[image]", req)  # marker, not the base64 blob
        self.assertNotIn("data:...", req)
        est = compact.estimate_tokens(msgs)
        self.assertGreaterEqual(est, 1100)  # the flat per-image estimate


if __name__ == "__main__":
    unittest.main()
