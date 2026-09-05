"""Display logic: friendly model names and the honest context readout."""

import unittest

from spark_code import config
from spark_code.ui import UI, ctx_display, friendly_model_name, short_model_name


class TestModelNames(unittest.TestCase):
    def test_alias_table_hit(self):
        self.assertEqual(friendly_model_name("/home/varvel/models/RVN-Q4_K_M-mtp.gguf"),
                         "Qwen 3.8 27B · Heretic")

    def test_unknown_model_falls_back_to_basename(self):
        self.assertEqual(friendly_model_name("/models/SomeOther-Q8.gguf"),
                         "SomeOther-Q8")

    def test_bare_id_without_path(self):
        self.assertEqual(short_model_name("RVN-Q4_K_M-mtp.gguf"), "RVN-Q4_K_M-mtp")

    def test_alias_table_entries_are_strings(self):
        for k, v in config.MODEL_ALIASES.items():
            self.assertIsInstance(k, str)
            self.assertIsInstance(v, str)


class TestCtxDisplay(unittest.TestCase):
    def test_full_262k_slot_shows_plain(self):
        # current config: -c 524288 -np 2 -> per-slot 262144
        self.assertEqual(ctx_display(766, 262144, 524288), "ctx 766/262,144 (0%)")

    def test_split_slot_shows_slot_cap_honestly(self):
        # old config: -c 262144 -np 2 -> per-slot 131072
        self.assertEqual(ctx_display(766, 131072, 262144),
                         "ctx 766/262,144 (slot cap 131,072) (1%)")

    def test_single_slot_server_plain(self):
        self.assertEqual(ctx_display(766, 131072, 131072), "ctx 766/131,072 (1%)")

    def test_status_text_contains_cwd_and_model(self):
        ui = UI(color=False)
        text = ui.status_text(model="Qwen 3.8 27B · Heretic", ctx_used=100,
                              ctx_limit=262144, ctx_total=524288, tok_s=40.0,
                              mode="Reasoning", cwd=r"C:\proj", yolo=False,
                              thinking=True, session_cloud=0.0123)
        self.assertTrue(text.startswith(r"C:\proj"))  # cwd leads the bar
        self.assertIn("Qwen 3.8 27B · Heretic", text)
        self.assertIn("ctx 100/262,144", text)
        self.assertIn("40.0 tok/s", text)
        self.assertIn("Reasoning", text)   # mode name, not old effort levels
        self.assertIn("thinking:on", text)
        self.assertIn("$0.00 local", text)
        self.assertIn("would-cost $0.0123", text)

    def test_status_text_fast_mode(self):
        ui = UI(color=False)
        text = ui.status_text(model="m", ctx_used=0, ctx_limit=262144,
                              ctx_total=524288, tok_s=0.0, mode="Fast",
                              cwd=r"C:\p", yolo=False, thinking=False)
        self.assertIn("Fast", text)
        self.assertIn("thinking:off", text)
        self.assertNotIn("effort", text)

    def test_tok_s_never_blank(self):
        # Jack's repro: "- tok/s" rendered mid-turn. 0.0 until first measurement.
        ui = UI(color=False)
        text = ui.status_text(model="m", ctx_used=0, ctx_limit=262144,
                              ctx_total=524288, tok_s=0.0, mode="Reasoning",
                              cwd=r"C:\p", yolo=False)
        self.assertIn("0.0 tok/s", text)
        self.assertNotIn("- tok/s", text)


class TestBannerHints(unittest.TestCase):
    """Discoverability: the startup banner must surface --yolo / [a]lways."""

    def banner(self, yolo):
        import contextlib
        import io
        ui = UI(yolo=yolo, color=False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ui.banner("0.0.0-test", "Model", 262144, 524288, "/props",
                      r"C:\proj", "already-up")
        return buf.getvalue()

    def test_approvals_hint_when_not_yolo(self):
        out = self.banner(yolo=False)
        self.assertIn("--yolo", out)
        self.assertIn("always", out)
        self.assertIn("/help", out)

    def test_yolo_state_shown_when_yolo(self):
        out = self.banner(yolo=True)
        self.assertIn("yolo on", out)
        self.assertNotIn("approvals on", out)


if __name__ == "__main__":
    unittest.main()
