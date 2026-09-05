"""Slash-command menu + TAB completion logic (pure, no console needed)."""

import unittest

from spark_code.commands import (COMMANDS, canonical, filter_commands,
                                 help_text, tab_complete)


class TestFilter(unittest.TestCase):
    def test_bare_slash_shows_all(self):
        self.assertEqual(len(filter_commands("/")), len(COMMANDS))

    def test_prefix_filtering(self):
        names = [c.name for c in filter_commands("/st")]
        # "/standard" is a valid sibling now, so assert membership + that every
        # returned command honors the typed prefix (not exclusivity).
        self.assertIn("/status", names)
        self.assertTrue(all(n.startswith("/st") for n in names))

    def test_multi_match(self):
        names = [c.name for c in filter_commands("/s")]
        self.assertIn("/status", names)
        self.assertIn("/sessions", names)

    def test_space_closes_menu(self):
        self.assertEqual(filter_commands("/effort "), [])
        self.assertEqual(filter_commands("/resume abc"), [])

    def test_no_match(self):
        self.assertEqual(filter_commands("/zzz"), [])

    def test_non_slash_buffer_no_menu(self):
        self.assertEqual(filter_commands("hello"), [])

    def test_every_command_has_description(self):
        for c in COMMANDS:
            self.assertTrue(c.description, c.name)
            self.assertTrue(c.name.startswith("/"))


class TestTabComplete(unittest.TestCase):
    def test_single_match_fills(self):
        buf, matches = tab_complete("/stat")
        self.assertEqual(buf, "/status")

    def test_single_match_with_args_gets_space(self):
        buf, _ = tab_complete("/eff")
        self.assertEqual(buf, "/effort ")

    def test_multi_match_common_prefix(self):
        buf, matches = tab_complete("/s")
        self.assertEqual(buf, "/s")  # common prefix of /status /sessions is "/s"
        self.assertGreater(len(matches), 1)

    def test_multi_match_extends_when_possible(self):
        buf, _ = tab_complete("/se")
        self.assertEqual(buf, "/sessions")

    def test_no_match_unchanged(self):
        buf, matches = tab_complete("/zzz")
        self.assertEqual(buf, "/zzz")
        self.assertEqual(matches, [])

    def test_usage_strings(self):
        by_name = {c.name: c for c in COMMANDS}
        self.assertEqual(by_name["/status"].usage(), "/status")
        self.assertEqual(by_name["/resume"].usage(), "/resume ")


class TestRegistry(unittest.TestCase):
    def test_alias(self):
        self.assertEqual(canonical("/quit"), "/exit")
        self.assertEqual(canonical("/status"), "/status")

    def test_mode_commands_present(self):
        names = {c.name for c in COMMANDS}
        self.assertIn("/fast", names)
        self.assertIn("/standard", names)  # the new balanced tier
        self.assertIn("/reasoning", names)
        effort = next(c for c in COMMANDS if c.name == "/effort")
        for tier in ("fast", "standard", "reasoning"):
            self.assertIn(tier, effort.args)

    def test_no_legacy_effort_levels_anywhere(self):
        for c in COMMANDS:
            for legacy in ("low", "medium", "high"):
                self.assertNotIn(legacy, c.args)
                self.assertNotIn(legacy, c.description)

    def test_help_lists_everything(self):
        text = help_text()
        for c in COMMANDS:
            self.assertIn(c.name, text)
            self.assertIn(c.description, text)


if __name__ == "__main__":
    unittest.main()
