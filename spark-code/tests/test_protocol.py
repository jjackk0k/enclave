"""Protocol parser tests: clean blocks, multiple calls, malformed JSON,
end-of-stream salvage, non-tool fences, and chunked streaming."""

import unittest

from spark_code.protocol import ToolStreamFilter, parse_tool_blocks


class TestParseOneShot(unittest.TestCase):
    def test_clean_block(self):
        calls, failures, display = parse_tool_blocks(
            'Let me read it.\n```tool\n{"tool": "read_file", "args": {"path": "a.py"}}\n```\nDone.')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].tool, "read_file")
        self.assertEqual(calls[0].args, {"path": "a.py"})
        self.assertEqual(failures, [])
        self.assertNotIn("read_file", display)
        self.assertIn("Let me read it.", display)
        self.assertIn("Done.", display)

    def test_multiple_calls(self):
        text = ('```tool\n{"tool": "read_file", "args": {"path": "a"}}\n```\n'
                'and\n```tool\n{"tool": "list_dir", "args": {}}\n```')
        calls, failures, _ = parse_tool_blocks(text)
        self.assertEqual([c.tool for c in calls], ["read_file", "list_dir"])
        self.assertEqual(calls[1].args, {})
        self.assertEqual(failures, [])

    def test_tool_call_alias_fence(self):
        calls, _, _ = parse_tool_blocks('```tool_call\n{"tool": "list_dir"}\n```')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args, {})

    def test_malformed_json_recorded_honestly(self):
        calls, failures, display = parse_tool_blocks(
            '```tool\n{"tool": "read_file", "args": {oops}}\n```')
        self.assertEqual(calls, [])
        self.assertEqual(len(failures), 1)
        self.assertIn("invalid JSON", failures[0].error)
        self.assertNotIn("oops", display)  # broken block is not shown as text

    def test_missing_tool_field(self):
        calls, failures, _ = parse_tool_blocks('```tool\n{"args": {}}\n```')
        self.assertEqual(calls, [])
        self.assertIn('"tool"', failures[0].error)

    def test_args_must_be_object(self):
        calls, failures, _ = parse_tool_blocks('```tool\n{"tool": "x", "args": [1]}\n```')
        self.assertEqual(calls, [])
        self.assertIn('"args"', failures[0].error)

    def test_unterminated_block_salvaged_at_finish(self):
        calls, failures, display = parse_tool_blocks(
            'text\n```tool\n{"tool": "list_dir", "args": {}}')
        self.assertEqual(len(calls), 1)
        self.assertEqual(display, "text\n")

    def test_unterminated_bad_block_reported(self):
        calls, failures, _ = parse_tool_blocks('```tool\n{not json')
        self.assertEqual(calls, [])
        self.assertEqual(len(failures), 1)

    def test_xml_close_tag_salvaged_no_correction_needed(self):
        # observed live twice in sessions/20260903-013756-bc42.jsonl: the model
        # ended the block with '</tool_call>' instead of the closing fence,
        # which used to cost a full correction round-trip (~81k prompt tokens)
        f = ToolStreamFilter()
        f.feed('```tool\n{"tool": "read_file", "args": {"path": "a"}}\n</tool_call>')
        f.finish()
        self.assertEqual(len(f.calls), 1)
        self.assertEqual(f.calls[0].tool, "read_file")
        self.assertEqual(f.failures, [])       # no correction round-trip
        self.assertEqual(len(f.salvaged), 1)   # ...but surfaced honestly
        self.assertIn("</tool_call>", f.salvaged[0].error)

    def test_xml_close_tag_inside_closed_fence_salvaged(self):
        f = ToolStreamFilter()
        f.feed('```tool\n{"tool": "list_dir", "args": {}}\n</tool_call>\n```')
        f.finish()
        self.assertEqual([c.tool for c in f.calls], ["list_dir"])
        self.assertEqual(len(f.salvaged), 1)

    def test_trailing_prose_after_json_still_fails(self):
        # only a bare XML close tag is salvaged; anything else stays a failure
        calls, failures, _ = parse_tool_blocks(
            '```tool\n{"tool": "read_file", "args": {}} oops\n```')
        self.assertEqual(calls, [])
        self.assertEqual(len(failures), 1)

    def test_two_json_objects_still_fails(self):
        calls, failures, _ = parse_tool_blocks(
            '```tool\n{"tool": "a"}{"tool": "b"}\n```')
        self.assertEqual(calls, [])
        self.assertEqual(len(failures), 1)

    def test_ordinary_code_fence_passes_through(self):
        calls, failures, display = parse_tool_blocks(
            'here is code:\n```python\nprint("hi")\n```\ndone')
        self.assertEqual(calls, [])
        self.assertEqual(failures, [])
        self.assertIn('```python', display)
        self.assertIn('print("hi")', display)

    def test_tool_block_with_braces_and_newlines_inside_strings(self):
        payload = '{"tool": "write_file", "args": {"path": "x.py", "content": "a{}\\nb"}}'
        calls, failures, _ = parse_tool_blocks(f'```tool\n{payload}\n```')
        self.assertEqual(failures, [])
        self.assertEqual(calls[0].args["content"], "a{}\nb")
        self.assertFalse(calls[0].truncated)  # clean parse is never marked


class TestStreamingFilter(unittest.TestCase):
    def feed_in_chunks(self, text, n=3):
        f = ToolStreamFilter()
        out = ""
        for i in range(0, len(text), n):
            out += f.feed(text[i:i + n])
        out += f.finish()
        return f, out

    def test_chunked_stream_equals_one_shot(self):
        text = ('hello ```tool\n{"tool": "read_file", "args": {"path": "z"}}\n``` world '
                '```python\nx=1\n``` end')
        f, display = self.feed_in_chunks(text, n=2)
        self.assertEqual(len(f.calls), 1)
        self.assertNotIn("read_file", display)
        self.assertIn("hello", display)
        self.assertIn("world", display)
        self.assertIn("x=1", display)

    def test_partial_backticks_held_then_released(self):
        f = ToolStreamFilter()
        out = f.feed("wait for it``")
        self.assertEqual(out, "wait for it")  # trailing `` held back
        out = f.feed("`tool\n{\"tool\": \"list_dir\"}\n```")
        self.assertEqual(out, "")
        f.feed("")
        out = f.finish()
        self.assertEqual(len(f.calls), 1)

    def test_double_backtick_inline_code_not_lost(self):
        f = ToolStreamFilter()
        out = f.feed("use ``inline`` code")
        out += f.finish()
        self.assertEqual(out, "use ``inline`` code")
        self.assertEqual(f.calls, [])

    def test_raw_text_is_verbatim(self):
        text = 'a ```tool\n{"tool":"list_dir"}\n``` b'
        f, _ = self.feed_in_chunks(text, n=1)
        self.assertEqual(f.raw_text, text)


class TestUnterminatedWriteSalvage(unittest.TestCase):
    """Live repro 2026-09-04 (sessions/20260904-131626-961d.jsonl): on
    Reasoning effort the model emitted a whole HTML page as one JSON string
    and never closed it - strict parse died with 'Unterminated string',
    the single correction failed the same way, and the work was lost.
    Everything up to the cut was well-formed, so the streamed content is
    recoverable verbatim."""

    def salvage(self, block, close_fence=False):
        f = ToolStreamFilter()
        f.feed(f"```tool\n{block}" + ("\n```" if close_fence else ""))
        f.finish()
        return f

    def test_clean_prefix_cut_recovers_verbatim_content(self):
        f = self.salvage('{"tool": "write_file", "args": {"path": "a.html", '
                         '"content": "<!DOCTYPE html>\\n<html>\\n<head>')
        self.assertEqual(f.failures, [])        # no correction round-trip
        self.assertEqual(len(f.salvaged), 1)
        self.assertIn("unterminated", f.salvaged[0].error)
        self.assertEqual(len(f.calls), 1)
        self.assertTrue(f.calls[0].truncated)
        self.assertEqual(f.calls[0].args["path"], "a.html")
        self.assertEqual(f.calls[0].args["content"],
                         "<!DOCTYPE html>\n<html>\n<head>")  # exactly what streamed

    def test_cut_mid_tag(self):
        f = self.salvage('{"tool": "write_file", "args": {"path": "a.html", '
                         '"content": "<body><div class=')
        self.assertEqual(f.calls[0].args["content"], "<body><div class=")

    def test_cut_mid_escape_drops_the_dangling_backslash(self):
        # the session-log shape (event 88): block ends '</span>\' + newline,
        # fence closed, string never did
        f = self.salvage('{"tool": "write_file", "args": {"path": "a.html", '
                         '"content": "<span>x</span>\\', close_fence=True)
        self.assertEqual(len(f.calls), 1)
        self.assertEqual(f.calls[0].args["content"], "<span>x</span>")
        self.assertTrue(f.calls[0].truncated)
        # same shape with no closing fence at all (stream just ended)
        f = self.salvage('{"tool": "write_file", "args": {"path": "a.html", '
                         '"content": "<span>x</span>\\')
        self.assertEqual(f.calls[0].args["content"], "<span>x</span>")

    def test_trailing_braces_kept_verbatim_and_disclosed(self):
        # event 66 shape: the model dropped '"}}' - its intended JSON closers
        # land inside the content. We do not guess: recover verbatim, mark
        # truncated, and let the model verify via the result note.
        f = self.salvage('{"tool": "write_file", "args": {"path": "a.css", '
                         '"content": "a{b:c}\\n}}', close_fence=True)
        self.assertEqual(f.calls[0].args["content"], "a{b:c}\n}}")
        self.assertTrue(f.calls[0].truncated)

    def test_pretty_printed_multiline_head(self):
        f = self.salvage('{\n  "tool": "write_file",\n  "args": {\n'
                         '    "path": "a.txt",\n    "content": "line one\\nline two')
        self.assertEqual(len(f.calls), 1)
        self.assertEqual(f.calls[0].args["path"], "a.txt")
        self.assertEqual(f.calls[0].args["content"], "line one\nline two")

    def test_edit_file_cut_in_new_recovers_with_old_intact(self):
        f = self.salvage('{"tool": "edit_file", "args": {"path": "a.py", '
                         '"old": "x = 1", "new": "x = 2\\ny = 3')
        self.assertEqual(f.calls[0].tool, "edit_file")
        self.assertEqual(f.calls[0].args["old"], "x = 1")
        self.assertEqual(f.calls[0].args["new"], "x = 2\ny = 3")
        self.assertTrue(f.calls[0].truncated)

    def test_escaped_quotes_inside_content_survive(self):
        f = self.salvage('{"tool": "write_file", "args": {"path": "a.html", '
                         '"content": "<a title=\\"hi\\">click')
        self.assertEqual(f.calls[0].args["content"], '<a title="hi">click')

    # -- refusal cases: ambiguity must still fail honestly ---------------------
    def test_cut_inside_path_refused(self):
        f = self.salvage('{"tool": "write_file", "args": {"path": "WORKS10')
        self.assertEqual(f.calls, [])
        self.assertEqual(len(f.failures), 1)
        self.assertIn("Unterminated string", f.failures[0].error)

    def test_non_write_tool_refused(self):
        f = self.salvage('{"tool": "run_shell", "args": {"command": "echo hel')
        self.assertEqual(f.calls, [])
        self.assertEqual(len(f.failures), 1)

    def test_closed_string_missing_braces_not_this_salvage(self):
        # the string DID close; the cut is elsewhere - a different family
        f = self.salvage('{"tool": "write_file", "args": {"path": "a", "content": "hi"')
        self.assertEqual(f.calls, [])
        self.assertEqual(len(f.failures), 1)
        self.assertEqual(f.salvaged, [])

    def test_extra_arg_after_content_refused(self):
        f = self.salvage('{"tool": "write_file", "args": {"path": "a", '
                         '"content": "hi", "note": "this got cut')
        self.assertEqual(f.calls, [])  # the cut was in 'note', not 'content'
        self.assertEqual(len(f.failures), 1)

    def test_edit_file_missing_old_refused(self):
        # content-first arg order: the cut ate path/old - nothing to execute
        f = self.salvage('{"tool": "edit_file", "args": {"new": "replacement text')
        self.assertEqual(f.calls, [])
        self.assertEqual(len(f.failures), 1)


if __name__ == "__main__":
    unittest.main()
