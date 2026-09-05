"""Compaction logic tests: request building, summary application, suggestion threshold."""

import unittest

from spark_code import compact


def msgs(n):
    return [{"role": "user" if i % 2 == 0 else "assistant", "content": f"m{i}"}
            for i in range(n)]


class TestCompact(unittest.TestCase):
    def test_apply_compaction_shape(self):
        history = msgs(8)
        new = compact.apply_compaction(history, "the summary", keep_last=4)
        self.assertEqual(len(new), 5)
        self.assertTrue(new[0]["content"].startswith(compact.SUMMARY_PREFIX))
        self.assertIn("the summary", new[0]["content"])
        self.assertEqual([m["content"] for m in new[1:]], ["m4", "m5", "m6", "m7"])

    def test_apply_compaction_short_history(self):
        new = compact.apply_compaction(msgs(2), "sum", keep_last=4)
        self.assertEqual(len(new), 3)

    def test_request_contains_instruction_and_history(self):
        req = compact.build_compaction_request(msgs(3))
        self.assertIn(compact.COMPACTION_INSTRUCTION.strip().splitlines()[0][:20], req)
        self.assertIn("m0", req)
        self.assertIn("USER", req)

    def test_request_truncates_long_history(self):
        big = [{"role": "user", "content": "x" * 50_000}]
        req = compact.build_compaction_request(big, max_chars=5_000)
        self.assertLess(len(req), 5_000 + len(compact.COMPACTION_INSTRUCTION) + 500)
        self.assertIn("truncated", req)

    def test_suggestion_threshold(self):
        self.assertFalse(compact.should_suggest_compact(50_000, 131_072))
        self.assertTrue(compact.should_suggest_compact(90_000, 131_072))
        self.assertFalse(compact.should_suggest_compact(90_000, 0))

    def test_structured_sections_present(self):
        req = compact.build_compaction_request(msgs(2))
        for section in ("## Goal", "## Requirements & constraints", "## Decisions made",
                        "## Files touched", "## Tool & environment state",
                        "## Open tasks & next steps"):
            self.assertIn(section, req)

    def test_estimate_tokens(self):
        m = [{"role": "user", "content": "x" * 400}]
        self.assertEqual(compact.estimate_tokens(m), 100)


if __name__ == "__main__":
    unittest.main()
