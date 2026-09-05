"""Task-list validation + rendering (the update_todos tool's payload)."""

import unittest

from spark_code.todos import MAX_ITEMS, render_todos, validate_todos


class TestValidate(unittest.TestCase):
    def test_valid_list_normalized(self):
        items, err = validate_todos([
            {"content": "  write tests ", "status": "in_progress"},
            {"content": "ship it"},  # missing status defaults to pending
        ])
        self.assertIsNone(err)
        self.assertEqual(items, [
            {"content": "write tests", "status": "in_progress"},
            {"content": "ship it", "status": "pending"},
        ])

    def test_not_a_list(self):
        items, err = validate_todos({"content": "x"})
        self.assertIsNone(items)
        self.assertIn("array", err)

    def test_bad_status_rejected(self):
        items, err = validate_todos([{"content": "x", "status": "doing"}])
        self.assertIsNone(items)
        self.assertIn("status", err)

    def test_empty_content_rejected(self):
        items, err = validate_todos([{"content": "  ", "status": "pending"}])
        self.assertIsNone(items)
        self.assertIn("content", err)

    def test_cap_enforced(self):
        items, err = validate_todos([{"content": str(i)} for i in range(MAX_ITEMS + 1)])
        self.assertIsNone(items)
        self.assertIn("max", err)


class TestRender(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(render_todos([]), "(task list is empty)")

    def test_counts_and_marks(self):
        out = render_todos([
            {"content": "a", "status": "done"},
            {"content": "b", "status": "in_progress"},
            {"content": "c", "status": "pending"},
        ])
        self.assertIn("1/3 done", out)
        self.assertIn("[x] a", out)
        self.assertIn("[>] b", out)
        self.assertIn("[ ] c", out)


if __name__ == "__main__":
    unittest.main()
