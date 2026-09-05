"""Hypothetical cloud-cost meter tests."""

import unittest

from spark_code import config, cost


class TestCost(unittest.TestCase):
    def test_reference_rates(self):
        self.assertAlmostEqual(cost.turn_cost(1_000_000, 0), 3.00)
        self.assertAlmostEqual(cost.turn_cost(0, 1_000_000), 15.00)
        self.assertAlmostEqual(cost.turn_cost(1_000_000, 1_000_000), 18.00)

    def test_typical_turn(self):
        # 800 prompt + 200 completion at 3/15 per 1M = 0.0024 + 0.003 = 0.0054
        self.assertAlmostEqual(cost.turn_cost(800, 200), 0.0054, places=6)

    def test_zero(self):
        self.assertEqual(cost.turn_cost(0, 0), 0.0)

    def test_format(self):
        self.assertEqual(cost.format_usd(0.0042), "$0.0042")
        self.assertEqual(cost.format_usd(123.456), "$123.46")

    def test_table_labeled_as_reference(self):
        self.assertIn("reference", config.CLOUD_REFERENCE["label"])


if __name__ == "__main__":
    unittest.main()
