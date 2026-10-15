import unittest

from packetscope.analysis import analyze_packets
from packetscope.evaluation import evaluate_result
from packetscope.models import Packet
from tests.fixtures.phase5_holdout import TRUTH, corpus


class HoldoutEvaluationTests(unittest.TestCase):
    def test_independent_holdout_is_evaluated_only_after_analysis(self):
        packets = [Packet(index, payload) for index, payload in enumerate(corpus())]
        result = analyze_packets(packets)
        self.assertNotIn("TRUTH", result)
        evaluation = evaluate_result(result, TRUTH)
        self.assertEqual(evaluation["expected_count"], 3)
        self.assertGreaterEqual(evaluation["recall"], 2 / 3)
        self.assertIn("top_1", evaluation["top_k_metrics"])
        self.assertIn("false_positive_breakdown", evaluation)


if __name__ == "__main__":
    unittest.main()
