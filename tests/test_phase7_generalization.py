import unittest

from packetscope.analysis import analyze_packets
from packetscope.evaluation import evaluate_result
from packetscope.models import Packet
from tests.fixtures.phase7_generalization import DEVELOPMENT, HOLDOUT, VALIDATION, generate


class Phase7GeneralizationTests(unittest.TestCase):
    def test_frozen_generators_are_deterministic_and_vary_parameters(self):
        for settings in DEVELOPMENT + VALIDATION + HOLDOUT:
            first = generate(settings)
            second = generate(settings)
            self.assertEqual(first, second)
            self.assertGreaterEqual(len(first[0]), 5)
            self.assertTrue(first[1])
        self.assertNotEqual(generate(DEVELOPMENT[0])[0], generate(DEVELOPMENT[1])[0])

    def test_holdout_truth_is_supplied_only_after_analysis(self):
        for settings in HOLDOUT:
            payloads, truth = generate(settings)
            result = analyze_packets([Packet(index, payload) for index, payload in enumerate(payloads)])
            self.assertNotIn("field_type", result)
            report = evaluate_result(result, truth)
            self.assertIn("alternative_group_aware", report)


if __name__ == "__main__":
    unittest.main()
