import unittest

from packetscope.analysis import analyze_packets
from packetscope.errors import InputLimitError
from packetscope.models import Limits, Packet


class AnalysisTests(unittest.TestCase):
    def test_comparison_and_hypotheses_are_explicit(self):
        packets = [
            Packet(0, bytes([0xAA, 0xBB, 0x10, 0x04, 0x01, 0x00])),
            Packet(1, bytes([0xAA, 0xBB, 0x11, 0x04, 0x01, 0x00])),
            Packet(2, bytes([0xAA, 0xBB, 0x12, 0x04, 0x01, 0x00])),
        ]
        result = analyze_packets(packets, annotations=[{"label": "type", "start": 0, "end": 1}])
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["observations"]["comparison"]["regions"][0]["kind"], "constant")
        kinds = {item["kind"] for item in result["hypotheses"]}
        self.assertIn("magic_bytes", kinds)
        self.assertIn("counter", kinds)
        self.assertTrue(all(item["status"] == "hypothesis" for item in result["hypotheses"]))
        self.assertEqual(result["annotations"][0]["source"], "manual")

    def test_single_packet_does_not_invent_comparison(self):
        result = analyze_packets([Packet(0, b"abc")])
        self.assertEqual(result["hypotheses"], [])
        self.assertEqual(result["observations"]["comparison"]["regions"], [])

    def test_two_packets_are_insufficient_for_heuristics(self):
        packets = [Packet(0, b"\xaa\xbb\x01"), Packet(1, b"\xaa\xbb\x02")]
        result = analyze_packets(packets)
        self.assertEqual(result["hypotheses"], [])

    def test_analysis_bounds_generators_and_packet_sizes(self):
        limits = Limits(max_packets=2, max_packet_bytes=3)
        with self.assertRaises(InputLimitError):
            analyze_packets((Packet(index, b"abc") for index in range(3)), limits=limits)
        with self.assertRaises(InputLimitError):
            analyze_packets([Packet(0, b"abcd")], limits=limits)

    def test_hypothesis_count_is_bounded_before_return(self):
        packets = [Packet(index, bytes([0xAA, index, 0x01, 0x02])) for index in range(3)]
        result = analyze_packets(packets, limits=Limits(max_hypotheses=1))
        self.assertLessEqual(len(result["hypotheses"]), 1)

    def test_non_unit_and_gap_progressions_remain_explicit_hypotheses(self):
        stepped = [Packet(index, b"\xaa\xbb" + value.to_bytes(2, "big") + b"\x10") for index, value in enumerate((0, 5, 10, 15))]
        stepped_result = analyze_packets(stepped)
        stepped_candidates = [item for item in stepped_result["hypotheses"] if item["field_type"] == "sequence_counter"]
        self.assertTrue(any("constant step of 5" in item["evidence"][0]["rationale"] for item in stepped_candidates))
        self.assertTrue(any("non-unit progression" in caveat for item in stepped_candidates for caveat in item["caveats"]))

        gapped = [Packet(index, b"\xaa\xbb" + value.to_bytes(2, "big") + b"\x10") for index, value in enumerate((0, 1, 3, 4))]
        gapped_result = analyze_packets(gapped)
        gapped_candidates = [item for item in gapped_result["hypotheses"] if item["field_type"] == "sequence_counter"]
        self.assertTrue(any("bounded gaps" in item["evidence"][0]["rationale"] for item in gapped_candidates))
        self.assertTrue(any("gaps" in caveat for item in gapped_candidates for caveat in item["caveats"]))


if __name__ == "__main__":
    unittest.main()
