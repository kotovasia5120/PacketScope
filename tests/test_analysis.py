import unittest

from packetscope.analysis import analyze_packets
from packetscope.models import Packet


class AnalysisTests(unittest.TestCase):
    def test_comparison_and_hypotheses_are_explicit(self):
        packets = [
            Packet(0, bytes([0xAA, 0xBB, 0x10, 0x04, 0x01, 0x00])),
            Packet(1, bytes([0xAA, 0xBB, 0x11, 0x04, 0x01, 0x00])),
            Packet(2, bytes([0xAA, 0xBB, 0x12, 0x04, 0x01, 0x00])),
        ]
        result = analyze_packets(packets, annotations=[{"label": "type", "start": 0, "end": 1}])
        self.assertEqual(result["schema_version"], 1)
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


if __name__ == "__main__":
    unittest.main()
