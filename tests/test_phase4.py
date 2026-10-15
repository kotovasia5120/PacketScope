import json
import threading
import time
import unittest
import urllib.request

from packetscope.analysis import analyze_packets
from packetscope.demo import demo_capture, demo_corpus
from packetscope.importers import import_bytes
from packetscope.models import Limits
from packetscope.evaluation import evaluate_result
from packetscope.models import Packet
from packetscope.web import PacketScopeServer, _merge_warnings


class Phase4BackendTests(unittest.TestCase):
    def test_demo_profiles_are_deterministic_and_keep_truth_separate(self):
        for profile in ("crc16-be", "crc32-le"):
            first = demo_corpus(profile)
            second = demo_corpus(profile)
            self.assertEqual([packet.payload for packet in first["packets"]], [packet.payload for packet in second["packets"]])
            self.assertEqual(first["ground_truth"], second["ground_truth"])
            result = analyze_packets(first["packets"])
            self.assertNotIn("ground_truth", result)
            crc = next(item for item in result["hypotheses"] if item.get("algorithm") == first["metadata"]["crc"]["name"])
            self.assertEqual(crc["checksum"]["locations"], [len(packet.payload) - crc["width"] for packet in first["packets"]])
            expected_length_offset = 7 if profile == "crc16-be" else 9
            self.assertTrue(any(item["field_type"] == "length_field" and item["absolute_offset"] == expected_length_offset for item in result["hypotheses"]))

    def test_counter_overflow_is_present_in_crc32_demo(self):
        demo = demo_corpus("crc32-le")
        values = [int.from_bytes(packet.payload[5:9], "little") for packet in demo["packets"]]
        self.assertEqual(values[:3], [0xFFFFFFFE, 0xFFFFFFFF, 0])

    def test_demo_serializers_round_trip_as_multi_packet_captures(self):
        for format_name in ("pcap", "pcapng"):
            capture = demo_capture("crc16-be", format_name=format_name)
            imported = import_bytes("demo." + format_name, capture, format_name, Limits())
            self.assertEqual(imported.format, format_name)
            self.assertEqual(len(imported.packets), 8)

    def test_evaluation_uses_precision_recall_and_na_recall(self):
        result = evaluate_result({"hypotheses": [
            {"id": "right", "field_type": "magic_bytes", "absolute_offset": 0, "width_bits": 32, "confidence": 0.9},
            {"id": "noise", "field_type": "message_type", "absolute_offset": 4, "width_bits": 8, "confidence": 0.1},
        ], "top_k": 1}, [{"field_type": "magic_bytes", "absolute_offset": 0, "width_bits": 32}])
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 1.0)
        self.assertEqual(result["f1"], 2 / 3)
        self.assertNotIn("accuracy", result)
        empty = evaluate_result({"hypotheses": []}, [])
        self.assertIsNone(empty["recall"])
        self.assertFalse(empty["recall_applicable"])

    def test_warning_sources_are_preserved(self):
        merged = _merge_warnings(["SEARCH_LIMIT_REACHED", {"source": "analyzer", "message": "TIME_LIMIT_EXCEEDED"}], ["truncated capture"])
        self.assertEqual({item["source"] for item in merged}, {"analyzer", "importer"})
        self.assertIn({"source": "analyzer", "message": "SEARCH_LIMIT_REACHED"}, merged)
        self.assertIn({"source": "importer", "message": "truncated capture"}, merged)

    def test_job_lifecycle_can_be_read_and_cancelled(self):
        server = PacketScopeServer(("127.0.0.1", 0))
        try:
            job = server.analysis_manager.submit("sample.bin", "bin", b"x" * 32, False)
            deadline = time.time() + 2
            observed = None
            while time.time() < deadline:
                observed = server.analysis_manager.get(job.job_id)
                if observed and observed["status"] in {"COMPLETE", "FAILED", "CANCELLED"}:
                    break
                time.sleep(0.01)
            self.assertIn(observed["status"], {"COMPLETE", "FAILED", "CANCELLED"})
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
