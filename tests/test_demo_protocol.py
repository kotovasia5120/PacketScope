import unittest

from packetscope.demo_protocol import (
    protocol_capture,
    protocol_reference_ground_truth,
    protocol_reference_schema,
)
from packetscope.importers.base import import_bytes
from packetscope.models import Limits
from packetscope.schema import validate_capture_against_schema


class DemoProtocolTests(unittest.TestCase):
    def test_request_response_corpus_is_deterministic_and_keeps_reference_separate(self):
        capture = protocol_capture()
        self.assertEqual(capture, protocol_capture())
        self.assertNotEqual(capture, protocol_capture(changed=True))
        self.assertNotIn("ground_truth", capture.decode("utf-8"))
        truth = protocol_reference_ground_truth()
        self.assertTrue(any(item["field_type"] == "crc" for item in truth))
        self.assertNotIn("payload", truth)

    def test_reviewed_schema_reports_valid_corrupt_and_truncated_messages(self):
        imported = import_bytes("phase29.jsonl", protocol_capture(), "jsonl", Limits(max_input_bytes=64 * 1024))
        report = validate_capture_against_schema(protocol_reference_schema(), imported.packets)
        self.assertEqual(report["summary"]["packet_count"], 6)
        self.assertEqual([packet["status"] for packet in report["packets"]], ["ok", "ok", "ok", "ok", "violated", "incomplete"])
        self.assertEqual(report["summary"]["relationship_counts"]["invalid"], 1)
        self.assertEqual(report["summary"]["relationship_counts"]["insufficient"], 1)
        self.assertEqual(report["summary"]["validation_completeness"], "partial")


if __name__ == "__main__":
    unittest.main()
