import json
import unittest

from packetscope.analysis import analyze_packets
from packetscope.models import Packet
from packetscope.schema import apply_schema, export_schema, loads_schema, validate_schema


class SchemaTests(unittest.TestCase):
    def setUp(self):
        packets = [Packet(0, b"\xaa\x01\x00\x04one"), Packet(1, b"\xaa\x02\x00\x04two"), Packet(2, b"\xaa\x03\x00\x04six")]
        self.result = analyze_packets(packets)
        self.packets = packets

    def test_export_import_and_apply_round_trip(self):
        schema = export_schema(self.result, [{"label": "manual type", "start": 1, "end": 3, "field_type": "message_type", "status": "confirmed"}])
        schema_json = json.dumps(schema)
        restored = loads_schema(schema_json)
        self.assertEqual(restored["schema_version"], 1)
        report = apply_schema(restored, self.packets)
        self.assertEqual(report["packet_count"], 3)
        self.assertEqual(report["field_count"], len(restored["fields"]))
        self.assertTrue(any(field["name"] == "manual type" for field in restored["fields"]))
        manual_value = next(field for field in report["values"][0]["fields"] if field["name"] == "manual type")
        self.assertEqual(manual_value["value"], "0100")
        self.assertIn('"schema_version": 1', schema_json)

    def test_overlapping_and_variable_length_fields_are_validated(self):
        schema = validate_schema({
            "schema_version": 1,
            "fields": [
                {"name": "wide", "type": "custom", "offset": 0, "width": 4, "endian": "big", "origin": "manual", "review_status": "confirmed"},
                {"name": "nested", "type": "custom", "offset": 1, "width": 2, "endian": "unknown", "origin": "inferred", "review_status": "hypothesis"},
                {"name": "tail", "type": "custom", "offset": 20, "width": 3, "endian": "unknown", "origin": "manual", "review_status": "confirmed"},
            ],
        })
        report = apply_schema(schema, self.packets)
        self.assertTrue(report["values"][0]["fields"][-1]["available"] is False)

    def test_invalid_schema_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_schema({"schema_version": 99, "fields": []})
        with self.assertRaises(ValueError):
            validate_schema({"schema_version": 1, "fields": [{"name": "bad", "offset": -1, "width": 1}]})


if __name__ == "__main__":
    unittest.main()
