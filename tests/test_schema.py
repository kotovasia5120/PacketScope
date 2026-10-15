import json
import struct
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

    def test_application_coordinate_transforms_and_unavailable_ranges_are_safe(self):
        udp = struct.pack("!HHHH", 1000, 2000, 10, 0) + b"ab"
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 30, 1, 0, 64, 17, 0, b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02") + udp
        packet = Packet(0, bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", 0x0800) + ip, link_type=1)
        result = analyze_packets([packet, Packet(1, packet.payload, link_type=1), Packet(2, packet.payload, link_type=1)])
        schema = export_schema(result)
        self.assertEqual(schema["coordinate_system"], "application_payload")
        magic = next(field for field in schema["fields"] if field["name"] == "magic_bytes")
        self.assertEqual(magic["offset"], 0)
        self.assertEqual(magic["coordinate_system"], "application_payload")
        applied = apply_schema(schema, [packet])
        applied_magic = next(field for field in applied["values"][0]["fields"] if field["name"] == "magic_bytes")
        self.assertTrue(applied_magic["available"])

        unavailable = validate_schema({
            "schema_version": 1,
            "coordinate_system": "application_payload",
            "fields": [{"name": "unknown", "offset": 0, "width": 1, "endian": "unknown"}],
        })
        unknown_packet = Packet(3, b"raw", link_type=999)
        unknown_value = apply_schema(unavailable, [unknown_packet])["values"][0]["fields"][0]
        self.assertFalse(unknown_value["available"])
        self.assertIsNone(unknown_value["value"])

        partial = validate_schema({
            "schema_version": 1,
            "fields": [{"name": "too wide", "offset": 2, "width": 4, "endian": "unknown"}],
        })
        partial_value = apply_schema(partial, [Packet(4, b"abc")])["values"][0]["fields"][0]
        self.assertFalse(partial_value["available"])
        self.assertIsNone(partial_value["value"])

    def test_integer_schema_values_are_lossless_decimal_strings(self):
        payload = (
            b"\xff\xff\xff\xff"  # UINT32 big
            + b"\xff\xff\xff\xff"  # UINT32 little
            + b"\xff" * 8  # UINT64 big
            + b"\xff" * 8  # UINT64 little
            + b"\x80" + b"\x00" * 7  # INT64 big minimum
            + b"\x00" * 7 + b"\x80"  # INT64 little minimum
        )
        schema = validate_schema({
            "schema_version": 1,
            "fields": [
                {"name": "u32 big", "type": "UINT32", "offset": 0, "width": 4, "endian": "big"},
                {"name": "u32 little", "type": "UINT32", "offset": 4, "width": 4, "endian": "little"},
                {"name": "u64 big", "type": "UINT64", "offset": 8, "width": 8, "endian": "big"},
                {"name": "u64 little", "type": "UINT64", "offset": 16, "width": 8, "endian": "little"},
                {"name": "i64 big", "type": "INT64", "offset": 24, "width": 8, "endian": "big"},
                {"name": "i64 little", "type": "INT64", "offset": 32, "width": 8, "endian": "little"},
            ],
        })
        fields = apply_schema(schema, [Packet(0, payload)])["values"][0]["fields"]
        self.assertEqual([field["value"] for field in fields], [
            "4294967295", "4294967295", "18446744073709551615", "18446744073709551615",
            "-9223372036854775808", "-9223372036854775808",
        ])
        self.assertTrue(all(field["value_encoding"] == "decimal_string" for field in fields))


if __name__ == "__main__":
    unittest.main()
