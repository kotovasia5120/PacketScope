import json
import unittest

from packetscope.analysis.crc import STANDARD_CRC, checksum_value, compute_crc
from packetscope.models import Packet
from packetscope.schema import apply_schema, migrate_schema, validate_capture_against_schema, validate_schema


class SchemaV2Tests(unittest.TestCase):
    def test_v1_migration_has_stable_ids_and_remains_applicable(self):
        v1 = {"schema_version": 1, "name": "legacy", "fields": [
            {"name": "kind", "type": "custom", "offset": 0, "width": 1, "endian": "unknown"},
        ]}
        migrated = migrate_schema(v1)
        self.assertEqual(migrated["schema_version"], 2)
        self.assertEqual(migrated["fields"][0]["id"], migrate_schema(v1)["fields"][0]["id"])
        report = apply_schema(migrated, [Packet(4, b"\x7f")])
        self.assertEqual(report["values"][0]["fields"][0]["status"], "RESOLVED")
        self.assertEqual(report["values"][0]["fields"][0]["value"], "7f")

    def test_length_prefixed_optional_dynamic_offset_and_array(self):
        schema = validate_schema({
            "schema_version": 2,
            "name": "first slice",
            "coordinate_system": "raw_packet",
            "fields": [
                {"id": "length", "name": "Length", "description": "payload length", "type": "uint8", "offset": 0, "length": 1},
                {"id": "payload", "name": "Payload", "type": "bytes", "offset": 1, "length": {"field": "length"}},
                {"id": "optional", "name": "Optional", "type": "uint8", "offset": {"field": "length", "add": 1}, "length": 1, "presence": {"op": "eq", "args": [{"field": "length"}, 3]}},
                {"id": "items", "name": "Items", "type": "array", "offset": 5, "array": {"count": 2, "element": {"type": "uint8", "length": 1}}},
            ],
        })
        report = apply_schema(schema, [Packet(0, b"\x03abc\x07\x08\x09")])
        fields = report["values"][0]["fields"]
        self.assertEqual([field["status"] for field in fields], ["RESOLVED"] * 4)
        self.assertEqual(fields[1]["value"], "616263")
        self.assertEqual(fields[2]["value"], 7)
        self.assertEqual(fields[3]["value"], [8, 9])
        self.assertEqual(fields[3]["items"][1]["index"], 1)
        json.dumps(report, sort_keys=True)

    def test_declarative_expression_allow_list_and_optional_absence(self):
        schema = validate_schema({
            "schema_version": 2,
            "fields": [
                {"id": "flags", "name": "Flags", "type": "uint8", "offset": 0, "length": 1},
                {"id": "aligned", "name": "Aligned", "type": "uint8", "offset": {"kind": "align", "value": {"field_id": "flags", "kind": "field_ref"}, "alignment": 2}, "length": 1, "presence": {"op": "eq", "args": [{"op": "mask", "args": [{"field": "flags"}, 1]}, 1]}},
            ],
        })
        present = apply_schema(schema, [Packet(0, b"\x01\x00\x09")])["values"][0]["fields"]
        self.assertEqual(present[1]["value"], 9)
        absent = apply_schema(schema, [Packet(0, b"\x00\x00\x09")])["values"][0]["fields"]
        self.assertEqual(absent[1]["status"], "RESOLVED")
        self.assertFalse(absent[1]["present"])
        self.assertEqual(absent[1]["diagnostics"][0]["code"], "conditional_absent")

    def test_missing_reference_and_cycle_are_diagnostics(self):
        missing = validate_schema({"schema_version": 2, "fields": [
            {"id": "x", "name": "X", "type": "uint8", "offset": {"field": "nope"}, "length": 1},
        ]})
        self.assertEqual(missing["diagnostics"][0]["code"], "missing_reference")
        missing_result = apply_schema(missing, [Packet(0, b"x")])
        self.assertEqual(missing_result["values"][0]["fields"][0]["status"], "INVALID")

        cycle = validate_schema({"schema_version": 2, "fields": [
            {"id": "a", "name": "A", "type": "uint8", "offset": {"field": "b"}, "length": 1},
            {"id": "b", "name": "B", "type": "uint8", "offset": {"field": "a"}, "length": 1},
        ]})
        self.assertEqual({item["status"] for item in cycle["diagnostics"]}, {"CYCLIC"})
        cycle_result = apply_schema(cycle, [Packet(0, b"xx")])
        self.assertEqual({field["status"] for field in cycle_result["values"][0]["fields"]}, {"CYCLIC"})

    def test_limits_and_truncation_are_distinct(self):
        limited = validate_schema({
            "schema_version": 2,
            "budgets": {"max_array_items": 1},
            "fields": [{"id": "items", "name": "Items", "type": "array", "offset": 0, "array": {"count": 2, "element": {"type": "uint8", "length": 1}}}],
        })
        limited_result = apply_schema(limited, [Packet(0, b"\x01\x02")])
        self.assertEqual(limited_result["values"][0]["fields"][0]["status"], "LIMIT_EXCEEDED")

        truncated = validate_schema({"schema_version": 2, "fields": [
            {"id": "body", "name": "Body", "type": "bytes", "offset": 1, "length": 2},
        ]})
        truncated_result = apply_schema(truncated, [Packet(0, b"x")])
        self.assertEqual(truncated_result["values"][0]["fields"][0]["status"], "OUT_OF_BOUNDS")

    def test_reviewed_checksum_relationships_validate_using_explicit_ranges(self):
        body = b"abc"
        checksum = compute_crc(body + b"z", STANDARD_CRC[0])
        packet = body + bytes([checksum]) + b"z"
        schema = validate_schema({
            "schema_version": 2,
            "fields": [
                {"id": "body", "name": "Body", "type": "bytes", "offset": 0, "length": 3},
                {"id": "crc", "name": "CRC", "type": "crc", "offset": 3, "length": 1, "endian": "big"},
            ],
            "relationships": [{
                "id": "body-crc", "kind": "checksum", "field_id": "crc",
                "algorithm": "CRC-8", "byte_order": "big",
                "covered_ranges": {"include": [[0, 5]], "exclude": [[3, 4]]},
            }],
        })
        applied = apply_schema(schema, [Packet(0, packet)])
        relationship = applied["values"][0]["relationships"][0]
        self.assertEqual(relationship["status"], "valid")
        self.assertEqual(relationship["covered_ranges"], [[0, 3], [4, 5]])
        self.assertEqual(relationship["actual"], compute_crc(body + b"z", STANDARD_CRC[0]))
        self.assertEqual(applied["values"][0]["fields"][1]["relationship_status"], "valid")

        corrupted = apply_schema(schema, [Packet(1, body + b"\x00z")])
        self.assertEqual(corrupted["values"][0]["relationships"][0]["status"], "invalid")
        report = validate_capture_against_schema(schema, [Packet(0, packet), Packet(1, body + b"\x00z")])
        self.assertEqual([item["status"] for item in report["packets"]], ["ok", "violated"])
        self.assertEqual(report["summary"]["relationship_counts"]["invalid"], 1)

    def test_checksum_algorithms_and_end_relative_location_are_allow_listed(self):
        cases = [
            ("CRC-8", 1, "big"),
            ("CRC-16/CCITT-FALSE", 2, "little"),
            ("CRC-16/MODBUS", 2, "big"),
            ("CRC-32/ISO-HDLC", 4, "little"),
            ("XOR-8", 1, "big"),
            ("ADDITIVE-8", 1, "big"),
            ("ADDITIVE-16", 2, "little"),
        ]
        body = b"payload"
        for index, (algorithm, width, byte_order) in enumerate(cases):
            if algorithm.startswith("CRC"):
                params = next(item for item in STANDARD_CRC if item.name == algorithm)
                expected = compute_crc(body, params)
            else:
                expected = checksum_value(body, algorithm)
            packet = body + expected.to_bytes(width, byte_order)
            schema = validate_schema({
                "schema_version": 2,
                "fields": [{"id": "tail", "type": "bytes", "offset": 0, "length": len(packet)}],
                "relationships": [{
                    "id": algorithm, "algorithm": algorithm, "byte_order": byte_order,
                    "location": {"mode": "from_end", "distance": width, "width": width},
                    "covered_ranges": [[0, len(body)]],
                }],
            })
            relationship = apply_schema(schema, [Packet(index, packet)])["values"][0]["relationships"][0]
            self.assertEqual(relationship["status"], "valid", algorithm)

    def test_checksum_incomplete_unsupported_and_unresolved_are_distinct(self):
        base = {
            "schema_version": 2,
            "fields": [
                {"id": "body", "type": "bytes", "offset": 0, "length": 3},
                {"id": "crc", "type": "crc", "offset": 3, "length": 1},
            ],
        }
        truncated_schema = validate_schema({**base, "relationships": [{
            "id": "truncated", "field_id": "crc", "algorithm": "CRC-8", "covered_ranges": [[0, 3]],
        }]})
        truncated = apply_schema(truncated_schema, [Packet(0, b"abc")])["values"][0]["relationships"][0]
        self.assertEqual(truncated["status"], "insufficient")
        self.assertEqual(validate_capture_against_schema(truncated_schema, [Packet(0, b"abc")])["packets"][0]["status"], "incomplete")

        unsupported_schema = validate_schema({**base, "relationships": [{
            "id": "unknown", "field_id": "crc", "algorithm": "CRC-64", "covered_ranges": [[0, 3]],
        }]})
        unsupported = apply_schema(unsupported_schema, [Packet(1, b"abc\x00")])["values"][0]["relationships"][0]
        self.assertEqual(unsupported["status"], "unsupported")

        unresolved_schema = validate_schema({**base, "relationships": [{
            "id": "dynamic", "field_id": "crc", "algorithm": "CRC-8",
            "covered_ranges": [[{"field": "missing-length"}, 3]],
        }]})
        unresolved = apply_schema(unresolved_schema, [Packet(2, b"abc\x00")])["values"][0]["relationships"][0]
        self.assertEqual(unresolved["status"], "unresolved")

    def test_field_checksum_descriptor_and_static_location(self):
        body = b"xy"
        checksum = checksum_value(body, "ADDITIVE-8")
        schema = validate_schema({
            "schema_version": 2,
            "fields": [
                {"id": "body", "type": "bytes", "offset": 0, "length": 2},
                {"id": "sum", "type": "checksum", "offset": 2, "length": 1,
                 "checksum": {"algorithm": "ADDITIVE-8", "location": {"offset": 2, "width": 1}, "covered_range": [0, 2]}},
            ],
        })
        relationship = apply_schema(schema, [Packet(0, body + bytes([checksum]))])["values"][0]["relationships"][0]
        self.assertEqual(relationship["status"], "valid")
        self.assertEqual(relationship["location"], {"offset": 2, "length": 1})


if __name__ == "__main__":
    unittest.main()
