import json
import unittest

from packetscope.models import Packet
from packetscope.schema import apply_schema, migrate_schema, validate_schema


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
        self.assertEqual(absent[1]["status"], "UNKNOWN")

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


if __name__ == "__main__":
    unittest.main()
