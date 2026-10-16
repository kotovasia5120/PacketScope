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

    def test_numeric_constraints_width_and_signed_semantics(self):
        schema = validate_schema({
            "schema_version": 2,
            "fields": [{
                "id": "signed", "type": "int8", "offset": 0, "length": 1,
                "constraints": {"minimum": -2, "maximum": 0, "exact": -1, "width_bits": 8, "signed": True},
            }, {
                "id": "allowed", "type": "uint8", "offset": 1, "length": 1,
                "constraints": {"allowed": [3], "forbidden": [4]},
            }],
        })
        valid = apply_schema(schema, [Packet(0, b"\xff\x03")])["values"][0]["fields"]
        self.assertEqual([field["status"] for field in valid], ["RESOLVED", "RESOLVED"])
        invalid = apply_schema(schema, [Packet(1, b"\x05\x04")])["values"][0]["fields"]
        self.assertEqual(invalid[0]["status"], "INVALID")
        self.assertIn("maximum", {item["code"] for item in invalid[0]["diagnostics"]})
        self.assertIn("allowed", {item["code"] for item in invalid[1]["diagnostics"]})
        self.assertIn("forbidden", {item["code"] for item in invalid[1]["diagnostics"]})
        signed_conflict = validate_schema({"schema_version": 2, "fields": [{"id": "u", "type": "uint8", "offset": 0, "length": 1, "signed": True}]})
        conflict_field = apply_schema(signed_conflict, [Packet(2, b"\xff")])["values"][0]["fields"][0]
        self.assertEqual(conflict_field["diagnostics"][0]["code"], "integer_signedness")

    def test_enum_policies_produce_diagnostics_without_hiding_unknown_values(self):
        schema = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "strict", "type": "uint8", "offset": 0, "length": 1, "constraints": {"enum": [1, 2]}},
                        {"id": "open", "type": "uint8", "offset": 1, "length": 1, "constraints": {"enum": {"values": [1, 2], "policy": "diagnostic"}}}],
        })
        fields = apply_schema(schema, [Packet(0, b"\x03\x03")])["values"][0]["fields"]
        self.assertEqual(fields[0]["status"], "INVALID")
        self.assertEqual(fields[0]["diagnostics"][0]["code"], "enum")
        self.assertEqual(fields[1]["status"], "RESOLVED")
        self.assertEqual(fields[1]["value"], 3)
        self.assertEqual(fields[1]["diagnostics"][0]["code"], "enum_unknown")

    def test_bit_masks_flags_reserved_and_mutual_exclusion(self):
        schema = validate_schema({
            "schema_version": 2,
            "fields": [{
                "id": "flags", "type": "uint8", "offset": 0, "length": 1,
                "constraints": {
                    "mask": 0x07, "reserved": 0x08,
                    "flags": {"read": 0x01, "write": 0x02, "exec": 0x04},
                    "required_flags": ["read"], "mutual_exclusion": ["write", "exec"],
                },
            }],
        })
        self.assertEqual(apply_schema(schema, [Packet(0, b"\x01")])["values"][0]["fields"][0]["status"], "RESOLVED")
        invalid = apply_schema(schema, [Packet(1, b"\x0f")])["values"][0]["fields"][0]
        self.assertEqual(invalid["status"], "INVALID")
        self.assertTrue({"mask", "reserved", "mutual_exclusion"} <= {item["code"] for item in invalid["diagnostics"]})

    def test_length_relationship_diagnostics_keep_invalid_and_incomplete_distinct(self):
        schema = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "length", "type": "uint8", "offset": 0, "length": 1},
                        {"id": "body", "type": "bytes", "offset": 1, "length": 2}],
            "relationships": [{"id": "body-length", "kind": "length", "field_id": "length", "target_field_id": "body"}],
        })
        valid = apply_schema(schema, [Packet(0, b"\x02ab")])["values"][0]["relationships"][0]
        self.assertEqual(valid["status"], "valid")
        mismatch = apply_schema(schema, [Packet(1, b"\x01ab")])["values"][0]
        self.assertEqual(mismatch["relationships"][0]["status"], "invalid")
        self.assertEqual(validate_capture_against_schema(schema, [Packet(1, b"\x01ab")])["packets"][0]["status"], "violated")
        incomplete = apply_schema(schema, [Packet(2, b"\x02a")])["values"][0]
        self.assertEqual(incomplete["relationships"][0]["status"], "insufficient")
        self.assertEqual(validate_capture_against_schema(schema, [Packet(2, b"\x02a")])["packets"][0]["status"], "incomplete")

    def test_constraints_skip_conditional_absence_and_preserve_truncation_or_unresolved(self):
        schema = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "gate", "type": "uint8", "offset": 0, "length": 1},
                        {"id": "optional", "type": "uint8", "offset": 1, "length": 1,
                         "presence": {"op": "eq", "args": [{"field": "gate"}, 1]}, "constraints": {"exact": 9}},
                        {"id": "truncated", "type": "uint8", "offset": 2, "length": 1, "constraints": {"minimum": 9}},
                        {"id": "dependent", "type": "uint8", "offset": {"field": "truncated"}, "length": 1}],
        })
        values = apply_schema(schema, [Packet(0, b"\x00\x01")])["values"][0]["fields"]
        self.assertEqual(values[1]["status"], "RESOLVED")
        self.assertEqual(values[1]["diagnostics"][0]["code"], "conditional_absent")
        self.assertEqual(values[2]["status"], "OUT_OF_BOUNDS")
        self.assertEqual(values[3]["status"], "OUT_OF_BOUNDS")
        unresolved = validate_schema({"schema_version": 2, "fields": [{"id": "x", "type": "uint8", "offset": 0, "length": 1, "presence": {"field": "missing"}}]})
        unresolved_field = apply_schema(unresolved, [Packet(1, b"\x01")])["values"][0]["fields"][0]
        self.assertEqual(unresolved_field["status"], "INVALID")
        self.assertEqual(unresolved_field["diagnostics"][0]["code"], "missing_reference")

    def test_malformed_constraint_and_constraint_value_limits_are_bounded(self):
        malformed = validate_schema({"schema_version": 2, "fields": [{"id": "x", "type": "uint8", "offset": 0, "length": 1, "constraints": {"minimum": "not-a-number"}}]})
        field = apply_schema(malformed, [Packet(0, b"\x01")])["values"][0]["fields"][0]
        self.assertEqual(field["status"], "INVALID")
        self.assertEqual(field["diagnostics"][0]["code"], "minimum_type")
        with self.assertRaises(ValueError):
            validate_schema({"schema_version": 2, "fields": [{"id": "x", "type": "uint8", "offset": 0, "length": 1, "constraints": {"allowed": list(range(10_001))}}]})
        limited = validate_schema({"schema_version": 2, "budgets": {"max_packets": 1}, "fields": [{"id": "x", "type": "uint8", "offset": 0, "length": 1}]})
        report = apply_schema(limited, [Packet(0, b"\x01"), Packet(1, b"\x02")])
        self.assertEqual(report["status"], "LIMIT_EXCEEDED")
        self.assertEqual(report["diagnostics"][0]["code"], "packet_count")

    def test_length_relationship_alias_defaults_to_length_kind(self):
        schema = validate_schema({
            "schema_version": 2,
            "fields": [
                {"id": "size", "type": "uint8", "offset": 0, "length": 1},
                {"id": "body", "type": "bytes", "offset": 1, "length": 2},
            ],
            "length_relationships": [{"id": "size-body", "field_id": "size", "target_field_id": "body"}],
        })
        self.assertEqual(schema["relationships"][0]["kind"], "length")
        relationship = apply_schema(schema, [Packet(0, b"\x02ab")])["values"][0]["relationships"][0]
        self.assertEqual(relationship["kind"], "length")
        self.assertEqual(relationship["status"], "valid")

    def test_structured_and_array_lengths_reject_non_integer_values(self):
        for raw in (1.5, -1):
            structured = validate_schema({
                "schema_version": 2,
                "fields": [{"id": "record", "type": "struct", "offset": 0, "length": raw,
                             "fields": [{"id": "value", "type": "uint8", "offset": 0, "length": 1}]}],
            })
            structured_field = apply_schema(structured, [Packet(0, b"\x01")])["values"][0]["fields"][0]
            self.assertEqual(structured_field["status"], "INVALID")
            self.assertEqual(structured_field["diagnostics"][0]["code"], "length")

            array = validate_schema({
                "schema_version": 2,
                "fields": [{"id": "items", "type": "array", "offset": 0, "length": raw,
                             "array": {"count": 1, "element": {"type": "uint8", "length": 1}}}],
            })
            array_field = apply_schema(array, [Packet(0, b"\x01")])["values"][0]["fields"][0]
            self.assertEqual(array_field["status"], "INVALID")
            self.assertEqual(array_field["diagnostics"][0]["code"], "length")

        boolean_count = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "items", "type": "array", "offset": 0,
                         "array": {"count": True, "element": {"type": "uint8", "length": 1}}}],
        })
        count_field = apply_schema(boolean_count, [Packet(0, b"\x01")])["values"][0]["fields"][0]
        self.assertEqual(count_field["status"], "INVALID")
        self.assertEqual(count_field["diagnostics"][0]["code"], "array_count")
        for raw in (1.5, -1):
            invalid_count = validate_schema({
                "schema_version": 2,
                "fields": [{"id": "items", "type": "array", "offset": 0,
                             "array": {"count": raw, "element": {"type": "uint8", "length": 1}}}],
            })
            invalid_count_field = apply_schema(invalid_count, [Packet(0, b"\x01")])["values"][0]["fields"][0]
            self.assertEqual(invalid_count_field["status"], "INVALID")
            self.assertEqual(invalid_count_field["diagnostics"][0]["code"], "array_count")
        with self.assertRaises(ValueError):
            validate_schema({
                "schema_version": 2,
                "fields": [{"id": "record", "type": "struct", "offset": 0, "length": True, "fields": []}],
            })

    def test_uint64_and_uint128_constraints_use_lossless_json_values(self):
        uint64_max = "18446744073709551615"
        uint128_max = "340282366920938463463374607431768211455"
        schema = validate_schema({
            "schema_version": 2,
            "fields": [
                {"id": "u64", "type": "uint64", "offset": 0, "length": 8, "constraints": {"exact": uint64_max}},
                {"id": "u128", "type": "uint128", "offset": 8, "length": 16, "constraints": {"minimum": uint128_max, "maximum": uint128_max}},
            ],
        })
        report = apply_schema(schema, [Packet(0, b"\xff" * 24)])
        fields = report["values"][0]["fields"]
        self.assertEqual([field["status"] for field in fields], ["RESOLVED", "RESOLVED"])
        self.assertEqual(fields[0]["value"], uint64_max)
        self.assertEqual(fields[1]["value"], uint128_max)
        json.dumps(report, sort_keys=True)

        mismatch_schema = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "u64", "type": "uint64", "offset": 0, "length": 8, "constraints": {"exact": "0"}}],
        })
        diagnostic = apply_schema(mismatch_schema, [Packet(1, b"\xff" * 8)])["values"][0]["fields"][0]["diagnostics"][0]
        self.assertEqual(diagnostic["code"], "exact")
        self.assertEqual(diagnostic["actual"], uint64_max)
        self.assertEqual(diagnostic["expected"], "0")

    def test_constraint_diagnostics_include_field_location_context(self):
        schema = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "count", "name": "Count", "type": "uint16", "offset": 3, "length": 2,
                         "constraints": {"minimum": 9}}],
        })
        field = apply_schema(schema, [Packet(0, b"xxx\x00\x01")])["values"][0]["fields"][0]
        diagnostic = field["diagnostics"][0]
        self.assertEqual(diagnostic["field_id"], "count")
        self.assertEqual(diagnostic["path"], "count")
        self.assertEqual(diagnostic["offset"], 3)
        self.assertEqual(diagnostic["length"], 2)

    def test_limits_apply_before_nested_or_output_expansion_and_keep_truncation(self):
        nested = {"id": "leaf", "type": "uint8", "offset": 0, "length": 1}
        for _ in range(5):
            nested = {"id": "node", "type": "struct", "offset": 0, "fields": [nested]}
        with self.assertRaises(ValueError):
            validate_schema({"schema_version": 2, "budgets": {"max_nesting": 2}, "fields": [nested]})

        output_limited = validate_schema({
            "schema_version": 2,
            "budgets": {"max_output_fields": 2},
            "fields": [{"id": "items", "type": "array", "offset": 0,
                        "array": {"count": 100, "element": {"type": "uint8", "length": 1}}}],
        })
        output_field = apply_schema(output_limited, [Packet(0, b"\x01" * 100)])["values"][0]["fields"][0]
        self.assertEqual(output_field["status"], "LIMIT_EXCEEDED")
        self.assertLessEqual(len(output_field.get("items", [])), 2)

        truncated = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "items", "type": "array", "offset": 0, "length": 3,
                        "array": {"count": 3, "element": {"type": "uint8", "length": 1}}}],
        })
        truncated_field = apply_schema(truncated, [Packet(0, b"\x01")])["values"][0]["fields"][0]
        self.assertEqual(truncated_field["status"], "OUT_OF_BOUNDS")

    def test_length_relationship_states_do_not_collapse(self):
        unsupported = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "size", "type": "text", "offset": 0, "length": 1},
                        {"id": "body", "type": "bytes", "offset": 1, "length": 1}],
            "relationships": [{"id": "unsupported", "kind": "length", "field_id": "size", "target_field_id": "body"}],
        })
        self.assertEqual(apply_schema(unsupported, [Packet(0, b"\xffx")])["values"][0]["relationships"][0]["status"], "unsupported")

        unresolved = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "size", "type": "uint8", "offset": 0, "length": 1}],
            "relationships": [{"id": "unresolved", "kind": "length", "field_id": "size", "target_field_id": "missing"}],
        })
        self.assertEqual(apply_schema(unresolved, [Packet(0, b"\x01")])["values"][0]["relationships"][0]["status"], "unresolved")

        insufficient = validate_schema({
            "schema_version": 2,
            "fields": [{"id": "size", "type": "uint8", "offset": 0, "length": 1},
                        {"id": "body", "type": "bytes", "offset": 1, "length": 2}],
            "relationships": [{"id": "insufficient", "kind": "length", "field_id": "size", "target_field_id": "body"}],
        })
        self.assertEqual(apply_schema(insufficient, [Packet(0, b"\x02x")])["values"][0]["relationships"][0]["status"], "insufficient")


if __name__ == "__main__":
    unittest.main()
