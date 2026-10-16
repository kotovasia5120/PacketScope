import unittest

from packetscope.interop import export_kaitai, export_wireshark_lua


class InteroperabilityExportTests(unittest.TestCase):
    def setUp(self):
        self.schema = {
            "schema_version": 1,
            "name": "Demo protocol",
            "fields": [
                {"name": "magic byte", "type": "custom", "offset": 0, "width": 1, "endian": "unknown", "coordinate_system": "raw_packet"},
                {"name": "counter", "type": "UINT32", "offset": 2, "width": 4, "endian": "little", "coordinate_system": "raw_packet"},
                {"name": "payload", "type": "custom", "offset": 6, "width": 2, "endian": "unknown", "coordinate_system": "application_payload"},
            ],
        }

    def test_kaitai_export_is_data_only_and_warns_on_unsupported_coordinates(self):
        result = export_kaitai(self.schema)
        self.assertIn("id: demo_protocol", result["content"])
        self.assertIn("type: u4le", result["content"])
        self.assertTrue(any("application_payload" in warning for warning in result["warnings"]))

    def test_lua_export_contains_bounds_checks_and_unsupported_warning(self):
        result = export_wireshark_lua(self.schema)
        self.assertIn("buffer:len() >= 6", result["content"])
        self.assertIn("subtree:add_le(fields.counter", result["content"])
        self.assertTrue(any("application_payload" in warning for warning in result["warnings"]))
        self.assertIn("return demo_protocol", result["content"])

    def test_v2_static_fields_export_and_dynamic_constructs_warn_without_crashing(self):
        schema = {
            "schema_version": 2,
            "name": "V2 protocol",
            "coordinate_system": "raw_packet",
            "fields": [
                {"id": "kind", "name": "Kind", "type": "uint8", "offset": 0, "length": 1, "endian": "big"},
                {"id": "payload", "name": "Payload", "type": "bytes", "offset": {"field": "kind", "add": 1}, "length": {"field": "kind"}},
                {"id": "nested", "name": "Nested", "type": "struct", "offset": 4, "fields": [{"id": "child", "name": "Child", "type": "uint8", "offset": 0, "length": 1}]},
            ],
            "relationships": [{"id": "checksum", "kind": "checksum", "algorithm": "CRC-32"}],
        }
        kaitai = export_kaitai(schema)
        lua = export_wireshark_lua(schema)
        self.assertIn("id: v2_protocol", kaitai["content"])
        self.assertIn("fields.kind", lua["content"])
        self.assertTrue(any("dynamic offset" in warning for warning in kaitai["warnings"]))
        self.assertTrue(any("nested/array" in warning for warning in lua["warnings"]))
        self.assertTrue(any("checksum relationship" in warning for warning in kaitai["warnings"]))


if __name__ == "__main__":
    unittest.main()
