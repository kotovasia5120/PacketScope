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


if __name__ == "__main__":
    unittest.main()
