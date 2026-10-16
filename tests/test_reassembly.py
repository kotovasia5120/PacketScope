import unittest

from packetscope.errors import InputLimitError
from packetscope.importers import import_bytes
from packetscope.models import Limits
from packetscope.reassembly import infer_message_boundaries, reconstruct_tcp_streams
from tests.fixtures.phase6_multiflow import pcap_bytes


class TcpReassemblyTests(unittest.TestCase):
    def test_fixture_reconstruction_keeps_provenance_and_reports_overlap(self):
        imported = import_bytes("fixture.pcap", pcap_bytes(), "pcap", Limits(max_input_bytes=4096))
        report = reconstruct_tcp_streams(imported.packets, limits=Limits(max_input_bytes=4096))
        self.assertEqual(report["stream_count"], 3)
        ipv4_forward = next(item for item in report["streams"] if item["flow_id"].startswith("ipv4/tcp") and item["direction"] == "forward")
        self.assertFalse(ipv4_forward["complete"])
        self.assertIsNone(ipv4_forward["data"])
        self.assertTrue(ipv4_forward["overlaps"])
        self.assertTrue(all("packet_id" in item for item in ipv4_forward["packet_to_stream"]))
        ipv6 = next(item for item in report["streams"] if item["flow_id"].startswith("ipv6/tcp"))
        self.assertTrue(ipv6["complete"])
        self.assertEqual(bytes.fromhex(ipv6["data"]), b"MF@\x00\x02tcp-v6-a\xcb\xfb")

    def test_framing_inference_is_conservative_and_explicitly_ambiguous(self):
        result = infer_message_boundaries(b"\xaa\x01\xaa\x02\xaa\x03")
        self.assertEqual(result["status"], "complete")
        self.assertTrue(any(item["kind"] == "magic_byte" for item in result["candidates"]))
        self.assertTrue(any("Multiple" in limitation for limitation in result["limitations"]))
        unavailable = infer_message_boundaries(None)
        self.assertEqual(unavailable["status"], "unavailable")

    def test_reassembly_respects_packet_budget_before_materializing(self):
        imported = import_bytes("fixture.pcap", pcap_bytes(), "pcap", Limits(max_input_bytes=4096))
        with self.assertRaises(InputLimitError):
            reconstruct_tcp_streams(imported.packets, limits=Limits(max_packets=1, max_input_bytes=4096))


if __name__ == "__main__":
    unittest.main()
