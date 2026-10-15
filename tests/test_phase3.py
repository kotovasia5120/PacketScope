import struct
import unittest

from packetscope.analysis import analyze_packets
from packetscope.models import Packet
from tests.fixtures.phase3_corpus import corpus_a, corpus_b, corpus_c, corpus_d


def ethernet_ipv4_udp(payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", 1000, 2000, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02") + udp
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", 0x0800) + ip


class Phase3CorpusTests(unittest.TestCase):
    def test_set_a_has_byte_precise_fields_and_crc(self):
        result = analyze_packets([Packet(index, payload) for index, payload in enumerate(corpus_a())])
        self.assertEqual(result["analysis"]["status"], "ok")
        self.assertTrue(all(item["status"] != "confirmed" for item in result["hypotheses"]))
        fields = result["hypotheses"]
        self.assertTrue(any(item["field_type"] == "magic_bytes" and item["absolute_offset"] == 0 and item["width_bits"] == 32 for item in fields))
        self.assertTrue(any(item["field_type"] == "length_field" and item["absolute_offset"] == 5 and item["width_bits"] == 16 for item in fields))
        self.assertTrue(any(item.get("algorithm") == "CRC-16/CCITT-FALSE" and item["checksum"]["location_mode"] == "from_end" for item in fields))
        crc = next(item for item in fields if item.get("algorithm") == "CRC-16/CCITT-FALSE")
        self.assertEqual(crc["packet_id"], 0)
        self.assertEqual(crc["absolute_offset"], len(corpus_a()[0]) - 2)

    def test_set_b_detects_little_endian_wrap_and_crc32(self):
        result = analyze_packets([Packet(index, payload) for index, payload in enumerate(corpus_b())])
        counters = [item for item in result["hypotheses"] if item["field_type"] == "sequence_counter" and item["width_bits"] == 32 and item["endian"] == "little"]
        self.assertTrue(counters)
        self.assertTrue(any(item.get("algorithm") == "CRC-32/ISO-HDLC" and item["endian"] == "little" for item in result["hypotheses"]))

    def test_set_c_reports_alignment_without_inventing_confirmation(self):
        result = analyze_packets([Packet(index, payload) for index, payload in enumerate(corpus_c())])
        self.assertTrue(result["observations"]["alignment"])
        self.assertTrue(all(item["status"] != "confirmed" for item in result["hypotheses"]))

    def test_set_d_rejects_corrupt_random_checksums(self):
        result = analyze_packets([Packet(index, payload) for index, payload in enumerate(corpus_d())])
        self.assertFalse(any(item.get("algorithm") for item in result["hypotheses"]))
        self.assertTrue(all(item["status"] != "confirmed" for item in result["hypotheses"]))

    def test_insufficient_evidence_is_explicit(self):
        result = analyze_packets([Packet(0, b"abc"), Packet(1, b"abd")])
        self.assertEqual(result["analysis"]["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["hypotheses"], [])

    def test_application_payload_offsets_are_not_raw_header_offsets(self):
        packets = [Packet(index, ethernet_ipv4_udp(b"\xaa\x01" + bytes((index, 2, 3))), link_type=1) for index in range(3)]
        payload_result = analyze_packets(packets)
        magic = next(item for item in payload_result["hypotheses"] if item["field_type"] == "magic_bytes")
        self.assertEqual(magic["absolute_offset"], 42)
        self.assertEqual(magic["payload_relative_offset"], 0)
        raw_result = analyze_packets(packets, analyze_raw=True)
        self.assertEqual(raw_result["analysis"]["scope"], "raw_packet")
        self.assertTrue(raw_result["analysis"]["contexts"][0]["scope"] == "raw_packet")


if __name__ == "__main__":
    unittest.main()
