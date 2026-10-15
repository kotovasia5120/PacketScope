import struct
import unittest

from packetscope.models import Packet
from packetscope.protocols import decode_packet


def ethernet(ip_payload: bytes, ether_type: int = 0x0800) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ether_type) + ip_payload


def ipv4(transport: bytes, protocol: int, flags_fragment: int = 0) -> bytes:
    total = 20 + len(transport)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        7,
        flags_fragment,
        64,
        protocol,
        0,
        bytes([192, 0, 2, 1]),
        bytes([192, 0, 2, 2]),
    )
    return header + transport


class ProtocolDecoderTests(unittest.TestCase):
    def test_ethernet_ipv4_tcp_extracts_application_payload(self):
        tcp = struct.pack("!HHIIHHHH", 1234, 4321, 1, 0, 0x5002, 4096, 0, 0) + b"hello"
        result = decode_packet(Packet(0, ethernet(ipv4(tcp, 6)), link_type=1))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["network"]["transport"]["protocol"], "tcp")
        self.assertEqual(result["network"]["transport"]["payload_length"], 5)
        self.assertEqual(result["network"]["transport"]["payload_offset"], 14 + 20 + 20)

    def test_ipv4_udp_and_ipv6_are_decoded(self):
        udp = struct.pack("!HHHH", 1, 2, 11, 0) + b"abc"
        ipv4_result = decode_packet(Packet(0, ipv4(udp, 17), link_type=101))
        self.assertEqual(ipv4_result["transport"]["protocol"], "udp")
        self.assertEqual(ipv4_result["transport"]["payload_length"], 3)
        ipv6_header = struct.pack("!IHBB", 6 << 28, 8, 17, 32)
        ipv6_header += bytes.fromhex("20010db8000000000000000000000001")
        ipv6_header += bytes.fromhex("20010db8000000000000000000000002")
        ipv6_result = decode_packet(Packet(0, ethernet(ipv6_header + udp, 0x86DD), link_type=1))
        self.assertEqual(ipv6_result["network"]["version"], 6)
        self.assertEqual(ipv6_result["network"]["transport"]["protocol"], "udp")

    def test_fragments_are_not_presented_as_complete_messages(self):
        tcp = struct.pack("!HHIIHHHH", 1, 2, 0, 0, 0x5000, 0, 0, 0) + b"partial"
        result = decode_packet(Packet(0, ethernet(ipv4(tcp, 6, flags_fragment=0x2000)), link_type=1))
        self.assertEqual(result["network"]["status"], "fragmented")
        self.assertNotIn("transport", result["network"])

    def test_truncated_and_unknown_link_types_are_explicit(self):
        truncated = decode_packet(Packet(0, b"\x00" * 10, link_type=1))
        self.assertEqual(truncated["status"], "truncated_ethernet")
        unknown = decode_packet(Packet(0, b"raw", link_type=999))
        self.assertEqual(unknown["status"], "unsupported_link_type")
        self.assertEqual(unknown["payload_length"], 3)


if __name__ == "__main__":
    unittest.main()
