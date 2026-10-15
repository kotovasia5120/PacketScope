import struct
import unittest

from packetscope.errors import FormatError, InputLimitError
from packetscope.importers import import_bytes
from packetscope.models import Limits


def make_pcap(payloads: list[bytes]) -> bytes:
    data = bytearray(struct.pack("<IHHiiii", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, payload in enumerate(payloads, 1):
        data.extend(struct.pack("<IIII", 100 + index, 123, len(payload), len(payload)))
        data.extend(payload)
    return bytes(data)


def make_pcapng(payload: bytes) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        padding = (-len(body)) % 4
        total = 12 + len(body) + padding
        return struct.pack("<II", kind, total) + body + bytes(padding) + struct.pack("<I", total)

    section = struct.pack("<II", 0x0A0D0D0A, 28) + b"\x4d\x3c\x2b\x1a" + struct.pack("<HHII", 1, 0, 0xFFFFFFFF, 0) + struct.pack("<I", 28)
    interface = block(1, struct.pack("<HHi", 1, 0, 65535))
    enhanced = block(6, struct.pack("<IIIII", 0, 0, 1, len(payload), len(payload)) + payload)
    return section + interface + enhanced


class ImporterTests(unittest.TestCase):
    def test_bin_and_hex(self):
        binary = import_bytes("sample.bin", b"\x00\x01\xff")
        self.assertEqual(binary.format, "bin")
        self.assertEqual(binary.packets[0].payload, b"\x00\x01\xff")
        text = import_bytes("sample.hex", b"0000: 00 01 ff\n# comment")
        self.assertEqual(text.packets[0].payload, b"\x00\x01\xff")

    def test_pcap_and_pcapng(self):
        pcap = import_bytes("capture.pcap", make_pcap([b"abc", b"defg"]))
        self.assertEqual([packet.payload for packet in pcap.packets], [b"abc", b"defg"])
        pcapng = import_bytes("capture.pcapng", make_pcapng(b"packet"))
        self.assertEqual(pcapng.packets[0].payload, b"packet")
        self.assertEqual(pcapng.packets[0].link_type, 1)

    def test_malformed_and_limits_are_bounded(self):
        with self.assertRaises(FormatError):
            import_bytes("bad.hex", b"0g")
        with self.assertRaises(InputLimitError):
            import_bytes("big.bin", b"1234", limits=Limits(max_packet_bytes=3))
        with self.assertRaises(FormatError):
            import_bytes("bad.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)


if __name__ == "__main__":
    unittest.main()
