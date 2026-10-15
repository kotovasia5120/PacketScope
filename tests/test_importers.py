import struct
import unittest

from packetscope.errors import FormatError, InputLimitError
from packetscope.importers import import_bytes
from packetscope.models import Limits


def make_pcap(
    payloads: list[bytes], *, endian: str = "<", nanoseconds: bool = False, snaplen: int = 65535, link_type: int = 1
) -> bytes:
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    data = bytearray(struct.pack(endian + "IHHiiII", magic, 2, 4, 0, 0, snaplen, link_type))
    for index, payload in enumerate(payloads, 1):
        data.extend(struct.pack(endian + "IIII", 100 + index, 123, len(payload), len(payload)))
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


def make_pcapng_section(payload: bytes, *, endian: str = "<", resolution: int | None = None, simple: bool = False) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        padding = (-len(body)) % 4
        total = 12 + len(body) + padding
        return struct.pack(endian + "II", kind, total) + body + bytes(padding) + struct.pack(endian + "I", total)

    byte_order_magic = bytes.fromhex("4d3c2b1a" if endian == "<" else "1a2b3c4d")
    section = (
        struct.pack(endian + "II", 0x0A0D0D0A, 28)
        + byte_order_magic
        + struct.pack(endian + "HHII", 1, 0, 0xFFFFFFFF, 0)
        + struct.pack(endian + "I", 28)
    )
    options = b""
    if resolution is not None:
        options = struct.pack(endian + "HH", 9, 1) + bytes([resolution]) + b"\x00\x00\x00" + struct.pack(endian + "HH", 0, 0)
    interface = block(1, struct.pack(endian + "HHi", 1, 0, 65535) + options)
    if simple:
        packet = block(3, struct.pack(endian + "I", len(payload)) + payload)
    else:
        packet = block(6, struct.pack(endian + "IIIII", 0, 0, 123, len(payload), len(payload)) + payload)
    return section + interface + packet


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

    def test_pcap_endianness_nanoseconds_and_truncated_record(self):
        big = import_bytes("capture.pcap", make_pcap([b"abc"], endian=">"))
        self.assertEqual(big.packets[0].payload, b"abc")
        nano = import_bytes("capture.pcap", make_pcap([b"x"], nanoseconds=True))
        self.assertAlmostEqual(nano.packets[0].timestamp or 0, 101.000000123)
        with self.assertRaises(FormatError):
            import_bytes("capture.pcap", make_pcap([b"abc"])[:-1])

    def test_pcap_snaplen_and_timestamp_validation(self):
        with self.assertRaises(FormatError):
            import_bytes("capture.pcap", make_pcap([b"abcd"], snaplen=3))
        invalid = bytearray(make_pcap([b"x"]))
        invalid[28:32] = struct.pack("<I", 1_000_000)
        with self.assertRaises(FormatError):
            import_bytes("capture.pcap", bytes(invalid))
        unknown = import_bytes("capture.pcap", make_pcap([b"raw"], link_type=0xFFFFFFFF))
        self.assertEqual(unknown.packets[0].link_type, 0xFFFFFFFF)

    def test_pcapng_sections_resolution_and_simple_padding(self):
        first = make_pcapng_section(b"abc", resolution=9)
        second = make_pcapng_section(b"xyz", endian=">")
        result = import_bytes("capture.pcapng", first + second)
        self.assertEqual([packet.payload for packet in result.packets], [b"abc", b"xyz"])
        self.assertAlmostEqual(result.packets[0].timestamp or 0, 0.000000123)
        self.assertEqual(result.packets[0].original_length, 3)
        simple = import_bytes("capture.pcapng", make_pcapng_section(b"abc", simple=True))
        self.assertEqual(simple.packets[0].payload, b"abc")

    def test_pcapng_trailer_and_interface_corruption(self):
        valid = bytearray(make_pcapng(b"packet"))
        valid[-4:] = struct.pack("<I", 12)
        with self.assertRaises(FormatError):
            import_bytes("capture.pcapng", bytes(valid))
        unknown = bytearray(make_pcapng(b"packet"))
        # EPB interface id is the first u32 in the EPB body.
        epb_offset = 28 + 20
        unknown[epb_offset + 8 : epb_offset + 12] = struct.pack("<I", 9)
        with self.assertRaises(FormatError):
            import_bytes("capture.pcapng", bytes(unknown))

    def test_malformed_and_limits_are_bounded(self):
        with self.assertRaises(FormatError):
            import_bytes("bad.hex", b"0g")
        with self.assertRaises(InputLimitError):
            import_bytes("big.bin", b"1234", limits=Limits(max_packet_bytes=3))
        with self.assertRaises(FormatError):
            import_bytes("bad.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)


if __name__ == "__main__":
    unittest.main()
