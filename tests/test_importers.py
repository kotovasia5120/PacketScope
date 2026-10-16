import struct
import unittest

from packetscope.analysis import analyze_packets
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

    def test_message_capture_formats_join_existing_import_and_analysis_pipeline(self):
        jsonl = (
            b'{"timestamp":2.5,"direction":"tx","source":"uart0",'
            b'"raw":"AQI="}\n\n'
            b'{"timestamp":1,"direction":"rx","source":"usb:1-2",'
            b'"raw":"/w==","metadata":{"channel":1}}\n'
        )
        imported = import_bytes("mixed.jsonl", jsonl)
        self.assertEqual(imported.format, "jsonl")
        self.assertEqual([packet.payload for packet in imported.packets], [b"\x01\x02", b"\xff"])
        self.assertEqual([packet.timestamp for packet in imported.packets], [2.5, 1])
        self.assertEqual([packet.direction for packet in imported.packets], ["tx", "rx"])
        self.assertEqual([packet.source_identity for packet in imported.packets], ["uart0", "usb:1-2"])
        self.assertEqual([packet.source_name for packet in imported.packets], ["mixed.jsonl"] * 2)
        self.assertEqual(imported.packets[1].metadata, {"channel": 1})

        result = analyze_packets(imported.packets)
        self.assertEqual(result["source"]["format"], "normalized")
        self.assertEqual(result["packets"][0]["direction"], "tx")
        self.assertEqual(result["packets"][0]["source_identity"], "uart0")
        self.assertEqual(result["packets"][0]["source"], "uart0")
        self.assertEqual(result["packets"][1]["timestamp"], 1)

    def test_uart_and_can_dispatch_keep_direction_timestamps_and_can_provenance(self):
        uart = import_bytes("serial.uart", b"1.25\trx\tserial0\tAAEC\n2\ttx\tserial0\t/w==\n")
        self.assertEqual(uart.format, "uart-lines")
        self.assertEqual([packet.direction for packet in uart.packets], ["rx", "tx"])
        self.assertEqual([packet.timestamp for packet in uart.packets], [1.25, 2])
        self.assertEqual(uart.packets[0].source_identity, "serial0")

        can = import_bytes("bus.can", b"3\trx\tcan0\t0x123#" + b"00" * 8 + b"\n")
        self.assertEqual(can.format, "can-lines")
        self.assertEqual(can.packets[0].metadata, {"can_id": 0x123})
        self.assertEqual(can.packets[0].direction, "rx")
        self.assertEqual(can.packets[0].source_identity, "can0")
        self.assertEqual(can.packets[0].timestamp, 3)

        fd = import_bytes("bus.can", b"4\ttx\tcan0\t1#" + b"ab" * 64 + b"\n", "can")
        self.assertEqual(len(fd.packets[0].payload), 64)

    def test_message_dispatch_rejects_mixed_malformed_empty_oversized_and_truncated_records(self):
        valid = b'{"timestamp":0,"direction":"rx","source":"s","raw":"AA=="}\n'
        self.assertEqual(import_bytes("empty.jsonl", b"").packets, [])
        with self.assertRaises(FormatError):
            import_bytes("mixed.jsonl", valid + b"1.0\trx\ts\tAA==\n")
        with self.assertRaises(FormatError):
            import_bytes("truncated.uart", b"1.0\trx\ts\tAA")
        with self.assertRaises(FormatError):
            import_bytes("truncated.can", b"1.0\trx\ts\t123#0\n")
        with self.assertRaises(InputLimitError):
            import_bytes(
                "oversized.jsonl",
                b'{"timestamp":0,"direction":"rx","source":"s","raw":"AQI="}\n',
                limits=Limits(max_packet_bytes=1),
            )
        with self.assertRaises(InputLimitError):
            import_bytes("oversized.can", b"1.0\trx\ts\t123#" + b"00" * 65 + b"\n")


if __name__ == "__main__":
    unittest.main()
