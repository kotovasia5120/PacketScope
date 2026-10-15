"""Deterministic multi-flow PCAP used for Phase 6 scope validation."""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

from packetscope.analysis.crc import STANDARD_CRC, compute_crc


def _ethernet(payload: bytes, ether_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ether_type) + payload


def _ipv4(transport: bytes, protocol: int, source: str, destination: str) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64, protocol, 0,
        ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed,
    )
    return _ethernet(header + transport, 0x0800)


def _ipv6(transport: bytes, next_header: int, source: str, destination: str) -> bytes:
    header = struct.pack("!IHBB", 6 << 28, len(transport), next_header, 32)
    return _ethernet(header + ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed + transport, 0x86DD)


def _udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def _tcp(source_port: int, destination_port: int, sequence: int, payload: bytes) -> bytes:
    return struct.pack("!HHIIHHHH", source_port, destination_port, sequence, 0, 0x5018, 4096, 0, 0) + payload


def _message(message_type: int, sequence: int, body: bytes) -> bytes:
    prefix = b"MF" + bytes((message_type,)) + sequence.to_bytes(2, "big") + body
    return prefix + compute_crc(prefix, STANDARD_CRC[1]).to_bytes(2, "big")


def packets() -> list[tuple[bytes, int | None]]:
    """Return ``(captured_frame, original_length)`` records in capture order."""
    return [
        (_ipv4(_udp(4000, 5000, _message(0x10, 0, b"u4-request-0")), 17, "192.0.2.10", "192.0.2.20"), None),
        (_ipv4(_udp(5000, 4000, _message(0x90, 100, b"u4-response")), 17, "192.0.2.20", "192.0.2.10"), None),
        (_ipv6(_udp(6000, 7000, _message(0x20, 0, b"u6-request")), 17, "2001:db8::1", "2001:db8::2"), None),
        (_ipv6(_udp(7000, 6000, _message(0xA0, 100, b"u6-response")), 17, "2001:db8::2", "2001:db8::1"), None),
        (_ipv4(_tcp(8000, 9000, 1000, _message(0x30, 1, b"tcp-v4-a")), 6, "192.0.2.30", "192.0.2.40"), None),
        (_ipv4(_tcp(9000, 8000, 9000, _message(0xB0, 1, b"tcp-v4-b")), 6, "192.0.2.40", "192.0.2.30"), None),
        (_ipv4(_tcp(8000, 9000, 1000, _message(0x30, 1, b"tcp-v4-a")), 6, "192.0.2.30", "192.0.2.40"), None),
        (_ipv6(_tcp(10000, 11000, 2000, _message(0x40, 2, b"tcp-v6-a")), 6, "2001:db8::3", "2001:db8::4"), None),
        (_ethernet(b"unsupported-link-payload", 0x88B5), None),
        (_ipv4(_udp(4000, 5000, b"truncated"), 17, "192.0.2.10", "192.0.2.20")[:-5], 1000),
    ]


def pcap_bytes() -> bytes:
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, (frame, original_length) in enumerate(packets()):
        original = original_length or len(frame)
        output.extend(struct.pack("<IIII", 1_700_100_000 + index, index * 1000, len(frame), original))
        output.extend(frame)
    return bytes(output)


def write_pcap(path: str | Path) -> None:
    Path(path).write_bytes(pcap_bytes())
