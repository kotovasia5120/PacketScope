from __future__ import annotations

import struct

from packetscope.errors import FormatError, InputLimitError
from packetscope.models import ImportResult, Limits, Packet


_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def parse_pcap(data: bytes, name: str, limits: Limits) -> ImportResult:
    if len(data) < 24:
        raise FormatError("PCAP global header is truncated")
    magic = data[:4]
    if magic not in _MAGICS:
        raise FormatError("unsupported PCAP magic")
    endian, resolution = _MAGICS[magic]
    version_major, version_minor, _zone, _sigfigs, snaplen, link_type = struct.unpack_from(
        endian + "HHiiii", data, 4
    )
    if (version_major, version_minor) != (2, 4):
        raise FormatError(f"unsupported PCAP version {version_major}.{version_minor}")
    packets: list[Packet] = []
    warnings: list[str] = []
    offset = 24
    while offset < len(data):
        if len(packets) >= limits.max_packets:
            raise InputLimitError(f"packet count exceeds limit {limits.max_packets}")
        if len(data) - offset < 16:
            raise FormatError(f"PCAP packet header at offset {offset} is truncated")
        ts_sec, ts_fraction, captured, original = struct.unpack_from(
            endian + "IIII", data, offset
        )
        payload_offset = offset + 16
        if captured > limits.max_packet_bytes:
            raise InputLimitError(
                f"PCAP packet at offset {offset} exceeds limit {limits.max_packet_bytes}"
            )
        if snaplen and captured > snaplen:
            raise FormatError(
                f"PCAP packet at offset {offset} exceeds declared snaplen {snaplen}"
            )
        if ts_fraction >= resolution:
            raise FormatError(f"PCAP packet at offset {offset} has an invalid timestamp fraction")
        end = payload_offset + captured
        if end > len(data):
            raise FormatError(f"PCAP packet at offset {offset} is truncated")
        timestamp = ts_sec + (ts_fraction / resolution)
        packets.append(
            Packet(
                index=len(packets),
                payload=data[payload_offset:end],
                source_offset=payload_offset,
                timestamp=timestamp,
                original_length=original,
                link_type=link_type,
                source_name=name,
            )
        )
        if captured > original:
            warnings.append(f"packet {len(packets) - 1} captured length exceeds original length")
        offset = end
    return ImportResult("pcap", packets, warnings)
