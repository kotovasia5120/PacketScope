from __future__ import annotations

import struct
from dataclasses import dataclass

from packetscope.errors import FormatError, InputLimitError
from packetscope.models import ImportResult, Limits, Packet


SHB = 0x0A0D0D0A
IDB = 0x00000001
SPB = 0x00000003
EPB = 0x00000006


@dataclass(frozen=True)
class _Interface:
    link_type: int
    timestamp_resolution: float = 1_000_000.0


def _read_u32(data: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(endian + "I", data, offset)[0]


def parse_pcapng(data: bytes, name: str, limits: Limits) -> ImportResult:
    packets: list[Packet] = []
    warnings: list[str] = []
    interfaces: dict[int, _Interface] = {}
    offset = 0
    endian: str | None = None
    while offset < len(data):
        if len(data) - offset < 12:
            raise FormatError(f"PCAPNG block at offset {offset} is truncated")
        raw_type = data[offset : offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            block_endian = _section_endian(data, offset)
            total = _read_u32(data, offset + 4, block_endian)
            _validate_block(data, offset, total, block_endian, limits)
            if total < 28:
                raise FormatError("PCAPNG section header is too short")
            endian = block_endian
            interfaces = {}
            offset += total
            continue
        if endian is None:
            raise FormatError("PCAPNG must begin with a section header")
        block_type = _read_u32(data, offset, endian)
        total = _read_u32(data, offset + 4, endian)
        _validate_block(data, offset, total, endian, limits)
        if block_type == IDB:
            if total < 20:
                raise FormatError("PCAPNG interface description is too short")
            link_type = struct.unpack_from(endian + "H", data, offset + 8)[0]
            interfaces[len(interfaces)] = _Interface(
                link_type, _timestamp_resolution(data, offset + 16, offset + total - 4, endian)
            )
        elif block_type == EPB:
            _parse_epb(data, offset, total, endian, interfaces, packets, name, limits)
        elif block_type == SPB:
            _parse_spb(data, offset, total, endian, interfaces, packets, name, limits)
        else:
            warnings.append(f"ignored PCAPNG block type 0x{block_type:08x} at offset {offset}")
        offset += total
    return ImportResult("pcapng", packets, warnings)


def _section_endian(data: bytes, offset: int) -> str:
    if len(data) - offset < 12:
        raise FormatError("PCAPNG section header is truncated")
    magic = data[offset + 8 : offset + 12]
    if magic == b"\x4d\x3c\x2b\x1a":
        return "<"
    if magic == b"\x1a\x2b\x3c\x4d":
        return ">"
    raise FormatError("PCAPNG section has invalid byte-order magic")


def _validate_block(data: bytes, offset: int, total: int, endian: str, limits: Limits) -> None:
    if total < 12 or total % 4:
        raise FormatError(f"invalid PCAPNG block length {total} at offset {offset}")
    if total > limits.max_pcapng_block_bytes:
        raise InputLimitError(
            f"PCAPNG block exceeds limit {limits.max_pcapng_block_bytes}"
        )
    if offset + total > len(data):
        raise FormatError(f"PCAPNG block at offset {offset} is truncated")
    trailer = _read_u32(data, offset + total - 4, endian)
    if trailer != total:
        raise FormatError(f"PCAPNG block at offset {offset} has a mismatched trailing length")


def _timestamp_resolution(data: bytes, start: int, end: int, endian: str) -> float:
    """Read IDB if_tsresol, defaulting to the PCAPNG microsecond resolution."""
    offset = start
    resolution = 1_000_000.0
    while offset + 4 <= end:
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            if length != 0:
                raise FormatError("PCAPNG end-of-options marker has a nonzero length")
            return resolution
        if offset + length > end:
            raise FormatError("PCAPNG interface option is truncated")
        value = data[offset : offset + length]
        offset += (length + 3) & ~3
        if offset > end:
            raise FormatError("PCAPNG interface option padding is truncated")
        if code == 9:
            if length != 1:
                raise FormatError("PCAPNG timestamp resolution option must contain one byte")
            raw = value[0]
            resolution = float(2**(raw & 0x7F) if raw & 0x80 else 10**raw)
    if offset != end:
        raise FormatError("PCAPNG interface options are not four-byte aligned")
    return resolution


def _append_packet(
    packets: list[Packet],
    payload: bytes,
    source_offset: int,
    original_length: int,
    link_type: int | None,
    interface_id: int | None,
    name: str,
    limits: Limits,
    timestamp: float | None,
) -> None:
    if len(packets) >= limits.max_packets:
        raise InputLimitError(f"packet count exceeds limit {limits.max_packets}")
    if len(payload) > limits.max_packet_bytes:
        raise InputLimitError(f"PCAPNG packet exceeds limit {limits.max_packet_bytes}")
    packets.append(
        Packet(
            index=len(packets),
            payload=payload,
            source_offset=source_offset,
            timestamp=timestamp,
            original_length=original_length,
            link_type=link_type,
            interface_id=interface_id,
            source_name=name,
        )
    )


def _parse_epb(
    data: bytes,
    offset: int,
    total: int,
    endian: str,
    interfaces: dict[int, _Interface],
    packets: list[Packet],
    name: str,
    limits: Limits,
) -> None:
    if total < 32:
        raise FormatError("PCAPNG enhanced packet block is too short")
    interface_id, ts_high, ts_low, captured, original = struct.unpack_from(
        endian + "IIIII", data, offset + 8
    )
    interface = interfaces.get(interface_id)
    if interface is None:
        raise FormatError(f"PCAPNG enhanced packet references unknown interface {interface_id}")
    payload_offset = offset + 28
    padded = (captured + 3) & ~3
    if payload_offset + padded + 4 > offset + total:
        raise FormatError("PCAPNG enhanced packet payload is truncated")
    _append_packet(
        packets,
        data[payload_offset : payload_offset + captured],
        payload_offset,
        original,
        interface.link_type,
        interface_id,
        name,
        limits,
        (ts_high * 2**32 + ts_low) / interface.timestamp_resolution,
    )


def _parse_spb(
    data: bytes,
    offset: int,
    total: int,
    endian: str,
    interfaces: dict[int, _Interface],
    packets: list[Packet],
    name: str,
    limits: Limits,
) -> None:
    if total < 16:
        raise FormatError("PCAPNG simple packet block is too short")
    original = _read_u32(data, offset + 8, endian)
    captured = min(original, total - 16)
    payload_offset = offset + 12
    if captured > limits.max_packet_bytes:
        raise InputLimitError(f"PCAPNG packet exceeds limit {limits.max_packet_bytes}")
    _append_packet(
        packets,
        data[payload_offset : payload_offset + captured],
        payload_offset,
        original,
        interfaces[0].link_type if 0 in interfaces else None,
        0,
        name,
        limits,
        None,
    )
