"""Bounded TCP stream reconstruction and conservative framing hints.

This module is intentionally separate from flow grouping and application
analysis.  It never fills a missing byte, treats sequence-derived ordering as
evidence, and keeps packet provenance alongside every reconstructed segment.
"""
from __future__ import annotations

from typing import Iterable

from packetscope.errors import InputLimitError
from packetscope.flows import group_flows
from packetscope.models import Limits, Packet


TCP_MODULUS = 1 << 32
TCP_HALF_RANGE = 1 << 31
MAX_FRAMING_CANDIDATES = 32


def reconstruct_tcp_streams(
    packets: Iterable[Packet],
    *,
    limits: Limits | None = None,
) -> dict:
    """Reconstruct bounded TCP payload streams without hiding gaps or overlap."""
    limits = limits or Limits()
    packet_list: list[Packet] = []
    total_bytes = 0
    for packet in packets:
        if len(packet_list) >= limits.max_packets:
            raise InputLimitError(f"packet count exceeds limit {limits.max_packets}")
        if len(packet.payload) > limits.max_packet_bytes:
            raise InputLimitError(f"packet exceeds limit {limits.max_packet_bytes}")
        total_bytes += len(packet.payload)
        if total_bytes > limits.max_input_bytes:
            raise InputLimitError(f"capture bytes exceed limit {limits.max_input_bytes}")
        packet_list.append(packet)

    by_id = {packet.index: packet for packet in packet_list}
    streams: list[dict] = []
    for flow in group_flows(packet_list, limits=limits):
        if flow.transport != "tcp":
            continue
        for direction in ("forward", "reverse"):
            flow_packets = [item for item in flow.packets if item.direction == direction and item.sequence is not None]
            if not flow_packets:
                continue
            streams.append(_reconstruct_direction(flow, direction, flow_packets, by_id, limits))
    streams.sort(key=lambda item: (item["flow_id"], item["direction"]))
    return {
        "schema_version": 1,
        "stream_count": len(streams),
        "streams": streams,
        "limitations": [
            "TCP sequence ordering is a reconstruction hypothesis; application message boundaries are not assumed.",
            "Missing bytes are reported as gaps and are never synthesized.",
            "Original Packet records remain immutable; stream data is a bounded derived view.",
        ],
    }


def infer_message_boundaries(
    data: bytes | None,
    *,
    max_messages: int = 1000,
    max_bytes: int = 16 * 1024 * 1024,
) -> dict:
    """Return conservative framing candidates for a complete stream payload."""
    if max_messages <= 0 or max_bytes <= 0:
        raise ValueError("framing limits must be positive")
    if data is None:
        return {"status": "unavailable", "candidates": [], "limitations": ["stream contains gaps"]}
    bounded = bytes(data[:max_bytes])
    candidates: list[dict] = []
    if len(bounded) != len(data):
        limitations = ["framing input was bounded before inference"]
    else:
        limitations = []

    for width in range(1, min(256, len(bounded) // 2 + 1)):
        if len(bounded) % width == 0 and len(bounded) // width >= 2:
            candidates.append({
                "kind": "fixed_length",
                "record_length": width,
                "message_count": len(bounded) // width,
                "evidence": "stream length divides evenly into repeated records",
                "status": "hypothesis",
            })
            if len(candidates) >= MAX_FRAMING_CANDIDATES:
                break

    for delimiter in (b"\x00", b"\n", b"\r\n", b"~"):
        occurrences = bounded.count(delimiter)
        if occurrences >= 2:
            candidates.append({
                "kind": "delimiter",
                "delimiter": delimiter.hex(),
                "message_count": min(occurrences, max_messages),
                "evidence": f"delimiter occurs {occurrences} times",
                "status": "hypothesis",
            })

    for magic_width in range(1, 5):
        if len(bounded) < magic_width:
            break
        magic = bounded[:magic_width]
        occurrences = sum(1 for offset in range(len(bounded) - magic_width + 1) if bounded[offset:offset + magic_width] == magic)
        if occurrences >= 2:
            candidates.append({
                "kind": "magic_byte",
                "magic": magic.hex(),
                "message_count": min(occurrences, max_messages),
                "evidence": "the stream prefix recurs at later offsets",
                "status": "hypothesis",
            })

    for width in (1, 2, 4):
        if len(bounded) < width * 2:
            continue
        for endian in ("big", "little"):
            offset = 0
            count = 0
            while offset + width <= len(bounded) and count < max_messages:
                length_value = int.from_bytes(bounded[offset:offset + width], endian)
                candidates_for_record = (width + length_value, length_value)
                record_size = next((size for size in candidates_for_record if size > width and offset + size <= len(bounded)), None)
                if record_size is None:
                    break
                offset += record_size
                count += 1
            if count >= 2 and offset == len(bounded):
                candidates.append({
                    "kind": "length_prefixed",
                    "length_width": width,
                    "endian": endian,
                    "message_count": count,
                    "evidence": "repeated bounded length interpretation consumes the complete stream",
                    "status": "hypothesis",
                })
    candidates = sorted(candidates, key=lambda item: (item["kind"], json_sort_key(item)))[:MAX_FRAMING_CANDIDATES]
    if len(candidates) > 1:
        limitations.append("Multiple framing interpretations remain viable; no candidate is confirmed.")
    if not candidates:
        limitations.append("No bounded fixed, delimiter, magic, or length-prefixed framing candidate was found.")
    return {"status": "complete", "candidates": candidates, "limitations": limitations}


def _reconstruct_direction(flow, direction: str, flow_packets: list, by_id: dict[int, Packet], limits: Limits) -> dict:
    origin = int(flow_packets[0].sequence)  # type: ignore[arg-type]
    records = []
    for position, item in enumerate(flow_packets):
        sequence = int(item.sequence)  # type: ignore[arg-type]
        relative = (sequence - origin) & (TCP_MODULUS - 1)
        if relative >= TCP_HALF_RANGE:
            relative -= TCP_MODULUS
        packet = by_id.get(item.packet_id)
        if packet is None:
            continue
        start = max(0, int(item.payload_offset))
        end = min(len(packet.payload), start + max(0, int(item.payload_length)))
        payload = packet.payload[start:end]
        records.append((relative, position, item, payload))
    records.sort(key=lambda record: (record[0], record[1], record[2].packet_id))
    base = min(record[0] for record in records)
    cursor = 0
    previous_relative = None
    gaps: list[dict] = []
    overlaps: list[dict] = []
    segments: list[dict] = []
    mapping: list[dict] = []
    assembled = bytearray()
    limitations: list[str] = [
        item for item in flow.limitations
        if item != "TCP stream reassembly is not performed; segments remain packet-scoped"
    ]
    for relative, _position, item, payload in records:
        offset = relative - base
        if previous_relative is not None and offset < previous_relative:
            limitations.append("captured packet order differs from sequence order")
        previous_relative = offset
        if offset > cursor:
            gaps.append({"offset": cursor, "length": offset - cursor})
        if offset < cursor:
            overlap = min(cursor - offset, len(payload))
            overlaps.append({"offset": offset, "length": overlap, "packet_id": item.packet_id})
        segments.append({
            "offset": offset,
            "length": len(payload),
            "data": payload.hex(),
            "packet_id": item.packet_id,
            "source_offset": item.source_offset,
            "timestamp": item.timestamp,
            "sequence": int(item.sequence),
        })
        mapping.append({
            "packet_id": item.packet_id,
            "source_offset": item.source_offset,
            "timestamp": item.timestamp,
            "direction": direction,
            "stream_offset": offset,
            "length": len(payload),
            "sequence": int(item.sequence),
        })
        if offset <= cursor and offset + len(payload) > cursor:
            new_bytes = payload[max(0, cursor - offset):]
            if len(assembled) + len(new_bytes) <= min(limits.max_input_bytes, limits.max_response_bytes // 2):
                assembled.extend(new_bytes)
            cursor = offset + len(payload)
        elif offset >= cursor:
            if len(assembled) + len(payload) <= min(limits.max_input_bytes, limits.max_response_bytes // 2):
                assembled.extend(payload)
            cursor = offset + len(payload)
    if gaps:
        limitations.append("one or more sequence gaps prevent a complete stream")
    if overlaps:
        limitations.append("overlapping or duplicate TCP segments were observed")
    if not assembled and any(segment["length"] for segment in segments):
        limitations.append("reconstructed byte output exceeded the response budget")
    complete = not gaps and not overlaps and bool(segments)
    return {
        "flow_id": flow.flow_id,
        "direction": direction,
        "sequence_origin": origin,
        "complete": complete,
        "data": assembled.hex() if complete else None,
        "segments": segments[:limits.max_packets],
        "packet_to_stream": mapping[:limits.max_packets],
        "gaps": gaps[:limits.max_packets],
        "overlaps": overlaps[:limits.max_packets],
        "limitations": sorted(set(limitations)),
    }


def json_sort_key(value: dict) -> tuple:
    return tuple((str(key), str(value[key])) for key in sorted(value))
