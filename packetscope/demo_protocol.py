"""Deterministic request/response protocol corpus for the full-workflow demo.

The capture generator and the reviewed reference schema are separate entry
points on purpose.  An investigation can import and analyze the capture before
the reference is supplied for validation; no ground-truth bytes are inferred
by this module at runtime.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Iterable

from packetscope.analysis.crc import STANDARD_CRC, compute_crc


def _message(index: int, *, changed: bool = False, corrupt: bool = False, truncate: bool = False) -> bytes:
    is_response = index % 2 == 1
    message_type = 0x90 if is_response else 0x10
    flags = (0x02 if is_response else 0x01) | (0x04 if index % 3 == 0 else 0)
    sequence = 100 + index if is_response else index
    record_count = 1 + (index % 3)
    records = b"".join(
        bytes((0x20 + record_index,))
        + (index * 17 + record_index).to_bytes(2, "little")
        for record_index in range(record_count)
    )
    payload = (b"response" if is_response else b"request") + bytes((index,))
    if changed:
        payload += b"-changed"
    header = b"PX" + bytes((message_type, flags)) + sequence.to_bytes(2, "big")
    header += bytes((len(payload), record_count))
    body = header + records + payload
    checksum = compute_crc(body, STANDARD_CRC[1]).to_bytes(2, "big")
    raw = body + checksum
    if corrupt:
        raw = raw[:-1] + bytes((raw[-1] ^ 0xFF,))
    if truncate:
        raw = raw[:-2]
    return raw


def protocol_capture(*, changed: bool = False, corrupt_indices: Iterable[int] = (4,), truncate_indices: Iterable[int] = (5,)) -> bytes:
    """Return deterministic JSONL request/response traffic.

    The default capture contains six messages, including one CRC corruption and
    one truncated message.  JSONL retains message boundaries and direction but
    does not add framing knowledge to the analyzer.
    """
    corrupt = set(corrupt_indices)
    truncate = set(truncate_indices)
    lines = []
    for index in range(6):
        direction = "reverse" if index % 2 else "forward"
        record = {
            "index": index,
            "timestamp": 1_700_200_000 + index,
            "direction": direction,
            "source": "phase29-device",
            "raw": base64.b64encode(_message(index, changed=changed, corrupt=index in corrupt, truncate=index in truncate)).decode("ascii"),
        }
        lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return ("\n".join(lines) + "\n").encode("utf-8")


def protocol_reference_schema() -> dict[str, Any]:
    """Return the reviewed schema supplied only after the inference stage."""
    record_element = {
        "id": "record",
        "type": "struct",
        "offset": 0,
        "fields": [
            {"id": "record_id", "type": "uint8", "offset": 0, "length": 1, "endian": "big"},
            {"id": "record_value", "type": "uint16", "offset": 1, "length": 2, "endian": "little"},
        ],
    }
    record_bytes = {"op": "multiply", "args": [{"field": "record_count"}, 3]}
    payload_offset = {"op": "add", "args": [8, record_bytes]}
    payload_end = {"op": "add", "args": [payload_offset, {"field": "payload_length"}]}
    return {
        "schema_version": 2,
        "name": "Phase 29 request response protocol",
        "coordinate_system": "raw_packet",
        "fields": [
            {"id": "magic", "type": "bytes", "offset": 0, "length": 2, "constraints": {"exact": "5058"}},
            {"id": "message_type", "type": "uint8", "offset": 2, "length": 1, "endian": "big", "constraints": {"enum": {"values": [16, 144], "names": {"16": "request", "144": "response"}}}},
            {"id": "flags", "type": "uint8", "offset": 3, "length": 1, "endian": "big", "constraints": {"flags": {"request": 1, "response": 2, "has_extension": 4}}},
            {"id": "sequence", "type": "uint16", "offset": 4, "length": 2, "endian": "big"},
            {"id": "payload_length", "type": "uint8", "offset": 6, "length": 1, "endian": "big"},
            {"id": "record_count", "type": "uint8", "offset": 7, "length": 1, "endian": "big"},
            {"id": "records", "type": "array", "offset": 8, "array": {"count": {"field": "record_count"}, "max_items": 4, "element": record_element}},
            {"id": "payload", "type": "bytes", "offset": payload_offset, "length": {"field": "payload_length"}},
            {"id": "crc", "type": "crc", "offset": payload_end, "length": 2, "endian": "big"},
        ],
        "relationships": [{
            "id": "payload-length",
            "kind": "length",
            "field_id": "payload_length",
            "target_field_id": "payload",
        }, {
            "id": "message-crc",
            "kind": "checksum",
            "field_id": "crc",
            "algorithm": "CRC-16/CCITT-FALSE",
            "byte_order": "big",
        }],
        "metadata": {"reference_stage": "reviewed_after_inference", "corpus": "phase29"},
    }


def protocol_reference_ground_truth() -> list[dict[str, Any]]:
    """Return human-reviewed reference facts separately from capture bytes."""
    return [
        {"field_type": "magic_bytes", "absolute_offset": 0, "width_bits": 16},
        {"field_type": "message_type", "absolute_offset": 2, "width_bits": 8},
        {"field_type": "sequence_counter", "absolute_offset": 4, "width_bits": 16, "endian": "big"},
        {"field_type": "length_field", "absolute_offset": 6, "width_bits": 8, "endian": "big"},
        {"field_type": "crc", "width_bits": 16, "endian": "big", "algorithm": "CRC-16/CCITT-FALSE", "location_mode": "from_end"},
    ]
