"""Adapters for bounded message-oriented capture formats.

The parsers in :mod:`packetscope.capture_formats` own validation and limits.
This module only maps their already-delimited records onto the existing
``ImportResult``/``Packet`` pipeline so analysis, jobs, and HTTP callers do
not need a second import path.
"""

from __future__ import annotations

from packetscope.capture_formats import parse_can, parse_jsonl, parse_uart
from packetscope.models import ImportResult, Limits, Packet


_PARSERS = {
    "jsonl": parse_jsonl,
    "uart": parse_uart,
    "can": parse_can,
}


def normalize_capture_format(format_name: str) -> str:
    """Return the canonical dispatch name for a message capture format."""

    aliases = {
        "jsonl": "jsonl",
        "json-lines": "jsonl",
        "normalized-jsonl": "jsonl",
        "normalized_jsonl": "jsonl",
        "ndjson": "jsonl",
        "uart": "uart",
        "uart-lines": "uart",
        "uart_lines": "uart",
        "can": "can",
        "can-lines": "can",
        "can_lines": "can",
    }
    try:
        return aliases[format_name.strip().lower()]
    except (AttributeError, KeyError) as exc:
        raise ValueError(f"unsupported message capture format: {format_name}") from exc


def import_message_capture(
    name: str,
    data: bytes,
    format_name: str,
    limits: Limits,
) -> ImportResult:
    """Parse and adapt one normalized/UART/CAN capture.

    ``source_name`` remains the uploaded filename for compatibility with the
    existing importer contract. The record's source identity, direction,
    timestamp, explicit boundary, and scalar metadata are carried on each
    packet separately.
    """

    canonical = normalize_capture_format(format_name)
    collection = _PARSERS[canonical](data, name, limits)
    packets = [
        Packet(
            index=message.index,
            payload=message.raw,
            timestamp=message.timestamp,
            source_name=name,
            direction=message.direction,
            source_identity=message.source_identity,
            boundary=message.boundary,
            metadata=dict(message.metadata),
        )
        for message in collection.messages
    ]
    return ImportResult(collection.format, packets, list(collection.warnings))


__all__ = ["import_message_capture", "normalize_capture_format"]
