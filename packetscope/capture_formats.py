"""Bounded, transport-neutral message capture formats.

This module deliberately does not turn a byte stream into messages.  The
normalized JSON-lines format has one object per already-delimited message;
UART and CAN text helpers have the same rule.  A caller that only has a
continuous UART/USB stream must provide framing before using these importers.

Raw bytes are represented as canonical padded base64 in JSON.  The returned
records keep the capture order and an explicit ``explicit-record`` boundary
marker so downstream analysis can distinguish a supplied message boundary
from a guessed one.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import json
import math
from typing import Any, Iterable

from packetscope.errors import FormatError, InputLimitError
from packetscope.models import Limits


BOUNDARY_KIND = "explicit-record"
MAX_DIRECTION_CHARS = 64
MAX_SOURCE_CHARS = 256
MAX_METADATA_ITEMS = 32
MAX_METADATA_KEY_CHARS = 64
MAX_METADATA_STRING_CHARS = 256
MAX_CAN_DATA_BYTES = 64

JsonScalar = str | int | float | bool | None


@dataclass(frozen=True)
class RawMessage:
    """One bounded, already-delimited raw message.

    ``raw`` is the exact message byte sequence supplied by the capture
    producer.  It is never split, joined, decoded, or otherwise interpreted
    by this module.  ``metadata`` is reserved for transport identity such as
    a CAN identifier and is sorted before serialization.
    """

    index: int
    timestamp: int | float
    direction: str
    raw: bytes
    source: str
    boundary: str = BOUNDARY_KIND
    metadata: tuple[tuple[str, JsonScalar], ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int) or self.index < 0:
            raise ValueError("message index must be a non-negative integer")
        _validate_timestamp(self.timestamp, "message timestamp")
        _validate_text(self.direction, "direction", MAX_DIRECTION_CHARS)
        _validate_text(self.source, "source", MAX_SOURCE_CHARS)
        if not isinstance(self.raw, bytes):
            raise TypeError("message raw data must be bytes")
        if self.boundary != BOUNDARY_KIND:
            raise ValueError(f"message boundary must be {BOUNDARY_KIND!r}")
        if not isinstance(self.metadata, tuple):
            raise TypeError("message metadata must be a tuple of key/value pairs")
        _normalize_metadata(self.metadata)

    @property
    def source_identity(self) -> str:
        """Alias that makes the identity-bearing field explicit to callers."""

        return self.source

    def as_record(self) -> dict[str, Any]:
        """Return the deterministic JSON-safe representation of this message."""

        return {
            "boundary": self.boundary,
            "direction": self.direction,
            "index": self.index,
            "metadata": dict(self.metadata),
            "raw": base64.b64encode(self.raw).decode("ascii"),
            "raw_encoding": "base64",
            "source": self.source,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class NormalizedMessageCollection:
    """A bounded collection returned by one of the capture format importers."""

    format: str
    messages: tuple[RawMessage, ...]
    source_name: str = ""
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.format or not isinstance(self.format, str):
            raise ValueError("collection format must be a non-empty string")
        if not isinstance(self.messages, tuple):
            raise TypeError("collection messages must be a tuple")
        for expected, message in enumerate(self.messages):
            if not isinstance(message, RawMessage):
                raise TypeError("collection messages must contain RawMessage objects")
            if message.index != expected:
                raise ValueError("message indexes must be contiguous capture order")
        if not isinstance(self.source_name, str):
            raise TypeError("collection source_name must be a string")

    def to_jsonl(self, limits: Limits | None = None) -> str:
        return dumps_jsonl(self, limits=limits)

    def to_jsonl_bytes(self, limits: Limits | None = None) -> bytes:
        return self.to_jsonl(limits=limits).encode("utf-8")


def parse_jsonl(
    data: bytes,
    name: str = "<messages.jsonl>",
    limits: Limits | None = None,
) -> NormalizedMessageCollection:
    """Parse normalized JSONL, with one explicit message object per line.

    Required fields are ``timestamp`` (JSON number), ``direction``,
    ``source``, and ``raw`` (canonical padded base64).  Blank lines are
    ignored.  An optional ``index`` must match capture order when present;
    the importer never sorts by timestamp.
    """

    checked_limits = limits or Limits()
    payload = _bounded_input(data, checked_limits)
    messages: list[RawMessage] = []
    for line_number, line in _nonempty_lines(payload):
        if len(messages) >= checked_limits.max_packets:
            raise InputLimitError(f"message count exceeds limit {checked_limits.max_packets}")
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FormatError(f"JSONL message at line {line_number} is not UTF-8") from exc
        try:
            value = json.loads(
                text,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_json_constant,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise FormatError(f"invalid JSONL message at line {line_number}") from exc
        if not isinstance(value, dict):
            raise FormatError(f"JSONL message at line {line_number} must be an object")
        _append_message(
            messages,
            _message_from_record(value, len(messages), checked_limits, line_number),
            checked_limits,
        )
    return NormalizedMessageCollection("jsonl", tuple(messages), str(name))


def parse_uart(
    data: bytes,
    name: str = "<uart.log>",
    limits: Limits | None = None,
) -> NormalizedMessageCollection:
    """Parse the explicit UART line representation documented in the docs.

    Each non-empty UTF-8 line is exactly four tab-separated fields:
    ``timestamp<TAB>direction<TAB>source<TAB>base64``.  The line is the
    supplied message boundary; no UART idle-time, delimiter, or baud-rate
    heuristic is applied.
    """

    checked_limits = limits or Limits()
    payload = _bounded_input(data, checked_limits)
    messages: list[RawMessage] = []
    for line_number, line in _nonempty_lines(payload):
        if len(messages) >= checked_limits.max_packets:
            raise InputLimitError(f"message count exceeds limit {checked_limits.max_packets}")
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FormatError(f"UART message at line {line_number} is not UTF-8") from exc
        fields = text.split("\t")
        if len(fields) != 4:
            raise FormatError(
                f"UART message at line {line_number} must have four tab-separated fields"
            )
        timestamp, direction, source, encoded = fields
        _validate_line_token(direction, "direction", line_number, MAX_DIRECTION_CHARS)
        _validate_line_token(source, "source", line_number, MAX_SOURCE_CHARS)
        message = _message_from_parts(
            len(messages),
            _parse_timestamp_token(timestamp, line_number, "UART"),
            direction,
            source,
            _decode_base64(encoded, checked_limits, line_number, "UART"),
        )
        _append_message(messages, message, checked_limits)
    return NormalizedMessageCollection("uart-lines", tuple(messages), str(name))


def parse_can(
    data: bytes,
    name: str = "<can.log>",
    limits: Limits | None = None,
) -> NormalizedMessageCollection:
    """Parse an explicit CAN text representation.

    Each non-empty ASCII line is exactly
    ``timestamp<TAB>direction<TAB>source<TAB>can_id#payload_hex``.  The raw
    message bytes are the CAN data bytes; the numeric identifier is retained
    in ``metadata.can_id``.  Identifiers are bounded to the 29-bit CAN range
    and payloads to 64 bytes (classic CAN and CAN-FD data sizes).  The parser
    does not infer direction, CAN mode, or boundaries.
    """

    checked_limits = limits or Limits()
    payload = _bounded_input(data, checked_limits)
    messages: list[RawMessage] = []
    for line_number, line in _nonempty_lines(payload):
        if len(messages) >= checked_limits.max_packets:
            raise InputLimitError(f"message count exceeds limit {checked_limits.max_packets}")
        try:
            text = line.decode("ascii")
        except UnicodeDecodeError as exc:
            raise FormatError(f"CAN message at line {line_number} is not ASCII") from exc
        fields = text.split("\t")
        if len(fields) != 4:
            raise FormatError(
                f"CAN message at line {line_number} must have four tab-separated fields"
            )
        timestamp, direction, source, frame = fields
        _validate_line_token(direction, "direction", line_number, MAX_DIRECTION_CHARS)
        _validate_line_token(source, "source", line_number, MAX_SOURCE_CHARS)
        if frame.count("#") != 1:
            raise FormatError(f"CAN message at line {line_number} has an invalid frame")
        identifier_text, data_text = frame.split("#")
        identifier = _parse_can_id(identifier_text, line_number)
        if len(data_text) % 2 or any(char not in "0123456789abcdefABCDEF" for char in data_text):
            raise FormatError(f"CAN message at line {line_number} has invalid payload hex")
        if len(data_text) // 2 > MAX_CAN_DATA_BYTES:
            raise InputLimitError(
                f"CAN message at line {line_number} exceeds {MAX_CAN_DATA_BYTES} data bytes"
            )
        try:
            raw = bytes.fromhex(data_text)
        except ValueError as exc:
            raise FormatError(f"CAN message at line {line_number} has invalid payload hex") from exc
        if len(raw) > checked_limits.max_packet_bytes:
            raise InputLimitError(
                f"CAN message at line {line_number} exceeds packet limit "
                f"{checked_limits.max_packet_bytes}"
            )
        message = _message_from_parts(
            len(messages),
            _parse_timestamp_token(timestamp, line_number, "CAN"),
            direction,
            source,
            raw,
            metadata=(("can_id", identifier),),
        )
        _append_message(messages, message, checked_limits)
    return NormalizedMessageCollection("can-lines", tuple(messages), str(name))


def dumps_jsonl(
    collection: NormalizedMessageCollection,
    *,
    limits: Limits | None = None,
) -> str:
    """Serialize a collection to deterministic canonical JSON-lines text."""

    if not isinstance(collection, NormalizedMessageCollection):
        raise TypeError("collection must be a NormalizedMessageCollection")
    checked_limits = limits or Limits()
    if len(collection.messages) > checked_limits.max_packets:
        raise InputLimitError(f"message count exceeds limit {checked_limits.max_packets}")
    lines: list[str] = []
    output_bytes = 0
    for message in collection.messages:
        if len(message.raw) > checked_limits.max_packet_bytes:
            raise InputLimitError(
                f"message {message.index} exceeds packet limit {checked_limits.max_packet_bytes}"
            )
        line = (
            json.dumps(
                message.as_record(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        )
        output_bytes += len(line.encode("utf-8"))
        if output_bytes > checked_limits.max_response_bytes:
            raise InputLimitError(
                f"JSONL output exceeds response limit {checked_limits.max_response_bytes}"
            )
        lines.append(line)
    return "".join(lines)


# Descriptive aliases keep the public surface easy to discover without making
# the generic JSONL parser part of the older Packet importer dispatch table.
import_jsonl = parse_jsonl
parse_normalized_jsonl = parse_jsonl
serialize_jsonl = dumps_jsonl


def _bounded_input(data: bytes, limits: Limits) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("capture input must be bytes")
    if len(data) > limits.max_input_bytes:
        raise InputLimitError(f"input is {len(data)} bytes; limit is {limits.max_input_bytes}")
    return bytes(data)


def _nonempty_lines(data: bytes) -> Iterable[tuple[int, bytes]]:
    for line_number, line in enumerate(data.splitlines(), 1):
        if line.strip():
            yield line_number, line


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JSON constant {value} is not allowed")


def _message_from_record(
    record: dict[str, Any],
    index: int,
    limits: Limits,
    line_number: int,
) -> RawMessage:
    allowed = {
        "boundary",
        "direction",
        "index",
        "metadata",
        "raw",
        "raw_encoding",
        "source",
        "timestamp",
    }
    unknown = sorted(set(record) - allowed)
    if unknown:
        raise FormatError(f"JSONL message at line {line_number} has unsupported fields")
    supplied_index = record.get("index")
    if supplied_index is not None and (
        isinstance(supplied_index, bool)
        or not isinstance(supplied_index, int)
        or supplied_index != index
    ):
        raise FormatError(f"JSONL message at line {line_number} has a non-sequential index")
    if "timestamp" not in record:
        raise FormatError(f"JSONL message at line {line_number} is missing timestamp")
    if "direction" not in record or not isinstance(record["direction"], str):
        raise FormatError(f"JSONL message at line {line_number} has an invalid direction")
    if "source" not in record or not isinstance(record["source"], str):
        raise FormatError(f"JSONL message at line {line_number} has an invalid source")
    if "raw" not in record or not isinstance(record["raw"], str):
        raise FormatError(f"JSONL message at line {line_number} has invalid raw data")
    boundary = record.get("boundary", BOUNDARY_KIND)
    if boundary != BOUNDARY_KIND:
        raise FormatError(f"JSONL message at line {line_number} has an unknown boundary kind")
    encoding = record.get("raw_encoding", "base64")
    if encoding != "base64":
        raise FormatError(f"JSONL message at line {line_number} must use base64 raw data")
    metadata = _normalize_metadata(record.get("metadata", {}), line_number=line_number)
    try:
        timestamp = _validate_timestamp(
            record["timestamp"], f"JSONL timestamp at line {line_number}"
        )
    except ValueError as exc:
        raise FormatError(str(exc)) from exc
    return _message_from_parts(
        index,
        timestamp,
        record["direction"],
        record["source"],
        _decode_base64(record["raw"], limits, line_number, "JSONL"),
        metadata=metadata,
    )


def _message_from_parts(
    index: int,
    timestamp: int | float,
    direction: str,
    source: str,
    raw: bytes,
    *,
    metadata: tuple[tuple[str, JsonScalar], ...] = (),
) -> RawMessage:
    try:
        _validate_text(direction, "direction", MAX_DIRECTION_CHARS)
        _validate_text(source, "source", MAX_SOURCE_CHARS)
    except ValueError as exc:
        raise FormatError(str(exc)) from exc
    return RawMessage(index, timestamp, direction, raw, source, BOUNDARY_KIND, metadata)


def _append_message(messages: list[RawMessage], message: RawMessage, limits: Limits) -> None:
    if len(messages) >= limits.max_packets:
        raise InputLimitError(f"message count exceeds limit {limits.max_packets}")
    if len(message.raw) > limits.max_packet_bytes:
        raise InputLimitError(
            f"message {message.index} exceeds packet limit {limits.max_packet_bytes}"
        )
    messages.append(message)


def _decode_base64(encoded: str, limits: Limits, line_number: int, label: str) -> bytes:
    if len(encoded) > 4 * ((limits.max_packet_bytes + 2) // 3):
        raise InputLimitError(
            f"{label} message at line {line_number} exceeds packet limit "
            f"{limits.max_packet_bytes}"
        )
    try:
        encoded_bytes = encoded.encode("ascii")
        raw = base64.b64decode(encoded_bytes, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise FormatError(f"{label} message at line {line_number} has invalid base64") from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise FormatError(f"{label} message at line {line_number} has non-canonical base64")
    if len(raw) > limits.max_packet_bytes:
        raise InputLimitError(
            f"{label} message at line {line_number} exceeds packet limit "
            f"{limits.max_packet_bytes}"
        )
    return raw


def _parse_timestamp_token(token: str, line_number: int, label: str) -> int | float:
    if not token or any(char.isspace() for char in token):
        raise FormatError(f"{label} message at line {line_number} has an invalid timestamp")
    try:
        value = json.loads(token, parse_constant=_reject_json_constant)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise FormatError(f"{label} message at line {line_number} has an invalid timestamp") from exc
    try:
        return _validate_timestamp(value, f"{label} timestamp at line {line_number}")
    except ValueError as exc:
        raise FormatError(str(exc)) from exc


def _parse_can_id(token: str, line_number: int) -> int:
    if not token or any(char.isspace() for char in token):
        raise FormatError(f"CAN message at line {line_number} has an invalid identifier")
    value_token = token[2:] if token.lower().startswith("0x") else token
    if not value_token or any(char not in "0123456789abcdefABCDEF" for char in value_token):
        raise FormatError(f"CAN message at line {line_number} has an invalid identifier")
    try:
        value = int(value_token, 16)
    except ValueError as exc:
        raise FormatError(f"CAN message at line {line_number} has an invalid identifier") from exc
    if value > 0x1FFFFFFF:
        raise FormatError(f"CAN message at line {line_number} has an out-of-range identifier")
    return value


def _validate_timestamp(value: Any, label: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a finite JSON number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{label} must be a finite JSON number")
    return value


def _validate_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{label} must be a non-empty string of at most {maximum} characters")
    return value


def _validate_line_token(value: str, label: str, line_number: int, maximum: int) -> None:
    if not value or any(char.isspace() for char in value):
        raise FormatError(f"{label} at line {line_number} is invalid")
    try:
        _validate_text(value, label, maximum)
    except ValueError as exc:
        raise FormatError(str(exc)) from exc


def _normalize_metadata(
    value: Any,
    *,
    line_number: int | None = None,
) -> tuple[tuple[str, JsonScalar], ...]:
    if value is None:
        value = {}
    if isinstance(value, dict):
        items = list(value.items())
    elif isinstance(value, tuple):
        items = list(value)
    else:
        items = []
    if not isinstance(value, (dict, tuple)) or len(items) > MAX_METADATA_ITEMS:
        raise FormatError(_metadata_error(line_number))
    normalized: list[tuple[str, JsonScalar]] = []
    keys: set[str] = set()
    for pair in items:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise FormatError(_metadata_error(line_number))
        key, item = pair
        if not isinstance(key, str) or not key or len(key) > MAX_METADATA_KEY_CHARS:
            raise FormatError(_metadata_error(line_number))
        if key in keys:
            raise FormatError(_metadata_error(line_number))
        keys.add(key)
        if isinstance(item, str):
            if len(item) > MAX_METADATA_STRING_CHARS:
                raise FormatError(_metadata_error(line_number))
        elif isinstance(item, bool) or item is None:
            pass
        elif isinstance(item, int):
            pass
        elif isinstance(item, float) and math.isfinite(item):
            pass
        else:
            raise FormatError(_metadata_error(line_number))
        normalized.append((key, item))
    normalized.sort(key=lambda pair: pair[0])
    return tuple(normalized)


def _metadata_error(line_number: int | None) -> str:
    suffix = f" at line {line_number}" if line_number is not None else ""
    return f"metadata{suffix} must contain at most {MAX_METADATA_ITEMS} scalar values"
