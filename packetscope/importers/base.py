from __future__ import annotations

from pathlib import PurePath

from packetscope.errors import FormatError, InputLimitError
from packetscope.models import ImportResult, Limits

from .bin_importer import parse_bin
from .capture_importer import import_message_capture
from .hex_importer import parse_hex
from .pcap_importer import parse_pcap
from .pcapng_importer import parse_pcapng


def detect_format(name: str, data: bytes) -> str:
    suffix = PurePath(name).suffix.lower()
    if suffix in {".pcap", ".cap"} or data[:4] in {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    }:
        return "pcap"
    if suffix in {".pcapng", ".ng"} or data[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix in {".uart", ".uartlog"}:
        return "uart"
    if suffix in {".can", ".candump"}:
        return "can"
    if suffix in {".hex", ".txt"}:
        return "hex"
    return "bin"


def import_bytes(
    name: str,
    data: bytes,
    format_name: str = "auto",
    limits: Limits | None = None,
) -> ImportResult:
    limits = limits or Limits()
    if not isinstance(format_name, str):
        raise FormatError("capture format must be a string")
    if len(data) > limits.max_input_bytes:
        raise InputLimitError(
            f"input is {len(data)} bytes; limit is {limits.max_input_bytes}"
        )
    requested = format_name.strip().lower()
    selected = detect_format(name, data) if requested == "auto" else requested
    parsers = {
        "bin": parse_bin,
        "hex": parse_hex,
        "pcap": parse_pcap,
        "pcapng": parse_pcapng,
    }
    if selected in parsers:
        result = parsers[selected](data, name, limits)
    else:
        try:
            result = import_message_capture(name, data, selected, limits)
        except ValueError as exc:
            raise FormatError(str(exc)) from exc
    if len(result.packets) > limits.max_packets:
        raise InputLimitError(f"packet count exceeds limit {limits.max_packets}")
    return result
