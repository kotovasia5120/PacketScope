from __future__ import annotations

import re

from packetscope.errors import FormatError, InputLimitError
from packetscope.models import ImportResult, Limits, Packet


_TOKEN = re.compile(r"^(?:0x)?([0-9a-fA-F]{2})$")


def parse_hex(data: bytes, name: str, limits: Limits) -> ImportResult:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FormatError("HEX input must contain ASCII text") from exc
    values: list[int] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if ":" in line:
            prefix, remainder = line.split(":", 1)
            if prefix.strip().replace("0x", "", 1).isdigit():
                line = remainder.strip()
        for token in line.replace(",", " ").split():
            match = _TOKEN.fullmatch(token)
            if not match:
                raise FormatError(f"invalid HEX token on line {line_number}: {token!r}")
            values.append(int(match.group(1), 16))
            if len(values) > limits.max_packet_bytes:
                raise InputLimitError(
                    f"HEX packet exceeds limit {limits.max_packet_bytes}"
                )
    payload = bytes(values)
    return ImportResult("hex", [Packet(0, payload, source_name=name)])
