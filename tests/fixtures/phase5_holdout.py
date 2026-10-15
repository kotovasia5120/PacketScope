"""Independent holdout messages; the analyzer never imports this module."""
from __future__ import annotations

from packetscope.analysis.crc import STANDARD_CRC, compute_crc


def corpus() -> list[bytes]:
    params = STANDARD_CRC[0]
    packets: list[bytes] = []
    for index in range(6):
        body = bytes((0x30 + index,)) + bytes((index + 3,)) * (1 + index % 3)
        header = bytes((0x7E, 0x41 if index % 2 == 0 else 0x52))
        header += (0x1200 + index).to_bytes(2, "little")
        total = len(header) + 2 + len(body) + 1
        message = header + total.to_bytes(2, "little") + body
        packets.append(message + compute_crc(message, params).to_bytes(1, "big"))
    return packets


TRUTH = [
    {"field_type": "sequence_counter", "absolute_offset": 2, "width_bits": 16, "endian": "little"},
    {"field_type": "length_field", "absolute_offset": 4, "width_bits": 16, "endian": "little"},
    {"field_type": "crc", "width_bits": 8, "endian": "big", "algorithm": "CRC-8", "location_mode": "from_end"},
]
