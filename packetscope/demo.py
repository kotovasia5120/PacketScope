"""Deterministic synthetic captures for the offline competition demonstration.

The truth set is deliberately returned as a separate value.  The web demo
endpoint keeps it server-side until the user explicitly requests evaluation.
"""
from __future__ import annotations

from dataclasses import asdict
import struct
from typing import Any

from packetscope.analysis.crc import CRCParams, STANDARD_CRC, compute_crc
from packetscope.models import Limits, Packet

_PROFILES = {"crc16-be", "crc32-le"}


def demo_corpus(profile: str = "crc16-be", *, count: int = 8, limits: Limits | None = None) -> dict[str, Any]:
    """Return packets and independent ground truth, with deterministic bounds."""
    if profile not in _PROFILES:
        raise ValueError(f"unknown demo profile: {profile}")
    limit = limits or Limits()
    count = max(1, min(int(count), 256, limit.max_packets))
    params = STANDARD_CRC[1] if profile == "crc16-be" else STANDARD_CRC[3]
    width = params.width // 8
    counter_width = 2 if profile == "crc16-be" else 4
    start = 0 if profile == "crc16-be" else 0xFFFFFFFE
    packets: list[Packet] = []
    for index in range(count):
        counter = (start + index) & ((1 << (width * 8)) - 1)
        # The body length changes for every third message so end-relative CRC
        # locations cannot accidentally be inferred from packet zero.
        body = b"demo-" + bytes((index % 251, (index * 17) % 251)) + bytes((index + 1)) * (index % 3)
        endian = "big" if profile == "crc16-be" else "little"
        message_type = (0x10 + index % 3).to_bytes(1, "big")
        header_without_length = b"PSCP" + message_type + counter.to_bytes(counter_width, endian)
        total_length = len(header_without_length) + 2 + len(body) + width
        raw = header_without_length + total_length.to_bytes(2, "big") + body
        crc = compute_crc(raw, params).to_bytes(width, "big" if profile == "crc16-be" else "little")
        packets.append(Packet(index, raw + crc, source_name=f"demo:{profile}"))
    endian = "big" if profile == "crc16-be" else "little"
    crc_locations = [len(packet.payload) - width for packet in packets]
    truth = [
        {"field_type": "magic_bytes", "absolute_offset": 0, "width_bits": 32},
        {"field_type": "message_type", "absolute_offset": 4, "width_bits": 8},
        {"field_type": "sequence_counter", "absolute_offset": 5, "width_bits": params.width, "endian": endian},
        {"field_type": "length_field", "absolute_offset": 5 + counter_width, "width_bits": 16, "endian": "big"},
        {"field_type": "crc", "absolute_offset": crc_locations[0], "width_bits": params.width,
         "endian": endian, "algorithm": params.name, "location_mode": "from_end",
         "locations": crc_locations},
    ]
    return {"profile": profile, "packets": packets, "ground_truth": truth,
            "metadata": {"count": count, "crc": asdict(params), "counter_start": start,
                         "counter_width": counter_width, "counter_overflow": profile == "crc32-le"}}


def demo_capture(profile: str = "crc16-be", *, format_name: str = "pcap", count: int = 8,
                 limits: Limits | None = None) -> bytes:
    """Serialize the deterministic corpus as classic PCAP or PCAPNG bytes."""
    demo = demo_corpus(profile, count=count, limits=limits)
    packets = demo["packets"]
    if format_name == "pcap":
        output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147))
        for index, packet in enumerate(packets):
            timestamp = 1_700_000_000 + index
            output.extend(struct.pack("<IIII", timestamp, index * 1000, len(packet.payload), len(packet.payload)))
            output.extend(packet.payload)
        return bytes(output)
    if format_name == "pcapng":
        output = bytearray()
        output.extend(struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28))
        output.extend(struct.pack("<IIHHII", 0x00000001, 20, 147, 0, 65535, 20))
        for index, packet in enumerate(packets):
            payload = packet.payload
            padding = b"\0" * ((4 - len(payload) % 4) % 4)
            block_length = 32 + len(payload) + len(padding)
            output.extend(struct.pack("<IIIIIII", 0x00000006, block_length, 0, 0, 1_000_000 + index, len(payload), len(payload)))
            output.extend(payload + padding)
            output.extend(struct.pack("<I", block_length))
        return bytes(output)
    raise ValueError("format_name must be 'pcap' or 'pcapng'")
