"""Deterministic Phase 7 corpus generator.

The settings below are frozen evaluation inputs.  The analyzer never imports
this module at runtime; the evaluation script generates bytes first, analyzes
them, and only then supplies the expected field descriptions to the evaluator.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from packetscope.analysis.crc import STANDARD_CRC, compute_crc


@dataclass(frozen=True)
class CaseSettings:
    name: str
    seed: int
    magic: bytes
    counter_width: int
    counter_endian: str
    counter_start: int
    counter_step: int
    optional_flags: bool
    type_values: tuple[int, ...]
    length_width: int
    length_endian: str
    length_convention: str
    crc_algorithm: str | None
    crc_byte_order: str
    crc_at_end: bool
    corrupted_indices: tuple[int, ...] = ()
    missing_indices: tuple[int, ...] = ()
    reorder: bool = False
    unrelated_bytes: bool = True


# Development and validation are tuneable only before a release.  Holdout
# settings are frozen and must not be used to choose detector rules.
DEVELOPMENT = (
    CaseSettings("dev-wide-be", 1701, b"\xA5\x5A", 2, "big", 250, 3, True, (1, 2, 3), 2, "big", "total", "CRC-16/CCITT-FALSE", "big", True),
    CaseSettings("dev-short-le", 1702, b"\x7E", 1, "little", 7, 2, False, (0x10, 0x20), 1, "little", "after", None, "big", True),
)
VALIDATION = (
    CaseSettings("validation-counter-le", 2701, b"\xCA\xFE\x01", 4, "little", 0xFFFFFFFC, 3, True, (4, 7, 9), 2, "little", "payload", "CRC-8", "big", True, reorder=True),
    CaseSettings("validation-noisy", 2702, b"\x42\x99", 2, "little", 0x1200, 5, True, (1, 3), 2, "little", "after", None, "big", True, corrupted_indices=(2,), unrelated_bytes=True),
)
HOLDOUT = (
    CaseSettings("holdout-variable-width", 3701, b"\xD3\x19\x77", 2, "little", 0xFE, 7, True, (0x41, 0x52, 0x61), 2, "little", "total", "CRC-8", "big", True, missing_indices=(1,), reorder=True),
    CaseSettings("holdout-byte-length", 3702, b"\x91", 1, "big", 11, 1, False, (2, 5, 8), 1, "big", "payload", None, "big", True, corrupted_indices=(4,), unrelated_bytes=True),
)


def generate(settings: CaseSettings) -> tuple[list[bytes], list[dict]]:
    rng = random.Random(settings.seed)
    packets: list[bytes] = []
    counter_values: list[int] = []
    modulus = 1 << (8 * settings.counter_width)
    crc_width = 0
    if settings.crc_algorithm:
        crc_width = next(item.width // 8 for item in STANDARD_CRC if item.name == settings.crc_algorithm)
    for index in range(8):
        counter = (settings.counter_start + index * settings.counter_step) % modulus
        counter_values.append(counter)
        message_type = settings.type_values[index % len(settings.type_values)]
        body = bytes(rng.randrange(0, 256) for _ in range(2 + (index * 3) % 7))
        if settings.unrelated_bytes:
            body += bytes((rng.randrange(0, 256),))
        value = settings.magic + bytes((message_type,))
        value += counter.to_bytes(settings.counter_width, settings.counter_endian)
        if settings.optional_flags:
            value += bytes((1 << (index % 3),))
        length_offset = len(value)
        length_size = settings.length_width
        value += b"\x00" * length_size + body
        if settings.length_convention == "total":
            length_value = len(value) + crc_width
        elif settings.length_convention == "payload":
            length_value = len(body)
        else:
            length_value = len(value) - length_offset
        if length_value >= (1 << (8 * length_size)):
            raise AssertionError("frozen generator settings exceed length width")
        encoded_length = length_value.to_bytes(length_size, settings.length_endian)
        value = value[:length_offset] + encoded_length + value[length_offset + length_size:]
        packets.append(value)
    if settings.crc_algorithm:
        params = next(item for item in STANDARD_CRC if item.name == settings.crc_algorithm)
        with_crc: list[bytes] = []
        for index, packet in enumerate(packets):
            checksum = compute_crc(packet, params)
            width = params.width // 8
            encoded = checksum.to_bytes(width, settings.crc_byte_order)
            with_crc.append(packet + encoded if settings.crc_at_end else encoded + packet)
        packets = with_crc
    for index in settings.corrupted_indices:
        if 0 <= index < len(packets) and packets[index]:
            altered = bytearray(packets[index])
            altered[min(len(altered) - 1, len(settings.magic))] ^= 0x01
            packets[index] = bytes(altered)
    packets = [packet for index, packet in enumerate(packets) if index not in settings.missing_indices]
    if settings.reorder:
        packets = list(reversed(packets[::2])) + packets[1::2]
    counter_offset = len(settings.magic) + 1
    length_offset = counter_offset + settings.counter_width + (1 if settings.optional_flags else 0)
    truth = [
        {"field_type": "sequence_counter", "absolute_offset": counter_offset, "width_bits": settings.counter_width * 8, "endian": settings.counter_endian},
        {"field_type": "length_field", "absolute_offset": length_offset, "width_bits": settings.length_width * 8, "endian": settings.length_endian},
    ]
    if settings.crc_algorithm:
        truth.append({"field_type": "crc" if settings.crc_algorithm.startswith("CRC") else "checksum", "width_bits": next(item.width for item in STANDARD_CRC if item.name == settings.crc_algorithm), "endian": settings.crc_byte_order, "algorithm": settings.crc_algorithm, "location_mode": "from_end" if settings.crc_at_end else "absolute"})
    return packets, truth
