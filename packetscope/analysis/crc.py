"""Bounded, explainable checksum and CRC discovery."""
from __future__ import annotations

from dataclasses import dataclass
from functools import reduce
import time
from typing import Iterable


@dataclass(frozen=True)
class CRCParams:
    width: int
    poly: int
    init: int
    refin: bool
    refout: bool
    xorout: int
    check: int | None = None
    residue: int | None = None
    name: str = "custom"


@dataclass(frozen=True)
class SearchBudget:
    time_limit_seconds: float = 1.0
    max_candidates: int = 10000
    max_samples: int = 1000
    max_packet_bytes: int = 4096
    max_ranges: int = 512
    min_samples: int = 3


@dataclass(frozen=True)
class ChecksumEvidence:
    location: int
    width: int
    byte_order: str
    covered_range: tuple[int, int]
    mismatches: tuple[dict, ...]
    matches: int
    samples: int
    location_mode: str = "absolute"
    covered_ranges: tuple[tuple[int, int], ...] = ()
    locations: tuple[int, ...] = ()


@dataclass(frozen=True)
class ChecksumHypothesis:
    algorithm: str
    params: CRCParams | None
    evidence: ChecksumEvidence
    status: str = "hypothesis"


@dataclass(frozen=True)
class DiscoveryResult:
    hypotheses: tuple[ChecksumHypothesis, ...]
    status: str
    candidates_tested: int


STANDARD_CRC = (
    CRCParams(8, 0x07, 0, False, False, 0, 0xF4, 0, "CRC-8"),
    CRCParams(16, 0x1021, 0xFFFF, False, False, 0, 0x29B1, 0, "CRC-16/CCITT-FALSE"),
    CRCParams(16, 0x8005, 0xFFFF, True, True, 0, 0x4B37, 0, "CRC-16/MODBUS"),
    CRCParams(32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xCBF43926, 0xDEBB20E3, "CRC-32/ISO-HDLC"),
)


def _reverse(value: int, width: int) -> int:
    return int(f"{value:0{width}b}"[::-1], 2)


def compute_crc(data: bytes, params: CRCParams) -> int:
    """Compute a Rocksoft CRC with the complete parameter set."""
    if params.width not in (8, 16, 32):
        raise ValueError("only 8, 16, and 32-bit CRCs are supported")
    mask = (1 << params.width) - 1
    crc = params.init & mask
    reflected_poly = _reverse(params.poly, params.width)
    for byte in data:
        if params.refin:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ reflected_poly if crc & 1 else crc >> 1
        else:
            crc ^= byte << (params.width - 8)
            for _ in range(8):
                crc = ((crc << 1) ^ params.poly) & mask if crc & (1 << (params.width - 1)) else (crc << 1) & mask
    if params.refout ^ params.refin:
        crc = _reverse(crc, params.width)
    return (crc ^ params.xorout) & mask


def checksum_value(data: bytes, algorithm: str) -> int:
    normalized = algorithm.upper().replace("_", "-")
    if normalized == "XOR-8":
        return reduce(int.__xor__, data, 0)
    if normalized in {"ADDITIVE-8", "SUM-8"}:
        return sum(data) & 0xFF
    if normalized in {"ADDITIVE-16", "SUM-16"}:
        return sum(data) & 0xFFFF
    raise ValueError(f"unknown checksum algorithm: {algorithm}")


def standard_vectors() -> dict[str, int]:
    return {params.name: compute_crc(b"123456789", params) for params in STANDARD_CRC}


def discover_checksums(samples: Iterable[bytes], *, budget: SearchBudget = SearchBudget()) -> DiscoveryResult:
    """Search a small, explicit family of checksum layouts.

    Both a fixed offset and a checksum immediately before the end of each
    message are considered.  The latter is what permits variable-length
    messages without trying arbitrary byte permutations or CRC parameters.
    """
    if budget.min_samples <= 0 or budget.max_candidates <= 0 or budget.max_ranges <= 0:
        return DiscoveryResult((), "SEARCH_LIMIT_REACHED", 0)
    started = time.monotonic()
    packets: list[bytes] = []
    for raw in samples:
        if len(packets) >= budget.max_samples:
            break
        value = bytes(raw)
        if len(value) <= budget.max_packet_bytes:
            packets.append(value)
    if len(packets) < budget.min_samples:
        return DiscoveryResult((), "INSUFFICIENT_EVIDENCE", 0)

    algorithms = [(params.name, params, params.width // 8) for params in STANDARD_CRC]
    algorithms.extend((name, None, width) for name, width in (("XOR-8", 1), ("ADDITIVE-8", 1), ("ADDITIVE-16", 2)))
    hypotheses: list[ChecksumHypothesis] = []
    candidates_tested = 0
    ranges_tested = 0
    for name, params, width in algorithms:
        max_length = max(len(packet) for packet in packets)
        fixed_positions = range(max(0, max_length - width + 1))
        candidates: list[tuple[str, int]] = [("absolute", position) for position in fixed_positions]
        candidates.extend(("from_end", distance) for distance in range(width, min(max_length, width + 256) + 1))
        seen: set[tuple[str, int]] = set()
        for mode, position in candidates:
            if (mode, position) in seen:
                continue
            seen.add((mode, position))
            ranges_tested += 1
            if ranges_tested > budget.max_ranges:
                return DiscoveryResult(tuple(hypotheses), "SEARCH_LIMIT_REACHED", candidates_tested)
            candidates_tested += 1
            if candidates_tested > budget.max_candidates:
                return DiscoveryResult(tuple(hypotheses), "SEARCH_LIMIT_REACHED", candidates_tested - 1)
            if time.monotonic() - started >= budget.time_limit_seconds:
                return DiscoveryResult(tuple(hypotheses), "TIME_LIMIT_EXCEEDED", candidates_tested)
            valid = True
            representative_location = 0
            locations: list[int] = []
            for sample_index, packet in enumerate(packets):
                location = position if mode == "absolute" else len(packet) - position
                if location < 0 or location + width > len(packet):
                    valid = False
                    break
                if sample_index == 0:
                    representative_location = location
                locations.append(location)
            if not valid:
                continue
            for order in ("big", "little"):
                mismatches: list[dict] = []
                matches = 0
                for sample_index, (packet, location) in enumerate(zip(packets, locations)):
                    expected = int.from_bytes(packet[location:location + width], order)
                    covered = packet[:location] + packet[location + width:]
                    actual = compute_crc(covered, params) if params else checksum_value(covered, name)
                    if actual == expected:
                        matches += 1
                    elif len(mismatches) < 8:
                        mismatches.append({"sample": sample_index, "expected": expected, "actual": actual, "location": location})
                if matches == len(packets):
                    covered_ranges = ((0, representative_location), (representative_location + width, len(packets[0])))
                    hypotheses.append(ChecksumHypothesis(name, params, ChecksumEvidence(representative_location, width, order, (0, len(packets[0])), tuple(mismatches), matches, len(packets), mode, covered_ranges, tuple(locations))))
    return DiscoveryResult(tuple(hypotheses), "COMPLETE", candidates_tested)


# Friendly aliases for callers that prefer shorter names.
discover = discover_checksums
crc = compute_crc
