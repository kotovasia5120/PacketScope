from __future__ import annotations

import struct
from dataclasses import asdict
from typing import Iterable

from packetscope.models import Limits, Packet


def analyze_packets(
    packets: Iterable[Packet],
    annotations: list[dict] | None = None,
    limits: Limits | None = None,
) -> dict:
    limits = limits or Limits()
    packet_list = list(packets)
    lengths = [len(packet.payload) for packet in packet_list]
    observations = {
        "packet_count": len(packet_list),
        "lengths": lengths,
        "min_length": min(lengths) if lengths else 0,
        "max_length": max(lengths) if lengths else 0,
    }
    comparison = _compare(packet_list)
    hypotheses = _hypotheses(packet_list, comparison, limits.max_hypotheses)
    return {
        "schema_version": 1,
        "tool": {"name": "PacketScope", "version": "0.1.0"},
        "source": {"format": "normalized", "packet_count": len(packet_list)},
        "packets": [_packet_json(packet) for packet in packet_list],
        "observations": observations | {"comparison": comparison},
        "hypotheses": hypotheses,
        "annotations": _clean_annotations(annotations or []),
        "warnings": [],
    }


def _packet_json(packet: Packet) -> dict:
    item = asdict(packet)
    item["payload"] = packet.payload.hex()
    return item


def _compare(packets: list[Packet]) -> dict:
    if len(packets) < 2:
        return {"aligned_length": len(packets[0].payload) if packets else 0, "regions": []}
    aligned_length = min(len(packet.payload) for packet in packets)
    regions: list[dict] = []
    current_kind: str | None = None
    start = 0
    for offset in range(aligned_length):
        values = {packet.payload[offset] for packet in packets}
        kind = "constant" if len(values) == 1 else "variable"
        if kind != current_kind:
            if current_kind is not None:
                regions.append(_region(current_kind, start, offset, packets))
            current_kind = kind
            start = offset
    if current_kind is not None:
        regions.append(_region(current_kind, start, aligned_length, packets))
    if any(len(packet.payload) != aligned_length for packet in packets):
        regions.append(
            {
                "kind": "length_difference",
                "start": aligned_length,
                "end": max(len(packet.payload) for packet in packets),
                "evidence": {"packet_lengths": [len(packet.payload) for packet in packets]},
            }
        )
    return {"aligned_length": aligned_length, "regions": regions}


def _region(kind: str, start: int, end: int, packets: list[Packet]) -> dict:
    return {
        "kind": kind,
        "start": start,
        "end": end,
        "width": end - start,
        "evidence": {
            "packet_indices": [packet.index for packet in packets],
            "values": [packet.payload[start:end].hex() for packet in packets],
        },
    }


def _hypotheses(packets: list[Packet], comparison: dict, max_count: int) -> list[dict]:
    if len(packets) < 2:
        return []
    findings: list[dict] = []
    aligned = comparison["aligned_length"]
    # A repeated prefix is evidence of a shared header/magic candidate only.
    prefix = 0
    for offset in range(aligned):
        if len({packet.payload[offset] for packet in packets}) != 1:
            break
        prefix += 1
    if prefix >= 2:
        width = min(prefix, 8)
        findings.append(
            _finding(
                "magic_bytes",
                0,
                width,
                0.63,
                f"all {len(packets)} packets share the prefix {packets[0].payload[:width].hex()}",
                "A repeated prefix may be framing, a version, or an ordinary constant.",
            )
        )
    # Single-byte monotonic values are common counters, but can also be data.
    for offset in range(aligned):
        values = [packet.payload[offset] for packet in packets]
        if len(set(values)) >= 2 and all(
            (right - left) % 256 == 1 for left, right in zip(values, values[1:])
        ):
            findings.append(
                _finding(
                    "counter",
                    offset,
                    1,
                    0.71,
                    f"byte values advance by one across packet order: {values}",
                    "Packet order is used as evidence; retransmission or sorting can change this interpretation.",
                )
            )
            if len(findings) >= max_count:
                return findings
    # Length candidates: test both endian interpretations for small widths.
    for offset in range(min(aligned, 4)):
        for width, fmt in ((2, "H"), (4, "I")):
            if offset + width > aligned:
                continue
            for endian_name, endian in (("little", "<"), ("big", ">")):
                values = [
                    struct.unpack_from(endian + fmt, packet.payload, offset)[0]
                    for packet in packets
                ]
                expected = [len(packet.payload) for packet in packets]
                if values == expected or values == [size - offset - width for size in expected]:
                    findings.append(
                        _finding(
                            "length_field",
                            offset,
                            width,
                            0.82,
                            f"{endian_name}-endian values {values} match packet lengths",
                            "The detector cannot determine whether the field includes its own header or represents another size.",
                        )
                    )
    # A simple additive byte at the end is useful evidence for a checksum-like field.
    for packet in packets:
        if len(packet.payload) < 2:
            break
    else:
        matches = sum(sum(packet.payload[:-1]) % 256 == packet.payload[-1] for packet in packets)
        if matches == len(packets):
            findings.append(
                _finding(
                    "checksum",
                    aligned - 1,
                    1,
                    0.58,
                    "last byte equals the modulo-256 sum of preceding bytes for every packet",
                    "This is only an additive checksum candidate; CRCs and covered ranges are not proven.",
                )
            )
    return findings[:max_count]


def _finding(kind: str, offset: int, width: int, confidence: float, evidence: str, caveat: str) -> dict:
    return {
        "id": f"{kind}:{offset}:{width}",
        "kind": kind,
        "status": "hypothesis",
        "offset": offset,
        "width": width,
        "confidence": confidence,
        "evidence": [evidence],
        "caveats": [caveat],
    }


def _clean_annotations(annotations: list[dict]) -> list[dict]:
    cleaned = []
    for item in annotations[:1000]:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label", "")).strip()[:120]
        if not label:
            continue
        try:
            start = max(0, int(item.get("start", 0)))
            end = max(start, int(item.get("end", start + 1)))
        except (TypeError, ValueError):
            continue
        cleaned.append({"label": label, "start": start, "end": end, "source": "manual"})
    return cleaned
