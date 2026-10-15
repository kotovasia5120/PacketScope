from __future__ import annotations

import struct
from dataclasses import asdict
from typing import Iterable

from packetscope.errors import InputLimitError
from packetscope.models import Limits, Packet
from packetscope.protocols import decode_packet


def analyze_packets(
    packets: Iterable[Packet],
    annotations: list[dict] | None = None,
    limits: Limits | None = None,
) -> dict:
    limits = limits or Limits()
    packet_list: list[Packet] = []
    for packet in packets:
        if len(packet_list) >= limits.max_packets:
            raise InputLimitError(f"packet count exceeds limit {limits.max_packets}")
        if len(packet.payload) > limits.max_packet_bytes:
            raise InputLimitError(f"packet exceeds limit {limits.max_packet_bytes}")
        packet_list.append(packet)
    lengths = [len(packet.payload) for packet in packet_list]
    observation_limit = max(1, limits.max_response_bytes // 128)
    observations = {
        "packet_count": len(packet_list),
        "lengths": lengths[:observation_limit],
        "min_length": min(lengths) if lengths else 0,
        "max_length": max(lengths) if lengths else 0,
    }
    if len(lengths) > observation_limit:
        observations["lengths_truncated"] = True
    comparison = _compare(packet_list, limits.max_response_bytes)
    hypotheses = _hypotheses(packet_list, comparison, limits.max_hypotheses)
    packet_budget = max(0, limits.max_response_bytes // 3)
    packet_json: list[dict] = []
    packet_bytes = 0
    for packet in packet_list:
        item = _packet_json(packet, max(0, packet_budget - packet_bytes))
        estimated = len(str(item).encode("utf-8"))
        if packet_json and packet_bytes + estimated > packet_budget:
            break
        packet_json.append(item)
        packet_bytes += estimated
    return {
        "schema_version": 1,
        "tool": {"name": "PacketScope", "version": "0.1.0"},
        "source": {"format": "normalized", "packet_count": len(packet_list)},
        "packets": packet_json,
        "packets_truncated": len(packet_json) != len(packet_list),
        "observations": observations | {"comparison": comparison},
        "hypotheses": hypotheses,
        "annotations": _clean_annotations(annotations or []),
        "warnings": [],
    }


def _packet_json(packet: Packet, payload_budget: int | None = None) -> dict:
    item = asdict(packet)
    if payload_budget is None:
        payload_budget = len(packet.payload)
    payload = packet.payload[: max(0, payload_budget // 2)]
    item["payload"] = payload.hex()
    item["payload_truncated"] = len(payload) != len(packet.payload)
    item["protocol"] = decode_packet(packet)
    return item


def _compare(packets: list[Packet], response_budget: int) -> dict:
    if len(packets) < 2:
        return {"aligned_length": len(packets[0].payload) if packets else 0, "regions": []}
    aligned_length = min(len(packet.payload) for packet in packets)
    max_regions = max(1, response_budget // 512)
    regions: list[dict] = []
    current_kind: str | None = None
    start = 0
    for offset in range(aligned_length):
        values = {packet.payload[offset] for packet in packets}
        kind = "constant" if len(values) == 1 else "variable"
        if kind != current_kind:
            if current_kind is not None:
                regions.append(_region(current_kind, start, offset, packets))
                if len(regions) >= max_regions:
                    return {
                        "aligned_length": aligned_length,
                        "regions": regions,
                        "regions_truncated": True,
                    }
            current_kind = kind
            start = offset
    if current_kind is not None:
        regions.append(_region(current_kind, start, aligned_length, packets))
        if len(regions) >= max_regions:
            return {
                "aligned_length": aligned_length,
                "regions": regions,
                "regions_truncated": True,
            }
    if any(len(packet.payload) != aligned_length for packet in packets):
        regions.append(
            {
                "kind": "length_difference",
                "start": aligned_length,
                "end": max(len(packet.payload) for packet in packets),
                "evidence": {"packet_lengths": [len(packet.payload) for packet in packets[:128]], "packets_truncated": len(packets) > 128},
            }
        )
        if len(regions) >= max_regions:
            return {
                "aligned_length": aligned_length,
                "regions": regions,
                "regions_truncated": True,
            }
    truncated = len(regions) > max_regions
    return {"aligned_length": aligned_length, "regions": regions[:max_regions], "regions_truncated": truncated}


def _region(kind: str, start: int, end: int, packets: list[Packet]) -> dict:
    evidence_packets = packets[:32]
    return {
        "kind": kind,
        "start": start,
        "end": end,
        "width": end - start,
        "evidence": {
            "packet_indices": [packet.index for packet in evidence_packets],
            "values": [packet.payload[start:end][:128].hex() for packet in evidence_packets],
            "packets_truncated": len(evidence_packets) != len(packets),
        },
    }


def _hypotheses(packets: list[Packet], comparison: dict, max_count: int) -> list[dict]:
    if len(packets) < 3 or max_count <= 0:
        return []
    findings: list[dict] = []

    def add(finding: dict) -> bool:
        if len(findings) >= max_count:
            return False
        findings.append(finding)
        return True
    aligned = comparison["aligned_length"]
    # A repeated prefix is evidence of a shared header/magic candidate only.
    prefix = 0
    for offset in range(aligned):
        if len({packet.payload[offset] for packet in packets}) != 1:
            break
        prefix += 1
    if prefix >= 2:
        width = min(prefix, 8)
        if not add(
            _finding(
                "magic_bytes",
                0,
                width,
                0.63,
                f"all {len(packets)} packets share the prefix {packets[0].payload[:width].hex()}",
                "A repeated prefix may be framing, a version, or an ordinary constant.",
            )
        ):
            return findings
    # Single-byte monotonic values are common counters, but can also be data.
    for offset in range(aligned):
        values = [packet.payload[offset] for packet in packets]
        if len(set(values)) >= 2 and all(
            (right - left) % 256 == 1 for left, right in zip(values, values[1:])
        ):
            if not add(
                _finding(
                    "counter",
                    offset,
                    1,
                    0.71,
                    f"byte values advance by one across packet order: {values}",
                    "Packet order is used as evidence; retransmission or sorting can change this interpretation.",
                )
            ):
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
                    if not add(
                        _finding(
                            "length_field",
                            offset,
                            width,
                            0.82,
                            f"{endian_name}-endian values {values} match packet lengths",
                            "The detector cannot determine whether the field includes its own header or represents another size.",
                        )
                    ):
                        return findings
    # A simple additive byte at the end is useful evidence for a checksum-like field.
    for packet in packets:
        if len(packet.payload) < 2:
            break
    else:
        matches = sum(sum(packet.payload[:-1]) % 256 == packet.payload[-1] for packet in packets)
        if matches == len(packets):
            add(
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
