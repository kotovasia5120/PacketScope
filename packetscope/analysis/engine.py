"""Bounded, explainable analysis of packet and application-payload bytes."""
from __future__ import annotations

import difflib
import math
import struct
from dataclasses import dataclass, asdict
from typing import Any, Callable, Iterable

from packetscope.errors import InputLimitError
from packetscope.models import FieldHypothesis, Limits, Packet
from packetscope.protocols import decode_packet
from .crc import SearchBudget, discover_checksums


@dataclass(frozen=True)
class _View:
    packet: Packet
    data: bytes
    absolute_base: int
    payload_relative_base: int | None
    scope: str
    limitation: str | None = None


def analyze_packets(
    packets: Iterable[Packet],
    annotations: list[dict] | None = None,
    limits: Limits | None = None,
    *,
    analyze_raw: bool = False,
    cancel: Callable[[], bool] | None = None,
    progress: Callable[[int], None] | None = None,
) -> dict:
    limits = limits or Limits()
    packet_list: list[Packet] = []
    for packet in packets:
        if cancel and cancel():
            return {"schema_version": 2, "status": "CANCELLED", "packets": [], "hypotheses": []}
        if len(packet_list) >= limits.max_packets:
            raise InputLimitError(f"packet count exceeds limit {limits.max_packets}")
        if len(packet.payload) > limits.max_packet_bytes:
            raise InputLimitError(f"packet exceeds limit {limits.max_packet_bytes}")
        packet_list.append(packet)
        if progress:
            progress(len(packet_list))

    lengths = [len(packet.payload) for packet in packet_list]
    observation_limit = max(1, limits.max_response_bytes // 128)
    views, contexts = _analysis_views(packet_list, analyze_raw)
    data_lengths = [len(view.data) for view in views]
    observations: dict[str, Any] = {
        "packet_count": len(packet_list),
        "lengths": lengths[:observation_limit],
        "min_length": min(lengths) if lengths else 0,
        "max_length": max(lengths) if lengths else 0,
        "analysis_scope": "raw_packet" if analyze_raw else "application_payload",
        "analyzable_packet_count": len(views),
        "analysis_lengths": data_lengths[:observation_limit],
    }
    if len(lengths) > observation_limit:
        observations["lengths_truncated"] = True

    comparison = _compare(views, limits.max_response_bytes)
    observations["comparison"] = comparison
    observations["byte_statistics"] = _byte_statistics(views, limits.max_response_bytes)
    observations["alignment"] = _alignment(views)

    analysis_status = "ok" if len(views) >= 3 else "INSUFFICIENT_EVIDENCE"
    hypotheses: list[dict] = []
    crc_status = "NOT_RUN"
    if analysis_status == "ok":
        hypotheses = _hypotheses(views, comparison, limits, cancel)
        crc_findings, crc_status = _crc_hypotheses(views, limits, cancel)
        for finding in crc_findings:
            if len(hypotheses) >= limits.max_hypotheses:
                break
            hypotheses.append(finding)
    if cancel and cancel():
        analysis_status = "CANCELLED"
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

    warnings = [context["limitation"] for context in contexts if context.get("limitation")]
    if crc_status not in {"NOT_RUN", "COMPLETE"}:
        warnings.append(f"checksum discovery stopped with status {crc_status}")
    return {
        "schema_version": 2,
        "tool": {"name": "PacketScope", "version": "0.2.0"},
        "source": {"format": "normalized", "packet_count": len(packet_list)},
        "packets": packet_json,
        "packets_truncated": len(packet_json) != len(packet_list),
        "analysis": {
            "status": analysis_status,
            "scope": "raw_packet" if analyze_raw else "application_payload",
            "contexts": contexts[:128],
            "crc_status": crc_status,
        },
        "observations": observations,
        "hypotheses": hypotheses[: limits.max_hypotheses],
        "annotations": _clean_annotations(annotations or []),
        "warnings": sorted(set(warnings)),
    }


def _analysis_views(packets: list[Packet], analyze_raw: bool) -> tuple[list[_View], list[dict]]:
    views: list[_View] = []
    contexts: list[dict] = []
    for packet in packets:
        decoded = decode_packet(packet)
        context: dict[str, Any] = {"packet_id": packet.index, "link_type": packet.link_type}
        if analyze_raw:
            context.update({"scope": "raw_packet", "payload_offset": 0})
            view = _View(packet, packet.payload, 0, 0, "raw_packet", "raw packet analysis was explicitly requested")
            views.append(view)
        elif packet.link_type is None:
            context.update({"scope": "application_payload", "payload_offset": 0})
            views.append(_View(packet, packet.payload, 0, 0, "application_payload", "no link-layer metadata; treating imported bytes as application payload"))
        else:
            transport = decoded.get("transport") or decoded.get("network", {}).get("transport")
            if isinstance(transport, dict) and transport.get("status") == "ok":
                absolute = int(transport.get("payload_offset", 0))
                data = packet.payload[absolute : absolute + int(transport.get("payload_length", 0))]
                context.update({"scope": "application_payload", "payload_offset": absolute, "payload_length": len(data), "protocol": transport.get("protocol")})
                limitation = "transport payload is truncated" if transport.get("truncated") else None
                views.append(_View(packet, data, absolute, 0, "application_payload", limitation))
            else:
                status = decoded.get("status", "unsupported")
                context.update({"scope": "application_payload", "payload_offset": None, "decoder_status": status})
                context["limitation"] = f"application payload unavailable: {status}; use raw packet analysis to inspect bytes"
        if view_limitation := (views[-1].limitation if views and views[-1].packet is packet else None):
            context["limitation"] = view_limitation
        contexts.append(context)
    return views, contexts


def _packet_json(packet: Packet, payload_budget: int | None = None) -> dict:
    item = asdict(packet)
    if payload_budget is None:
        payload_budget = len(packet.payload)
    payload = packet.payload[: max(0, payload_budget // 2)]
    item["payload"] = payload.hex()
    item["payload_truncated"] = len(payload) != len(packet.payload)
    item["raw_payload"] = payload.hex()
    decoded = decode_packet(packet)
    transport = decoded.get("transport") or decoded.get("network", {}).get("transport")
    if isinstance(transport, dict) and transport.get("status") == "ok":
        start = int(transport.get("payload_offset", 0))
        length = int(transport.get("payload_length", 0))
        application = packet.payload[start:start + length]
        application = application[: max(0, payload_budget // 2)]
        item["application_payload"] = application.hex()
        item["application_payload_truncated"] = len(application) != length
        item["application_payload_offset"] = start
    else:
        item["application_payload"] = payload.hex()
        item["application_payload_truncated"] = item["payload_truncated"]
        item["application_payload_offset"] = 0
    item["protocol"] = decoded
    return item


def _compare(views: list[_View], response_budget: int) -> dict:
    if len(views) < 2:
        return {"aligned_length": len(views[0].data) if views else 0, "regions": [], "scope": "application_payload"}
    aligned_length = min(len(view.data) for view in views)
    max_regions = max(1, response_budget // 512)
    regions: list[dict] = []
    current_kind: str | None = None
    start = 0
    for offset in range(aligned_length):
        values = {view.data[offset] for view in views}
        kind = "constant" if len(values) == 1 else "variable"
        if kind != current_kind:
            if current_kind is not None:
                regions.append(_region(current_kind, start, offset, views))
                if len(regions) >= max_regions:
                    return {"aligned_length": aligned_length, "regions": regions, "regions_truncated": True, "scope": views[0].scope}
            current_kind, start = kind, offset
    if current_kind is not None:
        regions.append(_region(current_kind, start, aligned_length, views))
    if any(len(view.data) != aligned_length for view in views):
        regions.append({"kind": "length_difference", "start": aligned_length, "end": max(len(view.data) for view in views), "width": max(len(view.data) for view in views) - aligned_length, "evidence": {"packet_lengths": [len(view.data) for view in views[:128]], "packets_truncated": len(views) > 128}})
    return {"aligned_length": aligned_length, "regions": regions[:max_regions], "regions_truncated": len(regions) > max_regions, "scope": views[0].scope}


def _region(kind: str, start: int, end: int, views: list[_View]) -> dict:
    evidence_views = views[:32]
    return {"kind": kind, "start": start, "end": end, "width": end - start, "evidence": {"packet_indices": [view.packet.index for view in evidence_views], "values": [view.data[start:end][:128].hex() for view in evidence_views], "packets_truncated": len(evidence_views) != len(views)}}


def _byte_statistics(views: list[_View], response_budget: int) -> list[dict]:
    if len(views) < 2:
        return []
    limit = min(min(len(view.data) for view in views), max(1, response_budget // 256), 256)
    result: list[dict] = []
    for offset in range(limit):
        values = [view.data[offset] for view in views]
        counts: dict[str, int] = {}
        for value in values:
            key = f"0x{value:02x}"
            counts[key] = counts.get(key, 0) + 1
        entropy = 0.0
        for count in counts.values():
            probability = count / len(values)
            entropy -= probability * math.log2(probability)
        result.append({"offset": offset, "sample_count": len(values), "distinct_values": len(counts), "entropy_bits": round(entropy, 6), "frequencies": dict(sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))[:8])})
    return result


def _alignment(views: list[_View]) -> list[dict]:
    if len(views) < 2 or len(views) > 64:
        return []
    reference = views[0]
    if all(len(view.data) == len(reference.data) for view in views):
        return []
    result: list[dict] = []
    for view in views[1:]:
        matcher = difflib.SequenceMatcher(None, reference.data[:4096], view.data[:4096], autojunk=False)
        result.append({"reference_packet_id": reference.packet.index, "packet_id": view.packet.index, "opcodes": [list(opcode) for opcode in matcher.get_opcodes()[:64]], "truncated": len(matcher.get_opcodes()) > 64})
    return result


def _hypotheses(views: list[_View], comparison: dict, limits: Limits, cancel: Callable[[], bool] | None) -> list[dict]:
    if len(views) < 3:
        return []
    findings: list[dict] = []
    def add(finding: dict) -> bool:
        if len(findings) >= limits.max_hypotheses:
            return False
        if cancel and cancel():
            return False
        findings.append(finding)
        return True

    aligned = comparison["aligned_length"]
    prefix = 0
    for offset in range(aligned):
        if len({view.data[offset] for view in views}) != 1:
            break
        prefix += 1
    if prefix >= 2:
        # Report the smallest conventional magic candidate as well as the
        # full repeated prefix; a message type or high counter byte can share
        # the prefix and must remain an explicit alternative.
        magic_width = 2
        add(_make_field("magic_bytes", views, 0, magic_width, "big", views[0].data[:magic_width].hex(), 0.63, f"all {len(views)} application samples share prefix {views[0].data[:magic_width].hex()}", [], ["framing", "version", "ordinary constant", "longer constant prefix"], "A repeated prefix may be framing, a version, or an ordinary constant."))
        width = min(prefix, 8)
        if width != magic_width:
            add(_make_field("magic_bytes", views, 0, width, "big", views[0].data[:width].hex(), 0.58, f"all {len(views)} application samples share longer prefix {views[0].data[:width].hex()}", [], ["framing plus message type", "version", "ordinary constant"], "The detector cannot separate adjacent constant fields without more messages."))

    suffix = 0
    for offset in range(1, aligned + 1):
        if len({view.data[-offset] for view in views}) != 1:
            break
        suffix += 1
    if suffix >= 2:
        width = min(suffix, 8)
        start = aligned - width
        add(_make_field("common_suffix", views, start, width, "big", views[0].data[start:aligned].hex(), 0.55, f"all {len(views)} application samples share suffix {views[0].data[start:aligned].hex()}", [], ["trailer", "padding", "ordinary constant"], "A common suffix may be a trailer or padding; its role is not proven."))

    max_offset = min(aligned, 128)
    for width in (1, 2, 4, 8):
        if width > aligned:
            continue
        for offset in range(max_offset - width + 1):
            if cancel and cancel():
                return findings
            for endian in ("big", "little"):
                values = [int.from_bytes(view.data[offset:offset + width], endian) for view in views]
                modulus = 1 << (width * 8)
                if len(set(values)) > 1 and all((right - left) % modulus == 1 for left, right in zip(values, values[1:])):
                    add(_make_field("sequence_counter", views, offset, width, endian, values, 0.71, f"{endian}-endian values advance by one in packet order: {values[:32]}", [], ["timestamp", "index", "monotonic application value"], "Packet order is evidence; retransmission, sorting, or direction changes can alter this interpretation."))
                    break
            if len(findings) >= limits.max_hypotheses:
                return findings

    for width in (1, 2, 4, 8):
        if width > aligned:
            continue
        for offset in range(max_offset - width + 1):
            for endian in ("big", "little"):
                values = [int.from_bytes(view.data[offset:offset + width], endian) for view in views]
                lengths = [len(view.data) for view in views]
                for label, expected in (("total message length", lengths), ("payload length", [length - offset - width for length in lengths]), ("bytes after field", [length - offset for length in lengths])):
                    if values == expected:
                        add(_make_field("length_field", views, offset, width, endian, values, 0.82, f"{endian}-endian values match {label}: {values[:32]}", [], ["record length", "payload length"], "The detector cannot determine whether the field includes its own header or represents another size."))
                        break
                if findings and findings[-1].get("field_type") == "length_field" and findings[-1].get("absolute_offset") == views[0].absolute_base + offset:
                    break
            if len(findings) >= limits.max_hypotheses:
                return findings

    for offset in range(max_offset):
        values = [view.data[offset] for view in views]
        distinct = len(set(values))
        if 1 < distinct <= min(8, len(views)):
            counts = {value: values.count(value) for value in sorted(set(values))}
            if max(counts.values()) >= 2:
                add(_make_field("message_type", views, offset, 1, "big", values, 0.52, f"byte has {distinct} recurring values with frequencies {counts}", [], ["enum", "flags", "small counter"], "A low-cardinality byte is not necessarily a message type."))
                break

    for offset in range(max_offset):
        values = [view.data[offset] for view in views]
        mask = 0
        for value in values:
            mask |= value
        varying = 0
        for bit in range(8):
            if len({(value >> bit) & 1 for value in values}) > 1:
                varying |= 1 << bit
        if varying and varying.bit_count() <= 4 and mask == varying:
            add(_make_field("bit_flags", views, offset, 1, "big", {"mask": f"0x{varying:02x}", "values": values}, 0.48, f"only mask 0x{varying:02x} varies at this byte", [], ["message type", "packed enum", "status flags"], "A small varying bit mask can also be an encoded value."))
            break
    return findings


def _make_field(field_type: str, views: list[_View], relative: int, width: int, endian: str, value: Any, confidence: float, rationale: str, contradictions: list[dict], alternatives: list[str], caveat: str) -> dict:
    primary = views[0]
    evidence = [{"packet_ids": [view.packet.index for view in views[:64]], "values": [view.data[relative:relative + width].hex() for view in views[:64]], "rationale": rationale}]
    field = FieldHypothesis(field_type, primary.packet.index, primary.absolute_base + relative, primary.payload_relative_base + relative if primary.payload_relative_base is not None else None, width * 8, endian, value, confidence, evidence, contradictions, len(views), "hypothesis", alternatives)
    result = field.as_dict()
    result.update({"id": f"{field_type}:{primary.packet.index}:{field.absolute_offset}:{width}:{endian}", "kind": "counter" if field_type == "sequence_counter" else field_type, "offset": field.absolute_offset, "width": width, "caveats": [caveat], "locations": [{"packet_id": view.packet.index, "absolute_offset": view.absolute_base + relative, "payload_relative_offset": view.payload_relative_base + relative if view.payload_relative_base is not None else None} for view in views[:128]]})
    return result


def _crc_hypotheses(views: list[_View], limits: Limits, cancel: Callable[[], bool] | None) -> tuple[list[dict], str]:
    if cancel and cancel():
        return [], "CANCELLED"
    budget = SearchBudget(time_limit_seconds=limits.max_analysis_seconds, max_candidates=limits.max_crc_candidates, max_samples=min(limits.max_packets, 256), max_packet_bytes=limits.max_packet_bytes, max_ranges=limits.max_crc_ranges)
    result = discover_checksums((view.data for view in views), budget=budget)
    hypotheses: list[dict] = []
    seen_ids: set[str] = set()
    for candidate in result.hypotheses:
        evidence = candidate.evidence
        view = views[0]
        values = [view.data[evidence.location:evidence.location + evidence.width].hex()]
        confidence = min(0.96, 0.5 + 0.08 * math.log2(max(2, evidence.samples)) - 0.015 * math.log2(max(2, result.candidates_tested)))
        field = FieldHypothesis("crc" if candidate.algorithm.startswith("CRC") else "checksum", view.packet.index, view.absolute_base + evidence.location, view.payload_relative_base + evidence.location if view.payload_relative_base is not None else None, evidence.width * 8, evidence.byte_order, values, confidence, [{"packet_ids": [item.packet.index for item in views[:64]], "rationale": f"{candidate.algorithm} matched {evidence.matches}/{evidence.samples} independent samples", "covered_range": list(evidence.covered_range), "covered_ranges": [list(item) for item in evidence.covered_ranges], "location_mode": evidence.location_mode, "mismatches": list(evidence.mismatches)}], [], evidence.samples, "hypothesis", ["another checksum range", "coincidental match"])
        item = field.as_dict()
        byte_order = "big" if evidence.width == 1 else evidence.byte_order
        locations = list(evidence.locations) or [evidence.location]
        identifier = f"{candidate.algorithm}:{evidence.location_mode}:{evidence.width}:{byte_order}:{','.join(map(str, locations))}"
        if identifier in seen_ids:
            continue
        seen_ids.add(identifier)
        item.update({"id": identifier, "kind": field.field_type, "offset": field.absolute_offset, "width": evidence.width, "algorithm": candidate.algorithm, "parameters": asdict(candidate.params) if candidate.params else None, "checksum": {"location": evidence.location, "locations": locations, "byte_order": byte_order, "covered_range": list(evidence.covered_range), "covered_ranges": [list(item) for item in evidence.covered_ranges], "location_mode": evidence.location_mode, "matches": evidence.matches, "samples": evidence.samples, "mismatches": list(evidence.mismatches)}, "locations": [{"packet_id": view.packet.index, "absolute_offset": view.absolute_base + location, "payload_relative_offset": view.payload_relative_base + location if view.payload_relative_base is not None else None} for view, location in zip(views, locations)], "caveats": ["A matching checksum remains a hypothesis until independently verified."]})
        hypotheses.append(item)
    return hypotheses, result.status


def _clean_annotations(annotations: list[dict]) -> list[dict]:
    cleaned = []
    for item in annotations[:1000]:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label", "")).strip()[:120]
        if not label:
            continue
        try:
            start = max(0, int(item.get("start", item.get("absolute_offset", 0))))
            end = max(start, int(item.get("end", start + 1)))
        except (TypeError, ValueError):
            continue
        cleaned.append({"label": label, "start": start, "end": end, "source": "manual", "field_type": str(item.get("field_type", "custom"))[:40], "endian": str(item.get("endian", "unknown"))[:12], "status": str(item.get("status", "hypothesis"))[:20]})
    return cleaned
