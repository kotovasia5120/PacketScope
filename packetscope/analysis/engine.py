"""Bounded, explainable analysis of packet and application-payload bytes."""
from __future__ import annotations

import difflib
import math
import struct
from dataclasses import dataclass, asdict
from typing import Any, Callable, Iterable

from packetscope.errors import InputLimitError
from packetscope.flows import group_flows, select_flow_packets
from packetscope.models import FieldHypothesis, Limits, Packet
from packetscope.profiles import AnalysisProfile, limits_for_profile, packet_dataset_sha256, profile_report, resolve_profile
from packetscope.protocols import coordinate_bytes, decode_packet
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
    selected_direction: str | None = None,
    flow_id: str | None = None,
    profile: AnalysisProfile | dict | None = None,
    input_sha256: str | None = None,
) -> dict:
    limits = limits or Limits()
    applied_profile = resolve_profile(profile)
    # A caller-supplied Limits object is authoritative for the legacy API.
    # CLI/profile callers pass the profile explicitly and receive its budgets.
    if profile is not None:
        limits = limits_for_profile(limits, applied_profile)
    if selected_direction is None:
        selected_direction = applied_profile.selected_direction
    if flow_id is None:
        flow_id = applied_profile.selected_flow
    if applied_profile.analysis_scope == "raw_packet":
        analyze_raw = True
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

    flows = group_flows(packet_list, limits=limits)
    if flow_id is not None and not any(flow.flow_id == flow_id for flow in flows):
        raise ValueError("unknown flow_id")
    selected_packets = select_flow_packets(
        packet_list,
        selected_direction=selected_direction,
        flow_id=flow_id,
        limits=limits,
    )
    analyzing_selection = selected_direction not in (None, "", "both", "all") or flow_id is not None
    analysis_packet_list = selected_packets if analyzing_selection else packet_list
    lengths = [len(packet.payload) for packet in analysis_packet_list]
    observation_limit = max(1, limits.max_response_bytes // 128)
    views, contexts = _analysis_views(analysis_packet_list, analyze_raw)
    data_lengths = [len(view.data) for view in views]
    observations: dict[str, Any] = {
        "packet_count": len(packet_list),
        "analysis_packet_count": len(analysis_packet_list),
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
    observations["alignment"] = _alignment(views, applied_profile.alignment_mode)

    analysis_status = "ok" if len(views) >= 3 else "INSUFFICIENT_EVIDENCE"
    hypotheses: list[dict] = []
    crc_status = "NOT_RUN"
    crc_candidates = 0
    if analysis_status == "ok":
        hypotheses = _hypotheses(views, comparison, limits, cancel, set(applied_profile.enabled_detectors), applied_profile)
        crc_findings, crc_status, crc_candidates = _crc_hypotheses(views, limits, cancel, applied_profile)
        for finding in crc_findings:
            if len(hypotheses) >= limits.max_hypotheses:
                break
            hypotheses.append(finding)
        hypotheses = _rank_and_group(hypotheses)
    if cancel and cancel():
        analysis_status = "CANCELLED"
    packet_budget = max(0, limits.max_response_bytes // 3)
    packet_json: list[dict] = []
    packet_bytes = 0
    output_packets = analysis_packet_list if analyzing_selection else packet_list
    for packet in output_packets:
        item = _packet_json(packet, max(0, packet_budget - packet_bytes))
        estimated = len(str(item).encode("utf-8"))
        if packet_json and packet_bytes + estimated > packet_budget:
            break
        packet_json.append(item)
        packet_bytes += estimated

    warnings = [context["limitation"] for context in contexts if context.get("limitation")]
    if crc_status not in {"NOT_RUN", "COMPLETE"}:
        warnings.append(f"checksum discovery stopped with status {crc_status}")
    flow_json: list[dict] = []
    flow_bytes = 0
    flow_budget = max(0, limits.max_response_bytes // 3)
    for flow in flows:
        item = flow.as_dict()
        estimated = len(str(item).encode("utf-8"))
        if flow_json and flow_bytes + estimated > flow_budget:
            break
        flow_json.append(item)
        flow_bytes += estimated
    constraints = []
    if len(packet_json) != len(output_packets):
        constraints.append("response_size_limit")
    if len(flow_json) != len(flows):
        constraints.append("flow_response_limit")
    if crc_status not in {"NOT_RUN", "COMPLETE"}:
        constraints.append(f"crc:{crc_status}")
    reproducibility = profile_report(
        applied_profile,
        input_sha256=input_sha256 or packet_dataset_sha256(packet_list),
        completeness="complete" if analysis_status == "ok" and not constraints else "bounded_or_incomplete",
        candidates_evaluated=crc_candidates,
        tested_algorithms=list(applied_profile.crc_algorithms),
        constraints=constraints,
    )
    return {
        "schema_version": 2,
        "tool": {"name": "PacketScope", "version": "0.2.0"},
        "source": {"format": "normalized", "packet_count": len(packet_list)},
        "packets": packet_json,
        "packets_truncated": len(packet_json) != len(output_packets),
        "flows": flow_json,
        "flows_truncated": len(flow_json) != len(flows),
        "flow_selection": {
            "flow_id": flow_id,
            "direction": selected_direction or "both",
            "applied": analyzing_selection,
        },
        "analysis": {
            "status": analysis_status,
            "scope": "raw_packet" if analyze_raw else "application_payload",
            "coordinate_system": "raw_packet" if analyze_raw else "application_payload",
            "coordinate_metadata": {
                "unit": "bytes",
                "raw_packet": {"origin": "captured_packet_start"},
                "application_payload": {"origin": "decoded_transport_payload_start"},
            },
            "contexts": contexts[:128],
            "crc_status": crc_status,
            "crc_candidates_tested": crc_candidates,
        },
        "reproducibility": reproducibility,
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
            context.update({"scope": "raw_packet", "coordinate_system": "raw_packet", "payload_offset": 0})
            view = _View(packet, packet.payload, 0, 0, "raw_packet", "raw packet analysis was explicitly requested")
            views.append(view)
        elif packet.link_type is None:
            context.update({"scope": "application_payload", "coordinate_system": "application_payload", "payload_offset": 0})
            views.append(_View(packet, packet.payload, 0, 0, "application_payload", "no link-layer metadata; treating imported bytes as application payload"))
        else:
            transport = decoded.get("transport") or decoded.get("network", {}).get("transport")
            if isinstance(transport, dict) and transport.get("status") == "ok":
                absolute = int(transport.get("payload_offset", 0))
                data = packet.payload[absolute : absolute + int(transport.get("payload_length", 0))]
                context.update({"scope": "application_payload", "coordinate_system": "application_payload", "payload_offset": absolute, "payload_length": len(data), "protocol": transport.get("protocol")})
                limitation = "transport payload is truncated" if transport.get("truncated") else None
                views.append(_View(packet, data, absolute, 0, "application_payload", limitation))
            else:
                status = decoded.get("status", "unsupported")
                context.update({"scope": "application_payload", "coordinate_system": "application_payload", "payload_offset": None, "decoder_status": status})
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
    application, application_meta = coordinate_bytes(packet, "application_payload")
    application_length = len(application) if application is not None else 0
    if application is not None and application_meta["available"]:
        start = int(application_meta.get("absolute_offset") or 0)
        application = application[: max(0, payload_budget // 2)]
        item["application_payload"] = application.hex()
        item["application_payload_truncated"] = len(application) != application_length
        item["application_payload_offset"] = start
        item["application_payload_available"] = True
    else:
        item["application_payload"] = ""
        item["application_payload_truncated"] = False
        item["application_payload_offset"] = None
        item["application_payload_available"] = False
    item["coordinate_metadata"] = {
        "raw_packet": {"available": True, "length": len(payload), "truncated": item["payload_truncated"]},
        "application_payload": {
            "available": bool(application_meta.get("available")),
            "offset": application_meta.get("absolute_offset"),
            "length": application_length,
            "truncated": bool(application_meta.get("truncated")) or item["application_payload_truncated"],
        },
    }
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


def _alignment(views: list[_View], mode: str = "bounded") -> list[dict]:
    if mode == "offset":
        return []
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


def _hypotheses(views: list[_View], comparison: dict, limits: Limits, cancel: Callable[[], bool] | None,
                enabled_detectors: set[str] | None = None,
                profile: AnalysisProfile | None = None) -> list[dict]:
    if len(views) < 3:
        return []
    findings: list[dict] = []
    def add(finding: dict) -> bool:
        if len(findings) >= limits.max_hypotheses:
            return False
        if cancel and cancel():
            return False
        if enabled_detectors is not None:
            detector = str(finding.get("field_type", finding.get("kind", "")))
            if detector not in enabled_detectors:
                return True
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
    widths = profile.integer_widths if profile else (1, 2, 4, 8)
    endians = profile.endianness_options if profile else ("big", "little")
    sequence_offsets: set[int] = set()
    for offset in range(max_offset):
        if cancel and cancel():
            return findings
        candidates: list[tuple[int, str, list[int], int]] = []
        for width in widths:
            if offset + width > aligned:
                continue
            for endian in endians:
                values = [int.from_bytes(view.data[offset:offset + width], endian) for view in views]
                modulus = 1 << (width * 8)
                deltas = {(right - left) % modulus for left, right in zip(values, values[1:])}
                # This detector deliberately reports only a unit-step counter.
                # Non-unit progressions are not rejected as impossible; they
                # remain an explicit limitation until independent samples can
                # distinguish a counter from an encoded value.
                if len(set(values)) > 1 and deltas == {1}:
                    candidates.append((width, endian, values, 1))
        if candidates:
            # Prefer the widest consistent interpretation. A low byte of a
            # wider counter is a viable projection, but emitting every nested
            # projection makes unrelated body bytes look like counters.
            widest = max(item[0] for item in candidates)
            selected = [item for item in candidates if item[0] == widest]
            seen_values: set[tuple[int, ...]] = set()
            for width, endian, values, step in selected:
                value_key = tuple(values)
                if value_key in seen_values:
                    continue
                seen_values.add(value_key)
                sequence_offsets.add(offset)
                add(_make_field("sequence_counter", views, offset, width, endian, values, 0.71, f"{endian}-endian values advance by one in packet order: {values[:32]}", [], ["timestamp", "index", "monotonic application value"], "Packet order is evidence; retransmission, sorting, direction changes, or a projected subfield can alter this interpretation."))
        if len(findings) >= limits.max_hypotheses:
            return findings

    seen_lengths: set[tuple[int, int, tuple[int, ...], str]] = set()
    for width in widths:
        if width > aligned:
            continue
        for offset in range(max_offset - width + 1):
            for endian in endians:
                values = [int.from_bytes(view.data[offset:offset + width], endian) for view in views]
                lengths = [len(view.data) for view in views]
                for label, expected in (("total message length", lengths), ("payload length", [length - offset - width for length in lengths]), ("bytes after field", [length - offset for length in lengths])):
                    if values == expected:
                        dedupe_key = (offset, width, tuple(values), label)
                        if dedupe_key in seen_lengths:
                            break
                        seen_lengths.add(dedupe_key)
                        add(_make_field("length_field", views, offset, width, endian, values, 0.82, f"{endian}-endian values match {label}: {values[:32]}", [], ["record length", "payload length"], "The detector cannot determine whether the field includes its own header or represents another size."))
                        break
            if len(findings) >= limits.max_hypotheses:
                return findings

    for offset in range(max_offset):
        values = [view.data[offset] for view in views]
        distinct = len(set(values))
        if 1 < distinct <= min(8, len(views)):
            counts = {value: values.count(value) for value in sorted(set(values))}
            if max(counts.values()) >= 2 and not _looks_like_bit_flags(values):
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
        if varying and varying.bit_count() <= 4 and mask == varying and offset not in sequence_offsets:
            add(_make_field("bit_flags", views, offset, 1, "big", {"mask": f"0x{varying:02x}", "values": values}, 0.48, f"only mask 0x{varying:02x} varies at this byte", [], ["message type", "packed enum", "status flags"], "A small varying bit mask can also be an encoded value."))
            break
    return findings


def _looks_like_bit_flags(values: list[int]) -> bool:
    mask = 0
    for value in values:
        mask |= value
    varying = 0
    for bit in range(8):
        if len({(value >> bit) & 1 for value in values}) > 1:
            varying |= 1 << bit
    return bool(varying) and varying.bit_count() <= 4 and mask == varying


def _what_would_help(field_type: str) -> list[str]:
    return {
        "length_field": [
            "A message longer than 255 bytes could distinguish uint8 from uint16.",
            "Messages with several lengths could distinguish total-message, payload-only, and bytes-after-field conventions.",
            "A direction-separated capture could show whether the same size rule holds independently.",
        ],
        "sequence_counter": [
            "More samples including a rollover, gap, duplicate, or retransmission could distinguish a counter from an accidental progression.",
            "Direction-separated captures could clarify whether the progression is scoped to one conversation.",
        ],
        "message_type": [
            "More message families with different payload structure could distinguish a type byte from flags or a small counter.",
            "Independent request/response samples could show whether values select message layouts.",
        ],
        "bit_flags": [
            "Samples that toggle bits independently, without monotonic progression, would better support a packed flag interpretation.",
            "Repeated states across message families could distinguish flags from an enum or counter.",
        ],
    }.get(field_type, ["Independent samples with varied payloads could test whether this interpretation remains stable."])


def _make_field(field_type: str, views: list[_View], relative: int, width: int, endian: str, value: Any, confidence: float, rationale: str, contradictions: list[dict], alternatives: list[str], caveat: str) -> dict:
    primary = views[0]
    evidence = [{"packet_ids": [view.packet.index for view in views[:64]], "values": [view.data[relative:relative + width].hex() for view in views[:64]], "rationale": rationale}]
    field = FieldHypothesis(field_type, primary.packet.index, primary.absolute_base + relative, primary.payload_relative_base + relative if primary.payload_relative_base is not None else None, width * 8, endian, value, confidence, evidence, contradictions, len(views), "hypothesis", alternatives, primary.scope)
    result = field.as_dict()
    result.update({"id": f"{field_type}:{primary.packet.index}:{field.absolute_offset}:{width}:{endian}", "kind": "counter" if field_type == "sequence_counter" else field_type, "offset": field.absolute_offset, "width": width, "caveats": [caveat], "what_would_help": _what_would_help(field_type), "evidence_quality": {"basis": "observed_packet_bytes", "independent_samples": len(views), "assumptions": ["packet order is meaningful"] if field_type == "sequence_counter" else []}, "locations": [{"packet_id": view.packet.index, "absolute_offset": view.absolute_base + relative, "payload_relative_offset": view.payload_relative_base + relative if view.payload_relative_base is not None else None} for view in views[:128]]})
    return result


def _crc_hypotheses(views: list[_View], limits: Limits, cancel: Callable[[], bool] | None,
                    profile: AnalysisProfile | None = None) -> tuple[list[dict], str, int]:
    if cancel and cancel():
        return [], "CANCELLED", 0
    budget = SearchBudget(time_limit_seconds=limits.max_analysis_seconds, max_candidates=limits.max_crc_candidates, max_samples=min(limits.max_packets, limits.max_samples), max_packet_bytes=limits.max_packet_bytes, max_ranges=limits.max_crc_ranges)
    result = discover_checksums((view.data for view in views), budget=budget,
                                allowed_algorithms=profile.crc_algorithms if profile else None)
    hypotheses: list[dict] = []
    seen_ids: set[str] = set()
    for candidate in result.hypotheses:
        evidence = candidate.evidence
        view = views[0]
        values = [view.data[evidence.location:evidence.location + evidence.width].hex()]
        confidence = min(0.96, 0.5 + 0.08 * math.log2(max(2, evidence.samples)) - 0.015 * math.log2(max(2, result.candidates_tested)))
        field = FieldHypothesis("crc" if candidate.algorithm.startswith("CRC") else "checksum", view.packet.index, view.absolute_base + evidence.location, view.payload_relative_base + evidence.location if view.payload_relative_base is not None else None, evidence.width * 8, evidence.byte_order, values, confidence, [{"packet_ids": [item.packet.index for item in views[:64]], "rationale": f"{candidate.algorithm} matched {evidence.matches}/{evidence.samples} independent samples", "covered_range": list(evidence.covered_range), "covered_ranges": [list(item) for item in evidence.covered_ranges], "location_mode": evidence.location_mode, "mismatches": list(evidence.mismatches)}], [], evidence.samples, "hypothesis", ["another checksum range", "coincidental match"], view.scope)
        item = field.as_dict()
        byte_order = "big" if evidence.width == 1 else evidence.byte_order
        locations = list(evidence.locations) or [evidence.location]
        identifier = f"{candidate.algorithm}:{evidence.location_mode}:{evidence.width}:{byte_order}:{','.join(map(str, locations))}"
        if identifier in seen_ids:
            continue
        seen_ids.add(identifier)
        item.update({"id": identifier, "kind": field.field_type, "offset": field.absolute_offset, "width": evidence.width, "algorithm": candidate.algorithm, "parameters": asdict(candidate.params) if candidate.params else None, "checksum": {"location": evidence.location, "locations": locations, "byte_order": byte_order, "covered_range": list(evidence.covered_range), "covered_ranges": [list(item) for item in evidence.covered_ranges], "location_mode": evidence.location_mode, "matches": evidence.matches, "samples": evidence.samples, "mismatches": list(evidence.mismatches)}, "locations": [{"packet_id": view.packet.index, "absolute_offset": view.absolute_base + location, "payload_relative_offset": view.payload_relative_base + location if view.payload_relative_base is not None else None} for view, location in zip(views, locations)], "caveats": ["A matching checksum remains a hypothesis until independently verified."]})
        hypotheses.append(item)
    return hypotheses, result.status, result.candidates_tested


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
        coordinate_system = str(item.get("coordinate_system", "application_payload"))
        if coordinate_system not in {"raw_packet", "application_payload"}:
            coordinate_system = "application_payload"
        cleaned.append({"label": label, "start": start, "end": end, "coordinate_system": coordinate_system, "source": "manual", "field_type": str(item.get("field_type", "custom"))[:40], "endian": str(item.get("endian", "unknown"))[:12], "status": str(item.get("status", "hypothesis"))[:20]})
    return cleaned


def _rank_and_group(hypotheses: list[dict]) -> list[dict]:
    """Rank hypotheses deterministically and retain overlapping explanations."""
    groups: dict[tuple, list[dict]] = {}
    for item in hypotheses:
        field_type = str(item.get("field_type", item.get("kind", "field")))
        offset = item.get("absolute_offset", item.get("offset"))
        width = item.get("width", int(item.get("width_bits", 8)) // 8)
        algorithm = item.get("algorithm")
        endian = item.get("endian")
        key = (field_type, offset, width, endian, algorithm)
        groups.setdefault(key, []).append(item)
    for group_index, items in enumerate(groups.values(), start=1):
        group_id = f"hypothesis-group-{group_index}"
        ids = sorted(str(item.get("id", "")) for item in items)
        for item in items:
            item["equivalence_group"] = group_id
            item["group_members"] = ids
            alternatives = list(item.get("alternative_interpretations", []))
            for other in items:
                if other is not item:
                    label = str(other.get("field_type", other.get("kind", "field")))
                    if label not in alternatives:
                        alternatives.append(label)
            item["alternative_interpretations"] = sorted(set(alternatives))

    # A shared byte range can support several compatible interpretations. Keep
    # every candidate, but make the ambiguity explicit instead of letting the
    # list order imply that one semantic meaning was proven.
    compatible_types = {"sequence_counter", "length_field", "message_type", "bit_flags"}
    overlap_items = [item for item in hypotheses if str(item.get("field_type")) in compatible_types]
    parents = list(range(len(overlap_items)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left, item in enumerate(overlap_items):
        start = int(item.get("absolute_offset", item.get("offset", 0)))
        width = int(item.get("width", int(item.get("width_bits", 8)) // 8))
        end = start + width
        for right in range(left):
            other = overlap_items[right]
            other_start = int(other.get("absolute_offset", other.get("offset", 0)))
            other_end = other_start + int(other.get("width", int(other.get("width_bits", 8)) // 8))
            if start < other_end and other_start < end:
                union(left, right)
    components: dict[int, list[dict]] = {}
    for index, item in enumerate(overlap_items):
        components.setdefault(find(index), []).append(item)
    overlap_groups = list(components.values())
    for index, items in enumerate(overlap_groups, start=1):
        if len(items) < 2:
            continue
        group_id = f"interpretation-group-{index}"
        member_ids = sorted(str(item.get("id", "")) for item in items)
        widest = max(int(item.get("width", int(item.get("width_bits", 8)) // 8)) for item in items)
        for item in items:
            item["interpretation_group"] = {
                "id": group_id,
                "member_ids": member_ids,
                "reason": "overlapping compatible field interpretations",
                "widths_bytes": sorted({int(other.get("width", int(other.get("width_bits", 8)) // 8)) for other in items}),
                "endianness": sorted({str(other.get("endian", "unknown")) for other in items}),
            }
            item["alternative_interpretations"] = sorted(set(item.get("alternative_interpretations", [])) | {
                str(other.get("field_type", other.get("kind", "field"))) for other in items if other is not item
            })
            item["evidence_quality"]["independently_verified"] = False
            item["evidence_quality"]["interpretation_group"] = group_id
            if int(item.get("width", 1)) < widest and item.get("field_type") in {"length_field", "sequence_counter"}:
                item["evidence_quality"]["alias_of_wider_candidate"] = True
                item.setdefault("caveats", []).append("A narrower overlapping interpretation remains viable, but a wider candidate explains more observed bytes.")

    # Scores are deterministic heuristic ordering aids, not probabilities. A
    # narrower projection is retained but ranked below a wider candidate only
    # when both candidates explain the same observed range.
    for item in hypotheses:
        support = max(0, int(item.get("sample_count", 0)))
        contradictions = len(item.get("contradictions", []))
        complexity = 1 if item.get("algorithm") or item.get("checksum") else 0
        score = float(item.get("confidence", 0.0)) + min(0.1, support / 1000)
        score -= contradictions * 0.05 + complexity * 0.005
        if item.get("evidence_quality", {}).get("alias_of_wider_candidate"):
            score -= 0.08
        if item.get("field_type") == "bit_flags" and any(other.get("field_type") == "sequence_counter" and other.get("absolute_offset", other.get("offset")) == item.get("absolute_offset", item.get("offset")) for other in hypotheses):
            score -= 0.06
        item["ranking"] = {
            "score": round(score, 6),
            "confidence_label": "heuristic",
            "supporting_samples": support,
            "contradictions": contradictions,
            "complexity_penalty": complexity * 0.005,
            "ranking_factors": ["sample support", "contradictions", "model complexity", "overlap/alias penalty"],
        }
    return sorted(hypotheses, key=lambda item: (
        -float(item.get("ranking", {}).get("score", item.get("confidence", 0.0))),
        -int(item.get("sample_count", 0)), str(item.get("id", "")),
    ))
