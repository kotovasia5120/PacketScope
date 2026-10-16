"""Bounded comparison of a baseline capture and one controlled-change capture.

The comparison deliberately reports association, not causation.  It pairs
messages by capture order, records when that assumption is weak, and keeps the
raw analysis engine independent from this experiment-oriented view.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Callable, Iterable

from packetscope.errors import InputLimitError
from packetscope.models import Limits, Packet
from packetscope.protocols import coordinate_bytes


MAX_EVIDENCE_PAIRS = 32


class ExperimentCancelled(Exception):
    """Internal cooperative cancellation signal for bounded comparisons."""


def compare_controlled_change(
    baseline: Iterable[Packet],
    changed: Iterable[Packet],
    *,
    limits: Limits | None = None,
    analyze_raw: bool = False,
    change_label: str = "controlled change",
    cancel: Callable[[], bool] | None = None,
    progress: Callable[[int], None] | None = None,
) -> dict:
    """Compare two captures while retaining uncertainty and bounded evidence."""

    limits = limits or Limits()
    _report_progress(progress, 0)
    baseline_packets = _bounded_packets(baseline, limits, cancel=cancel)
    _report_progress(progress, 18)
    changed_packets = _bounded_packets(changed, limits, cancel=cancel)
    _report_progress(progress, 35)
    coordinate_system = "raw_packet" if analyze_raw else "application_payload"
    baseline_views, baseline_unavailable = _views(baseline_packets, coordinate_system, cancel=cancel)
    changed_views, changed_unavailable = _views(changed_packets, coordinate_system, cancel=cancel)

    pair_count = min(len(baseline_views), len(changed_views))
    records: dict[int, dict] = {}
    total_positions = sum(
        min(len(left), len(right))
        for (_left_packet, left), (_right_packet, right)
        in zip(baseline_views[:pair_count], changed_views[:pair_count])
    )
    visited_positions = 0
    for pair_index in range(pair_count):
        _check_cancel(cancel)
        left_packet, left = baseline_views[pair_index]
        right_packet, right = changed_views[pair_index]
        width = min(len(left), len(right))
        for offset in range(width):
            if offset % 256 == 0:
                _check_cancel(cancel)
            record = records.setdefault(offset, {"changed": 0, "compared": 0, "evidence": []})
            record["compared"] += 1
            if left[offset] != right[offset]:
                record["changed"] += 1
                if len(record["evidence"]) < MAX_EVIDENCE_PAIRS:
                    record["evidence"].append({
                        "pair_index": pair_index,
                        "baseline_packet_id": left_packet.index,
                        "changed_packet_id": right_packet.index,
                        "baseline_byte": f"{left[offset]:02x}",
                        "changed_byte": f"{right[offset]:02x}",
                    })
            visited_positions += 1
        if total_positions:
            _report_progress(progress, 35 + int(60 * visited_positions / total_positions))

    _check_cancel(cancel)
    ranges = _changed_ranges(records, limits)
    hypotheses = [_range_hypothesis(item, change_label, coordinate_system) for item in ranges[: limits.max_hypotheses]]
    limitations: list[str] = [
        "Byte ranges are correlated with the capture-level change; correlation does not establish causation.",
        "Messages are paired by capture order, not by a confirmed application message identity.",
    ]
    if len(baseline_packets) != len(changed_packets):
        limitations.append("The captures contain different packet counts, so unpaired messages may hide or mimic effects.")
    if baseline_unavailable or changed_unavailable:
        limitations.append("Some application payloads were unavailable; those packets were excluded from byte pairing.")
    if not hypotheses:
        limitations.append("No consistently changing byte range was observed in the comparable payloads.")

    _report_progress(progress, 95)
    return {
        "schema_version": 1,
        "comparison_type": "controlled_change",
        "change_label": str(change_label)[:120] or "controlled change",
        "coordinate_system": coordinate_system,
        "coordinate_metadata": {
            "unit": "bytes",
            "raw_packet": {"origin": "captured_packet_start"},
            "application_payload": {"origin": "decoded_transport_payload_start"},
        },
        "baseline": _capture_summary(baseline_packets, baseline_unavailable),
        "changed": _capture_summary(changed_packets, changed_unavailable),
        "pairing": {
            "paired_messages": pair_count,
            "unpaired_baseline_messages": max(0, len(baseline_views) - pair_count),
            "unpaired_changed_messages": max(0, len(changed_views) - pair_count),
        },
        "message_distributions": {
            "baseline": _distribution(baseline_views),
            "changed": _distribution(changed_views),
        },
        "correlated_ranges": ranges,
        "hypotheses": hypotheses,
        "suggested_experiments": _suggestions(baseline_packets, changed_packets, bool(hypotheses)),
        "limitations": limitations,
    }


def _bounded_packets(
    packets: Iterable[Packet],
    limits: Limits,
    *,
    cancel: Callable[[], bool] | None = None,
) -> list[Packet]:
    result: list[Packet] = []
    total = 0
    for packet in packets:
        _check_cancel(cancel)
        if len(result) >= limits.max_packets:
            raise InputLimitError(f"packet count exceeds limit {limits.max_packets}")
        if len(packet.payload) > limits.max_packet_bytes:
            raise InputLimitError(f"packet exceeds limit {limits.max_packet_bytes}")
        total += len(packet.payload)
        if total > limits.max_input_bytes:
            raise InputLimitError(f"capture bytes exceed limit {limits.max_input_bytes}")
        result.append(packet)
    return result


def _views(
    packets: list[Packet],
    coordinate_system: str,
    *,
    cancel: Callable[[], bool] | None = None,
) -> tuple[list[tuple[Packet, bytes]], int]:
    views: list[tuple[Packet, bytes]] = []
    unavailable = 0
    for packet in packets:
        _check_cancel(cancel)
        data, metadata = coordinate_bytes(packet, coordinate_system)
        if data is None or not metadata.get("available"):
            unavailable += 1
            continue
        views.append((packet, data))
    return views, unavailable


def _check_cancel(cancel: Callable[[], bool] | None) -> None:
    if cancel is not None and cancel():
        raise ExperimentCancelled()


def _report_progress(progress: Callable[[int], None] | None, value: int) -> None:
    if progress is not None:
        progress(max(0, min(95, int(value))))


def _capture_summary(packets: list[Packet], unavailable: int) -> dict:
    digest = hashlib.sha256()
    for packet in packets:
        digest.update(packet.index.to_bytes(8, "big", signed=False))
        digest.update(len(packet.payload).to_bytes(8, "big", signed=False))
        digest.update(packet.payload)
    return {
        "packet_count": len(packets),
        "unavailable_payloads": unavailable,
        "input_sha256": digest.hexdigest(),
    }


def _distribution(views: list[tuple[Packet, bytes]]) -> list[dict]:
    counts = Counter((len(data), data[0] if data else None) for _packet, data in views)
    return [
        {"length": length, "first_byte": None if first is None else f"{first:02x}", "count": count}
        for (length, first), count in sorted(counts.items())
    ]


def _changed_ranges(records: dict[int, dict], limits: Limits) -> list[dict]:
    offsets = sorted(offset for offset, record in records.items() if record["changed"])
    if not offsets:
        return []
    ranges: list[dict] = []
    start = previous = offsets[0]
    for offset in offsets[1:] + [None]:
        if offset is not None and offset == previous + 1:
            previous = offset
            continue
        selected = [records[index] for index in range(start, previous + 1)]
        evidence = []
        for relative_offset, item in enumerate(selected):
            for entry in item["evidence"]:
                if len(evidence) >= MAX_EVIDENCE_PAIRS:
                    break
                evidence.append({"offset": start + relative_offset, **entry})
        compared = sum(item["compared"] for item in selected)
        changed = sum(item["changed"] for item in selected)
        ranges.append({
            "offset": start,
            "width": previous - start + 1,
            "compared_bytes": compared,
            "changed_bytes": changed,
            "change_rate": round(changed / compared, 6) if compared else 0.0,
            "evidence": evidence,
        })
        if offset is not None:
            start = previous = offset
    ranges.sort(key=lambda item: (-item["change_rate"], -item["width"], item["offset"]))
    return ranges[: max(1, min(limits.max_hypotheses, limits.max_response_bytes // 1024))]


def _range_hypothesis(item: dict, change_label: str, coordinate_system: str) -> dict:
    rate = float(item["change_rate"])
    return {
        "field_type": "experimental_correlation",
        "status": "hypothesis",
        "coordinate_system": coordinate_system,
        "offset": item["offset"],
        "width": item["width"],
        "confidence": round(min(0.9, 0.35 + rate * 0.5), 6),
        "evidence": [{
            "rationale": f"Bytes changed in {rate:.1%} of comparable positions after {change_label!r}.",
            "changed_bytes": item["changed_bytes"],
            "compared_bytes": item["compared_bytes"],
            "sample_pairs": item["evidence"][:MAX_EVIDENCE_PAIRS],
        }],
        "contradictions": [
            {"reason": "The paired captures do not isolate application message identity or causation."},
        ],
        "caveats": [
            "This is an association with the controlled capture change, not a confirmed field meaning.",
        ],
        "what_would_help": [
            "Repeat the same change while holding message order and unrelated inputs constant.",
            "Revert the setting and check whether this range returns to its baseline bytes.",
            "Vary one candidate parameter at a time to distinguish a command field from a correlated counter or checksum.",
        ],
    }


def _suggestions(baseline: list[Packet], changed: list[Packet], has_hypotheses: bool) -> list[str]:
    suggestions = [
        "Repeat the controlled change and include a no-change capture recorded at the same time.",
        "Reverse the change and test whether the candidate ranges revert; reversal is stronger evidence than one correlation.",
    ]
    if len(baseline) != len(changed):
        suggestions.append("Capture equal message counts or add an application-level grouping key before interpreting positional differences.")
    if not has_hypotheses:
        suggestions.append("Increase independent samples or vary the controlled setting farther before assigning a field hypothesis.")
    return suggestions
