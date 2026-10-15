"""Deterministic post-analysis evaluation against a separately supplied truth set."""
from __future__ import annotations

from typing import Any, Iterable


def evaluate_result(result: dict[str, Any], expected: Iterable[dict[str, Any]]) -> dict[str, Any]:
    expected_items = list(expected)
    hypotheses = sorted(
        (item for item in result.get("hypotheses", []) if isinstance(item, dict)),
        key=lambda item: (-float(item.get("confidence", 0.0)), str(item.get("id", ""))),
    )
    used: set[int] = set()
    matched: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for truth in expected_items:
        match_index = next((index for index, candidate in enumerate(hypotheses) if index not in used and _matches(candidate, truth)), None)
        if match_index is None:
            missing.append(truth)
            continue
        used.add(match_index)
        matched.append({"expected": truth, "hypothesis_id": hypotheses[match_index].get("id")})
    false_positive_indices = [index for index in range(len(hypotheses)) if index not in used]
    precision = len(matched) / len(hypotheses) if hypotheses else (1.0 if not expected_items else 0.0)
    recall = len(matched) / len(expected_items) if expected_items else None
    top_k = result.get("top_k")
    if top_k is None:
        top_k = len(hypotheses)
    top_k = max(0, min(int(top_k), len(hypotheses)))
    top_matches = sum(1 for truth in expected_items if any(_matches(candidate, truth) for candidate in hypotheses[:top_k]))
    ranked = [dict(item, rank=index + 1) for index, item in enumerate(hypotheses)]
    return {
        "expected_count": len(expected_items),
        "matched_count": len(matched),
        "precision": precision,
        "recall": recall,
        "f1": (2 * precision * recall / (precision + recall)) if recall is not None and precision + recall else (0.0 if recall == 0 else None),
        "matched": len(matched),
        "unmatched": len(false_positive_indices) if 'false_positive_indices' in locals() else 0,
        "missed": len(expected_items) - len(matched),
        "top_k": top_k,
        "top_k_matched": top_matches,
        "top_k_recall": top_matches / len(expected_items) if expected_items else None,
        "missing": missing,
        "false_positive_count": len(false_positive_indices),
        "false_positive_ids": [hypotheses[index].get("id") for index in false_positive_indices],
        "automatic_confirmed_count": sum(candidate.get("status") == "confirmed" for candidate in hypotheses),
        "matched_items": matched,
        "ranking": ranked,
        "recall_applicable": bool(expected_items),
    }


def _matches(candidate: dict[str, Any], truth: dict[str, Any]) -> bool:
    candidate_type = candidate.get("field_type", candidate.get("kind"))
    expected_type = truth.get("field_type", truth.get("kind"))
    if expected_type and candidate_type != expected_type:
        return False
    expected_offset = truth.get("absolute_offset", truth.get("offset"))
    actual_offset = candidate.get("absolute_offset", candidate.get("offset"))
    if expected_offset is not None and actual_offset != expected_offset:
        return False
    expected_width = truth.get("width_bits")
    if expected_width is None and truth.get("width") is not None:
        expected_width = truth["width"] * 8
    actual_width = candidate.get("width_bits")
    if actual_width is None and candidate.get("width") is not None:
        actual_width = candidate["width"] * 8
    if expected_width is not None and actual_width != expected_width:
        return False
    for key in ("endian", "algorithm"):
        if truth.get(key) is not None and candidate.get(key) != truth[key]:
            return False
    if truth.get("location_mode") is not None and candidate.get("checksum", {}).get("location_mode") != truth["location_mode"]:
        return False
    return True
