"""Deterministic post-analysis evaluation against a separately supplied truth set."""
from __future__ import annotations

from typing import Any, Iterable


def evaluate_result(result: dict[str, Any], expected: Iterable[dict[str, Any]]) -> dict[str, Any]:
    expected_items = list(expected)
    hypotheses = sorted(
        (item for item in result.get("hypotheses", []) if isinstance(item, dict)),
        key=lambda item: (-float(item.get("ranking", {}).get("score", item.get("confidence", 0.0))),
                          -float(item.get("confidence", 0.0)), str(item.get("id", ""))),
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
    top_k_metrics = {}
    for requested in (1, 3, 5):
        actual_k = min(requested, len(hypotheses))
        matched_at_k = sum(1 for truth in expected_items if any(_matches(candidate, truth) for candidate in hypotheses[:actual_k]))
        top_k_metrics[f"top_{requested}"] = {
            "k": requested,
            "matched": matched_at_k,
            "recall": matched_at_k / len(expected_items) if expected_items else None,
        }
    duplicate_keys = [_duplicate_key(item) for item in hypotheses]
    duplicate_aware = {
        "candidate_count": len(hypotheses),
        "unique_candidate_count": len(set(duplicate_keys)),
        "duplicate_count": len(duplicate_keys) - len(set(duplicate_keys)),
    }
    type_matches = sum(1 for item in matched if item["expected"].get("field_type", item["expected"].get("kind")) ==
                       next((candidate.get("field_type", candidate.get("kind")) for candidate in hypotheses
                             if candidate.get("id") == item.get("hypothesis_id")), None))
    offset_matches = sum(1 for item in matched if _same_offset(item["expected"], next((candidate for candidate in hypotheses if candidate.get("id") == item.get("hypothesis_id")), {})))
    checksum_matches = sum(1 for item in matched if item["expected"].get("algorithm") and
                           item["expected"].get("algorithm") == next((candidate.get("algorithm") for candidate in hypotheses if candidate.get("id") == item.get("hypothesis_id")), None))
    false_positive_breakdown: dict[str, int] = {}
    for index in false_positive_indices:
        label = str(hypotheses[index].get("field_type", hypotheses[index].get("kind", "unknown")))
        false_positive_breakdown[label] = false_positive_breakdown.get(label, 0) + 1
    candidate_groups = [_alternative_group_key(item) for item in hypotheses]
    matched_group_keys = {candidate_groups[index] for index in used}
    group_count = len(set(candidate_groups))
    group_false_positive_count = sum(1 for key in set(candidate_groups) if key not in matched_group_keys)
    group_precision = len(matched_group_keys) / group_count if group_count else (1.0 if not expected_items else 0.0)
    group_recall = len(matched_group_keys) / len(expected_items) if expected_items else None
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
        "top_k_metrics": top_k_metrics,
        "duplicate_aware": duplicate_aware,
        "alternative_group_aware": {
            "candidate_group_count": group_count,
            "matched_group_count": len(matched_group_keys),
            "false_positive_group_count": group_false_positive_count,
            "precision": group_precision,
            "recall": group_recall,
            "f1": (2 * group_precision * group_recall / (group_precision + group_recall)) if group_recall is not None and group_precision + group_recall else (0.0 if group_recall == 0 else None),
            "grouping_basis": "server-provided interpretation_group, equivalence_group, or exact field identity",
        },
        "field_type_accuracy": type_matches / len(matched) if matched else None,
        "offset_accuracy": offset_matches / len(matched) if matched else None,
        "checksum_algorithm_accuracy": checksum_matches / len(matched) if matched else None,
        "false_positive_breakdown": dict(sorted(false_positive_breakdown.items())),
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


def _duplicate_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (item.get("field_type", item.get("kind")), item.get("absolute_offset", item.get("offset")),
            item.get("width_bits", item.get("width")), item.get("endian"), item.get("algorithm"))


def _alternative_group_key(item: dict[str, Any]) -> tuple[Any, ...]:
    interpretation = item.get("interpretation_group")
    if isinstance(interpretation, dict) and interpretation.get("id"):
        return ("interpretation", interpretation["id"])
    if item.get("equivalence_group"):
        return ("equivalence", item["equivalence_group"])
    return ("exact",) + _duplicate_key(item)


def _same_offset(expected: dict[str, Any], candidate: dict[str, Any]) -> bool:
    return expected.get("absolute_offset", expected.get("offset")) == candidate.get("absolute_offset", candidate.get("offset"))
