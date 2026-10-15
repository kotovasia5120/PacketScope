"""Versioned, bounded analysis profiles.

Profiles are data, not executable configuration.  They make the choices that
affect an analysis explicit and provide a stable fingerprint for reports.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from packetscope.models import Limits


PROFILE_SCHEMA_VERSION = 1
PACKETSCOPE_VERSION = "0.2.0"
ANALYZER_VERSION = "engine-1"

_DETECTORS = (
    "magic_bytes", "message_type", "sequence_counter", "length_field",
    "bit_flags", "checksum", "crc",
)
_ENDIANS = ("big", "little")
_CRC_ALGORITHMS = (
    "CRC-8", "CRC-16/CCITT-FALSE", "CRC-16/MODBUS", "CRC-32/ISO-HDLC",
    "XOR-8", "ADDITIVE-8", "ADDITIVE-16",
)


@dataclass(frozen=True)
class AnalysisProfile:
    schema_version: int
    profile_id: str
    analysis_scope: str
    selected_flow: str | None
    selected_direction: str
    enabled_detectors: tuple[str, ...]
    integer_widths: tuple[int, ...]
    endianness_options: tuple[str, ...]
    crc_algorithms: tuple[str, ...]
    crc_search_budget: dict[str, int | float]
    alignment_mode: str
    maximum_samples: int
    timeout: float
    ranking_options: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "analysis_scope": self.analysis_scope,
            "selected_flow": self.selected_flow,
            "selected_direction": self.selected_direction,
            "enabled_detectors": list(self.enabled_detectors),
            "integer_widths": list(self.integer_widths),
            "endianness_options": list(self.endianness_options),
            "crc_algorithms": list(self.crc_algorithms),
            "crc_search_budget": dict(self.crc_search_budget),
            "alignment_mode": self.alignment_mode,
            "maximum_samples": self.maximum_samples,
            "timeout": self.timeout,
            "ranking_options": dict(self.ranking_options),
        }

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


def _profile(profile_id: str, *, maximum_samples: int, timeout: float,
             alignment_mode: str, candidates: int, ranges: int) -> AnalysisProfile:
    return AnalysisProfile(
        PROFILE_SCHEMA_VERSION, profile_id, "application_payload", None, "both",
        _DETECTORS, (1, 2, 4, 8), _ENDIANS, _CRC_ALGORITHMS,
        {"time_limit_seconds": timeout, "max_candidates": candidates, "max_ranges": ranges},
        alignment_mode, maximum_samples, timeout,
        {"order": "score_desc_then_id", "complexity_penalty": True, "confidence_label": "heuristic"},
    )


BUILTIN_PROFILES = {
    "default": _profile("default", maximum_samples=128, timeout=2.0, alignment_mode="bounded", candidates=4000, ranges=512),
    "fast": _profile("fast", maximum_samples=32, timeout=0.5, alignment_mode="offset", candidates=512, ranges=64),
    "deep": _profile("deep", maximum_samples=256, timeout=2.0, alignment_mode="sequence", candidates=4000, ranges=512),
}


def validate_profile(value: Mapping[str, Any]) -> AnalysisProfile:
    if not isinstance(value, Mapping):
        raise ValueError("profile must be a JSON object")
    raw = dict(value)
    version = raw.get("schema_version", 0)
    if version == 0:
        raw = migrate_profile(raw)
        version = raw["schema_version"]
    if version != PROFILE_SCHEMA_VERSION:
        raise ValueError(f"unsupported profile schema version: {version}")

    def text(name: str, allowed: set[str] | None = None) -> str:
        item = raw.get(name)
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"profile field {name} must be a non-empty string")
        item = item.strip()
        if allowed and item not in allowed:
            raise ValueError(f"profile field {name} has an unsupported value")
        return item

    profile_id = text("profile_id")[:64]
    scope = text("analysis_scope", {"application_payload", "raw_packet"})
    direction = text("selected_direction", {"both", "forward", "reverse"})
    selected_flow = raw.get("selected_flow")
    if selected_flow is not None and (not isinstance(selected_flow, str) or len(selected_flow) > 200):
        raise ValueError("selected_flow must be null or a bounded string")

    def choices(name: str, allowed: set[str]) -> tuple[str, ...]:
        items = raw.get(name)
        if not isinstance(items, list) or not items or len(items) > 32:
            raise ValueError(f"profile field {name} must be a non-empty list")
        result = tuple(dict.fromkeys(item for item in items if isinstance(item, str)))
        if not result or any(item not in allowed for item in result):
            raise ValueError(f"profile field {name} contains an unsupported value")
        return result

    detectors = choices("enabled_detectors", set(_DETECTORS))
    endian = choices("endianness_options", set(_ENDIANS))
    crc = choices("crc_algorithms", set(_CRC_ALGORITHMS))
    widths_raw = raw.get("integer_widths")
    if not isinstance(widths_raw, list) or not widths_raw:
        raise ValueError("integer_widths must be a non-empty list")
    widths = tuple(sorted(set(int(item) for item in widths_raw)))
    if any(item not in (1, 2, 4, 8) for item in widths):
        raise ValueError("integer_widths must contain only 1, 2, 4, or 8")

    budget = raw.get("crc_search_budget")
    if not isinstance(budget, Mapping):
        raise ValueError("crc_search_budget must be an object")
    candidates = _bounded_int(budget, "max_candidates", 1, 100_000)
    ranges = _bounded_int(budget, "max_ranges", 1, 100_000)
    budget_time = _bounded_float(budget, "time_limit_seconds", 0.01, 120.0)
    alignment = text("alignment_mode", {"offset", "bounded", "sequence"})
    samples = _bounded_int(raw, "maximum_samples", 1, 100_000)
    timeout = _bounded_float(raw, "timeout", 0.01, 120.0)
    ranking = raw.get("ranking_options", {})
    if not isinstance(ranking, Mapping) or len(ranking) > 32:
        raise ValueError("ranking_options must be a bounded object")
    return AnalysisProfile(
        PROFILE_SCHEMA_VERSION, profile_id, scope, selected_flow, direction,
        detectors, widths, endian, crc,
        {"time_limit_seconds": budget_time, "max_candidates": candidates, "max_ranges": ranges},
        alignment, samples, timeout, dict(ranking),
    )


def _bounded_int(value: Mapping[str, Any], name: str, minimum: int, maximum: int) -> int:
    item = value.get(name)
    if isinstance(item, bool):
        raise ValueError(f"profile field {name} must be an integer")
    try:
        item = int(item)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"profile field {name} must be an integer") from exc
    if not minimum <= item <= maximum:
        raise ValueError(f"profile field {name} is outside its limit")
    return item


def _bounded_float(value: Mapping[str, Any], name: str, minimum: float, maximum: float) -> float:
    item = value.get(name)
    try:
        item = float(item)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"profile field {name} must be numeric") from exc
    if not minimum <= item <= maximum:
        raise ValueError(f"profile field {name} is outside its limit")
    return item


def migrate_profile(value: Mapping[str, Any]) -> dict[str, Any]:
    """Migrate the pre-versioned draft shape used by early local scripts."""
    raw = dict(value)
    raw.setdefault("profile_id", "migrated")
    raw.setdefault("analysis_scope", "application_payload")
    raw.setdefault("selected_flow", None)
    raw.setdefault("selected_direction", "both")
    raw.setdefault("enabled_detectors", list(_DETECTORS))
    raw.setdefault("integer_widths", [1, 2, 4, 8])
    raw.setdefault("endianness_options", list(_ENDIANS))
    raw.setdefault("crc_algorithms", list(_CRC_ALGORITHMS))
    raw.setdefault("crc_search_budget", {"time_limit_seconds": 2.0, "max_candidates": 4000, "max_ranges": 512})
    raw.setdefault("alignment_mode", "bounded")
    raw.setdefault("maximum_samples", 128)
    raw.setdefault("timeout", 2.0)
    raw.setdefault("ranking_options", {"confidence_label": "heuristic"})
    raw["schema_version"] = PROFILE_SCHEMA_VERSION
    return raw


def resolve_profile(value: str | Mapping[str, Any] | None = None) -> AnalysisProfile:
    if value is None:
        return BUILTIN_PROFILES["default"]
    if isinstance(value, AnalysisProfile):
        return value
    if isinstance(value, Mapping):
        return validate_profile(value)
    if value in BUILTIN_PROFILES:
        return BUILTIN_PROFILES[value]
    path = Path(value)
    return validate_profile(json.loads(path.read_text(encoding="utf-8")))


def limits_for_profile(base: Limits, profile: AnalysisProfile) -> Limits:
    budget = profile.crc_search_budget
    return Limits(
        max_input_bytes=base.max_input_bytes, max_packet_bytes=base.max_packet_bytes,
        max_packets=base.max_packets, max_pcapng_block_bytes=base.max_pcapng_block_bytes,
        max_hypotheses=base.max_hypotheses, max_response_bytes=base.max_response_bytes,
        max_analysis_seconds=profile.timeout,
        max_crc_candidates=int(budget["max_candidates"]), max_crc_ranges=int(budget["max_ranges"]),
        max_flows=base.max_flows, max_samples=profile.maximum_samples,
        max_job_payload_bytes=base.max_job_payload_bytes, max_retained_jobs=base.max_retained_jobs,
    )


def dump_profile(profile: AnalysisProfile, path: str | Path) -> None:
    Path(path).write_text(json.dumps(profile.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def profile_report(profile: AnalysisProfile, *, input_sha256: str, completeness: str,
                   candidates_evaluated: int, tested_algorithms: list[str],
                   constraints: list[str]) -> dict[str, Any]:
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_id": profile.profile_id,
        "profile_fingerprint": profile.fingerprint,
        "packetscope_version": PACKETSCOPE_VERSION,
        "analyzer_version": ANALYZER_VERSION,
        "input_sha256": input_sha256,
        "analysis_completeness": completeness,
        "tested_algorithms": sorted(set(tested_algorithms)),
        "candidates_evaluated": int(candidates_evaluated),
        "constraints": sorted(set(constraints)),
        "profile": profile.as_dict(),
    }


def packet_dataset_sha256(packets: Any) -> str:
    """Hash packet evidence without including a machine-local path."""
    digest = hashlib.sha256()
    for packet in packets:
        payload = bytes(packet.payload)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()
