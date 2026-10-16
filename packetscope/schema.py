"""Versioned, non-executable protocol schema export and validation.

Schemas describe reviewed or inferred byte ranges.  They never become parser
code and applying one only reads bounded bytes from already imported packets.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from packetscope.models import Packet
from packetscope.protocols import COORDINATE_SYSTEMS, coordinate_bytes


SCHEMA_VERSION = 1
MAX_FIELDS = 1000
MAX_FIELD_WIDTH = 16 * 1024 * 1024
DEFAULT_COORDINATE_SYSTEM = "raw_packet"


def export_schema(result: dict[str, Any], annotations: Iterable[dict[str, Any]] | None = None, name: str = "PacketScope protocol") -> dict[str, Any]:
    analysis_scope = result.get("analysis", {}).get("coordinate_system", result.get("analysis", {}).get("scope"))
    coordinate_system = analysis_scope if isinstance(analysis_scope, str) and analysis_scope in COORDINATE_SYSTEMS else DEFAULT_COORDINATE_SYSTEM
    fields: list[dict[str, Any]] = []
    for item in result.get("hypotheses", []):
        if not isinstance(item, dict):
            continue
        fields.append(_field_from_item(item, origin="inferred", review_status="hypothesis", default_coordinate_system=coordinate_system))
    for item in annotations or result.get("annotations", []):
        if isinstance(item, dict):
            fields.append(_field_from_item(item, origin="manual", review_status=str(item.get("status", "confirmed")), default_coordinate_system=coordinate_system))
    fields.sort(key=lambda item: (int(item["offset"]), int(item["width"]), str(item["name"]), str(item["origin"])))
    return {
        "schema_version": SCHEMA_VERSION,
        "name": str(name)[:120] or "PacketScope protocol",
        "coordinate_system": coordinate_system,
        "fields": fields[:MAX_FIELDS],
        "source": {
            "input_sha256": result.get("reproducibility", {}).get("input_sha256"),
            "analysis_scope": result.get("analysis", {}).get("scope"),
            "packet_count": len(result.get("packets", [])) if isinstance(result.get("packets"), list) else 0,
        },
        "limitations": [
            "Fields are byte-range descriptions, not executable parser definitions.",
            "Inferred fields remain hypotheses until a person reviews them.",
            "Variable-length and overlapping fields are allowed and must be interpreted with their constraints.",
        ],
    }


def validate_schema(schema: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(schema, dict) or schema.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported protocol schema version")
    fields = schema.get("fields")
    if not isinstance(fields, list) or len(fields) > MAX_FIELDS:
        raise ValueError("schema fields are missing or exceed the limit")
    coordinate_system = schema.get("coordinate_system", DEFAULT_COORDINATE_SYSTEM)
    if not isinstance(coordinate_system, str) or coordinate_system not in COORDINATE_SYSTEMS:
        raise ValueError("schema coordinate_system is invalid")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(fields):
        if not isinstance(item, dict):
            raise ValueError(f"schema field {index} must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise ValueError(f"schema field {index} has an invalid name")
        try:
            offset = int(item["offset"])
            width = int(item["width"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"schema field {index} offset/width is invalid") from exc
        if offset < 0 or width <= 0 or width > MAX_FIELD_WIDTH:
            raise ValueError(f"schema field {index} offset/width is out of bounds")
        endian = str(item.get("endian", "unknown"))
        if endian not in {"big", "little", "unknown"}:
            raise ValueError(f"schema field {index} endian is invalid")
        field_coordinate_system = item.get("coordinate_system", coordinate_system)
        if not isinstance(field_coordinate_system, str) or field_coordinate_system not in COORDINATE_SYSTEMS:
            raise ValueError(f"schema field {index} coordinate_system is invalid")
        type_name = str(item.get("type", "custom"))[:40]
        integer_widths = {"UINT32": 4, "UINT64": 8, "INT64": 8}
        expected_width = integer_widths.get(type_name.upper())
        if expected_width is not None and width != expected_width:
            raise ValueError(f"schema field {index} type {type_name} requires width {expected_width}")
        origin = str(item.get("origin", "inferred"))
        if origin not in {"inferred", "manual"}:
            raise ValueError(f"schema field {index} origin is invalid")
        status = str(item.get("review_status", "hypothesis"))
        if status not in {"hypothesis", "confirmed", "rejected"}:
            raise ValueError(f"schema field {index} review status is invalid")
        normalized.append({
            "name": name.strip()[:120],
            "type": type_name,
            "offset": offset,
            "width": width,
            "endian": endian,
            "coordinate_system": field_coordinate_system,
            "observed_values": item.get("observed_values", []),
            "constraints": item.get("constraints", []),
            "origin": origin,
            "review_status": status,
            "evidence_refs": item.get("evidence_refs", []),
            "known_limitations": item.get("known_limitations", []),
        })
    return {**schema, "coordinate_system": coordinate_system, "fields": normalized}


def apply_schema(schema: dict[str, Any], packets: Iterable[Packet], max_packets: int = 100_000) -> dict[str, Any]:
    checked = validate_schema(schema)
    packet_list: list[Packet] = []
    for packet in packets:
        if len(packet_list) >= max_packets:
            raise ValueError("packet count exceeds schema application limit")
        packet_list.append(packet)
    values: list[dict[str, Any]] = []
    for packet in packet_list:
        fields: list[dict[str, Any]] = []
        coordinate_cache: dict[str, tuple[bytes | None, dict]] = {}
        for field in checked["fields"]:
            coordinate_system = field["coordinate_system"]
            if coordinate_system not in coordinate_cache:
                coordinate_cache[coordinate_system] = coordinate_bytes(packet, coordinate_system)
            data, metadata = coordinate_cache[coordinate_system]
            start = field["offset"]
            end = start + field["width"]
            raw = data[start:end] if data is not None and metadata.get("available") else b""
            available = len(raw) == field["width"]
            value, value_encoding = _schema_value(raw, field, available)
            fields.append({
                "name": field["name"],
                "offset": start,
                "width": field["width"],
                "coordinate_system": coordinate_system,
                "available": available,
                "value": value,
                "value_encoding": value_encoding,
            })
        values.append({"packet_id": packet.index, "fields": fields})
    return {"schema_version": SCHEMA_VERSION, "field_count": len(checked["fields"]), "packet_count": len(packet_list), "values": values}


def validate_capture_against_schema(
    schema: dict[str, Any],
    packets: Iterable[Packet],
    *,
    max_packets: int = 100_000,
) -> dict[str, Any]:
    """Return per-packet diagnostics without treating incomplete input as a violation."""
    checked = validate_schema(schema)
    applied = apply_schema(checked, packets, max_packets=max_packets)
    diagnostics: list[dict[str, Any]] = []
    decoded_packets = 0
    missing_fields = 0
    constraint_violations = 0
    unsupported_fields = 0
    for packet in applied["values"]:
        missing: list[str] = []
        violations: list[dict[str, Any]] = []
        unsupported: list[str] = []
        for field, value in zip(checked["fields"], packet["fields"]):
            if not value["available"]:
                missing.append(field["name"])
                continue
            constraints = field.get("constraints", {})
            if not isinstance(constraints, dict):
                constraints = {}
            if str(field.get("type", "")).upper() in {"CRC", "CHECKSUM"} and not constraints.get("algorithm"):
                unsupported.append(field["name"])
                continue
            number = _numeric_value(value["value"])
            allowed = constraints.get("allowed", constraints.get("enum"))
            if isinstance(allowed, list) and value["value"] not in {str(item) for item in allowed}:
                violations.append({"field": field["name"], "reason": "value is outside the declared enumeration"})
            if number is not None:
                for key, comparator, reason in (("minimum", lambda actual, expected: actual < expected, "value is below the minimum"), ("maximum", lambda actual, expected: actual > expected, "value is above the maximum")):
                    if key in constraints:
                        try:
                            expected = int(constraints[key])
                        except (TypeError, ValueError):
                            unsupported.append(field["name"])
                            continue
                        if comparator(number, expected):
                            violations.append({"field": field["name"], "reason": reason})
        status = "ok" if not missing and not violations and not unsupported else "incomplete" if missing and not violations else "violated" if violations else "unsupported"
        if status == "ok":
            decoded_packets += 1
        missing_fields += len(missing)
        constraint_violations += len(violations)
        unsupported_fields += len(unsupported)
        diagnostics.append({"packet_id": packet["packet_id"], "status": status, "missing_fields": missing, "constraint_violations": violations, "unsupported_fields": unsupported})
    return {
        "schema_version": checked["schema_version"],
        "summary": {
            "packet_count": len(diagnostics),
            "decoded_packets": decoded_packets,
            "incomplete_packets": sum(item["status"] == "incomplete" for item in diagnostics),
            "missing_fields": missing_fields,
            "constraint_violations": constraint_violations,
            "unsupported_fields": unsupported_fields,
        },
        "packets": diagnostics,
    }


def dumps_schema(schema: dict[str, Any]) -> str:
    return json.dumps(validate_schema(schema), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def loads_schema(payload: str | bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("protocol schema must be valid JSON") from exc
    return validate_schema(value)


def _field_from_item(item: dict[str, Any], *, origin: str, review_status: str, default_coordinate_system: str) -> dict[str, Any]:
    width = item.get("width")
    if width is None:
        if "end" in item and "start" in item:
            width = int(item["end"]) - int(item["start"])
        else:
            width = int(item.get("width_bits", 8)) // 8
    coordinate_system = item.get("coordinate_system", item.get("offset_basis", default_coordinate_system))
    if not isinstance(coordinate_system, str) or coordinate_system not in COORDINATE_SYSTEMS:
        coordinate_system = default_coordinate_system
    if coordinate_system == "application_payload" and item.get("payload_relative_offset") is not None:
        offset = item["payload_relative_offset"]
    else:
        offset = item.get("absolute_offset", item.get("offset", item.get("start", 0)))
    evidence = item.get("evidence", [])
    observed = item.get("candidate_value", item.get("observed_values", []))
    return {
        "name": str(item.get("label", item.get("field_type", item.get("kind", "field"))))[:120] or "field",
        "type": str(item.get("field_type", item.get("kind", "custom")))[:40],
        "offset": int(offset),
        "width": int(width),
        "endian": str(item.get("endian", "unknown")),
        "coordinate_system": coordinate_system,
        "observed_values": observed if isinstance(observed, list) else [observed],
        "constraints": item.get("interpretation_group", {}),
        "origin": origin,
        "review_status": review_status if review_status in {"hypothesis", "confirmed", "rejected"} else "hypothesis",
        "evidence_refs": [entry.get("packet_ids", []) for entry in evidence if isinstance(entry, dict)],
        "known_limitations": list(item.get("caveats", [])) + list(item.get("what_would_help", [])),
    }


def _schema_value(raw: bytes, field: dict[str, Any], available: bool) -> tuple[Any, str | None]:
    """Return a JSON-safe value; incomplete ranges never expose partial data."""
    if not available:
        return None, None
    if field["endian"] in {"big", "little"} and field["width"] <= 8:
        signed = field["type"].upper() == "INT64"
        return str(int.from_bytes(raw, field["endian"], signed=signed)), "decimal_string"
    return raw.hex(), "hex"


def _numeric_value(value: Any) -> int | None:
    if isinstance(value, str) and value.lstrip("-").isdigit():
        try:
            return int(value)
        except ValueError:
            return None
    return value if isinstance(value, int) and not isinstance(value, bool) else None
