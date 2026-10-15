"""Versioned, non-executable protocol schema export and validation.

Schemas describe reviewed or inferred byte ranges.  They never become parser
code and applying one only reads bounded bytes from already imported packets.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from packetscope.models import Packet


SCHEMA_VERSION = 1
MAX_FIELDS = 1000
MAX_FIELD_WIDTH = 16 * 1024 * 1024


def export_schema(result: dict[str, Any], annotations: Iterable[dict[str, Any]] | None = None, name: str = "PacketScope protocol") -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    for item in result.get("hypotheses", []):
        if not isinstance(item, dict):
            continue
        fields.append(_field_from_item(item, origin="inferred", review_status="hypothesis"))
    for item in annotations or result.get("annotations", []):
        if isinstance(item, dict):
            fields.append(_field_from_item(item, origin="manual", review_status=str(item.get("status", "confirmed"))))
    fields.sort(key=lambda item: (int(item["offset"]), int(item["width"]), str(item["name"]), str(item["origin"])))
    return {
        "schema_version": SCHEMA_VERSION,
        "name": str(name)[:120] or "PacketScope protocol",
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
        origin = str(item.get("origin", "inferred"))
        if origin not in {"inferred", "manual"}:
            raise ValueError(f"schema field {index} origin is invalid")
        status = str(item.get("review_status", "hypothesis"))
        if status not in {"hypothesis", "confirmed", "rejected"}:
            raise ValueError(f"schema field {index} review status is invalid")
        normalized.append({
            "name": name.strip()[:120],
            "type": str(item.get("type", "custom"))[:40],
            "offset": offset,
            "width": width,
            "endian": endian,
            "observed_values": item.get("observed_values", []),
            "constraints": item.get("constraints", []),
            "origin": origin,
            "review_status": status,
            "evidence_refs": item.get("evidence_refs", []),
            "known_limitations": item.get("known_limitations", []),
        })
    return {**schema, "fields": normalized}


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
        for field in checked["fields"]:
            start = field["offset"]
            end = start + field["width"]
            raw = packet.payload[start:end]
            value: Any = raw.hex()
            if len(raw) == field["width"] and field["endian"] in {"big", "little"} and field["width"] <= 8:
                value = int.from_bytes(raw, field["endian"])
            fields.append({"name": field["name"], "offset": start, "width": field["width"], "available": len(raw) == field["width"], "value": value})
        values.append({"packet_id": packet.index, "fields": fields})
    return {"schema_version": SCHEMA_VERSION, "field_count": len(checked["fields"]), "packet_count": len(packet_list), "values": values}


def dumps_schema(schema: dict[str, Any]) -> str:
    return json.dumps(validate_schema(schema), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def loads_schema(payload: str | bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("protocol schema must be valid JSON") from exc
    return validate_schema(value)


def _field_from_item(item: dict[str, Any], *, origin: str, review_status: str) -> dict[str, Any]:
    width = item.get("width")
    if width is None:
        if "end" in item and "start" in item:
            width = int(item["end"]) - int(item["start"])
        else:
            width = int(item.get("width_bits", 8)) // 8
    offset = item.get("absolute_offset", item.get("offset", item.get("start", 0)))
    evidence = item.get("evidence", [])
    observed = item.get("candidate_value", item.get("observed_values", []))
    return {
        "name": str(item.get("label", item.get("field_type", item.get("kind", "field"))))[:120] or "field",
        "type": str(item.get("field_type", item.get("kind", "custom")))[:40],
        "offset": int(offset),
        "width": int(width),
        "endian": str(item.get("endian", "unknown")),
        "observed_values": observed if isinstance(observed, list) else [observed],
        "constraints": item.get("interpretation_group", {}),
        "origin": origin,
        "review_status": review_status if review_status in {"hypothesis", "confirmed", "rejected"} else "hypothesis",
        "evidence_refs": [entry.get("packet_ids", []) for entry in evidence if isinstance(entry, dict)],
        "known_limitations": list(item.get("caveats", [])) + list(item.get("what_would_help", [])),
    }
