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
SCHEMA_V2_VERSION = 2
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


def _validate_schema_v1(schema: dict[str, Any]) -> dict[str, Any]:
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


def _apply_schema_v1(schema: dict[str, Any], packets: Iterable[Packet], max_packets: int = 100_000) -> dict[str, Any]:
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


def _validate_capture_against_schema_v1(
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


# ---------------------------------------------------------------------------
# Schema V2
# ---------------------------------------------------------------------------
# V1 is intentionally kept above. V2 is a data-only descriptor language: the
# evaluator below is an explicit allow-list interpreter, never Python source.

CURRENT_SCHEMA_VERSION = SCHEMA_V2_VERSION
V2_STATUSES = frozenset({
    "RESOLVED", "UNKNOWN", "UNAVAILABLE", "INVALID", "CYCLIC",
    "OUT_OF_BOUNDS", "LIMIT_EXCEEDED",
})
_V2_MAX_DEFINITIONS = 128
_V2_MAX_EXPRESSION_DEPTH = 32
_V2_MAX_EXPRESSION_KEYS = 32
_V2_MAX_DESCRIPTION = 2000
_V2_DEFAULT_BUDGETS = {
    "max_packets": 100_000,
    "max_fields": MAX_FIELDS,
    "max_array_items": 10_000,
    "max_total_array_items": 100_000,
    "max_bytes_per_packet": MAX_FIELD_WIDTH,
    "max_field_length": MAX_FIELD_WIDTH,
    "max_expression_depth": _V2_MAX_EXPRESSION_DEPTH,
    "max_expression_value": 1 << 31,
    "max_nesting": 16,
    "max_output_fields": 100_000,
}
_V2_INT_TYPES = {
    "u8": (1, False), "uint8": (1, False), "byte": (1, False),
    "u16": (2, False), "uint16": (2, False),
    "u32": (4, False), "uint32": (4, False),
    "u64": (8, False), "uint64": (8, False),
    "u128": (16, False), "uint128": (16, False),
    "i8": (1, True), "int8": (1, True),
    "i16": (2, True), "int16": (2, True),
    "i32": (4, True), "int32": (4, True),
    "i64": (8, True), "int64": (8, True),
    "i128": (16, True), "int128": (16, True),
}
_V2_OP_ALIASES = {
    "plus": "add", "minus": "subtract", "sub": "subtract",
    "mul": "multiply", "times": "multiply", "bounded_mul": "multiply",
    "bit_and": "mask", "and_bits": "mask", "bitand": "mask",
    "bit_or": "bitor", "bit_xor": "xor",
    "equal": "eq", "equals": "eq", "not_equal": "ne",
    "less_than": "lt", "less_equal": "lte", "le": "lte",
    "greater_than": "gt", "greater_equal": "gte", "ge": "gte",
    "logical_and": "and", "logical_or": "or", "all": "and", "any": "or",
    "conjunction": "and", "disjunction": "or", "align_up": "align",
    "alignment": "align", "bitmask": "mask", "bounded_multiply": "multiply",
    "==": "eq", "!=": "ne", "<": "lt", "<=": "lte", ">": "gt", ">=": "gte",
}
_V2_OPERATION_NAMES = {
    "add", "subtract", "multiply", "mask", "bitor", "xor", "min", "max",
    "align", "eq", "ne", "lt", "lte", "gt", "gte", "and", "or", "not",
    "negate",
}


def _v2_json_safe(value: Any, *, depth: int = 0) -> Any:
    """Copy only bounded JSON values; schema data never becomes executable."""
    if depth > _V2_MAX_EXPRESSION_DEPTH * 2:
        raise ValueError("schema JSON nesting exceeds the limit")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, int) and not isinstance(value, bool) and abs(value) > (1 << 63):
            raise ValueError("schema integer exceeds the limit")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("schema numbers must be finite")
        return value
    if isinstance(value, list):
        if len(value) > 100_000:
            raise ValueError("schema list exceeds the limit")
        return [_v2_json_safe(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > _V2_MAX_EXPRESSION_KEYS:
            raise ValueError("schema object exceeds the limit")
        result: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item)):
            if not isinstance(key, str):
                raise ValueError("schema object keys must be strings")
            result[key] = _v2_json_safe(value[key], depth=depth + 1)
        return result
    raise ValueError("schema contains a non-JSON value")


def _v2_text(value: Any, name: str, maximum: int = 120) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"schema {name} is invalid")
    return value.strip()


def _v2_budget_int(raw: dict[str, Any], names: tuple[str, ...], default: int, maximum: int) -> int:
    value = next((raw[name] for name in names if name in raw), default)
    if isinstance(value, bool):
        raise ValueError(f"schema budget {names[0]} must be an integer")
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"schema budget {names[0]} must be an integer") from exc
    if value <= 0 or value > maximum:
        raise ValueError(f"schema budget {names[0]} is outside the limit")
    return value


def _v2_budgets(raw: Any) -> dict[str, int]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("schema budgets must be an object")
    return {
        "max_packets": _v2_budget_int(raw, ("max_packets",), _V2_DEFAULT_BUDGETS["max_packets"], 1_000_000),
        "max_fields": _v2_budget_int(raw, ("max_fields",), _V2_DEFAULT_BUDGETS["max_fields"], MAX_FIELDS),
        "max_array_items": _v2_budget_int(raw, ("max_array_items", "max_items"), _V2_DEFAULT_BUDGETS["max_array_items"], 1_000_000),
        "max_total_array_items": _v2_budget_int(raw, ("max_total_array_items",), _V2_DEFAULT_BUDGETS["max_total_array_items"], 2_000_000),
        "max_bytes_per_packet": _v2_budget_int(raw, ("max_bytes_per_packet",), _V2_DEFAULT_BUDGETS["max_bytes_per_packet"], MAX_FIELD_WIDTH),
        "max_field_length": _v2_budget_int(raw, ("max_field_length",), _V2_DEFAULT_BUDGETS["max_field_length"], MAX_FIELD_WIDTH),
        "max_expression_depth": _v2_budget_int(raw, ("max_expression_depth",), _V2_DEFAULT_BUDGETS["max_expression_depth"], 128),
        "max_expression_value": _v2_budget_int(raw, ("max_expression_value",), _V2_DEFAULT_BUDGETS["max_expression_value"], 1 << 62),
        "max_nesting": _v2_budget_int(raw, ("max_nesting",), _V2_DEFAULT_BUDGETS["max_nesting"], 64),
        "max_output_fields": _v2_budget_int(raw, ("max_output_fields",), _V2_DEFAULT_BUDGETS["max_output_fields"], 1_000_000),
    }


def _v2_normalize_expr(value: Any, *, path: str = "expression", depth: int = 0, max_depth: int = _V2_MAX_EXPRESSION_DEPTH) -> Any:
    if depth > max_depth:
        raise ValueError(f"{path} exceeds expression depth limit")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, int) and not isinstance(value, bool) and abs(value) > (1 << 63):
            raise ValueError(f"{path} integer exceeds the limit")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"{path} must be finite")
        return value
    if isinstance(value, list):
        if len(value) > _V2_MAX_EXPRESSION_KEYS:
            raise ValueError(f"{path} has too many arguments")
        return [_v2_normalize_expr(item, path=f"{path}[{index}]", depth=depth + 1, max_depth=max_depth) for index, item in enumerate(value)]
    if isinstance(value, dict):
        if len(value) > _V2_MAX_EXPRESSION_KEYS:
            raise ValueError(f"{path} has too many keys")
        result: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise ValueError(f"{path} keys must be strings")
            result[key] = _v2_normalize_expr(value[key], path=f"{path}.{key}", depth=depth + 1, max_depth=max_depth)
        return result
    raise ValueError(f"{path} contains an unsupported value")


def _v2_type_width(type_name: str) -> int | None:
    return _V2_INT_TYPES[type_name.lower()][0] if type_name.lower() in _V2_INT_TYPES else None


def _v2_slug(value: str) -> str:
    result = "".join(character.lower() if character.isalnum() else "_" for character in value).strip("_")
    return result or "field"


def _v2_normalize_field(item: Any, *, index: int, parent_id: str | None = None, require_id: bool = False) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(f"schema field {index} must be an object")
    raw_id = item.get("id", item.get("field_id"))
    if raw_id is None and require_id:
        raise ValueError(f"schema field {index} is missing a stable id")
    field_id = _v2_text(raw_id, f"field {index} id", 120) if raw_id is not None else f"{parent_id + '.' if parent_id else ''}{_v2_slug(str(item.get('name', item.get('type', 'field'))))}_{index}"
    name = item.get("name", field_id)
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ValueError(f"schema field {index} has an invalid name")
    description = item.get("description", item.get("desc", ""))
    if not isinstance(description, str) or len(description) > _V2_MAX_DESCRIPTION:
        raise ValueError(f"schema field {index} has an invalid description")
    type_name = str(item.get("type", item.get("kind", "bytes"))).strip().lower()
    if not type_name or len(type_name) > 40:
        raise ValueError(f"schema field {index} has an invalid type")
    coordinate = item.get("coordinate")
    if coordinate is not None and not isinstance(coordinate, dict):
        raise ValueError(f"schema field {index} coordinate metadata is invalid")
    coordinate_system = item.get("coordinate_system")
    if coordinate_system is None and isinstance(coordinate, dict):
        coordinate_system = coordinate.get("system", coordinate.get("coordinate_system"))
    normalized_coordinate = _v2_json_safe(coordinate) if coordinate is not None else None
    endian = str(item.get("endian", "big")).lower()
    if endian not in {"big", "little", "unknown"}:
        raise ValueError(f"schema field {index} endian is invalid")
    offset = item.get("offset", item.get("offset_expr", 0))
    length = item.get("length", item.get("width", item.get("length_expr")))
    if isinstance(offset, bool) or isinstance(length, bool):
        raise ValueError(f"schema field {index} offset/length is invalid")
    offset = _v2_normalize_expr(offset, path=f"field {field_id} offset")
    length = _v2_normalize_expr(length, path=f"field {field_id} length") if length is not None else None
    presence = _v2_normalize_expr(item.get("presence", item.get("when", item.get("condition", True))), path=f"field {field_id} presence")
    nested_raw = item.get("fields")
    nested: list[dict[str, Any]] | None = None
    if nested_raw is not None:
        if not isinstance(nested_raw, list) or len(nested_raw) > MAX_FIELDS:
            raise ValueError(f"schema field {index} nested fields exceed the limit")
        nested = [_v2_normalize_field(child, index=child_index, parent_id=field_id, require_id=False) for child_index, child in enumerate(nested_raw)]
    array_raw = item.get("array")
    if array_raw is True:
        array_raw = {}
    elif array_raw is None and ("count" in item or "element" in item or type_name == "array"):
        array_raw = {"count": item.get("count"), "element": item.get("element")}
    array: dict[str, Any] | None = None
    if array_raw is not None:
        if not isinstance(array_raw, dict):
            raise ValueError(f"schema field {index} array descriptor is invalid")
        count = array_raw.get("count", array_raw.get("length", item.get("count")))
        element = array_raw.get("element", item.get("element"))
        if count is not None:
            count = _v2_normalize_expr(count, path=f"field {field_id} array count")
        if element is None:
            element = {"type": item.get("element_type", "bytes"), "length": item.get("element_length")}
        element = _v2_normalize_field(element, index=0, parent_id=f"{field_id}[]", require_id=False)
        max_items = array_raw.get("max_items", array_raw.get("max_count"))
        if max_items is not None:
            if isinstance(max_items, bool):
                raise ValueError(f"schema field {index} array max_items is invalid")
            try:
                max_items = int(max_items)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"schema field {index} array max_items is invalid") from exc
            if max_items <= 0 or max_items > 1_000_000:
                raise ValueError(f"schema field {index} array max_items is out of bounds")
        array = {"count": count, "element": element, "max_items": max_items}
    definition = item.get("definition", item.get("use"))
    if definition is not None and not isinstance(definition, str):
        raise ValueError(f"schema field {index} definition is invalid")
    return {
        "id": field_id, "name": name.strip(), "description": description,
        "type": type_name, "coordinate_system": coordinate_system,
        "coordinate": normalized_coordinate, "offset": offset, "length": length,
        "endian": endian, "encoding": str(item.get("encoding", ""))[:40],
        "presence": presence, "fields": nested, "array": array,
        "definition": definition, "constraints": _v2_json_safe(item.get("constraints", {})),
        "metadata": _v2_json_safe(item.get("metadata", {})),
        "checksum": _v2_json_safe(item.get("checksum")) if item.get("checksum") is not None else None,
        "relationship": _v2_json_safe(item.get("relationship")) if item.get("relationship") is not None else None,
    }


def _v2_walk_fields(fields: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    for field in fields:
        yield field
        nested = field.get("fields")
        if isinstance(nested, list):
            yield from _v2_walk_fields(nested)
        array = field.get("array")
        if isinstance(array, dict) and isinstance(array.get("element"), dict):
            nested_element = array["element"].get("fields")
            if isinstance(nested_element, list):
                yield from _v2_walk_fields(nested_element)


def _v2_expression_refs(expr: Any, refs: set[str] | None = None) -> set[str]:
    refs = refs if refs is not None else set()
    if isinstance(expr, dict):
        for key in ("field", "ref", "field_ref"):
            value = expr.get(key)
            if isinstance(value, str):
                refs.add(value)
        kind = expr.get("kind")
        if kind in {"field", "field_ref", "field_reference", "reference", "ref"}:
            for key in ("field_id", "id", "name"):
                value = expr.get(key)
                if isinstance(value, str):
                    refs.add(value)
                    break
        for key in ("field_id",):
            value = expr.get(key)
            if isinstance(value, str) and expr.get("kind") in {"field", "field_ref", "field_reference"}:
                refs.add(value)
        for value in expr.values():
            _v2_expression_refs(value, refs)
    elif isinstance(expr, list):
        for value in expr:
            _v2_expression_refs(value, refs)
    return refs


def _v2_field_expressions(field: dict[str, Any]) -> Iterable[Any]:
    yield field.get("offset")
    yield field.get("length")
    yield field.get("presence")
    array = field.get("array")
    if isinstance(array, dict):
        yield array.get("count")
    nested = field.get("fields")
    if isinstance(nested, list):
        for child in nested:
            yield from _v2_field_expressions(child)


def _v2_schema_graph(fields: list[dict[str, Any]], definitions: dict[str, dict[str, Any]]) -> tuple[dict[str, set[str]], list[dict[str, Any]]]:
    all_ids = {field["id"] for field in _v2_walk_fields(fields)}
    for definition in definitions.values():
        all_ids.update(field["id"] for field in _v2_walk_fields(definition.get("fields", [])))
    refs_by_id: dict[str, set[str]] = {}
    diagnostics: list[dict[str, Any]] = []
    every_field = list(_v2_walk_fields(fields)) + [field for definition in definitions.values() for field in _v2_walk_fields(definition.get("fields", []))]
    for field in every_field:
        refs: set[str] = set()
        for expression in _v2_field_expressions(field):
            _v2_expression_refs(expression, refs)
        refs_by_id[field["id"]] = refs
        for ref in sorted(refs):
            if ref not in all_ids:
                diagnostics.append({"status": "INVALID", "code": "missing_reference", "field_id": field["id"], "reference": ref, "message": f"field reference {ref!r} does not exist"})
        definition = field.get("definition")
        if definition is not None and definition not in definitions:
            diagnostics.append({"status": "INVALID", "code": "missing_definition", "field_id": field["id"], "reference": definition, "message": f"definition {definition!r} does not exist"})
    state: dict[str, int] = {}
    stack: list[str] = []
    cyclic: set[str] = set()

    def visit(node: str) -> None:
        if state.get(node) == 1:
            if node in stack:
                cyclic.update(stack[stack.index(node):])
            return
        if state.get(node) == 2:
            return
        state[node] = 1
        stack.append(node)
        for dependency in sorted(refs_by_id.get(node, set())):
            if dependency in refs_by_id:
                visit(dependency)
        stack.pop()
        state[node] = 2

    for field_id in sorted(refs_by_id):
        visit(field_id)
    for field_id in sorted(cyclic):
        diagnostics.append({"status": "CYCLIC", "code": "dependency_cycle", "field_id": field_id, "message": "field dependency cycle prevents evaluation"})
    return refs_by_id, sorted(diagnostics, key=lambda item: (item.get("field_id", ""), item.get("code", ""), item.get("reference", "")))


def _v2_fill_coordinates(fields: list[dict[str, Any]], coordinate_system: str) -> None:
    for field in fields:
        field["coordinate_system"] = field.get("coordinate_system") or coordinate_system
        if not isinstance(field["coordinate_system"], str) or field["coordinate_system"] not in COORDINATE_SYSTEMS:
            raise ValueError(f"field {field['id']} coordinate_system is invalid")
        nested = field.get("fields")
        if isinstance(nested, list):
            _v2_fill_coordinates(nested, field["coordinate_system"])
        array = field.get("array")
        if isinstance(array, dict) and isinstance(array.get("element"), dict):
            _v2_fill_coordinates([array["element"]], field["coordinate_system"])


def _validate_schema_v2(schema: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(schema, dict) or schema.get("schema_version") != SCHEMA_V2_VERSION:
        raise ValueError("unsupported protocol schema version")
    coordinate_system = schema.get("coordinate_system", DEFAULT_COORDINATE_SYSTEM)
    if not isinstance(coordinate_system, str) or coordinate_system not in COORDINATE_SYSTEMS:
        raise ValueError("schema coordinate_system is invalid")
    budgets = _v2_budgets(schema.get("budgets", schema.get("limits")))
    fields_raw = schema.get("fields")
    if not isinstance(fields_raw, list) or len(fields_raw) > budgets["max_fields"]:
        raise ValueError("schema fields are missing or exceed the limit")
    fields = [_v2_normalize_field(item, index=index, require_id=True) for index, item in enumerate(fields_raw)]
    _v2_fill_coordinates(fields, coordinate_system)
    definitions_raw = schema.get("definitions", {})
    if not isinstance(definitions_raw, dict) or len(definitions_raw) > _V2_MAX_DEFINITIONS:
        raise ValueError("schema definitions are invalid or exceed the limit")
    definitions: dict[str, dict[str, Any]] = {}
    for name in sorted(definitions_raw):
        definition_name = _v2_text(name, "definition name", 120)
        raw_definition = definitions_raw[name]
        if not isinstance(raw_definition, dict):
            raise ValueError(f"schema definition {definition_name} must be an object")
        raw_definition_fields = raw_definition.get("fields", [])
        if not isinstance(raw_definition_fields, list) or len(raw_definition_fields) > budgets["max_fields"]:
            raise ValueError(f"schema definition {definition_name} fields exceed the limit")
        definitions[definition_name] = {
            "name": str(raw_definition.get("name", definition_name))[:120],
            "description": str(raw_definition.get("description", ""))[:_V2_MAX_DESCRIPTION],
            "fields": [_v2_normalize_field(item, index=index, parent_id=definition_name, require_id=False) for index, item in enumerate(raw_definition_fields)],
        }
        _v2_fill_coordinates(definitions[definition_name]["fields"], coordinate_system)
    all_fields = list(_v2_walk_fields(fields)) + [field for definition in definitions.values() for field in _v2_walk_fields(definition["fields"])]
    if len(all_fields) > budgets["max_fields"]:
        raise ValueError("schema fields are missing or exceed the limit")
    field_ids = [field["id"] for field in all_fields]
    duplicates = sorted({field_id for field_id in field_ids if field_ids.count(field_id) > 1})
    if duplicates:
        raise ValueError(f"schema field ids must be unique: {duplicates[0]}")
    relationships_raw = schema.get("relationships", schema.get("checksums", schema.get("checksum_relationships", [])))
    if not isinstance(relationships_raw, list) or len(relationships_raw) > budgets["max_fields"]:
        raise ValueError("schema relationships are invalid or exceed the limit")
    relationships: list[dict[str, Any]] = []
    for index, relationship in enumerate(relationships_raw):
        if not isinstance(relationship, dict):
            raise ValueError(f"schema relationship {index} must be an object")
        item = _v2_json_safe(relationship)
        item.setdefault("id", f"relationship_{index}")
        item.setdefault("kind", "checksum")
        relationships.append(item)
    refs_by_id, diagnostics = _v2_schema_graph(fields, definitions)
    normalized = {
        "schema_version": SCHEMA_V2_VERSION,
        "name": str(schema.get("name", "PacketScope protocol"))[:120] or "PacketScope protocol",
        "description": str(schema.get("description", ""))[:_V2_MAX_DESCRIPTION],
        "coordinate_system": coordinate_system,
        "coordinate": _v2_json_safe(schema.get("coordinate")) if schema.get("coordinate") is not None else None,
        "coordinates": _v2_json_safe(schema.get("coordinates", {})),
        "budgets": budgets, "fields": fields, "definitions": definitions,
        "relationships": relationships, "source": _v2_json_safe(schema.get("source", {})),
        "metadata": _v2_json_safe(schema.get("metadata", {})),
        "diagnostics": diagnostics,
        "dependencies": {field_id: sorted(refs_by_id.get(field_id, set())) for field_id in sorted(refs_by_id)},
    }
    json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return normalized


def _v2_status_result(status: str, *, value: Any = None, internal: Any = None, diagnostics: list[dict[str, Any]] | None = None, offset: int | None = None, length: int | None = None) -> dict[str, Any]:
    return {"status": status, "value": value, "internal": internal, "diagnostics": diagnostics or [], "offset": offset, "length": length}


def _v2_diag(status: str, code: str, message: str, **extra: Any) -> dict[str, Any]:
    result = {"status": status, "code": code, "message": message}
    result.update(extra)
    return result


def _v2_numeric(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _v2_eval_expr(expr: Any, values: dict[str, dict[str, Any]], budgets: dict[str, int], *, depth: int = 0) -> dict[str, Any]:
    if depth > budgets["max_expression_depth"]:
        return {"status": "LIMIT_EXCEEDED", "value": None, "diagnostics": [_v2_diag("LIMIT_EXCEEDED", "expression_depth", "expression depth exceeds the schema budget")]}
    if expr is None:
        return {"status": "UNKNOWN", "value": None, "diagnostics": [_v2_diag("UNKNOWN", "missing_expression", "expression is not declared")]}
    if isinstance(expr, (str, bool, int, float)):
        if isinstance(expr, float) and (expr != expr or expr in (float("inf"), float("-inf"))):
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "non_finite", "expression number is not finite")]}
        return {"status": "RESOLVED", "value": expr, "diagnostics": []}
    if isinstance(expr, list):
        return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "expression_object_required", "expression lists are only valid as operation arguments")]}
    if not isinstance(expr, dict):
        return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "expression_type", "expression value is unsupported")]}
    if "static" in expr and len(expr) == 1:
        return _v2_eval_expr(expr["static"], values, budgets, depth=depth + 1)
    kind = str(expr.get("kind", "")).lower()
    if kind in {"constant", "const", "literal", "static"}:
        return _v2_eval_expr(expr.get("value", expr.get("constant", expr.get("const"))), values, budgets, depth=depth + 1)
    if kind in {"field", "field_ref", "field_reference", "reference", "ref"}:
        reference = next((expr.get(key) for key in ("field_id", "id", "name", "field", "ref") if isinstance(expr.get(key), str)), None)
        return _v2_eval_expr({"field": reference}, values, budgets, depth=depth + 1)
    if "const" in expr or "constant" in expr:
        return _v2_eval_expr(expr.get("const", expr.get("constant")), values, budgets, depth=depth + 1)
    ref_key = next((key for key in ("field", "ref", "field_ref") if key in expr), None)
    if ref_key is not None:
        reference = expr[ref_key]
        if not isinstance(reference, str):
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "reference_type", "field reference must be a string")]}
        entry = values.get(reference)
        if entry is None:
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "missing_reference", f"field reference {reference!r} does not exist", reference=reference)]}
        if entry.get("status") != "RESOLVED":
            return {"status": entry.get("status", "UNKNOWN"), "value": None, "diagnostics": [_v2_diag(entry.get("status", "UNKNOWN"), "dependency_status", f"field reference {reference!r} is not resolved", reference=reference)]}
        result = {"status": "RESOLVED", "value": entry.get("internal"), "diagnostics": []}
        for key in ("add", "subtract", "multiply", "mask", "min", "max", "align"):
            if key in expr:
                result = _v2_apply_op(key, [result, _v2_eval_expr(expr[key], values, budgets, depth=depth + 1)], budgets)
                if result["status"] != "RESOLVED":
                    return result
        return result
    op = expr.get("op", kind or None)
    if op in {"comparison", "compare", "boolean", "arithmetic"}:
        op = expr.get("operator", expr.get("operation"))
    args = expr.get("args", expr.get("terms", expr.get("operands", expr.get("values"))))
    if str(op).lower() in {"const", "constant", "literal"}:
        return _v2_eval_expr(expr.get("value", expr.get("constant", expr.get("const"))), values, budgets, depth=depth + 1)
    if str(op).lower() in {"field", "field_ref", "field_reference", "reference", "ref"}:
        reference = next((expr.get(key) for key in ("field_id", "id", "name", "field", "ref") if isinstance(expr.get(key), str)), None)
        return _v2_eval_expr({"field": reference}, values, budgets, depth=depth + 1)
    if op is None:
        for candidate in sorted(_V2_OPERATION_NAMES | set(_V2_OP_ALIASES)):
            if candidate in expr:
                op, args = candidate, expr[candidate]
                break
        if op is None:
            if "value" in expr:
                result = _v2_eval_expr(expr["value"], values, budgets, depth=depth + 1)
                if "mask" in expr and result["status"] == "RESOLVED":
                    result = _v2_apply_op("mask", [result, _v2_eval_expr(expr["mask"], values, budgets, depth=depth + 1)], budgets)
                return result
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "unsupported_expression", "expression form is unsupported")]}
    op = _V2_OP_ALIASES.get(str(op).lower(), str(op).lower())
    if args is None:
        if "left" in expr or "right" in expr:
            args = [expr.get("left"), expr.get("right")]
        elif op in {"not", "negate"}:
            args = [expr.get("value", expr.get("arg", expr.get("input")))]
        elif op == "mask":
            args = [expr.get("value", expr.get("input")), expr.get("mask")]
        elif op == "align":
            args = [expr.get("value"), expr.get("alignment", expr.get("boundary"))]
        elif op == "multiply" and "factor" in expr:
            args = [expr.get("value"), expr.get("factor")]
    if not isinstance(args, list):
        args = [args]
    if len(args) > _V2_MAX_EXPRESSION_KEYS:
        return {"status": "LIMIT_EXCEEDED", "value": None, "diagnostics": [_v2_diag("LIMIT_EXCEEDED", "expression_arguments", "expression has too many arguments")]}
    evaluated = [_v2_eval_expr(arg, values, budgets, depth=depth + 1) for arg in args]
    for result in evaluated:
        if result["status"] != "RESOLVED":
            return result
    result = _v2_apply_op(op, evaluated, budgets)
    bounded_limit = expr.get("max", expr.get("limit", expr.get("bound"))) if op == "multiply" else None
    if result["status"] == "RESOLVED" and bounded_limit is not None:
        limit_result = _v2_eval_expr(bounded_limit, values, budgets, depth=depth + 1)
        limit = _v2_numeric(limit_result.get("value")) if limit_result["status"] == "RESOLVED" else None
        if limit is None or _v2_numeric(result.get("value")) is None:
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "multiply_limit", "bounded multiply limit must be an integer")]}
        if abs(_v2_numeric(result["value"])) > limit:
            return {"status": "LIMIT_EXCEEDED", "value": None, "diagnostics": [_v2_diag("LIMIT_EXCEEDED", "multiply_limit", "bounded multiply exceeds its declared limit")]}
    return result


def _v2_apply_op(op: str, evaluated: list[dict[str, Any]], budgets: dict[str, int]) -> dict[str, Any]:
    values = [item.get("value") for item in evaluated]
    def numbers() -> list[int] | None:
        converted = [_v2_numeric(value) for value in values]
        return converted if all(value is not None for value in converted) else None
    if op in {"add", "subtract", "multiply", "mask", "bitor", "xor", "min", "max", "align"}:
        converted = numbers()
        if converted is None or not converted:
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "numeric_operands", f"{op} requires integer operands")]}
        if op == "add": result = sum(converted)
        elif op == "subtract": result = converted[0] - sum(converted[1:]) if len(converted) > 1 else -converted[0]
        elif op == "multiply":
            result = 1
            for value in converted: result *= value
        elif op == "mask":
            if len(converted) != 2:
                return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "mask_operands", "mask requires a value and a mask")]}
            result = converted[0] & converted[1]
        elif op == "bitor":
            result = 0
            for value in converted: result |= value
        elif op == "xor":
            result = 0
            for value in converted: result ^= value
        elif op == "min": result = min(converted)
        elif op == "max": result = max(converted)
        else:
            if len(converted) != 2 or converted[1] <= 0:
                return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "alignment", "alignment requires a positive boundary")]}
            result = ((converted[0] + converted[1] - 1) // converted[1]) * converted[1]
        if abs(result) > budgets["max_expression_value"]:
            return {"status": "LIMIT_EXCEEDED", "value": None, "diagnostics": [_v2_diag("LIMIT_EXCEEDED", "expression_value", "expression result exceeds the schema budget")]}
        return {"status": "RESOLVED", "value": result, "diagnostics": []}
    if op in {"eq", "ne", "lt", "lte", "gt", "gte"}:
        if len(values) != 2:
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "comparison_operands", "comparison requires two operands")]}
        if op == "eq": result = values[0] == values[1]
        elif op == "ne": result = values[0] != values[1]
        elif op == "lt": result = values[0] < values[1]
        elif op == "lte": result = values[0] <= values[1]
        elif op == "gt": result = values[0] > values[1]
        else: result = values[0] >= values[1]
        return {"status": "RESOLVED", "value": bool(result), "diagnostics": []}
    if op in {"and", "or"}:
        if not all(isinstance(value, (bool, int)) for value in values):
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "boolean_operands", f"{op} requires boolean operands")]}
        result = all(bool(value) for value in values) if op == "and" else any(bool(value) for value in values)
        return {"status": "RESOLVED", "value": result, "diagnostics": []}
    if op == "not":
        if len(values) != 1 or not isinstance(values[0], (bool, int)):
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "boolean_operand", "not requires one boolean operand")]}
        return {"status": "RESOLVED", "value": not bool(values[0]), "diagnostics": []}
    if op == "negate":
        converted = numbers()
        if len(converted or []) != 1:
            return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "numeric_operand", "negate requires one integer operand")]}
        if abs(-converted[0]) > budgets["max_expression_value"]:
            return {"status": "LIMIT_EXCEEDED", "value": None, "diagnostics": [_v2_diag("LIMIT_EXCEEDED", "expression_value", "expression result exceeds the schema budget")]}
        return {"status": "RESOLVED", "value": -converted[0], "diagnostics": []}
    return {"status": "INVALID", "value": None, "diagnostics": [_v2_diag("INVALID", "unsupported_operation", f"operation {op!r} is unsupported")]}


def _v2_decode_value(raw: bytes, field: dict[str, Any]) -> tuple[str, Any, Any, list[dict[str, Any]]]:
    type_name = field["type"].lower()
    if type_name in _V2_INT_TYPES or type_name in {"uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer"}:
        if type_name in _V2_INT_TYPES:
            width, signed = _V2_INT_TYPES[type_name]
            if len(raw) != width:
                return "INVALID", None, None, [_v2_diag("INVALID", "integer_width", "integer field width does not match its type")]
        else:
            width, signed = len(raw), type_name in {"int", "signed", "signed_integer"}
            if width <= 0 or width > 16:
                return "INVALID", None, None, [_v2_diag("INVALID", "integer_width", "generic integer width is unsupported")]
        if field["endian"] not in {"big", "little"}:
            return "INVALID", None, None, [_v2_diag("INVALID", "integer_endian", "integer fields require big or little endian")]
        value = int.from_bytes(raw, field["endian"], signed=signed)
        return "RESOLVED", value, value, []
    if type_name in {"bool", "boolean"}:
        value = bool(int.from_bytes(raw, "big"))
        return "RESOLVED", value, value, []
    if type_name in {"text", "string", "utf8", "ascii"}:
        encoding = field.get("encoding") or ("ascii" if type_name == "ascii" else "utf-8")
        try:
            value = raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            return "INVALID", None, None, [_v2_diag("INVALID", "text_decode", f"cannot decode field as {encoding}")]
        return "RESOLVED", value, value, []
    if type_name in {"bytes", "raw", "opaque", "custom", "hex", "checksum", "crc"}:
        value = raw.hex()
        return "RESOLVED", value, raw, []
    if type_name in {"struct", "structure", "array"}:
        return "INVALID", None, None, [_v2_diag("INVALID", "unsupported_shape", "structured field requires a structure or array descriptor")]
    return "INVALID", None, None, [_v2_diag("INVALID", "unsupported_type", f"field type {type_name!r} is unsupported")]


def _v2_public_field(field: dict[str, Any], result: dict[str, Any], *, value: Any = None, present: bool = True, items: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    diagnostics = sorted(result.get("diagnostics", []), key=lambda item: (item.get("code", ""), item.get("message", ""), str(item.get("reference", ""))))
    output = {
        "id": field["id"], "name": field["name"], "description": field.get("description", ""),
        "status": result["status"], "present": present,
        "available": result["status"] == "RESOLVED" and present,
        "offset": result.get("offset"), "length": result.get("length"), "width": result.get("length"),
        "coordinate_system": field.get("coordinate_system"), "value": value if present else None,
        "value_encoding": "decimal" if isinstance(value, int) and not isinstance(value, bool) else "boolean" if isinstance(value, bool) else "text" if isinstance(value, str) and field["type"] in {"text", "string", "utf8", "ascii"} else "hex" if isinstance(value, str) else None,
        "diagnostics": diagnostics,
    }
    if items is not None: output["items"] = items
    if field.get("checksum") is not None or field.get("relationship") is not None:
        output["relationship"] = field.get("checksum", field.get("relationship"))
    return output


def _v2_parse_field(field: dict[str, Any], *, base_offset: int, data: bytes | None, metadata: dict[str, Any], values: dict[str, dict[str, Any]], checked: dict[str, Any], depth: int = 0, store: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    budgets = checked["budgets"]
    if depth > budgets["max_nesting"]:
        result = _v2_status_result("LIMIT_EXCEEDED", diagnostics=[_v2_diag("LIMIT_EXCEEDED", "nesting", "nested structure exceeds the schema budget")])
        return _v2_public_field(field, result, present=False), result
    presence = _v2_eval_expr(field.get("presence", True), values, budgets)
    if presence["status"] != "RESOLVED":
        result = _v2_status_result(presence["status"], diagnostics=presence.get("diagnostics", []))
        output = _v2_public_field(field, result, present=False)
        if store: values[field["id"]] = result
        return output, result
    if not bool(presence.get("value")):
        # A resolved false condition is a legitimate absence, not an
        # unresolved dependency. Keep the field status RESOLVED while
        # retaining an explicit diagnostic so consumers can distinguish it
        # from UNKNOWN (condition could not be evaluated).
        result = _v2_status_result("RESOLVED", diagnostics=[_v2_diag("RESOLVED", "conditional_absent", "field is not present because its condition is false")])
        output = _v2_public_field(field, result, present=False)
        if store: values[field["id"]] = result
        return output, result
    offset_result = _v2_eval_expr(field.get("offset", 0), values, budgets)
    if offset_result["status"] != "RESOLVED":
        result = _v2_status_result(offset_result["status"], diagnostics=offset_result.get("diagnostics", []))
        output = _v2_public_field(field, result)
        if store: values[field["id"]] = result
        return output, result
    relative_offset = _v2_numeric(offset_result.get("value"))
    if isinstance(offset_result.get("value"), bool):
        relative_offset = None
    if relative_offset is None or relative_offset < 0:
        result = _v2_status_result("INVALID", diagnostics=[_v2_diag("INVALID", "offset", "field offset must be a non-negative integer")])
        output = _v2_public_field(field, result)
        if store: values[field["id"]] = result
        return output, result
    absolute_offset = base_offset + relative_offset
    if absolute_offset > budgets["max_bytes_per_packet"]:
        result = _v2_status_result("LIMIT_EXCEEDED", offset=absolute_offset, diagnostics=[_v2_diag("LIMIT_EXCEEDED", "packet_budget", "field offset exceeds the packet budget")])
        output = _v2_public_field(field, result)
        if store: values[field["id"]] = result
        return output, result
    if data is None or not metadata.get("available"):
        result = _v2_status_result("UNAVAILABLE", offset=absolute_offset, diagnostics=[_v2_diag("UNAVAILABLE", "coordinate_unavailable", "declared coordinate system is unavailable for this packet")])
        output = _v2_public_field(field, result)
        if store: values[field["id"]] = result
        return output, result
    array = field.get("array")
    nested_fields = field.get("fields")
    definition = field.get("definition")
    if definition is not None:
        definition_item = checked["definitions"].get(definition)
        if definition_item is None:
            result = _v2_status_result("INVALID", offset=absolute_offset, diagnostics=[_v2_diag("INVALID", "missing_definition", f"definition {definition!r} does not exist")])
            output = _v2_public_field(field, result)
            if store: values[field["id"]] = result
            return output, result
        nested_fields = definition_item.get("fields", [])
    if isinstance(array, dict):
        output, result = _v2_parse_array(field, array, absolute_offset, data, metadata, values, checked, depth)
        if store: values[field["id"]] = result
        return output, result
    if isinstance(nested_fields, list) or field["type"] in {"struct", "structure"}:
        if not isinstance(nested_fields, list):
            result = _v2_status_result("INVALID", offset=absolute_offset, diagnostics=[_v2_diag("INVALID", "nested_fields", "structured field has no fields")])
            output = _v2_public_field(field, result)
            if store: values[field["id"]] = result
            return output, result
        nested_values: dict[str, dict[str, Any]] = {}
        nested_outputs: list[dict[str, Any]] = []
        nested_end = absolute_offset
        nested_status = "RESOLVED"
        for child in nested_fields:
            child_output, child_result = _v2_parse_field(child, base_offset=absolute_offset, data=data, metadata=metadata, values={**values, **nested_values}, checked=checked, depth=depth + 1)
            nested_outputs.append(child_output)
            nested_values[child["id"]] = child_result
            if child_result.get("status") != "RESOLVED":
                nested_status = _v2_merge_status(nested_status, child_result.get("status", "INVALID"))
            child_offset, child_length = child_result.get("offset"), child_result.get("length")
            if isinstance(child_offset, int) and isinstance(child_length, int):
                nested_end = max(nested_end, child_offset + child_length)
        explicit_length = None
        if field.get("length") is not None:
            length_result = _v2_eval_expr(field["length"], values, budgets)
            if length_result["status"] != "RESOLVED":
                nested_status = _v2_merge_status(nested_status, length_result["status"])
            else:
                explicit_length = _v2_numeric(length_result.get("value"))
        length = explicit_length if explicit_length is not None else max(0, nested_end - absolute_offset)
        if length > budgets["max_field_length"]: nested_status = _v2_merge_status(nested_status, "LIMIT_EXCEEDED")
        if absolute_offset + length > len(data): nested_status = _v2_merge_status(nested_status, "OUT_OF_BOUNDS")
        diagnostics = [] if nested_status == "RESOLVED" else [_v2_diag(nested_status, "nested_status", "nested structure contains a non-resolved field")]
        result = _v2_status_result(nested_status, value={child["id"]: child_output.get("value") for child, child_output in zip(nested_fields, nested_outputs)}, internal={child["id"]: nested_values[child["id"]].get("internal") for child in nested_fields}, diagnostics=diagnostics, offset=absolute_offset, length=length)
        output = _v2_public_field(field, result, value=result.get("value"))
        output["fields"] = nested_outputs
        if store: values[field["id"]] = result
        return output, result
    length_result = _v2_eval_expr(field.get("length"), values, budgets) if field.get("length") is not None else None
    if length_result is None:
        length = _v2_type_width(field["type"])
        if length is None:
            result = _v2_status_result("INVALID", offset=absolute_offset, diagnostics=[_v2_diag("INVALID", "missing_length", "byte field requires a static or dynamic length")])
            output = _v2_public_field(field, result)
            if store: values[field["id"]] = result
            return output, result
    else:
        if length_result["status"] != "RESOLVED":
            result = _v2_status_result(length_result["status"], offset=absolute_offset, diagnostics=length_result.get("diagnostics", []))
            output = _v2_public_field(field, result)
            if store: values[field["id"]] = result
            return output, result
        length = _v2_numeric(length_result.get("value"))
        if isinstance(length_result.get("value"), bool):
            length = None
    if length is None or length < 0:
        result = _v2_status_result("INVALID", offset=absolute_offset, diagnostics=[_v2_diag("INVALID", "length", "field length must be a non-negative integer")])
        output = _v2_public_field(field, result)
        if store: values[field["id"]] = result
        return output, result
    if length > budgets["max_field_length"]:
        result = _v2_status_result("LIMIT_EXCEEDED", offset=absolute_offset, length=length, diagnostics=[_v2_diag("LIMIT_EXCEEDED", "field_length", "field length exceeds the schema budget")])
        output = _v2_public_field(field, result)
        if store: values[field["id"]] = result
        return output, result
    if absolute_offset + length > budgets["max_bytes_per_packet"]:
        result = _v2_status_result("LIMIT_EXCEEDED", offset=absolute_offset, length=length, diagnostics=[_v2_diag("LIMIT_EXCEEDED", "packet_budget", "field range exceeds the packet budget")])
        output = _v2_public_field(field, result)
        if store: values[field["id"]] = result
        return output, result
    if absolute_offset + length > len(data):
        result = _v2_status_result("OUT_OF_BOUNDS", offset=absolute_offset, length=length, diagnostics=[_v2_diag("OUT_OF_BOUNDS", "truncated_field", "field range extends beyond captured bytes")])
        output = _v2_public_field(field, result)
        if store: values[field["id"]] = result
        return output, result
    status, public_value, internal, diagnostics = _v2_decode_value(data[absolute_offset:absolute_offset + length], field)
    result = _v2_status_result(status, value=public_value, internal=internal, diagnostics=diagnostics, offset=absolute_offset, length=length)
    output = _v2_public_field(field, result, value=public_value)
    if store: values[field["id"]] = result
    return output, result


def _v2_parse_array(field: dict[str, Any], array: dict[str, Any], absolute_offset: int, data: bytes, metadata: dict[str, Any], values: dict[str, dict[str, Any]], checked: dict[str, Any], depth: int) -> tuple[dict[str, Any], dict[str, Any]]:
    budgets = checked["budgets"]
    count_result = _v2_eval_expr(array.get("count"), values, budgets)
    if count_result["status"] != "RESOLVED":
        result = _v2_status_result(count_result["status"], offset=absolute_offset, diagnostics=count_result.get("diagnostics", []))
        return _v2_public_field(field, result), result
    count = _v2_numeric(count_result.get("value"))
    if isinstance(count_result.get("value"), bool):
        count = None
    if count is None or count < 0:
        result = _v2_status_result("INVALID", offset=absolute_offset, diagnostics=[_v2_diag("INVALID", "array_count", "array count must be a non-negative integer")])
        return _v2_public_field(field, result), result
    max_items = array.get("max_items") or budgets["max_array_items"]
    if count > min(max_items, budgets["max_array_items"]):
        result = _v2_status_result("LIMIT_EXCEEDED", offset=absolute_offset, diagnostics=[_v2_diag("LIMIT_EXCEEDED", "array_items", "array count exceeds the schema budget", count=count, limit=min(max_items, budgets["max_array_items"]))])
        return _v2_public_field(field, result), result
    runtime = checked.setdefault("_runtime", {"array_items": 0})
    if runtime["array_items"] + count > budgets["max_total_array_items"]:
        result = _v2_status_result("LIMIT_EXCEEDED", offset=absolute_offset, diagnostics=[_v2_diag("LIMIT_EXCEEDED", "array_items_total", "total array items exceed the schema budget", count=count, used=runtime["array_items"], limit=budgets["max_total_array_items"])])
        return _v2_public_field(field, result), result
    runtime["array_items"] += count
    element = array.get("element")
    if not isinstance(element, dict):
        result = _v2_status_result("INVALID", offset=absolute_offset, diagnostics=[_v2_diag("INVALID", "array_element", "array element descriptor is invalid")])
        return _v2_public_field(field, result), result
    items: list[dict[str, Any]] = []
    public_values: list[Any] = []
    cursor, status = absolute_offset, "RESOLVED"
    for index in range(count):
        item_output, item_result = _v2_parse_field(element, base_offset=cursor, data=data, metadata=metadata, values=values, checked=checked, depth=depth + 1, store=False)
        item_output["index"] = index
        items.append(item_output)
        public_values.append(item_output.get("value"))
        status = _v2_merge_status(status, item_result.get("status", "INVALID"))
        item_offset, item_length = item_result.get("offset"), item_result.get("length")
        if isinstance(item_offset, int) and isinstance(item_length, int): cursor = item_offset + item_length
        else: break
        if cursor > len(data):
            status = _v2_merge_status(status, "OUT_OF_BOUNDS")
            break
    length = max(0, cursor - absolute_offset)
    if field.get("length") is not None:
        declared = _v2_eval_expr(field["length"], values, budgets)
        if declared["status"] != "RESOLVED": status = _v2_merge_status(status, declared["status"])
        else:
            declared_length = _v2_numeric(declared.get("value"))
            if declared_length is not None and length > declared_length: status = _v2_merge_status(status, "OUT_OF_BOUNDS")
            elif declared_length is not None: length = declared_length
    result = _v2_status_result(status, value=public_values, internal=public_values, diagnostics=[] if status == "RESOLVED" else [_v2_diag(status, "array_status", "array contains a non-resolved element")], offset=absolute_offset, length=length)
    return _v2_public_field(field, result, value=public_values, items=items), result


def _v2_merge_status(current: str, candidate: str) -> str:
    priority = {"RESOLVED": 0, "UNKNOWN": 1, "UNAVAILABLE": 2, "OUT_OF_BOUNDS": 3, "INVALID": 4, "CYCLIC": 5, "LIMIT_EXCEEDED": 6}
    return candidate if priority.get(candidate, 4) > priority.get(current, 0) else current


def _v2_apply_packet(checked: dict[str, Any], packet: Packet) -> dict[str, Any]:
    checked["_runtime"] = {"array_items": 0}
    values: dict[str, dict[str, Any]] = {}
    records: dict[str, dict[str, Any]] = {}
    field_outputs: dict[str, dict[str, Any]] = {}
    field_map = {field["id"]: field for field in checked["fields"]}
    refs_by_id, graph_diagnostics = _v2_schema_graph(checked["fields"], checked["definitions"])
    cyclic = {item["field_id"] for item in graph_diagnostics if item.get("code") == "dependency_cycle"}
    missing = {(item.get("field_id"), item.get("reference")) for item in graph_diagnostics if item.get("code") == "missing_reference"}
    state: dict[str, int] = {}
    order: list[str] = []

    def visit(field_id: str) -> None:
        if state.get(field_id) in {1, 2}:
            return
        state[field_id] = 1
        for dependency in sorted(refs_by_id.get(field_id, set())):
            if dependency in field_map:
                visit(dependency)
        state[field_id] = 2
        order.append(field_id)

    for field in checked["fields"]:
        visit(field["id"])
    for field_id in order:
        field = field_map[field_id]
        if field_id in cyclic:
            result = _v2_status_result("CYCLIC", diagnostics=[_v2_diag("CYCLIC", "dependency_cycle", "field dependency cycle prevents evaluation")])
            output = _v2_public_field(field, result, present=False)
        elif any(item[0] == field_id for item in missing):
            refs = sorted(item[1] for item in missing if item[0] == field_id)
            result = _v2_status_result("INVALID", diagnostics=[_v2_diag("INVALID", "missing_reference", f"field reference {reference!r} does not exist", reference=reference) for reference in refs])
            output = _v2_public_field(field, result)
        else:
            coordinate_system = field.get("coordinate_system") or checked["coordinate_system"]
            data, metadata = coordinate_bytes(packet, coordinate_system)
            output, result = _v2_parse_field(field, base_offset=0, data=data, metadata=metadata, values=values, checked=checked)
        values[field_id] = result
        records[field_id] = result
        field_outputs[field_id] = output
    fields = [field_outputs[field["id"]] for field in checked["fields"]]
    diagnostics = list(checked.get("diagnostics", []))
    diagnostics.extend(item for item in graph_diagnostics if item not in diagnostics)
    for relationship in checked.get("relationships", []):
        diagnostics.append(_v2_diag("INVALID", "checksum_relationship_unsupported", "checksum relationship is descriptive and is not executed", relationship_id=str(relationship.get("id", "relationship"))))
    diagnostics = sorted(diagnostics, key=lambda item: (str(item.get("field_id", "")), str(item.get("code", "")), str(item.get("reference", item.get("relationship_id", "")))))
    packet_status = "RESOLVED"
    for field in fields:
        packet_status = _v2_merge_status(packet_status, field.get("status", "INVALID"))
    return {"packet_id": packet.index, "status": packet_status, "fields": fields, "diagnostics": diagnostics}


def _apply_schema_v2(schema: dict[str, Any], packets: Iterable[Packet], max_packets: int = 100_000) -> dict[str, Any]:
    checked = _validate_schema_v2(schema)
    packet_limit = min(max_packets, checked["budgets"]["max_packets"])
    if packet_limit <= 0:
        raise ValueError("packet count exceeds schema application limit")
    values: list[dict[str, Any]] = []
    truncated_input = False
    for packet in packets:
        if len(values) >= packet_limit:
            truncated_input = True
            break
        values.append(_v2_apply_packet(checked, packet))
    diagnostics: list[dict[str, Any]] = []
    if truncated_input:
        diagnostics.append(_v2_diag("LIMIT_EXCEEDED", "packet_count", "packet input exceeded the application budget", limit=packet_limit))
    result = {
        "schema_version": SCHEMA_V2_VERSION,
        "status": "LIMIT_EXCEEDED" if truncated_input else "RESOLVED",
        "field_count": len(checked["fields"]), "packet_count": len(values),
        "values": values, "diagnostics": diagnostics,
        "schema_diagnostics": checked.get("diagnostics", []),
        "budgets": checked["budgets"],
    }
    json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return result


def validate_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Validate either the unchanged V1 shape or the declarative V2 shape."""
    if isinstance(schema, dict) and schema.get("schema_version") == SCHEMA_V2_VERSION:
        return _validate_schema_v2(schema)
    return _validate_schema_v1(schema)


def apply_schema(schema: dict[str, Any], packets: Iterable[Packet], max_packets: int = 100_000) -> dict[str, Any]:
    if isinstance(schema, dict) and schema.get("schema_version") == SCHEMA_V2_VERSION:
        return _apply_schema_v2(schema, packets, max_packets=max_packets)
    return _apply_schema_v1(schema, packets, max_packets=max_packets)


def _validate_capture_against_schema_v2(schema: dict[str, Any], packets: Iterable[Packet], *, max_packets: int = 100_000) -> dict[str, Any]:
    checked = _validate_schema_v2(schema)
    applied = _apply_schema_v2(checked, packets, max_packets=max_packets)
    packet_diagnostics: list[dict[str, Any]] = []
    for packet in applied["values"]:
        field_statuses = {field.get("status") for field in packet.get("fields", [])}
        if field_statuses <= {"RESOLVED", "UNKNOWN"}:
            status = "ok" if "UNKNOWN" not in field_statuses else "incomplete"
        else:
            status = "violated"
        packet_diagnostics.append({"packet_id": packet["packet_id"], "status": status, "schema_status": packet.get("status"), "fields": packet.get("fields", []), "diagnostics": packet.get("diagnostics", [])})
    return {
        "schema_version": SCHEMA_V2_VERSION,
        "summary": {
            "packet_count": len(packet_diagnostics),
            "decoded_packets": sum(item["status"] == "ok" for item in packet_diagnostics),
            "incomplete_packets": sum(item["status"] == "incomplete" for item in packet_diagnostics),
            "invalid_packets": sum(item["status"] == "violated" for item in packet_diagnostics),
            "schema_diagnostics": len(applied.get("schema_diagnostics", [])),
            "application_status": applied.get("status"),
        },
        "packets": packet_diagnostics,
        "diagnostics": applied.get("diagnostics", []),
        "schema_diagnostics": applied.get("schema_diagnostics", []),
    }


def validate_capture_against_schema(schema: dict[str, Any], packets: Iterable[Packet], *, max_packets: int = 100_000) -> dict[str, Any]:
    if isinstance(schema, dict) and schema.get("schema_version") == SCHEMA_V2_VERSION:
        return _validate_capture_against_schema_v2(schema, packets, max_packets=max_packets)
    return _validate_capture_against_schema_v1(schema, packets, max_packets=max_packets)


def migrate_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Convert a V1 fixed-range schema to V2 without inventing dynamic rules."""
    checked = _validate_schema_v1(schema)
    import hashlib
    fields: list[dict[str, Any]] = []
    for field in checked["fields"]:
        identity = json.dumps({"name": field["name"], "type": field["type"], "offset": field["offset"], "width": field["width"], "coordinate_system": field["coordinate_system"]}, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        fields.append({
            "id": f"{_v2_slug(field['name'])}_{digest}", "name": field["name"],
            "description": "Migrated from Schema V1 fixed-range field.",
            "type": field["type"].lower(), "offset": field["offset"], "length": field["width"],
            "endian": field["endian"], "coordinate_system": field["coordinate_system"],
            "constraints": field.get("constraints", {}),
            "metadata": {"origin": field.get("origin"), "review_status": field.get("review_status"), "evidence_refs": field.get("evidence_refs", []), "known_limitations": field.get("known_limitations", [])},
        })
    return _validate_schema_v2({
        "schema_version": SCHEMA_V2_VERSION, "name": schema.get("name", "PacketScope protocol"),
        "coordinate_system": checked.get("coordinate_system", DEFAULT_COORDINATE_SYSTEM), "fields": fields,
        "source": {"migrated_from_schema_version": 1, "source": checked.get("source", {})},
    })


migrate_v1_schema = migrate_schema


def export_schema_v2(result: dict[str, Any], annotations: Iterable[dict[str, Any]] | None = None, name: str = "PacketScope protocol") -> dict[str, Any]:
    """Export the existing evidence shape as a V2 static schema."""
    return migrate_schema(export_schema(result, annotations=annotations, name=name))
