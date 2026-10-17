"""Versioned, non-executable protocol schema export and validation.

Schemas describe reviewed or inferred byte ranges.  They never become parser
code and applying one only reads bounded bytes from already imported packets.
"""
from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Iterable

from packetscope.analysis.crc import STANDARD_CRC, checksum_value, compute_crc
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
_V2_MAX_CONSTRAINT_VALUES = 10_000
_V2_JSON_SAFE_INTEGER_MAX = (1 << 53) - 1
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

# Relationship evaluation intentionally uses the public checksum engine rather
# than maintaining a second implementation here.  The map is an explicit
# allow-list: schema data can select one of these reviewed algorithms, but it
# can never turn a string into a callable.
_V2_CHECKSUM_ALGORITHMS = {
    **{params.name: ("crc", params) for params in STANDARD_CRC},
    "XOR-8": ("checksum", None),
    "ADDITIVE-8": ("checksum", None),
    "ADDITIVE-16": ("checksum", None),
}
_V2_MAX_CHECKSUM_RANGES = 1024


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


def _v2_preflight_field_tree(fields: Any, *, max_fields: int, max_depth: int, path: str, count: list[int]) -> None:
    """Check field-tree expansion limits before recursively normalizing it.

    Normalization copies nested descriptors and array element descriptors.  A
    schema may therefore exhaust the field or nesting budget before the later
    normalized-tree checks get a chance to run.  Keep this pass iterative so a
    hostile descriptor cannot consume Python recursion first.
    """
    if not isinstance(fields, list):
        return
    pending: list[tuple[Any, int, str]] = [(item, 0, f"{path}[{index}]") for index, item in reversed(list(enumerate(fields)))]
    while pending:
        item, depth, item_path = pending.pop()
        count[0] += 1
        if count[0] > max_fields:
            raise ValueError("schema fields are missing or exceed the limit")
        if depth > max_depth:
            raise ValueError(f"{item_path} exceeds the nesting limit")
        if not isinstance(item, dict):
            continue
        nested = item.get("fields")
        if isinstance(nested, list):
            if len(nested) > max_fields:
                raise ValueError("schema fields are missing or exceed the limit")
            pending.extend(
                (child, depth + 1, f"{item_path}.fields[{index}]")
                for index, child in reversed(list(enumerate(nested)))
            )
        array = item.get("array")
        if array is True:
            array = {}
        elif array is None and ("count" in item or "element" in item or str(item.get("type", "")).lower() == "array"):
            array = {"count": item.get("count"), "element": item.get("element")}
        if isinstance(array, dict):
            element = array.get("element", item.get("element"))
            if element is None:
                element = {"type": item.get("element_type", "bytes"), "length": item.get("element_length")}
            pending.append((element, depth + 1, f"{item_path}.array.element"))


def _v2_constraint_container_limits(constraints: dict[str, Any], *, field_index: int) -> None:
    """Reject large constraint collections before copying their values."""
    if len(constraints) > _V2_MAX_EXPRESSION_KEYS:
        raise ValueError(f"schema field {field_index} constraints have too many keys")
    for key, candidate in constraints.items():
        if isinstance(candidate, list) and len(candidate) > _V2_MAX_CONSTRAINT_VALUES:
            raise ValueError(f"schema field {field_index} {key} values exceed the limit")
        if key == "enum" and isinstance(candidate, dict):
            enum_values = candidate.get("values", candidate.get("allowed"))
            if enum_values is None:
                enum_values = list(candidate)
            if isinstance(enum_values, list) and len(enum_values) > _V2_MAX_CONSTRAINT_VALUES:
                raise ValueError(f"schema field {field_index} enum values exceed the limit")


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
    signed = item.get("signed")
    if signed is not None and not isinstance(signed, bool):
        raise ValueError(f"schema field {index} signed is invalid")
    if signed is not None and type_name not in _V2_INT_TYPES and type_name not in {"uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer"}:
        raise ValueError(f"schema field {index} signed is only valid for integer fields")
    offset = item.get("offset", item.get("offset_expr", 0))
    length = item.get("length", item.get("width", item.get("length_expr")))
    if length is None and "width_bits" in item:
        width_bits = item["width_bits"]
        if isinstance(width_bits, bool) or not isinstance(width_bits, int) or width_bits <= 0 or width_bits % 8:
            raise ValueError(f"schema field {index} width_bits is invalid")
        length = width_bits // 8
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
            if isinstance(max_items, bool) or isinstance(max_items, float):
                raise ValueError(f"schema field {index} array max_items is invalid")
            if isinstance(max_items, int):
                normalized_max_items = max_items
            elif isinstance(max_items, str) and max_items.strip().lstrip("-").isdigit():
                normalized_max_items = int(max_items.strip())
            else:
                raise ValueError(f"schema field {index} array max_items is invalid")
            max_items = normalized_max_items
            if max_items <= 0 or max_items > 1_000_000:
                raise ValueError(f"schema field {index} array max_items is out of bounds")
        array = {"count": count, "element": element, "max_items": max_items}
    definition = item.get("definition", item.get("use"))
    if definition is not None and not isinstance(definition, str):
        raise ValueError(f"schema field {index} definition is invalid")
    constraints = item.get("constraints", {})
    if not isinstance(constraints, dict):
        raise ValueError(f"schema field {index} constraints must be an object")
    _v2_constraint_container_limits(constraints, field_index=index)
    constraints = _v2_json_safe(constraints)
    field_path = field_id if parent_id and field_id.startswith(f"{parent_id}.") else f"{parent_id}.{field_id}" if parent_id else field_id
    source_local_id = field_id
    if parent_id and field_id.startswith(f"{parent_id}."):
        source_local_id = field_id[len(parent_id) + 1:]
    return {
        "id": field_id, "name": name.strip(), "description": description,
        "type": type_name, "coordinate_system": coordinate_system,
        "coordinate": normalized_coordinate, "offset": offset, "length": length,
        "endian": endian, "signed": signed, "encoding": str(item.get("encoding", ""))[:40],
        "presence": presence, "fields": nested, "array": array,
        "definition": definition, "constraints": constraints,
        "path": field_path,
        # Retained separately from ``id`` so a definition/template can be
        # instantiated without leaking its declaration scope into instance
        # IDs.  This is intentionally internal; public reports expose the
        # resulting instance path and provenance instead.
        "_source_local_id": source_local_id,
        "metadata": _v2_json_safe(item.get("metadata", {})),
        "provenance": _v2_json_safe(item.get("provenance", {})),
        "algorithm": _v2_json_safe(item.get("algorithm")) if item.get("algorithm") is not None else None,
        "byte_order": _v2_json_safe(item.get("byte_order")) if item.get("byte_order") is not None else None,
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


def _v2_walk_declared_fields(fields: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """Walk field declarations including an array's element template."""
    for field in fields:
        yield field
        nested = field.get("fields")
        if isinstance(nested, list):
            yield from _v2_walk_declared_fields(nested)
        array = field.get("array")
        if isinstance(array, dict) and isinstance(array.get("element"), dict):
            yield from _v2_walk_declared_fields([array["element"]])


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
    constraints = field.get("constraints")
    if isinstance(constraints, dict):
        relation = _v2_constraint_relation_descriptor(field, constraints)
        if isinstance(relation, dict):
            target = relation.get("target", relation.get("field", relation.get("field_id", relation.get("target_field", relation.get("target_field_id")))))
            if isinstance(target, str):
                yield {"field": target}


def _v2_direct_field_expressions(field: dict[str, Any]) -> Iterable[Any]:
    """Yield only expressions owned by one field, not its descendants."""
    yield field.get("offset")
    yield field.get("length")
    yield field.get("presence")
    array = field.get("array")
    if isinstance(array, dict):
        yield array.get("count")
    constraints = field.get("constraints")
    if isinstance(constraints, dict):
        relation = _v2_constraint_relation_descriptor(field, constraints)
        if isinstance(relation, dict):
            target = relation.get("target", relation.get("field", relation.get("field_id", relation.get("target_field", relation.get("target_field_id")))))
            if isinstance(target, str):
                yield {"field": target}
    for descriptor in (field.get("checksum"), field.get("relationship")):
        if isinstance(descriptor, dict):
            yield descriptor


def _v2_schema_graph(fields: list[dict[str, Any]], definitions: dict[str, dict[str, Any]]) -> tuple[dict[str, set[str]], list[dict[str, Any]]]:
    all_ids = {field["id"] for field in _v2_walk_fields(fields)}
    for definition in definitions.values():
        all_ids.update(field["id"] for field in _v2_walk_fields(definition.get("fields", [])))
    refs_by_id: dict[str, set[str]] = {}
    diagnostics: list[dict[str, Any]] = []
    every_field = list(_v2_walk_fields(fields)) + [field for definition in definitions.values() for field in _v2_walk_fields(definition.get("fields", []))]
    for field in every_field:
        refs: set[str] = set()
        for expression in _v2_direct_field_expressions(field):
            _v2_expression_refs(expression, refs)
        refs_by_id[field["id"]] = refs
        for ref in sorted(refs):
            if ref not in all_ids:
                diagnostics.append({"status": "INVALID", "code": "missing_reference", "field_id": field["id"], "reference": ref, "message": f"field reference {ref!r} does not exist"})
        definition = field.get("definition")
        if definition is not None and not field.get("_definition_expanded") and not field.get("_definition_cycle") and definition not in definitions:
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


def _v2_order_scope_fields(fields: list[dict[str, Any]], refs_by_id: dict[str, set[str]]) -> list[dict[str, Any]]:
    """Topologically order one lexical scope while preserving stable ties."""
    by_id = {field["id"]: field for field in fields}
    position = {field["id"]: index for index, field in enumerate(fields)}
    state: dict[str, int] = {}
    ordered: list[dict[str, Any]] = []

    def visit(field_id: str) -> None:
        if state.get(field_id) == 1:
            return
        if state.get(field_id) == 2:
            return
        state[field_id] = 1
        dependencies = [dependency for dependency in refs_by_id.get(field_id, ()) if dependency in by_id]
        dependencies.sort(key=lambda dependency: position[dependency])
        for dependency in dependencies:
            visit(dependency)
        state[field_id] = 2
        ordered.append(by_id[field_id])

    for field in fields:
        visit(field["id"])
    return ordered


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


_V2_REFERENCE_KEYS = frozenset({
    "field", "ref", "field_ref", "field_id", "target", "target_field",
    "target_field_id", "length_field", "length_field_id", "source",
    "source_field_id", "length_of", "covers",
})


def _v2_field_aliases(field: dict[str, Any]) -> tuple[str, ...]:
    """Return local names accepted for a field in its lexical scope."""
    raw = str(field.get("_source_local_id", field.get("id", "")))
    aliases = [raw]
    if "." in raw:
        aliases.append(raw.rsplit(".", 1)[-1])
    if "[]" in raw:
        aliases.append(raw.rsplit("[]", 1)[-1].lstrip("."))
    name = field.get("name")
    if isinstance(name, str) and name.strip():
        aliases.append(name.strip())
    return tuple(dict.fromkeys(alias for alias in aliases if alias))


def _v2_scope_reference(reference: str, local_refs: dict[str, str], visible_refs: dict[str, str]) -> str:
    """Resolve a reference against local then parent scopes.

    Explicit ``./`` and ``../`` prefixes are accepted for callers that need
    to disambiguate a parent field from a same-named child.  Unqualified
    references follow the usual lexical rule: nearest scope wins.
    """
    if reference.startswith("./"):
        return local_refs.get(reference[2:], reference)
    if reference.startswith("../"):
        return visible_refs.get(reference[3:], reference)
    return local_refs.get(reference, visible_refs.get(reference, reference))


def _v2_rewrite_scoped_value(value: Any, local_refs: dict[str, str], visible_refs: dict[str, str]) -> Any:
    """Rewrite declarative reference strings without evaluating schema data."""
    if isinstance(value, list):
        return [_v2_rewrite_scoped_value(item, local_refs, visible_refs) for item in value]
    if not isinstance(value, dict):
        return value
    rewritten: dict[str, Any] = {}
    kind = str(value.get("kind", "")).lower()
    for key, candidate in value.items():
        if key in _V2_REFERENCE_KEYS and isinstance(candidate, str):
            if key in {"field", "ref", "field_ref"} or kind in {"field", "field_ref", "field_reference", "reference", "ref"} or key.endswith("field") or key.endswith("field_id"):
                rewritten[key] = _v2_scope_reference(candidate, local_refs, visible_refs)
                continue
        if key in {"id", "name"} and isinstance(candidate, str) and kind in {"field", "field_ref", "field_reference", "reference", "ref"}:
            rewritten[key] = _v2_scope_reference(candidate, local_refs, visible_refs)
            continue
        rewritten[key] = _v2_rewrite_scoped_value(candidate, local_refs, visible_refs)
    return rewritten


def _v2_direct_scope(fields: list[dict[str, Any]], prefix: str, root_ids: list[str] | None = None) -> tuple[dict[str, str], list[tuple[dict[str, Any], str, str]]]:
    """Assign deterministic IDs to one field scope before rewriting refs."""
    refs: dict[str, str] = {}
    entries: list[tuple[dict[str, Any], str, str]] = []
    for index, field in enumerate(fields):
        local = str(field.get("_source_local_id", field.get("id", f"field_{index}")))
        canonical = root_ids[index] if root_ids is not None else f"{prefix}.{local}" if prefix else local
        entries.append((field, local, canonical))
        for alias in _v2_field_aliases({**field, "_source_local_id": local}):
            refs[alias] = canonical
    return refs, entries


def _v2_field_provenance(
    field: dict[str, Any], canonical_id: str, definition_name: str | None,
    definition_source: Any = None,
) -> dict[str, Any]:
    existing = field.get("provenance")
    provenance = dict(existing) if isinstance(existing, dict) else {}
    provenance.setdefault("source_id", field.get("id"))
    provenance["instance_path"] = canonical_id
    metadata = field.get("metadata")
    if isinstance(metadata, dict) and metadata:
        provenance.setdefault("metadata", deepcopy(metadata))
    if definition_name is not None:
        provenance["definition"] = definition_name
        provenance.setdefault("definition_field_id", field.get("_source_local_id", field.get("id")))
        if isinstance(definition_source, dict) and definition_source:
            provenance.setdefault("definition_source", deepcopy(definition_source))
    return provenance


def _v2_expand_fields(
    fields: list[dict[str, Any]],
    definitions: dict[str, dict[str, Any]],
    *,
    prefix: str = "",
    visible_refs: dict[str, str] | None = None,
    root_ids: list[str] | None = None,
    definition_stack: tuple[str, ...] = (),
    source_definition: str | None = None,
    source_definition_meta: Any = None,
    depth: int = 0,
    max_nesting: int = 16,
) -> list[dict[str, Any]]:
    """Expand reusable structures into an instance-scoped field tree.

    Expansion is deterministic and bounded.  It copies only normalized schema
    data, rewrites references to the nearest lexical scope, and retains the
    declaration identity in ``provenance``.  Definition cycles/depth limits
    are represented as markers consumed by the parser, rather than causing
    unbounded recursion.
    """
    if not isinstance(fields, list):
        return []
    visible = dict(visible_refs or {})
    local_refs, entries = _v2_direct_scope(fields, prefix, root_ids=root_ids)
    scope_refs = {**visible, **local_refs}
    expanded: list[dict[str, Any]] = []
    for source, local_id, canonical_id in entries:
        field = deepcopy(source)
        field["id"] = canonical_id
        field["path"] = canonical_id
        field["_source_local_id"] = local_id
        field["provenance"] = _v2_field_provenance(source, canonical_id, source_definition, source_definition_meta)
        field["_array_visible_refs"] = dict(scope_refs)
        for key in ("offset", "length", "presence", "constraints", "checksum", "relationship"):
            if key in field:
                field[key] = _v2_rewrite_scoped_value(field[key], local_refs, visible)
        array = field.get("array")
        if isinstance(array, dict):
            array = deepcopy(array)
            if "count" in array:
                array["count"] = _v2_rewrite_scoped_value(array["count"], local_refs, visible)
            # Array elements are expanded per item, once an index supplies the
            # missing instance identity.  Keeping the normalized template here
            # avoids sharing mutable output or values between repetitions.
            field["array"] = array

        definition_name = field.get("definition")
        inline_fields = source.get("fields")
        if isinstance(definition_name, str):
            definition_item = definitions.get(definition_name)
            if definition_item is None:
                field["_definition_missing"] = True
            elif definition_name in definition_stack:
                field["_definition_cycle"] = True
            elif depth >= max_nesting:
                field["_definition_depth"] = True
            else:
                field["_definition_expanded"] = True
                field["fields"] = _v2_expand_fields(
                    definition_item.get("fields", []), definitions,
                    prefix=canonical_id, visible_refs=scope_refs,
                    definition_stack=(*definition_stack, definition_name),
                    source_definition=definition_name, depth=depth + 1,
                    source_definition_meta=definition_item.get("source", {}),
                    max_nesting=max_nesting,
                )
        elif isinstance(inline_fields, list):
            field["fields"] = _v2_expand_fields(
                inline_fields, definitions, prefix=canonical_id,
                visible_refs=scope_refs, definition_stack=definition_stack,
                source_definition=source_definition, depth=depth + 1,
                source_definition_meta=source_definition_meta,
                max_nesting=max_nesting,
            )
        expanded.append(field)
    return expanded


def _v2_definition_graph(definitions: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Return deterministic recursive-definition diagnostics."""
    edges: dict[str, set[str]] = {name: set() for name in definitions}
    diagnostics: list[dict[str, Any]] = []
    for name, definition in definitions.items():
        for field in _v2_walk_declared_fields(definition.get("fields", [])):
            target = field.get("definition")
            if isinstance(target, str):
                if target not in definitions:
                    diagnostics.append({
                        "status": "INVALID", "code": "missing_definition",
                        "field_id": f"{name}.{field.get('id', '')}",
                        "reference": target,
                        "message": f"definition {target!r} does not exist",
                    })
                    continue
                edges[name].add(target)
    state: dict[str, int] = {}
    stack: list[str] = []
    cyclic: set[str] = set()

    def visit(name: str) -> None:
        if state.get(name) == 1:
            if name in stack:
                cyclic.update(stack[stack.index(name):])
            return
        if state.get(name) == 2:
            return
        state[name] = 1
        stack.append(name)
        for target in sorted(edges.get(name, ())):
            visit(target)
        stack.pop()
        state[name] = 2

    for name in sorted(edges):
        visit(name)
    diagnostics.extend([
        {"status": "CYCLIC", "code": "definition_cycle", "definition": name,
         "message": f"definition cycle prevents expansion of {name!r}"}
        for name in sorted(cyclic)
    ])
    return sorted(diagnostics, key=lambda item: (
        str(item.get("field_id", "")), str(item.get("code", "")),
        str(item.get("reference", item.get("definition", ""))),
    ))


def _v2_validate_scoped_ids(fields: list[dict[str, Any]], scope: str) -> None:
    """Reject duplicate IDs only within the scope that owns them."""
    seen: set[str] = set()
    for field in fields:
        field_id = str(field.get("id", ""))
        if field_id in seen:
            raise ValueError(f"schema field ids must be unique within {scope}: {field_id}")
        seen.add(field_id)
        nested = field.get("fields")
        if isinstance(nested, list):
            _v2_validate_scoped_ids(nested, f"{scope}.{field_id}")
        array = field.get("array")
        if isinstance(array, dict) and isinstance(array.get("element"), dict):
            _v2_validate_scoped_ids([array["element"]], f"{scope}.{field_id}[]")


def _v2_expansion_diagnostics(fields: list[dict[str, Any]]) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    for field in _v2_walk_declared_fields(fields):
        if field.get("_definition_depth"):
            diagnostics.append({
                "status": "LIMIT_EXCEEDED", "code": "definition_depth",
                "field_id": field["id"], "definition": field.get("definition"),
                "message": "definition expansion exceeds the schema nesting budget",
            })
    return diagnostics


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
    field_count = [0]
    _v2_preflight_field_tree(fields_raw, max_fields=budgets["max_fields"], max_depth=budgets["max_nesting"], path="fields", count=field_count)
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
        _v2_preflight_field_tree(raw_definition_fields, max_fields=budgets["max_fields"], max_depth=budgets["max_nesting"], path=f"definitions.{definition_name}.fields", count=field_count)
        definitions[definition_name] = {
            "name": str(raw_definition.get("name", definition_name))[:120],
            "description": str(raw_definition.get("description", ""))[:_V2_MAX_DESCRIPTION],
            "source": _v2_json_safe(raw_definition.get("source", raw_definition.get("provenance", {}))),
            "metadata": _v2_json_safe(raw_definition.get("metadata", {})),
            "fields": [_v2_normalize_field(item, index=index, parent_id=definition_name, require_id=False) for index, item in enumerate(raw_definition_fields)],
        }
        _v2_fill_coordinates(definitions[definition_name]["fields"], coordinate_system)
    all_fields = list(_v2_walk_fields(fields)) + [field for definition in definitions.values() for field in _v2_walk_fields(definition["fields"])]
    if len(all_fields) > budgets["max_fields"]:
        raise ValueError("schema fields are missing or exceed the limit")
    _v2_validate_scoped_ids(fields, "fields")
    for definition_name, definition in definitions.items():
        _v2_validate_scoped_ids(definition.get("fields", []), f"definition {definition_name}")
    relationship_key = next((key for key in ("relationships", "checksums", "checksum_relationships", "length_relationships") if key in schema), None)
    relationships_raw = schema.get(relationship_key, []) if relationship_key is not None else []
    if not isinstance(relationships_raw, list) or len(relationships_raw) > budgets["max_fields"]:
        raise ValueError("schema relationships are invalid or exceed the limit")
    relationships: list[dict[str, Any]] = []
    for index, relationship in enumerate(relationships_raw):
        if not isinstance(relationship, dict):
            raise ValueError(f"schema relationship {index} must be an object")
        item = _v2_json_safe(relationship)
        item.setdefault("id", f"relationship_{index}")
        item.setdefault("kind", "length" if relationship_key == "length_relationships" else "checksum")
        relationships.append(item)
    # Expand one deterministic instance of each root field for validation.
    # This validates references in the same scopes used during application,
    # while definition-only templates remain bounded and reusable.
    expanded_fields = _v2_expand_fields(
        fields, definitions, max_nesting=budgets["max_nesting"]
    )
    refs_by_id, diagnostics = _v2_schema_graph(expanded_fields, {})
    diagnostics.extend(_v2_expansion_diagnostics(expanded_fields))
    diagnostics.extend(_v2_definition_graph(definitions))
    diagnostics.sort(key=lambda item: (
        str(item.get("field_id", "")), str(item.get("code", "")),
        str(item.get("reference", item.get("definition", ""))),
    ))
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


def _v2_public_integer(value: int) -> int | str:
    """Keep integers lossless without emitting unsafe JSON numbers."""
    return value if -_V2_JSON_SAFE_INTEGER_MAX <= value <= _V2_JSON_SAFE_INTEGER_MAX else str(value)


def _v2_is_integer_type(type_name: Any) -> bool:
    normalized = str(type_name or "").lower()
    return normalized in _V2_INT_TYPES or normalized in {"uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer"}


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
        signed_override = field.get("signed")
        if signed_override is None and isinstance(field.get("constraints"), dict) and isinstance(field["constraints"].get("signed"), bool):
            signed_override = field["constraints"]["signed"]
        if signed_override is not None:
            if type_name in _V2_INT_TYPES and signed_override != signed:
                return "INVALID", None, None, [_v2_diag("INVALID", "integer_signedness", "signedness conflicts with the declared integer type")]
            signed = signed_override
        if field["endian"] not in {"big", "little"}:
            return "INVALID", None, None, [_v2_diag("INVALID", "integer_endian", "integer fields require big or little endian")]
        value = int.from_bytes(raw, field["endian"], signed=signed)
        return "RESOLVED", _v2_public_integer(value), value, []
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


def _v2_constraint_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _v2_constraint_equal(actual: Any, expected: Any) -> bool:
    actual_number = _v2_constraint_number(actual)
    expected_number = _v2_constraint_number(expected)
    if actual_number is not None and expected_number is not None:
        return actual_number == expected_number
    return type(actual) is type(expected) and actual == expected


def _v2_constraint_public_number(raw: Any, parsed: int) -> int | str:
    """Keep constraint evidence in the same JSON-safe form as field values."""
    return raw.strip() if isinstance(raw, str) else _v2_public_integer(parsed)


def _v2_constraint_values(raw: Any) -> tuple[list[Any] | None, str | None]:
    if not isinstance(raw, list):
        return None, "constraint values must be an array"
    if len(raw) > _V2_MAX_CONSTRAINT_VALUES:
        return None, "constraint values exceed the limit"
    return raw, None


def _v2_mask_value(raw: Any) -> int | None:
    number = _v2_constraint_number(raw)
    if number is not None and number >= 0:
        return number
    if isinstance(raw, list):
        mask = 0
        for bit in raw:
            bit_number = _v2_constraint_number(bit)
            if bit_number is None or bit_number < 0 or bit_number >= 128:
                return None
            mask |= 1 << bit_number
        return mask
    return None


def _v2_constraint_diag(
    field: dict[str, Any],
    result: dict[str, Any],
    code: str,
    message: str,
    *,
    status: str = "INVALID",
    **extra: Any,
) -> dict[str, Any]:
    """Create a constraint diagnostic with stable field-local evidence."""
    extra.setdefault("field_id", field["id"])
    extra.setdefault("path", field.get("path", field["id"]))
    extra.setdefault("offset", result.get("offset"))
    extra.setdefault("length", result.get("length"))
    return _v2_diag(status, code, message, **extra)


_V2_CONSTRAINT_DIAG_BASE = _v2_constraint_diag


def _v2_constraint_relation_descriptor(field: dict[str, Any], constraints: dict[str, Any]) -> dict[str, Any] | None:
    relation = constraints.get("length_relationship", constraints.get("length_relation"))
    if relation is None and constraints.get("length_of") is not None:
        relation = {"target": constraints.get("length_of")}
    if relation is None and constraints.get("matches_length") is not None:
        relation = {"target": constraints.get("matches_length")}
    if relation is None:
        return None
    if isinstance(relation, str):
        relation = {"target": relation}
    if not isinstance(relation, dict):
        return {"target": relation}
    return dict(relation)


def _v2_validate_field_constraints(
    field: dict[str, Any],
    result: dict[str, Any],
    values: dict[str, dict[str, Any]],
    checked: dict[str, Any],
) -> tuple[str, list[dict[str, Any]]]:
    """Evaluate reviewed data constraints after a field has decoded.

    Constraint failures deliberately use the existing INVALID field state.  A
    constraint whose dependency is incomplete keeps that dependency's state so
    truncation and unresolved conditions are not reported as bad bytes.
    """
    constraints = field.get("constraints", {})
    base_constraint_diag = _V2_CONSTRAINT_DIAG_BASE
    def constraint_diag(code: str, message: str, *, status: str = "INVALID", **extra: Any) -> dict[str, Any]:
        return base_constraint_diag(field, result, code, message, status=status, **extra)

    # Keep the constraint evaluation below concise while ensuring every
    # diagnostic gets field-local evidence.
    _v2_constraint_diag = constraint_diag
    if not isinstance(constraints, dict):
        return "INVALID", [constraint_diag("constraints_type", "field constraints must be an object")]
    # Use the public JSON-safe value for diagnostics and exact comparisons;
    # numeric helpers still recover the integer represented by wide decimal
    # strings.  The internal value remains available to dependent expressions.
    actual = result.get("value")
    diagnostics: list[dict[str, Any]] = []
    invalid = False

    def require_number(raw: Any, code: str, label: str) -> int | None:
        number = _v2_constraint_number(raw)
        if number is None:
            diagnostics.append(_v2_constraint_diag(code, f"{label} must be an integer"))
            return None
        return number

    numeric_actual = _v2_constraint_number(actual)
    for key, aliases, comparator, reason in (
        ("minimum", ("minimum", "min"), lambda value, bound: value >= bound, "value is below the minimum"),
        ("maximum", ("maximum", "max"), lambda value, bound: value <= bound, "value is above the maximum"),
        ("exact", ("exact", "equals", "equal"), lambda value, bound: value == bound, "value does not equal the required value"),
    ):
        declared = next((constraints[name] for name in aliases if name in constraints), None)
        if not any(name in constraints for name in aliases):
            continue
        if key == "exact":
            if not _v2_constraint_equal(actual, declared):
                expected_number = _v2_constraint_number(declared)
                expected = _v2_constraint_public_number(declared, expected_number) if expected_number is not None else declared
                diagnostics.append(_v2_constraint_diag("exact", reason, expected=expected, actual=actual))
                invalid = True
            continue
        bound = require_number(declared, f"{key}_type", key)
        if bound is None:
            invalid = True
        elif numeric_actual is None:
            diagnostics.append(_v2_constraint_diag(f"{key}_value", f"{key} requires an integer field value"))
            invalid = True
        elif not comparator(numeric_actual, bound):
            diagnostics.append(_v2_constraint_diag(key, reason, expected=_v2_constraint_public_number(declared, bound), actual=_v2_public_integer(numeric_actual)))
            invalid = True

    for key, aliases, reason in (
        ("allowed", ("allowed", "one_of"), "value is not in the allowed set"),
        ("forbidden", ("forbidden", "not_allowed", "disallowed"), "value is in the forbidden set"),
    ):
        declared = next((constraints[name] for name in aliases if name in constraints), None)
        if not any(name in constraints for name in aliases):
            continue
        candidates, error = _v2_constraint_values(declared)
        if error:
            diagnostics.append(_v2_constraint_diag(f"{key}_type", error))
            invalid = True
        elif key == "allowed" and not any(_v2_constraint_equal(actual, candidate) for candidate in candidates or []):
            diagnostics.append(_v2_constraint_diag("allowed", reason, actual=actual, allowed=candidates))
            invalid = True
        elif key == "forbidden" and any(_v2_constraint_equal(actual, candidate) for candidate in candidates or []):
            diagnostics.append(_v2_constraint_diag("forbidden", reason, actual=actual, forbidden=candidates))
            invalid = True

    enum = constraints.get("enum")
    enum_policy = constraints.get("enum_policy", "strict")
    enum_values = enum
    if isinstance(enum, dict):
        enum_policy = enum.get("policy", enum.get("unknown_policy", enum_policy))
        enum_values = enum.get("values", enum.get("allowed"))
        if enum_values is None:
            enum_values = list(enum)
    if enum is not None:
        if enum_policy not in {"strict", "diagnostic", "warn", "allow_unknown", "permissive", "open", "ignore"}:
            diagnostics.append(_v2_constraint_diag("enum_policy", "enum policy is unsupported"))
            invalid = True
        else:
            candidates, error = _v2_constraint_values(enum_values)
            if error:
                diagnostics.append(_v2_constraint_diag("enum_type", error))
                invalid = True
            elif not any(_v2_constraint_equal(actual, candidate) for candidate in candidates or []):
                if enum_policy == "strict":
                    diagnostics.append(_v2_constraint_diag("enum", "value is not declared by the enum", actual=actual, enum=candidates))
                    invalid = True
                elif enum_policy != "ignore":
                    diagnostics.append(_v2_constraint_diag("enum_unknown", "value is not declared by the enum; policy permits it", status="RESOLVED", actual=actual, enum=candidates, policy=enum_policy))

    width = next((constraints[name] for name in ("width", "width_bytes") if name in constraints), None)
    if width is not None:
        expected_width = require_number(width, "width_type", "width")
        if expected_width is not None and result.get("length") not in {expected_width, expected_width // 8 if expected_width > 0 and expected_width % 8 == 0 else -1}:
            diagnostics.append(_v2_constraint_diag("width", "field byte width does not match the constraint", expected=expected_width, actual=result.get("length")))
            invalid = True
    if "width_bits" in constraints:
        expected_bits = require_number(constraints["width_bits"], "width_bits_type", "width_bits")
        if expected_bits is None or expected_bits <= 0 or expected_bits % 8:
            diagnostics.append(_v2_constraint_diag("width_bits", "width_bits must be a positive multiple of eight"))
            invalid = True
        elif result.get("length") != expected_bits // 8:
            diagnostics.append(_v2_constraint_diag("width_bits", "field byte width does not match width_bits", expected=expected_bits, actual=(result.get("length") or 0) * 8))
            invalid = True
    if "signed" in constraints:
        expected_signed = constraints["signed"]
        if not isinstance(expected_signed, bool):
            diagnostics.append(_v2_constraint_diag("signed_type", "signed constraint must be boolean"))
            invalid = True
        elif field.get("type") not in _V2_INT_TYPES and field.get("type") not in {"uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer"}:
            diagnostics.append(_v2_constraint_diag("signed_type", "signed constraint requires an integer field"))
            invalid = True
        elif field.get("signed") is not None and field.get("signed") != expected_signed:
            diagnostics.append(_v2_constraint_diag("signed", "field signedness conflicts with its constraint", expected=expected_signed, actual=field.get("signed")))
            invalid = True

    bit_constraint_present = any(key in constraints for key in ("mask", "bit_mask", "bitmask", "reserved", "reserved_bits", "flags", "required_flags", "forbidden_flags", "mutual_exclusion", "mutually_exclusive", "exclusive"))
    if numeric_actual is not None:
        mask_raw = next((constraints[name] for name in ("mask", "bit_mask", "bitmask") if name in constraints), None)
        if mask_raw is not None:
            mask = _v2_mask_value(mask_raw.get("mask", mask_raw.get("allowed", mask_raw)) if isinstance(mask_raw, dict) else mask_raw)
            expected = next((mask_raw[name] for name in ("value", "expected") if name in mask_raw), None) if isinstance(mask_raw, dict) else None
            if mask is None:
                diagnostics.append(_v2_constraint_diag("mask_type", "bit mask must be a non-negative integer or bit list"))
                invalid = True
            elif expected is not None:
                expected_number = require_number(expected, "mask_value", "mask value")
                if expected_number is None or numeric_actual & mask != expected_number & mask:
                    diagnostics.append(_v2_constraint_diag("mask", "masked value does not match the expected bits", mask=mask, expected=expected_number, actual=numeric_actual & mask))
                    invalid = True
            elif numeric_actual & ~mask:
                diagnostics.append(_v2_constraint_diag("mask", "value contains bits outside the allowed mask", mask=mask, actual=numeric_actual))
                invalid = True

        reserved = constraints.get("reserved", constraints.get("reserved_bits"))
        if reserved is not None:
            reserved_mask = _v2_mask_value(reserved.get("mask", reserved.get("bits", reserved)) if isinstance(reserved, dict) else reserved)
            if reserved_mask is None:
                diagnostics.append(_v2_constraint_diag("reserved_type", "reserved bits must be a non-negative mask or bit list"))
                invalid = True
            elif numeric_actual & reserved_mask:
                diagnostics.append(_v2_constraint_diag("reserved", "reserved bits are set", mask=reserved_mask, actual=numeric_actual & reserved_mask))
                invalid = True

        flags = constraints.get("flags")
        flag_masks: dict[str, int | None] = {}
        if isinstance(flags, dict):
            flag_masks = {str(name): _v2_mask_value(mask) for name, mask in flags.items() if name not in {"required", "forbidden", "reserved", "mutual_exclusion"}}
        elif isinstance(flags, list):
            if len(flags) > _V2_MAX_CONSTRAINT_VALUES:
                diagnostics.append(_v2_constraint_diag("flags_type", "flags exceed the limit"))
                invalid = True
            else:
                for index, flag in enumerate(flags):
                    if isinstance(flag, dict):
                        name = flag.get("name", f"flag_{index}")
                        mask = flag.get("mask", flag.get("value", flag.get("bit")))
                    else:
                        name, mask = f"flag_{index}", flag
                    if not isinstance(name, str):
                        diagnostics.append(_v2_constraint_diag("flags_type", "flag names must be strings"))
                        invalid = True
                    else:
                        flag_masks[name] = _v2_mask_value(mask)
        elif flags is not None:
            diagnostics.append(_v2_constraint_diag("flags_type", "flags must be an object or array of flag descriptors"))
            invalid = True

        required_flags = constraints.get("required_flags", constraints.get("required"))
        forbidden_flags = constraints.get("forbidden_flags")
        if flag_masks:
            for flag_key, flag_set, reason in (("required_flags", required_flags, "required flag is not set"), ("forbidden_flags", forbidden_flags, "forbidden flag is set")):
                if flag_set is None:
                    continue
                names = flag_set if isinstance(flag_set, list) else [flag_set]
                if not all((isinstance(name, str) and name in flag_masks) or _v2_mask_value(name) is not None for name in names):
                    diagnostics.append(_v2_constraint_diag(f"{flag_key}_type", f"{flag_key} must name declared flags"))
                    invalid = True
                    continue
                for name in names:
                    flag_mask = flag_masks.get(name) if isinstance(name, str) else _v2_mask_value(name)
                    if flag_mask is None:
                        diagnostics.append(_v2_constraint_diag("flag_mask", f"flag {name!r} has an invalid mask"))
                        invalid = True
                    elif ((numeric_actual & flag_mask) == 0 if flag_key == "required_flags" else (numeric_actual & flag_mask) != 0):
                        diagnostics.append(_v2_constraint_diag(flag_key, reason, flag=name, mask=flag_mask))
                        invalid = True
        elif required_flags is not None or forbidden_flags is not None:
            for flag_key, flag_set, reason in (("required_flags", required_flags, "required flag is not set"), ("forbidden_flags", forbidden_flags, "forbidden flag is set")):
                if flag_set is None:
                    continue
                masks = flag_set if isinstance(flag_set, list) else [flag_set]
                for raw_mask in masks:
                    flag_mask = _v2_mask_value(raw_mask)
                    if flag_mask is None:
                        diagnostics.append(_v2_constraint_diag(f"{flag_key}_type", f"{flag_key} must contain flag names or masks"))
                        invalid = True
                    elif ((numeric_actual & flag_mask) == 0 if flag_key == "required_flags" else (numeric_actual & flag_mask) != 0):
                        diagnostics.append(_v2_constraint_diag(flag_key, reason, mask=flag_mask))
                        invalid = True

        exclusions = constraints.get("mutual_exclusion", constraints.get("mutually_exclusive", constraints.get("exclusive")))
        if exclusions is not None:
            named_exclusions = bool(flag_masks) and isinstance(exclusions, list) and all(isinstance(item, str) for item in exclusions)
            groups = [exclusions] if named_exclusions or (isinstance(exclusions, list) and all(not isinstance(item, (list, dict)) for item in exclusions)) else exclusions if isinstance(exclusions, list) else [exclusions]
            for group in groups:
                raw_items = group if isinstance(group, list) else [group]
                if flag_masks and named_exclusions:
                    masks = [flag_masks.get(item) for item in raw_items]
                elif flag_masks and all(isinstance(item, str) for item in raw_items):
                    masks = [flag_masks.get(item) for item in raw_items]
                else:
                    masks = [_v2_mask_value(item.get("mask") if isinstance(item, dict) else item) for item in raw_items]
                if len(masks) < 2 or any(mask is None for mask in masks):
                    diagnostics.append(_v2_constraint_diag("mutual_exclusion_type", "mutual exclusion must contain at least two valid flags or masks"))
                    invalid = True
                elif sum(bool(numeric_actual & mask) for mask in masks if mask is not None) > 1:
                    diagnostics.append(_v2_constraint_diag("mutual_exclusion", "mutually exclusive flags are set", masks=masks))
                    invalid = True
    elif bit_constraint_present:
        diagnostics.append(_v2_constraint_diag("bit_constraint_type", "bit masks and flags require an integer field"))
        invalid = True

    relation = _v2_constraint_relation_descriptor(field, constraints)
    if relation is not None:
        target = relation.get("target", relation.get("field", relation.get("field_id", relation.get("target_field", relation.get("target_field_id")))))
        if not isinstance(target, str):
            diagnostics.append(_v2_constraint_diag("length_relationship", "length relationship target must be a field id"))
            invalid = True
        else:
            target_result = values.get(target)
            if target_result is None:
                diagnostics.append(_v2_constraint_diag("length_relationship", f"length relationship target {target!r} does not exist", reference=target))
                invalid = True
            elif target_result.get("status") != "RESOLVED":
                dependency_status = target_result.get("status", "UNKNOWN")
                return dependency_status, [_v2_constraint_diag("length_relationship_dependency", f"length relationship target {target!r} is not resolved", status=dependency_status, reference=target)]
            else:
                if not isinstance(target_result.get("length"), int):
                    return "UNKNOWN", [_v2_constraint_diag("length_relationship_absent", f"length relationship target {target!r} has no concrete length", status="UNKNOWN", reference=target)]
                mode = str(relation.get("mode", relation.get("kind", "length"))).lower()
                expected = target_result.get("length")
                if mode in {"total", "through_end", "end"}:
                    expected = (target_result.get("offset") or 0) + (target_result.get("length") or 0)
                elif mode in {"after", "bytes_after"}:
                    expected = (checked.get("_current_data_length") or 0) - (target_result.get("offset") or 0)
                adjustment = _v2_constraint_number(relation.get("adjust", relation.get("offset", 0)))
                if adjustment is None:
                    diagnostics.append(_v2_constraint_diag("length_relationship", "length relationship adjustment must be an integer"))
                    invalid = True
                else:
                    expected = (expected or 0) + adjustment
                    if numeric_actual != expected:
                        diagnostics.append(_v2_constraint_diag("length_relationship", "length does not match the related field", reference=target, expected=expected, actual=numeric_actual, mode=mode))
                        invalid = True

    return ("INVALID" if invalid else "RESOLVED"), diagnostics


def _v2_public_field(field: dict[str, Any], result: dict[str, Any], *, value: Any = None, present: bool = True, items: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    diagnostics: list[dict[str, Any]] = []
    for diagnostic in result.get("diagnostics", []):
        if not isinstance(diagnostic, dict):
            continue
        contextual = dict(diagnostic)
        contextual.setdefault("field_id", field["id"])
        contextual.setdefault("path", field.get("path", field["id"]))
        contextual.setdefault("offset", result.get("offset"))
        contextual.setdefault("length", result.get("length"))
        diagnostics.append(contextual)
    result["diagnostics"] = diagnostics
    diagnostics.sort(key=lambda item: (item.get("code", ""), item.get("message", ""), str(item.get("reference", ""))))
    diagnostics = diagnostics[:32]
    result["diagnostics"] = diagnostics
    integer_type = _v2_is_integer_type(field.get("type"))
    output = {
        "id": field["id"], "path": field.get("path", field["id"]), "name": field["name"], "description": field.get("description", ""),
        "status": result["status"], "present": present,
        "available": result["status"] == "RESOLVED" and present,
        "offset": result.get("offset"), "length": result.get("length"), "width": result.get("length"),
        "coordinate_system": field.get("coordinate_system"), "value": value if present else None,
        "value_encoding": "decimal" if integer_type and (isinstance(value, (int, str)) and not isinstance(value, bool)) else "boolean" if isinstance(value, bool) else "text" if isinstance(value, str) and field["type"] in {"text", "string", "utf8", "ascii"} else "hex" if isinstance(value, str) else None,
        "diagnostics": diagnostics,
    }
    if isinstance(field.get("provenance"), dict):
        output["provenance"] = deepcopy(field["provenance"])
        # ``source`` is the compact compatibility spelling used by schema
        # consumers that predate the more descriptive ``provenance`` key.
        output["source"] = deepcopy(field["provenance"])
    if field.get("definition") is not None:
        output["definition"] = field.get("definition")
    if items is not None: output["items"] = items
    if field.get("checksum") is not None or field.get("relationship") is not None:
        output["relationship"] = field.get("checksum", field.get("relationship"))
    return output


def _v2_resolve_nonnegative_length(expr: Any, values: dict[str, dict[str, Any]], budgets: dict[str, int], *, code: str = "length") -> tuple[str, int | None, list[dict[str, Any]]]:
    """Evaluate a byte/item length without coercing floats or booleans."""
    evaluated = _v2_eval_expr(expr, values, budgets)
    if evaluated["status"] != "RESOLVED":
        return evaluated["status"], None, evaluated.get("diagnostics", [])
    raw = evaluated.get("value")
    value = None if isinstance(raw, (bool, float)) else _v2_numeric(raw)
    if value is None or value < 0:
        return "INVALID", None, [_v2_diag("INVALID", code, "length must be a non-negative integer")]
    return "RESOLVED", value, []


def _v2_parse_field(field: dict[str, Any], *, base_offset: int, data: bytes | None, metadata: dict[str, Any], values: dict[str, dict[str, Any]], checked: dict[str, Any], depth: int = 0, store: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    budgets = checked["budgets"]
    if data is not None:
        checked["_current_data_length"] = len(data)
    runtime = checked.setdefault("_runtime", {"array_items": 0, "output_fields": 0})
    if runtime.setdefault("output_fields", 0) >= budgets["max_output_fields"]:
        result = _v2_status_result("LIMIT_EXCEEDED", diagnostics=[_v2_diag("LIMIT_EXCEEDED", "output_fields", "decoded field output exceeds the schema budget")])
        return _v2_public_field(field, result, present=False), result
    runtime["output_fields"] += 1
    if depth > budgets["max_nesting"]:
        result = _v2_status_result("LIMIT_EXCEEDED", diagnostics=[_v2_diag("LIMIT_EXCEEDED", "nesting", "nested structure exceeds the schema budget")])
        return _v2_public_field(field, result, present=False), result
    if data is not None and len(data) > budgets["max_bytes_per_packet"]:
        result = _v2_status_result("LIMIT_EXCEEDED", diagnostics=[_v2_diag("LIMIT_EXCEEDED", "packet_bytes", "packet coordinate bytes exceed the schema budget")])
        return _v2_public_field(field, result, present=False), result
    missing_references = checked.get("_runtime_missing_references", {}).get(field.get("id"), ())
    if missing_references:
        result = _v2_status_result(
            "INVALID", diagnostics=[_v2_diag(
                "INVALID", "missing_reference", f"field reference {reference!r} does not exist",
                reference=reference,
            ) for reference in sorted(missing_references)]
        )
        output = _v2_public_field(field, result)
        if store:
            values[field["id"]] = result
        return output, result
    if field.get("id") in checked.get("_runtime_cyclic_fields", set()):
        result = _v2_status_result("CYCLIC", diagnostics=[_v2_diag("CYCLIC", "dependency_cycle", "field dependency cycle prevents evaluation")])
        output = _v2_public_field(field, result, present=False)
        if store:
            values[field["id"]] = result
        return output, result
    if field.get("_definition_missing"):
        definition = field.get("definition")
        result = _v2_status_result("INVALID", diagnostics=[_v2_diag("INVALID", "missing_definition", f"definition {definition!r} does not exist", reference=definition)])
        output = _v2_public_field(field, result, present=False)
        if store:
            values[field["id"]] = result
        return output, result
    if field.get("_definition_cycle"):
        definition = field.get("definition")
        result = _v2_status_result("CYCLIC", diagnostics=[_v2_diag("CYCLIC", "definition_cycle", f"definition cycle prevents expansion of {definition!r}", definition=definition)])
        output = _v2_public_field(field, result, present=False)
        if store:
            values[field["id"]] = result
        return output, result
    if field.get("_definition_depth"):
        result = _v2_status_result("LIMIT_EXCEEDED", diagnostics=[_v2_diag("LIMIT_EXCEEDED", "nesting", "definition expansion exceeds the schema nesting budget")])
        output = _v2_public_field(field, result, present=False)
        if store:
            values[field["id"]] = result
        return output, result
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
    if definition is not None and not field.get("_definition_expanded"):
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
        explicit_length = None
        if field.get("length") is not None:
            length_status, explicit_length, length_diagnostics = _v2_resolve_nonnegative_length(field["length"], values, budgets)
            if length_status != "RESOLVED" or explicit_length is None:
                result = _v2_status_result(length_status, offset=absolute_offset, diagnostics=length_diagnostics)
                output = _v2_public_field(field, result)
                if store: values[field["id"]] = result
                return output, result
            if explicit_length > budgets["max_field_length"]:
                result = _v2_status_result("LIMIT_EXCEEDED", offset=absolute_offset, length=explicit_length, diagnostics=[_v2_diag("LIMIT_EXCEEDED", "field_length", "field length exceeds the schema budget")])
                output = _v2_public_field(field, result)
                if store: values[field["id"]] = result
                return output, result
            if absolute_offset + explicit_length > budgets["max_bytes_per_packet"]:
                result = _v2_status_result("LIMIT_EXCEEDED", offset=absolute_offset, length=explicit_length, diagnostics=[_v2_diag("LIMIT_EXCEEDED", "packet_budget", "field range exceeds the packet budget")])
                output = _v2_public_field(field, result)
                if store: values[field["id"]] = result
                return output, result
            if absolute_offset + explicit_length > len(data):
                result = _v2_status_result("OUT_OF_BOUNDS", offset=absolute_offset, length=explicit_length, diagnostics=[_v2_diag("OUT_OF_BOUNDS", "truncated_field", "field range extends beyond captured bytes")])
                output = _v2_public_field(field, result)
                if store: values[field["id"]] = result
                return output, result
        nested_values: dict[str, dict[str, Any]] = {}
        nested_outputs_by_id: dict[str, dict[str, Any]] = {}
        nested_end = absolute_offset
        nested_status = "RESOLVED"
        nested_graph, nested_graph_diagnostics = _v2_schema_graph(nested_fields, {})
        runtime_cyclic = checked.setdefault("_runtime_cyclic_fields", set())
        runtime_missing = checked.setdefault("_runtime_missing_references", {})
        effective_nested_diagnostics: list[dict[str, Any]] = []
        for nested_diagnostic in nested_graph_diagnostics:
            nested_field_id = nested_diagnostic.get("field_id")
            if nested_diagnostic.get("code") == "dependency_cycle" and isinstance(nested_field_id, str):
                runtime_cyclic.add(nested_field_id)
                effective_nested_diagnostics.append(nested_diagnostic)
            elif nested_diagnostic.get("code") == "missing_reference" and isinstance(nested_field_id, str):
                reference = nested_diagnostic.get("reference")
                if reference not in values and reference not in checked.get("_runtime_field_ids", set()):
                    runtime_missing.setdefault(nested_field_id, set()).add(reference)
                    effective_nested_diagnostics.append(nested_diagnostic)
        nested_order = _v2_order_scope_fields(nested_fields, nested_graph)
        for child in nested_order:
            child_output, child_result = _v2_parse_field(child, base_offset=absolute_offset, data=data, metadata=metadata, values={**values, **nested_values}, checked=checked, depth=depth + 1)
            nested_outputs_by_id[child["id"]] = child_output
            nested_values[child["id"]] = child_result
            if child_result.get("status") != "RESOLVED":
                nested_status = _v2_merge_status(nested_status, child_result.get("status", "INVALID"))
            child_offset, child_length = child_result.get("offset"), child_result.get("length")
            if isinstance(child_offset, int) and isinstance(child_length, int):
                nested_end = max(nested_end, child_offset + child_length)
        length = explicit_length if explicit_length is not None else max(0, nested_end - absolute_offset)
        if length > budgets["max_field_length"]: nested_status = _v2_merge_status(nested_status, "LIMIT_EXCEEDED")
        if absolute_offset + length > len(data): nested_status = _v2_merge_status(nested_status, "OUT_OF_BOUNDS")
        nested_outputs = [nested_outputs_by_id[child["id"]] for child in nested_fields]
        if effective_nested_diagnostics:
            for diagnostic in effective_nested_diagnostics:
                if diagnostic not in checked.setdefault("_runtime_diagnostics", []):
                    checked["_runtime_diagnostics"].append(diagnostic)
        values.update(nested_values)
        diagnostics = [] if nested_status == "RESOLVED" else [_v2_diag(nested_status, "nested_status", "nested structure contains a non-resolved field")]
        result = _v2_status_result(nested_status, value={child["id"]: nested_outputs_by_id[child["id"]].get("value") for child in nested_fields}, internal={child["id"]: nested_values[child["id"]].get("internal") for child in nested_fields}, diagnostics=diagnostics, offset=absolute_offset, length=length)
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
    if status == "RESOLVED":
        constraint_status, constraint_diagnostics = _v2_validate_field_constraints(field, result, values, checked)
        result["diagnostics"].extend(constraint_diagnostics)
        if constraint_status != "RESOLVED":
            result["status"] = constraint_status
    output = _v2_public_field(field, result, value=public_value)
    if store: values[field["id"]] = result
    return output, result


def _v2_parse_array(field: dict[str, Any], array: dict[str, Any], absolute_offset: int, data: bytes, metadata: dict[str, Any], values: dict[str, dict[str, Any]], checked: dict[str, Any], depth: int) -> tuple[dict[str, Any], dict[str, Any]]:
    budgets = checked["budgets"]
    declared_length = None
    if field.get("length") is not None:
        length_status, declared_length, length_diagnostics = _v2_resolve_nonnegative_length(field["length"], values, budgets)
        if length_status != "RESOLVED" or declared_length is None:
            result = _v2_status_result(length_status, offset=absolute_offset, diagnostics=length_diagnostics)
            return _v2_public_field(field, result), result
        if declared_length > budgets["max_field_length"]:
            result = _v2_status_result("LIMIT_EXCEEDED", offset=absolute_offset, length=declared_length, diagnostics=[_v2_diag("LIMIT_EXCEEDED", "field_length", "field length exceeds the schema budget")])
            return _v2_public_field(field, result), result
        if absolute_offset + declared_length > budgets["max_bytes_per_packet"]:
            result = _v2_status_result("LIMIT_EXCEEDED", offset=absolute_offset, length=declared_length, diagnostics=[_v2_diag("LIMIT_EXCEEDED", "packet_budget", "field range exceeds the packet budget")])
            return _v2_public_field(field, result), result
        if absolute_offset + declared_length > len(data):
            result = _v2_status_result("OUT_OF_BOUNDS", offset=absolute_offset, length=declared_length, diagnostics=[_v2_diag("OUT_OF_BOUNDS", "truncated_field", "field range extends beyond captured bytes")])
            return _v2_public_field(field, result), result
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
        item_id = f"{field['id']}[{index}]"
        item_fields = _v2_expand_fields(
            [element], checked.get("definitions", {}), prefix=item_id,
            root_ids=[item_id], visible_refs={**field.get("_array_visible_refs", {}), **{key: key for key in values}},
            depth=depth + 1, max_nesting=budgets["max_nesting"],
        )
        item_field = item_fields[0] if item_fields else element
        item_output, item_result = _v2_parse_field(item_field, base_offset=cursor, data=data, metadata=metadata, values=values, checked=checked, depth=depth + 1, store=False)
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
    if declared_length is not None:
        if length > declared_length:
            status = _v2_merge_status(status, "OUT_OF_BOUNDS")
        else:
            length = declared_length
    result = _v2_status_result(status, value=public_values, internal=public_values, diagnostics=[] if status == "RESOLVED" else [_v2_diag(status, "array_status", "array contains a non-resolved element")], offset=absolute_offset, length=length)
    return _v2_public_field(field, result, value=public_values, items=items), result


def _v2_merge_status(current: str, candidate: str) -> str:
    priority = {"RESOLVED": 0, "UNKNOWN": 1, "UNAVAILABLE": 2, "OUT_OF_BOUNDS": 3, "INVALID": 4, "CYCLIC": 5, "LIMIT_EXCEEDED": 6}
    return candidate if priority.get(candidate, 4) > priority.get(current, 0) else current


def _v2_checksum_algorithm(value: Any) -> str | None:
    """Return a canonical algorithm name from the explicit checksum allow-list."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper().replace("_", "-")
    for name in _V2_CHECKSUM_ALGORITHMS:
        if name.upper().replace("_", "-") == normalized:
            return name
    return None


def _v2_relationship_descriptors(checked: dict[str, Any]) -> list[tuple[str, str | None, dict[str, Any]]]:
    """Collect top-level and field-owned checksum descriptors deterministically."""
    candidates: list[tuple[str, str | None, dict[str, Any], int]] = []
    sequence = 0

    for relationship in checked.get("relationships", []):
        if not isinstance(relationship, dict):
            continue
        descriptor = dict(relationship)
        nested = descriptor.get("checksum")
        if isinstance(nested, dict):
            merged = dict(nested)
            merged.update({key: value for key, value in descriptor.items() if key != "checksum"})
            descriptor = merged
        elif isinstance(nested, str):
            descriptor.setdefault("checksum_field", nested)
        relationship_id = str(descriptor.get("id", f"relationship_{sequence}"))
        candidates.append((relationship_id, None, descriptor, sequence))
        sequence += 1

    for field in _v2_walk_fields(checked.get("fields", [])):
        field_descriptors: list[tuple[str, Any]] = [("checksum", field.get("checksum")), ("relationship", field.get("relationship"))]
        if all(raw is None for _, raw in field_descriptors) and str(field.get("type", "")).lower() in {"crc", "checksum"} and field.get("algorithm") is not None:
            field_descriptors.append(("checksum", {"algorithm": field.get("algorithm"), "byte_order": field.get("byte_order")}))
        for descriptor_key, raw in field_descriptors:
            if raw is None:
                continue
            if isinstance(raw, dict):
                descriptor = dict(raw)
            else:
                # A scalar field descriptor is retained as an unsupported
                # descriptor, so malformed reviewed metadata is observable.
                descriptor = {"algorithm": raw}
            for key in ("algorithm", "byte_order"):
                if key not in descriptor and field.get(key) is not None:
                    descriptor[key] = field[key]
            relationship_id = str(descriptor.get("id", f"field:{field['id']}:{descriptor_key}"))
            candidates.append((relationship_id, field["id"], descriptor, sequence))
            sequence += 1

    # Preserve explicit IDs while making duplicate IDs stable and unambiguous.
    seen: dict[str, int] = {}
    result: list[tuple[str, str | None, dict[str, Any]]] = []
    for relationship_id, owner_id, descriptor, _ in candidates:
        count = seen.get(relationship_id, 0)
        seen[relationship_id] = count + 1
        if count:
            relationship_id = f"{relationship_id}#{count + 1}"
        result.append((relationship_id, owner_id, descriptor))
    return result


def _v2_relationship_dependency_status(result: dict[str, Any] | None) -> str:
    """Map a field evaluation state without collapsing its meaning.

    ``insufficient`` means captured bytes or a coordinate are unavailable;
    ``unresolved`` means a reference/dependency cannot be determined; and
    ``unsupported`` means the reviewed relationship cannot operate on the
    decoded value or schema shape.
    """
    if result is None:
        return "unresolved"
    status = result.get("status")
    if status in {"OUT_OF_BOUNDS", "UNAVAILABLE"}:
        return "insufficient"
    if status in {"UNKNOWN", "CYCLIC"}:
        return "unresolved"
    if status == "INVALID":
        codes = {item.get("code") for item in result.get("diagnostics", []) if isinstance(item, dict)}
        if codes & {"missing_reference", "missing_definition", "dependency_status"}:
            return "unresolved"
        return "unsupported"
    if status == "LIMIT_EXCEEDED":
        return "unsupported"
    return "unresolved"


def _v2_length_relationship(
    descriptor_id: str,
    descriptor: dict[str, Any],
    *,
    values: dict[str, dict[str, Any]],
    field_map: dict[str, dict[str, Any]],
    data_length: int,
) -> dict[str, Any]:
    """Validate a declarative length field against another decoded field."""
    source_id = next((descriptor.get(key) for key in ("field_id", "length_field_id", "length_field", "source_field_id", "source", "field") if isinstance(descriptor.get(key), str)), None)
    target_id = next((descriptor.get(key) for key in ("target_field_id", "target", "length_of", "target_field", "covers") if isinstance(descriptor.get(key), str)), None)
    base = {
        "id": descriptor_id, "kind": "length", "status": "unsupported",
        "field_id": source_id, "target_field_id": target_id,
        "expected": None, "actual": None, "diagnostics": [],
    }
    if source_id is None or target_id is None:
        base["diagnostics"] = [_v2_diag("unsupported", "length_fields", "length relationship requires source and target field ids", relationship_id=descriptor_id)]
        return base
    if source_id not in field_map or target_id not in field_map:
        base["status"] = "unresolved"
        base["diagnostics"] = [_v2_diag("unresolved", "length_fields", "length relationship references an unknown field", relationship_id=descriptor_id, source=source_id, target=target_id)]
        return base
    if not _v2_is_integer_type(field_map[source_id].get("type")):
        base["status"] = "unsupported"
        base["diagnostics"] = [_v2_diag("unsupported", "length_value", "length relationship source field is not an integer type", relationship_id=descriptor_id, field_id=source_id)]
        return base
    source = values.get(source_id)
    target = values.get(target_id)
    if source is None or target is None:
        base["status"] = "unresolved"
        base["diagnostics"] = [_v2_diag("unresolved", "length_fields", "length relationship fields were not evaluated", relationship_id=descriptor_id)]
        return base
    for item, role in ((source, "source"), (target, "target")):
        if item.get("status") != "RESOLVED":
            mapped = _v2_relationship_dependency_status(item)
            base["status"] = mapped
            base["diagnostics"] = [_v2_diag(mapped, "length_dependency", f"length relationship {role} field is not resolved", relationship_id=descriptor_id, field_id=source_id if role == "source" else target_id)]
            return base
    if not isinstance(target.get("length"), int) or not isinstance(target.get("offset"), int):
        base["status"] = "unresolved"
        base["diagnostics"] = [_v2_diag("unresolved", "length_absent", "length relationship target has no concrete range", relationship_id=descriptor_id, field_id=target_id)]
        return base
    actual = _v2_constraint_number(source.get("internal"))
    if actual is None:
        base["status"] = "unsupported"
        base["diagnostics"] = [_v2_diag("unsupported", "length_value", "length relationship source is not an integer", relationship_id=descriptor_id)]
        return base
    public_actual = _v2_public_integer(actual)
    mode = str(descriptor.get("mode", descriptor.get("length_mode", "field"))).lower()
    if mode in {"total", "through_end", "end"}:
        expected = (target.get("offset") or 0) + (target.get("length") or 0)
    elif mode in {"after", "bytes_after"}:
        expected = data_length - (target.get("offset") or 0)
    elif mode in {"payload", "field", "length", "body"}:
        expected = target.get("length")
    else:
        base["diagnostics"] = [_v2_diag("unsupported", "length_mode", "length relationship mode is unsupported", relationship_id=descriptor_id, mode=mode)]
        return base
    adjustment = _v2_constraint_number(descriptor.get("adjust", descriptor.get("offset", 0)))
    if adjustment is None:
        base["diagnostics"] = [_v2_diag("unsupported", "length_adjustment", "length relationship adjustment must be an integer", relationship_id=descriptor_id)]
        return base
    expected = (expected or 0) + adjustment
    base["expected"], base["actual"] = expected, public_actual
    base["status"] = "valid" if actual == expected else "invalid"
    base["diagnostics"] = [_v2_diag(base["status"], "length_valid" if actual == expected else "length_mismatch", "length matches the related field" if actual == expected else "length does not match the related field", relationship_id=descriptor_id, expected=expected, actual=public_actual)]
    return base


def _v2_relationship_target_id(descriptor: dict[str, Any], owner_id: str | None) -> str | None:
    for key in ("checksum_field", "checksum_field_id", "target_field", "target_field_id", "field_id", "target", "field"):
        value = descriptor.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    location = descriptor.get("location")
    if isinstance(location, str) and location.strip():
        return location.strip()
    if isinstance(location, dict):
        for key in ("field_id", "field", "ref", "field_ref", "target"):
            value = location.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        location_kind = str(location.get("kind", location.get("type", ""))).lower()
        if (location_kind in {"field", "field_id", "field_ref", "reference"} or not any(key in location for key in ("start", "offset", "absolute_offset", "end", "length", "width", "range"))) and isinstance(location.get("id"), str):
            return location["id"].strip()
    return owner_id


def _v2_relationship_failure(status: str, relationship_id: str, code: str, message: str, **extra: Any) -> dict[str, Any]:
    diagnostic = _v2_diag(status, code, message, relationship_id=relationship_id, **extra)
    return {
        "id": relationship_id,
        "kind": "checksum",
        "status": status,
        "algorithm": extra.pop("algorithm", None),
        "checksum_field_id": extra.pop("checksum_field_id", None),
        "byte_order": extra.pop("byte_order", None),
        "location": None,
        "covered_ranges": [],
        "expected": None,
        "actual": None,
        "diagnostics": [diagnostic],
    }


def _v2_eval_checksum_integer(value: Any, values: dict[str, dict[str, Any]], budgets: dict[str, int]) -> tuple[str, int | None, str]:
    if isinstance(value, bool):
        return "unsupported", None, "boolean range coordinates are not supported"
    if isinstance(value, int):
        return "resolved", value, ""
    if isinstance(value, dict):
        evaluated = _v2_eval_expr(value, values, budgets)
        if evaluated.get("status") == "RESOLVED":
            numeric = _v2_numeric(evaluated.get("value"))
            if numeric is not None and not isinstance(evaluated.get("value"), bool):
                return "resolved", numeric, ""
        status = evaluated.get("status")
        codes = {item.get("code") for item in evaluated.get("diagnostics", []) if isinstance(item, dict)}
        if "missing_reference" in codes or status in {"UNKNOWN", "CYCLIC"}:
            return "unresolved", None, "range coordinate depends on an unresolved field"
        if status in {"OUT_OF_BOUNDS", "UNAVAILABLE"}:
            return "insufficient", None, "range coordinate depends on incomplete field data"
        if "dependency_status" in codes:
            return _v2_relationship_dependency_status({"status": status, "diagnostics": evaluated.get("diagnostics", [])}), None, "range coordinate depends on an unsupported field"
    return "unsupported", None, "range coordinate must be a bounded integer or field expression"


def _v2_checksum_range_items(raw: Any) -> tuple[str, list[Any], str]:
    if raw is None:
        return "resolved", [], ""
    if isinstance(raw, dict):
        # A single explicit range is accepted in addition to include/exclude
        # collections.  This keeps covered_range and covered_ranges symmetric.
        if any(key in raw for key in ("start", "offset", "from", "begin", "end", "to", "stop", "length", "width")):
            return "resolved", [raw], ""
        return "unsupported", [], "range collection must contain include or range entries"
    if isinstance(raw, (list, tuple)):
        if len(raw) == 2 and not isinstance(raw[0], (list, tuple, dict)) and not isinstance(raw[1], (list, tuple, dict)):
            return "resolved", [raw], ""
        return "resolved", list(raw), ""
    return "unsupported", [], "range collection must be a range or list of ranges"


def _v2_checksum_one_range(raw: Any, values: dict[str, dict[str, Any]], budgets: dict[str, int], *, data_length: int) -> tuple[str, tuple[int, int] | None, str]:
    if isinstance(raw, (list, tuple)):
        if len(raw) != 2:
            return "unsupported", None, "range arrays must contain start and end"
        start_raw, end_raw = raw
    elif isinstance(raw, dict):
        if "range" in raw:
            return _v2_checksum_one_range(raw["range"], values, budgets, data_length=data_length)
        start_raw = raw.get("start", raw.get("offset", raw.get("from", raw.get("begin"))))
        if "end" in raw or "to" in raw or "stop" in raw:
            end_raw = raw.get("end", raw.get("to", raw.get("stop")))
        elif "length" in raw or "width" in raw:
            length_status, length, length_message = _v2_eval_checksum_integer(raw.get("length", raw.get("width")), values, budgets)
            if length_status != "resolved" or length is None:
                return length_status, None, length_message
            start_status, start, start_message = _v2_eval_checksum_integer(start_raw, values, budgets)
            if start_status != "resolved" or start is None:
                return start_status, None, start_message
            end_raw = start + length
        else:
            return "unsupported", None, "range requires an end or length"
    else:
        return "unsupported", None, "range must be an array or object"
    start_status, start, start_message = _v2_eval_checksum_integer(start_raw, values, budgets)
    end_status, end, end_message = _v2_eval_checksum_integer(end_raw, values, budgets)
    if start_status != "resolved":
        return start_status, None, start_message
    if end_status != "resolved":
        return end_status, None, end_message
    assert start is not None and end is not None
    if start < 0 or end < start:
        return "unsupported", None, "range bounds are invalid"
    if end > budgets["max_bytes_per_packet"]:
        return "unsupported", None, "range exceeds the packet budget"
    if end > data_length:
        return "insufficient", (start, end), "range extends beyond captured bytes"
    return "resolved", (start, end), ""


def _v2_checksum_coverage(
    descriptor: dict[str, Any],
    *,
    location: tuple[int, int],
    data: bytes,
    values: dict[str, dict[str, Any]],
    budgets: dict[str, int],
) -> tuple[str, list[tuple[int, int]], bytes | None, str]:
    coverage_raw = None
    for key in ("coverage", "covered", "covered_ranges", "covered_range", "ranges"):
        if key in descriptor:
            coverage_raw = descriptor[key]
            break
    explicit = coverage_raw is not None or "include" in descriptor or "exclude" in descriptor
    include_raw: Any = coverage_raw
    exclude_raw: Any = None
    if isinstance(coverage_raw, dict):
        include_raw = coverage_raw.get("include", coverage_raw.get("ranges", coverage_raw.get("covered_ranges")))
        exclude_raw = coverage_raw.get("exclude")
    if "include" in descriptor:
        include_raw = descriptor.get("include")
    if "exclude" in descriptor:
        exclude_raw = descriptor.get("exclude")
    if not explicit:
        include_items: list[Any] = [[0, len(data)]]
        exclude_items: list[Any] = [list(location)]
    else:
        if include_raw is None:
            include_items = [[0, len(data)]]
        else:
            include_status, include_items, include_message = _v2_checksum_range_items(include_raw)
            if include_status != "resolved":
                return include_status, [], None, include_message
        if exclude_raw is None:
            exclude_items = []
        else:
            exclude_status, exclude_items, exclude_message = _v2_checksum_range_items(exclude_raw)
            if exclude_status != "resolved":
                return exclude_status, [], None, exclude_message
    if len(include_items) + len(exclude_items) > _V2_MAX_CHECKSUM_RANGES:
        return "unsupported", [], None, "checksum range count exceeds the limit"
    includes: list[tuple[int, int]] = []
    excludes: list[tuple[int, int]] = []
    for raw, destination in ((item, includes) for item in include_items):
        status, value, message = _v2_checksum_one_range(raw, values, budgets, data_length=len(data))
        if status != "resolved" or value is None:
            return status, [], None, message
        destination.append(value)
    for raw, destination in ((item, excludes) for item in exclude_items):
        status, value, message = _v2_checksum_one_range(raw, values, budgets, data_length=len(data))
        if status != "resolved" or value is None:
            return status, [], None, message
        destination.append(value)
    covered_ranges: list[tuple[int, int]] = []
    parts: list[bytes] = []
    total = 0
    for start, end in includes:
        segments = [(start, end)]
        for excluded_start, excluded_end in excludes:
            next_segments: list[tuple[int, int]] = []
            for segment_start, segment_end in segments:
                if excluded_end <= segment_start or excluded_start >= segment_end:
                    next_segments.append((segment_start, segment_end))
                    continue
                if segment_start < excluded_start:
                    next_segments.append((segment_start, min(excluded_start, segment_end)))
                if excluded_end < segment_end:
                    next_segments.append((max(excluded_end, segment_start), segment_end))
            segments = next_segments
        for segment_start, segment_end in segments:
            if segment_end <= segment_start:
                continue
            total += segment_end - segment_start
            if total > budgets["max_bytes_per_packet"]:
                return "unsupported", [], None, "covered bytes exceed the packet budget"
            covered_ranges.append((segment_start, segment_end))
            parts.append(data[segment_start:segment_end])
    return "resolved", covered_ranges, b"".join(parts), ""


def _v2_checksum_location(
    descriptor: dict[str, Any],
    *,
    target_id: str | None,
    values: dict[str, dict[str, Any]],
    field_map: dict[str, dict[str, Any]],
    data_length: int,
    budgets: dict[str, int],
    width: int,
) -> tuple[str, tuple[int, int] | None, str, str | None]:
    location = descriptor.get("location")
    mode = str(descriptor.get("location_mode", descriptor.get("mode", "absolute"))).lower().replace("-", "_")
    explicit_location = location is not None
    selected_target = target_id
    if isinstance(location, str):
        selected_target = location
        explicit_location = False
    elif isinstance(location, dict):
        reference = next((location.get(key) for key in ("field_id", "field", "ref", "field_ref", "target") if isinstance(location.get(key), str)), None)
        location_kind = str(location.get("kind", location.get("type", ""))).lower()
        if reference is None and (location_kind in {"field", "field_id", "field_ref", "reference"} or not any(key in location for key in ("start", "offset", "absolute_offset", "end", "length", "width", "range"))) and isinstance(location.get("id"), str):
            reference = location["id"]
        if reference is not None:
            selected_target = reference
            explicit_location = False
        mode = str(location.get("location_mode", location.get("mode", location.get("type", location.get("relative_to", mode))))).lower().replace("-", "_")
    if not explicit_location and selected_target is not None:
        target = values.get(selected_target)
        if target is None or selected_target not in field_map:
            return "unresolved", None, f"checksum field {selected_target!r} does not exist", selected_target
        target_status = target.get("status")
        if target_status != "RESOLVED":
            relationship_status = _v2_relationship_dependency_status(target)
            return relationship_status, None, f"checksum field {selected_target!r} is not resolved", selected_target
        start, target_length = target.get("offset"), target.get("length")
        if not isinstance(start, int) or not isinstance(target_length, int):
            return "unresolved", None, f"checksum field {selected_target!r} has no concrete location", selected_target
        if target_length != width:
            return "unsupported", None, "checksum field width does not match the selected algorithm", selected_target
        return "resolved", (start, start + target_length), "", selected_target
    if isinstance(location, (list, tuple)):
        if len(location) != 2:
            return "unsupported", None, "checksum location arrays must contain start and end", selected_target
        start_status, start, start_message = _v2_eval_checksum_integer(location[0], values, budgets)
        end_status, end, end_message = _v2_eval_checksum_integer(location[1], values, budgets)
        if start_status != "resolved" or end_status != "resolved" or start is None or end is None:
            return (start_status, None, start_message, selected_target) if start_status != "resolved" else (end_status, None, end_message, selected_target)
        location_range = (start, end)
    elif isinstance(location, dict):
        if "range" in location:
            range_status, location_range, range_message = _v2_checksum_one_range(location["range"], values, budgets, data_length=data_length)
            if range_status != "resolved" or location_range is None:
                return range_status, None, range_message, selected_target
        else:
            length_raw = location.get("length", location.get("width", width))
            length_status, length, length_message = _v2_eval_checksum_integer(length_raw, values, budgets)
            if length_status != "resolved" or length is None:
                return length_status, None, length_message, selected_target
            if mode in {"from_end", "end_relative", "relative_to_end", "end"} or any(key in location for key in ("from_end", "offset_from_end", "end_relative", "distance")):
                distance_raw = next((location.get(key) for key in ("from_end", "offset_from_end", "end_relative", "distance", "offset", "start") if key in location), length)
                distance_status, distance, distance_message = _v2_eval_checksum_integer(distance_raw, values, budgets)
                if distance_status != "resolved" or distance is None:
                    return distance_status, None, distance_message, selected_target
                if distance == 0:
                    distance = length
                location_range = (data_length - distance, data_length - distance + length)
            else:
                start_raw = location.get("start", location.get("offset", location.get("absolute_offset")))
                start_status, start, start_message = _v2_eval_checksum_integer(start_raw, values, budgets)
                if start_status != "resolved" or start is None:
                    return start_status, None, start_message, selected_target
                location_range = (start, start + length)
    elif location is not None:
        if mode in {"from_end", "end_relative", "relative_to_end", "end"}:
            distance_status, distance, distance_message = _v2_eval_checksum_integer(location, values, budgets)
            if distance_status != "resolved" or distance is None:
                return distance_status, None, distance_message, selected_target
            if distance == 0:
                distance = width
            location_range = (data_length - distance, data_length - distance + width)
        else:
            start_status, start, start_message = _v2_eval_checksum_integer(location, values, budgets)
            if start_status != "resolved" or start is None:
                return start_status, None, start_message, selected_target
            location_range = (start, start + width)
    elif mode in {"from_end", "end_relative", "relative_to_end", "end"}:
        distance_raw = descriptor.get("offset_from_end", descriptor.get("distance", width))
        distance_status, distance, distance_message = _v2_eval_checksum_integer(distance_raw, values, budgets)
        if distance_status != "resolved" or distance is None:
            return distance_status, None, distance_message, selected_target
        if distance == 0:
            distance = width
        location_range = (data_length - distance, data_length - distance + width)
    elif "offset" in descriptor or "start" in descriptor or "absolute_offset" in descriptor:
        start_status, start, start_message = _v2_eval_checksum_integer(descriptor.get("offset", descriptor.get("start", descriptor.get("absolute_offset"))), values, budgets)
        if start_status != "resolved" or start is None:
            return start_status, None, start_message, selected_target
        location_range = (start, start + width)
    else:
        return "unsupported", None, "checksum location is not declared", selected_target
    start, end = location_range
    if start < 0 and mode in {"from_end", "end_relative", "relative_to_end", "end"}:
        return "insufficient", location_range, "end-relative checksum location extends before captured bytes", selected_target
    if start < 0 or end <= start or end - start != width:
        return "unsupported", None, "checksum location width or bounds are invalid", selected_target
    if start > budgets["max_bytes_per_packet"] or end > budgets["max_bytes_per_packet"]:
        return "unsupported", None, "checksum location exceeds the packet budget", selected_target
    if end > data_length:
        return "insufficient", location_range, "checksum location extends beyond captured bytes", selected_target
    return "resolved", location_range, "", selected_target


def _v2_apply_checksum_relationship(
    descriptor_id: str,
    owner_id: str | None,
    descriptor: dict[str, Any],
    *,
    packet: Packet,
    checked: dict[str, Any],
    values: dict[str, dict[str, Any]],
    field_map: dict[str, dict[str, Any]],
    coordinate_cache: dict[str, tuple[bytes | None, dict[str, Any]]],
) -> dict[str, Any]:
    nested = descriptor.get("checksum")
    if isinstance(nested, dict):
        merged = dict(nested)
        merged.update({key: value for key, value in descriptor.items() if key != "checksum"})
        descriptor = merged
    algorithm = _v2_checksum_algorithm(descriptor.get("algorithm"))
    target_id = _v2_relationship_target_id(descriptor, owner_id)
    if algorithm is None:
        return _v2_relationship_failure("unsupported", descriptor_id, "checksum_algorithm", "checksum algorithm is not in the reviewed allow-list", algorithm=descriptor.get("algorithm"), checksum_field_id=target_id)
    kind = str(descriptor.get("kind", "checksum")).lower()
    if kind not in {"checksum", "crc", "checksum_relationship", "check"}:
        return _v2_relationship_failure("unsupported", descriptor_id, "relationship_kind", "relationship kind is not a checksum relationship", algorithm=algorithm, checksum_field_id=target_id)
    target_declared = owner_id is not None or any(key in descriptor for key in ("checksum_field", "checksum_field_id", "target_field", "target_field_id", "field_id", "target", "field"))
    if target_declared and (target_id is None or target_id not in field_map):
        return _v2_relationship_failure("unresolved", descriptor_id, "checksum_field", "checksum field reference does not exist", algorithm=algorithm, checksum_field_id=target_id)
    algorithm_kind, params = _V2_CHECKSUM_ALGORITHMS[algorithm]
    algorithm_width = params.width // 8 if params is not None else {"XOR-8": 1, "ADDITIVE-8": 1, "ADDITIVE-16": 2}[algorithm]
    coordinate_system = descriptor.get("coordinate_system")
    if coordinate_system is None and target_id in field_map:
        coordinate_system = field_map[target_id].get("coordinate_system")
    coordinate_system = coordinate_system or checked["coordinate_system"]
    if not isinstance(coordinate_system, str) or coordinate_system not in COORDINATE_SYSTEMS:
        return _v2_relationship_failure("unsupported", descriptor_id, "coordinate_system", "checksum coordinate system is invalid", algorithm=algorithm, checksum_field_id=target_id)
    if coordinate_system not in coordinate_cache:
        coordinate_cache[coordinate_system] = coordinate_bytes(packet, coordinate_system)
    data, metadata = coordinate_cache[coordinate_system]
    if data is None or not metadata.get("available"):
        return _v2_relationship_failure("insufficient", descriptor_id, "coordinate_unavailable", "checksum coordinate bytes are unavailable", algorithm=algorithm, checksum_field_id=target_id)
    if len(data) > checked["budgets"]["max_bytes_per_packet"]:
        return _v2_relationship_failure("unsupported", descriptor_id, "packet_budget", "checksum coordinate bytes exceed the packet budget", algorithm=algorithm, checksum_field_id=target_id)
    byte_order = descriptor.get("byte_order", descriptor.get("endianness", descriptor.get("endian", descriptor.get("order"))))
    if byte_order is None and target_id in field_map:
        byte_order = field_map[target_id].get("endian")
    if byte_order is None or byte_order == "unknown":
        byte_order = "big"
    elif isinstance(byte_order, str):
        byte_order = byte_order.lower()
    if byte_order not in {"big", "little"}:
        return _v2_relationship_failure("unsupported", descriptor_id, "byte_order", "checksum byte order must be big or little", algorithm=algorithm, checksum_field_id=target_id)
    declared_width = descriptor.get("width", descriptor.get("checksum_width"))
    if declared_width is not None:
        width_status, width_value, width_message = _v2_eval_checksum_integer(declared_width, values, checked["budgets"])
        if width_status != "resolved" or width_value is None:
            return _v2_relationship_failure(width_status, descriptor_id, "checksum_width", width_message, algorithm=algorithm, checksum_field_id=target_id, byte_order=byte_order)
        if width_value != algorithm_width:
            return _v2_relationship_failure("unsupported", descriptor_id, "checksum_width", "declared checksum width does not match the selected algorithm", algorithm=algorithm, checksum_field_id=target_id, byte_order=byte_order)
    location_status, location, location_message, resolved_target_id = _v2_checksum_location(
        descriptor, target_id=target_id, values=values, field_map=field_map,
        data_length=len(data), budgets=checked["budgets"], width=algorithm_width,
    )
    if location_status != "resolved" or location is None:
        return _v2_relationship_failure(location_status, descriptor_id, "checksum_location", location_message, algorithm=algorithm, checksum_field_id=resolved_target_id or target_id, byte_order=byte_order)
    coverage_status, covered_ranges, covered_data, coverage_message = _v2_checksum_coverage(
        descriptor, location=location, data=data, values=values, budgets=checked["budgets"],
    )
    if coverage_status != "resolved" or covered_data is None:
        return _v2_relationship_failure(coverage_status, descriptor_id, "checksum_coverage", coverage_message, algorithm=algorithm, checksum_field_id=resolved_target_id or target_id, byte_order=byte_order)
    start, end = location
    expected = int.from_bytes(data[start:end], byte_order)
    actual = compute_crc(covered_data, params) if algorithm_kind == "crc" else checksum_value(covered_data, algorithm)
    status = "valid" if actual == expected else "invalid"
    code = "checksum_valid" if status == "valid" else "checksum_mismatch"
    diagnostic = _v2_diag(status, code, "checksum matches covered bytes" if status == "valid" else "checksum does not match covered bytes", relationship_id=descriptor_id, expected=expected, actual=actual)
    return {
        "id": descriptor_id,
        "kind": "checksum",
        "status": status,
        "algorithm": algorithm,
        "checksum_field_id": resolved_target_id or target_id,
        "byte_order": byte_order,
        "location": {"offset": start, "length": end - start},
        "covered_ranges": [[range_start, range_end] for range_start, range_end in covered_ranges],
        "expected": expected,
        "actual": actual,
        "diagnostics": [diagnostic],
    }


def _v2_apply_packet(checked: dict[str, Any], packet: Packet) -> dict[str, Any]:
    checked["_runtime"] = {"array_items": 0, "output_fields": 0}
    checked["_runtime_diagnostics"] = []
    values: dict[str, dict[str, Any]] = {}
    records: dict[str, dict[str, Any]] = {}
    field_outputs: dict[str, dict[str, Any]] = {}
    runtime_fields = _v2_expand_fields(
        checked["fields"], checked["definitions"],
        max_nesting=checked["budgets"]["max_nesting"],
    )
    field_map = {field["id"]: field for field in _v2_walk_fields(runtime_fields)}
    checked["_runtime_field_ids"] = set(field_map)
    refs_by_id, graph_diagnostics = _v2_schema_graph(runtime_fields, {})
    cyclic = {item["field_id"] for item in graph_diagnostics if item.get("code") == "dependency_cycle"}
    missing = {(item.get("field_id"), item.get("reference")) for item in graph_diagnostics if item.get("code") == "missing_reference"}
    checked["_runtime_cyclic_fields"] = cyclic
    checked["_runtime_missing_references"] = {}
    for field_id, reference in missing:
        checked["_runtime_missing_references"].setdefault(field_id, set()).add(reference)

    root_by_id: dict[str, str] = {}
    for root in runtime_fields:
        root_by_id[root["id"]] = root["id"]
        for nested in _v2_walk_fields(root.get("fields", []) or []):
            root_by_id[nested["id"]] = root["id"]
    root_dependencies: dict[str, set[str]] = {field["id"]: set() for field in runtime_fields}
    for field_id, dependencies in refs_by_id.items():
        owner = root_by_id.get(field_id)
        if owner is None:
            continue
        for dependency in dependencies:
            dependency_owner = root_by_id.get(dependency)
            if dependency_owner is not None and dependency_owner != owner:
                root_dependencies[owner].add(dependency_owner)
    # Array element declarations are instantiated later, so they are not in
    # the ordinary runtime field graph yet.  Their references can still make
    # the containing root field depend on a later sibling.
    root_reference_map: dict[str, str] = {}
    for root in runtime_fields:
        root_reference_map[root["id"]] = root["id"]
        if isinstance(root.get("name"), str):
            root_reference_map[root["name"]] = root["id"]
        for nested in _v2_walk_fields(root.get("fields", []) or []):
            root_reference_map[nested["id"]] = root["id"]
    for root in runtime_fields:
        for declared in _v2_walk_declared_fields([root]):
            if declared is root:
                continue
            owner = root["id"]
            references: set[str] = set()
            for expression in _v2_direct_field_expressions(declared):
                _v2_expression_refs(expression, references)
            for reference in references:
                dependency_owner = root_reference_map.get(reference)
                if dependency_owner is not None and dependency_owner != owner:
                    root_dependencies[owner].add(dependency_owner)
    root_order = _v2_order_scope_fields(runtime_fields, root_dependencies)
    for field in root_order:
        field_id = field["id"]
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
    fields = [field_outputs[field["id"]] for field in runtime_fields]
    diagnostics = list(checked.get("diagnostics", []))
    diagnostics.extend(item for item in graph_diagnostics if item not in diagnostics)
    diagnostics.extend(item for item in checked.get("_runtime_diagnostics", []) if item not in diagnostics)
    coordinate_cache: dict[str, tuple[bytes | None, dict[str, Any]]] = {}
    relationship_results: list[dict[str, Any]] = []
    relationship_checked = {**checked, "fields": runtime_fields}
    for relationship_id, owner_id, descriptor in _v2_relationship_descriptors(relationship_checked):
        relationship_kind = str(descriptor.get("kind", "checksum")).lower()
        if relationship_kind in {"length", "length_relationship", "size"}:
            if owner_id is not None and not any(key in descriptor for key in ("field_id", "length_field_id", "length_field", "source_field_id", "source", "field")):
                descriptor = {**descriptor, "field_id": owner_id}
            source_id = next((descriptor.get(key) for key in ("field_id", "length_field_id", "length_field", "source_field_id", "source", "field") if isinstance(descriptor.get(key), str)), owner_id)
            coordinate_system = descriptor.get("coordinate_system") or (field_map.get(source_id or "", {}).get("coordinate_system")) or checked["coordinate_system"]
            if coordinate_system not in coordinate_cache:
                coordinate_cache[coordinate_system] = coordinate_bytes(packet, coordinate_system)
            relation_data, relation_metadata = coordinate_cache[coordinate_system]
            relationship = _v2_length_relationship(
                relationship_id, descriptor, values=values, field_map=field_map,
                data_length=len(relation_data) if relation_data is not None and relation_metadata.get("available") else 0,
            )
        else:
            relationship = _v2_apply_checksum_relationship(
                relationship_id, owner_id, descriptor, packet=packet, checked=checked,
                values=values, field_map=field_map, coordinate_cache=coordinate_cache,
            )
        relationship_results.append(relationship)
        diagnostics.extend(relationship.get("diagnostics", []))
        target_id = relationship.get("checksum_field_id") or relationship.get("field_id") or owner_id
        if target_id in field_outputs:
            target_output = field_outputs[target_id]
            target_output.setdefault("checksum_diagnostics", []).append(relationship)
            target_output["relationship_status"] = relationship["status"]
    relationship_results.sort(key=lambda item: str(item.get("id", "")))
    for output in field_outputs.values():
        if "checksum_diagnostics" in output:
            output["checksum_diagnostics"].sort(key=lambda item: str(item.get("id", "")))
    diagnostics = sorted(diagnostics, key=lambda item: (str(item.get("field_id", "")), str(item.get("code", "")), str(item.get("reference", item.get("relationship_id", "")))))
    packet_status = "RESOLVED"
    for field in fields:
        packet_status = _v2_merge_status(packet_status, field.get("status", "INVALID"))
    return {
        "packet_id": packet.index, "status": packet_status, "fields": fields,
        "relationships": relationship_results,
        "checksum_diagnostics": relationship_results,
        "diagnostics": diagnostics,
    }


def _apply_schema_v2(schema: dict[str, Any], packets: Iterable[Packet], max_packets: int = 100_000) -> dict[str, Any]:
    checked = _validate_schema_v2(schema)
    if isinstance(max_packets, bool) or not isinstance(max_packets, int) or max_packets <= 0:
        raise ValueError("packet count exceeds schema application limit")
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
        relationship_results = packet.get("relationships", packet.get("checksum_diagnostics", []))
        relationship_statuses = {item.get("status") for item in relationship_results}
        field_incomplete = field_statuses & {"UNKNOWN", "UNAVAILABLE", "OUT_OF_BOUNDS"}
        field_violated = field_statuses & {"INVALID", "CYCLIC", "LIMIT_EXCEEDED"}
        relationship_invalid = "invalid" in relationship_statuses
        relationship_incomplete = relationship_statuses & {"insufficient", "unresolved", "unsupported"}
        if field_violated or relationship_invalid:
            status = "violated"
        elif field_incomplete or relationship_incomplete:
            # A missing byte, unavailable coordinate, or unresolved reviewed
            # range means validation could not be completed.  It is not a
            # checksum mismatch and must not be reported as invalid data.
            status = "incomplete"
        else:
            status = "ok"
        packet_diagnostics.append({
            "packet_id": packet["packet_id"], "status": status,
            "schema_status": packet.get("status"),
            "fields": packet.get("fields", []),
            "relationships": relationship_results,
            "checksum_diagnostics": relationship_results,
            "diagnostics": packet.get("diagnostics", []),
        })
    relationship_counts = {status: 0 for status in ("valid", "invalid", "insufficient", "unsupported", "unresolved")}
    for packet in packet_diagnostics:
        for relationship in packet.get("relationships", []):
            status = relationship.get("status")
            if status in relationship_counts:
                relationship_counts[status] += 1
    return {
        "schema_version": SCHEMA_V2_VERSION,
        "summary": {
            "packet_count": len(packet_diagnostics),
            "decoded_packets": sum(item["status"] == "ok" for item in packet_diagnostics),
            "incomplete_packets": sum(item["status"] == "incomplete" for item in packet_diagnostics),
            "invalid_packets": sum(item["status"] == "violated" for item in packet_diagnostics),
            "relationship_counts": relationship_counts,
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
    fields: list[dict[str, Any]] = []
    for field in checked["fields"]:
        identity = json.dumps({"coordinate_system": field["coordinate_system"], "name": field["name"], "offset": field["offset"], "type": field["type"], "width": field["width"]}, sort_keys=True, separators=(",", ":"))
        digest_value = 2166136261
        for byte in identity.encode("utf-8"):
            digest_value ^= byte
            digest_value = (digest_value * 16777619) & 0xFFFFFFFF
        digest = f"{digest_value:08x}"
        fields.append({
            "id": f"{_v2_slug(field['name'])}_{digest}", "name": field["name"],
            "description": "Migrated from Schema V1 fixed-range field.",
            "type": field["type"].lower(), "offset": field["offset"], "length": field["width"],
            "endian": field["endian"], "coordinate_system": field["coordinate_system"],
            "constraints": field.get("constraints", {}) if isinstance(field.get("constraints", {}), dict) else {},
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
