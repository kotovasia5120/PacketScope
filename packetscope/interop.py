"""Data-only interoperability exporters for explicitly reviewed schemas."""
from __future__ import annotations

import re

from packetscope.schema import validate_schema


def export_kaitai(schema: dict) -> dict:
    checked = validate_schema(schema)
    warnings: list[str] = []
    lines = ["meta:", f"  id: {safe_identifier(checked.get('name', 'packetscope_protocol'))}", "  endian: be"]
    cursor = 0
    enum_definitions: list[tuple[str, list[tuple[int, str]]]] = []
    enum_ids: set[str] = set()
    export_fields = _representable_fields(checked, warnings)
    for index, field in enumerate(sorted(export_fields, key=lambda item: (item["offset"], item["name"]))):
        offset, width = field["offset"], field["width"]
        if field["coordinate_system"] != "raw_packet":
            warnings.append(f"field {field['name']} uses application_payload coordinates and was not emitted")
            continue
        if offset < cursor:
            warnings.append(f"field {field['name']} overlaps an earlier field and was not emitted")
            continue
        if offset > cursor:
            lines.extend([f"  - id: _padding_{cursor:x}", "    type: u1", f"    repeat: expr", f"    repeat-expr: {offset - cursor}"])
        identifier = safe_identifier(field["name"], fallback=f"field_{index}")
        type_name = _kaitai_type(field, warnings)
        lines.extend([f"  - id: {identifier}", f"    type: {type_name}"])
        if type_name == "bytes":
            lines.append(f"    size: {width}")
        else:
            enum_entries = _named_enum_entries(field, warnings)
            if enum_entries:
                enum_id = f"{identifier}_enum"
                suffix = 2
                while enum_id in enum_ids:
                    enum_id = f"{identifier}_enum_{suffix}"
                    suffix += 1
                enum_ids.add(enum_id)
                enum_definitions.append((enum_id, enum_entries))
                lines.append(f"    enum: {enum_id}")
        if _named_flag_entries(field, warnings):
            warnings.append(f"field {field['name']} named bit masks are not representable in Kaitai Struct and were not emitted")
        cursor = offset + width
    field_lines = lines[3:]
    lines = lines[:3]
    if enum_definitions:
        enum_lines = ["enums:"]
        for enum_id, entries in enum_definitions:
            enum_lines.append(f"  {enum_id}:")
            enum_lines.extend(f"    {value}: {label}" for value, label in entries)
        lines.extend(enum_lines)
    lines.append("seq:")
    lines.extend(field_lines)
    return {"format": "kaitai", "content": "\n".join(lines) + "\n", "warnings": sorted(set(warnings))}


def export_wireshark_lua(schema: dict) -> dict:
    checked = validate_schema(schema)
    warnings: list[str] = []
    protocol = safe_identifier(checked.get("name", "packetscope_protocol"), fallback="packetscope_protocol")
    lua_name = "".join(part.title() for part in protocol.split("_")) or "PacketScope"
    lines = [
        f"local {protocol} = Proto('{protocol}', '{lua_name}')",
        f"local fields = {{}}",
    ]
    emitted: list[tuple[str, dict]] = []
    emitted_flags: list[tuple[str, dict, int]] = []
    export_fields = _representable_fields(checked, warnings)
    for index, field in enumerate(sorted(export_fields, key=lambda item: (item["offset"], item["name"]))):
        identifier = safe_identifier(field["name"], fallback=f"field_{index}")
        if field["coordinate_system"] != "raw_packet":
            warnings.append(f"field {field['name']} uses application_payload coordinates and needs a transport payload dissector")
            continue
        if field["offset"] < 0 or field["width"] <= 0:
            warnings.append(f"field {field['name']} has an unsupported range")
            continue
        lua_type = _lua_type(field, warnings)
        enum_entries = _named_enum_entries(field, warnings)
        enum_table = None
        if enum_entries:
            enum_table = f"{identifier}_enum"
            rendered = ", ".join(f"[{value}] = {_lua_quote(label)}" for value, label in enum_entries)
            lines.append(f"local {enum_table} = {{ {rendered} }}")
        if enum_table is not None and _is_numeric_field(field):
            lines.append(f"fields.{identifier} = ProtoField.{lua_type}('{protocol}.{identifier}', {_lua_quote(field['name'])}, base.DEC, {enum_table})")
        else:
            lines.append(f"fields.{identifier} = ProtoField.{lua_type}('{protocol}.{identifier}', {_lua_quote(field['name'])})")
        emitted.append((identifier, field))
        flag_entries = _named_flag_entries(field, warnings)
        if flag_entries:
            if field["width"] != 1 or not _is_numeric_field(field):
                warnings.append(f"field {field['name']} named bit masks require a one-byte numeric field and were not emitted")
            else:
                for flag_name, mask in flag_entries:
                    flag_identifier = f"{identifier}_{safe_identifier(flag_name)}"
                    flag_label = f"{field['name']}.{flag_name}"
                    lines.append(
                        f"fields.{flag_identifier} = ProtoField.bool('{protocol}.{flag_identifier}', "
                        f"{_lua_quote(flag_label)}, 8, nil, {mask})"
                    )
                    emitted_flags.append((flag_identifier, field, mask))
    lines.append(f"{protocol}.fields = fields")
    lines.extend([f"function {protocol}.dissector(buffer, pinfo, tree)", f"  local subtree = tree:add({protocol}, buffer())"])
    for identifier, field in emitted:
        offset, width = field["offset"], field["width"]
        add_method = "add_le" if field.get("endian") == "little" and _is_numeric_field(field) else "add"
        lines.extend([f"  if buffer:len() >= {offset + width} then", f"    subtree:{add_method}(fields.{identifier}, buffer({offset}, {width}))", "  end"])
    for flag_identifier, field, _mask in emitted_flags:
        offset, width = field["offset"], field["width"]
        lines.extend([f"  if buffer:len() >= {offset + width} then", f"    subtree:add(fields.{flag_identifier}, buffer({offset}, {width}))", "  end"])
    lines.extend(["end", f"return {protocol}"])
    return {"format": "wireshark-lua", "content": "\n".join(lines) + "\n", "warnings": sorted(set(warnings))}


def _representable_fields(schema: dict, warnings: list[str]) -> list[dict]:
    """Project V2 fields only when the flat exporters preserve their meaning.

    The current generators emit flat, bounded ranges. Static V2 fields can be
    projected to that shape; dynamic ranges, conditions, arrays, and nested
    structures are reported and omitted instead of becoming misleading parser
    definitions. V1 fields already have the required shape.
    """
    if schema.get("schema_version") == 1:
        return list(schema["fields"])
    result: list[dict] = []
    for field in schema.get("fields", []):
        name = field.get("name", field.get("id", "field"))
        if field.get("fields") or field.get("array") or field.get("definition"):
            warnings.append(f"field {name} uses nested/array structure and was not emitted")
            continue
        if field.get("presence") is not True:
            warnings.append(f"field {name} uses a conditional presence rule and was not emitted")
            continue
        offset = field.get("offset")
        length = field.get("length")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            warnings.append(f"field {name} uses a dynamic offset and was not emitted")
            continue
        if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
            warnings.append(f"field {name} uses a dynamic length and was not emitted")
            continue
        result.append({**field, "offset": offset, "width": length})
    for relationship in schema.get("relationships", []):
        relationship_id = relationship.get("id", "relationship") if isinstance(relationship, dict) else "relationship"
        warnings.append(f"checksum relationship {relationship_id} is descriptive and was not emitted")
    return result


def safe_identifier(value: object, *, fallback: str = "field") -> str:
    result = re.sub(r"[^A-Za-z0-9_]", "_", str(value).strip()).strip("_").lower()
    if not result:
        result = fallback
    if result[0].isdigit():
        result = f"_{result}"
    return result[:80]


def _lua_quote(value: object) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'"


def _named_enum_entries(field: dict, warnings: list[str]) -> list[tuple[int, str]]:
    constraints = field.get("constraints")
    if not isinstance(constraints, dict) or "enum" not in constraints:
        return []
    raw = constraints.get("enum")
    names = constraints.get("enum_names")
    values = raw
    if isinstance(raw, dict):
        if "values" in raw or "allowed" in raw:
            values = raw.get("values", raw.get("allowed"))
            names = raw.get("names", names)
        else:
            pairs = raw.items()
            values = [key for key, _label in pairs]
            names = {str(key): label for key, label in raw.items()}
    if not isinstance(values, list) or not isinstance(names, dict):
        warnings.append(f"field {field['name']} enum values have no reviewed names and were not emitted")
        return []
    entries: list[tuple[int, str]] = []
    for raw_value in values:
        if isinstance(raw_value, bool):
            continue
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            continue
        label = names.get(str(raw_value), names.get(str(value)))
        if not isinstance(label, str) or not label.strip():
            continue
        entries.append((value, safe_identifier(label, fallback=f"value_{value}")))
    if not entries:
        warnings.append(f"field {field['name']} enum values have no representable reviewed names and were not emitted")
    return sorted(set(entries), key=lambda item: item[0])


def _named_flag_entries(field: dict, warnings: list[str]) -> list[tuple[str, int]]:
    constraints = field.get("constraints")
    flags = constraints.get("flags") if isinstance(constraints, dict) else None
    if flags is None:
        return []
    if not isinstance(flags, dict):
        warnings.append(f"field {field['name']} named flags are malformed and were not emitted")
        return []
    entries: list[tuple[str, int]] = []
    for raw_name, raw_mask in flags.items():
        if isinstance(raw_mask, bool):
            continue
        try:
            mask = int(raw_mask)
        except (TypeError, ValueError):
            continue
        if isinstance(raw_name, str) and raw_name.strip() and mask > 0:
            entries.append((raw_name.strip(), mask))
    if len(entries) != len(flags):
        warnings.append(f"field {field['name']} has invalid named flags that were not emitted")
    return sorted(entries, key=lambda item: (item[1], item[0]))


def _kaitai_type(field: dict, warnings: list[str]) -> str:
    type_name = str(field.get("type", "custom")).upper()
    width = field["width"]
    endian = field.get("endian")
    if type_name in {"UINT8", "U8", "BYTE"} and width == 1:
        return "u1"
    if type_name in {"UINT16", "U16"} and width == 2:
        return "u2le" if endian == "little" else "u2"
    if type_name == "UINT32" and width == 4:
        return "u4le" if endian == "little" else "u4"
    if type_name == "UINT64" and width == 8:
        return "u8le" if endian == "little" else "u8"
    if type_name in {"INT8", "I8"} and width == 1:
        return "s1"
    if type_name in {"INT16", "I16"} and width == 2:
        return "s2le" if endian == "little" else "s2"
    if type_name == "INT32" and width == 4:
        return "s4le" if endian == "little" else "s4"
    if type_name == "INT64" and width == 8:
        return "s8le" if endian == "little" else "s8"
    if type_name not in {"CUSTOM", "MESSAGE_TYPE", "LENGTH_FIELD", "BIT_FLAGS"}:
        warnings.append(f"field {field['name']} type {field['type']} was emitted as bytes")
    if field.get("constraints"):
        warnings.append(f"field {field['name']} constraints/enumerations are not represented in Kaitai output")
    return "bytes"


def _lua_type(field: dict, warnings: list[str]) -> str:
    type_name = str(field.get("type", "custom")).upper()
    width = field["width"]
    if type_name in {"UINT8", "U8", "BYTE"} and width == 1:
        return "uint8"
    if type_name in {"UINT16", "U16"} and width == 2:
        return "uint16"
    if type_name in {"UINT32", "LENGTH_FIELD"} and width == 4:
        return "uint32"
    if type_name in {"UINT64", "INT64"} and width == 8:
        return "uint64"
    if type_name in {"INT8", "I8"} and width == 1:
        return "int8"
    if type_name in {"INT16", "I16"} and width == 2:
        return "int16"
    if type_name == "INT32" and width == 4:
        return "int32"
    if type_name == "CUSTOM":
        return "bytes"
    if width == 1:
        return "uint8"
    warnings.append(f"field {field['name']} type/width is not mapped exactly in Lua and was emitted as bytes")
    return "bytes"


def _is_numeric_field(field: dict) -> bool:
    return str(field.get("type", "")).upper() in {"UINT32", "UINT64", "INT64", "LENGTH_FIELD"} or field.get("width") == 1
