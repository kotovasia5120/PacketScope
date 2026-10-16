"""Data-only interoperability exporters for explicitly reviewed schemas."""
from __future__ import annotations

import re

from packetscope.schema import validate_schema


def export_kaitai(schema: dict) -> dict:
    checked = validate_schema(schema)
    warnings: list[str] = []
    lines = ["meta:", f"  id: {safe_identifier(checked.get('name', 'packetscope_protocol'))}", "  endian: be", "seq:"]
    cursor = 0
    for index, field in enumerate(sorted(checked["fields"], key=lambda item: (item["offset"], item["name"]))):
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
        cursor = offset + width
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
    for index, field in enumerate(sorted(checked["fields"], key=lambda item: (item["offset"], item["name"]))):
        identifier = safe_identifier(field["name"], fallback=f"field_{index}")
        if field["coordinate_system"] != "raw_packet":
            warnings.append(f"field {field['name']} uses application_payload coordinates and needs a transport payload dissector")
            continue
        if field["offset"] < 0 or field["width"] <= 0:
            warnings.append(f"field {field['name']} has an unsupported range")
            continue
        lua_type = _lua_type(field, warnings)
        lines.append(f"fields.{identifier} = ProtoField.{lua_type}('{protocol}.{identifier}', '{field['name']}')")
        emitted.append((identifier, field))
    lines.append(f"{protocol}.fields = fields")
    lines.extend([f"function {protocol}.dissector(buffer, pinfo, tree)", f"  local subtree = tree:add({protocol}, buffer())"])
    for identifier, field in emitted:
        offset, width = field["offset"], field["width"]
        add_method = "add_le" if field.get("endian") == "little" and _is_numeric_field(field) else "add"
        lines.extend([f"  if buffer:len() >= {offset + width} then", f"    subtree:{add_method}(fields.{identifier}, buffer({offset}, {width}))", "  end"])
    lines.extend(["end", f"return {protocol}"])
    return {"format": "wireshark-lua", "content": "\n".join(lines) + "\n", "warnings": sorted(set(warnings))}


def safe_identifier(value: object, *, fallback: str = "field") -> str:
    result = re.sub(r"[^A-Za-z0-9_]", "_", str(value).strip()).strip("_").lower()
    if not result:
        result = fallback
    if result[0].isdigit():
        result = f"_{result}"
    return result[:80]


def _kaitai_type(field: dict, warnings: list[str]) -> str:
    type_name = str(field.get("type", "custom")).upper()
    width = field["width"]
    endian = field.get("endian")
    if type_name == "UINT32" and width == 4:
        return "u4le" if endian == "little" else "u4"
    if type_name == "UINT64" and width == 8:
        return "u8le" if endian == "little" else "u8"
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
    if type_name in {"UINT32", "LENGTH_FIELD"} and width == 4:
        return "uint32"
    if type_name in {"UINT64", "INT64"} and width == 8:
        return "uint64"
    if type_name == "CUSTOM":
        return "bytes"
    if width == 1:
        return "uint8"
    warnings.append(f"field {field['name']} type/width is not mapped exactly in Lua and was emitted as bytes")
    return "bytes"


def _is_numeric_field(field: dict) -> bool:
    return str(field.get("type", "")).upper() in {"UINT32", "UINT64", "INT64", "LENGTH_FIELD"} or field.get("width") == 1
