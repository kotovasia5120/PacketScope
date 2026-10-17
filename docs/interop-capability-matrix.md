# Interoperability capability matrix

PacketScope exports are **descriptive artifacts**, not an execution path. The
exporter must preserve meaning or emit a bounded warning explaining what was
omitted. PacketScope never executes generated Kaitai or Lua code.

Status meanings:

- **SUPPORTED** — the generated artifact preserves the reviewed construct in
  the current exporter.
- **PARTIALLY_SUPPORTED** — a bounded static subset is emitted and the
  omitted semantics are warned about.
- **UNSUPPORTED** — the target cannot currently represent the construct
  faithfully; PacketScope omits it rather than inventing parser behavior.

| Schema V2 construct | Kaitai Struct `.ksy` | Wireshark Lua | Current policy |
| --- | --- | --- | --- |
| Signed/unsigned 8/16/32/64-bit integers | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | Static widths and selected endianness map to target integer types; unsupported width/type combinations warn. |
| Endianness | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | Kaitai emits `u*le`/`s*le`; Lua uses `add_le` for supported numeric fields. Other fields remain explicit warnings. |
| Enumerations | UNSUPPORTED | UNSUPPORTED | Constraint metadata is not silently converted into target enum declarations. |
| Named bit masks / flags | UNSUPPORTED | UNSUPPORTED | The static range may be omitted or emitted as bytes with a warning; flag meaning is not claimed. |
| Flat static fields | SUPPORTED | SUPPORTED | Raw-packet coordinates, non-overlapping positive static ranges are emitted with bounds checks. |
| Application-payload coordinates | UNSUPPORTED | UNSUPPORTED | A transport payload dissector is required; the field is warned and omitted. |
| Nested structures | UNSUPPORTED | UNSUPPORTED | No flattening is performed because it can change scoped offsets and identity. |
| Reusable definitions | UNSUPPORTED | UNSUPPORTED | Definition expansion is authoritative in Python and is not projected into a flat target. |
| Fixed arrays | UNSUPPORTED | UNSUPPORTED | Repetition syntax is target-specific and not yet generated with semantic checks. |
| Count-dependent arrays | UNSUPPORTED | UNSUPPORTED | Dynamic count and element bounds are warned and omitted. |
| Dynamic lengths / offsets | UNSUPPORTED | UNSUPPORTED | Dynamic expressions are never reduced to guessed constants. |
| Conditional presence | UNSUPPORTED | UNSUPPORTED | Conditional fields are omitted with an explicit warning. |
| Relative offsets | UNSUPPORTED | UNSUPPORTED | Relative expressions are not representable in the current flat exporter. |
| Length relationships | UNSUPPORTED | UNSUPPORTED | Relationships remain in PacketScope validation diagnostics only. |
| Checksum relationships | UNSUPPORTED | UNSUPPORTED | Checksum coverage is warned as descriptive and omitted from generated code. |
| Variable-size payloads | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | Static byte ranges are emitted; dynamic byte sequences warn and are omitted. |

## Validation policy

The exporter unit tests verify deterministic syntax fragments, bounds checks,
endianness handling, and warnings for unsupported constructs. External Kaitai
or Wireshark execution is optional and is not reported as passed when the
tooling is unavailable. A future exporter extension must add synthetic
fixtures, syntax validation, and semantic comparison against authoritative
PacketScope results before changing an entry to **SUPPORTED**.
