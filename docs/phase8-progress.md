# Phase 8–10 continuation progress

This is the persistent continuation plan for work after commit `65a9fef`.
Status is deliberately split by acceptance criteria; later phases remain
unstarted until the P0 browser workflow is proven.

## Phase 8.1 — Browser controlled experiments

**Status: COMPLETE locally; Docker and hosted CI remain unresolved release gates.**

Implemented:

- `POST /api/experiments/prepare` imports two bounded captures and returns
  provenance plus normalized flow choices without returning packet payloads.
- `POST /api/experiments` submits a two-capture controlled comparison to the
  existing bounded single-worker job lifecycle. `GET /api/jobs/<id>` reports
  progress and `DELETE /api/jobs/<id>` requests cooperative cancellation.
- `GET /api/jobs/<id>/report` exports the retained deterministic JSON report
  with a server-generated filename.
- Baseline and changed files accept BIN, HEX, PCAP, and PCAPNG. File names are
  path-free and bounded; raw input SHA-256, effective format, packet counts,
  byte counts, coordinate system, and independent flow/direction selections
  are retained in the report.
- Comparison still runs only in `packetscope/experiments.py`. It reports
  changed ranges, message distributions, bounded sample evidence,
  contradictions, limitations, and rule-based follow-up suggestions. It
  never upgrades correlation to causation.
- The browser workspace loads each capture independently, scopes each side,
  polls a cancellable job, renders selected synchronized HEX evidence,
  promotes a range to a manual annotation, exports a report-only project, and
  restores that project with a clear reselect-sources message.

Measured acceptance evidence:

- Python suite: **PASS — 114 tests** with `make test`.
- JavaScript syntax: **PASS** with `node --check packetscope/static/app.js`.
- Real Chromium: **PASS — 8 tests** with `npm run e2e` using the pinned
  Python runtime, including two experiment workflows, schema construction/
  validation, and TCP stream reconstruction in the existing PCAP flow.
- Controlled comparison cancellation/progress and independent PCAP flow
  scopes have regression coverage in `tests/test_experiments.py`,
  `tests/test_jobs.py`, and `tests/test_web_integration.py`.

## Phase 8.2–8.3 — Evidence model and active suggestions

**Status: PARTIAL.** The existing report now carries experiment identity,
source hashes, counts, scope, coordinate metadata, distributions, evidence,
contradictions, limitations, and suggestions. Suggestions are deterministic
rules already exposed in the browser. Independent repeated-experiment
identities, richer statistical tests, and persisted annotation history remain
future work.

## Phase 9 — Schema workbench and validation

**Status: PARTIAL.** The existing version 1 schema path remains intact. The
browser now has a dependency-free reviewed-field editor for bounded fixed
ranges, applies those fields to the current capture, and calls
`/api/schema/validate` for per-packet incomplete/constraint/unsupported
diagnostics. Dependency-aware offsets, arrays, conditions, nested structures,
and length/CRC relationships are still not implemented; the editor does not
claim those constructs yet. Reviewed fixed-range schemas can now export to
Kaitai Struct and Wireshark Lua text with explicit unsupported warnings; the
generated text is not executed.

## Phase 10 — TCP reconstruction and interoperability

**Status: PARTIAL.** `packetscope/reassembly.py` now provides bounded,
sequence-ordered TCP direction streams with wraparound-aware offsets,
overlap/retransmission and gap records, timestamps, packet-to-stream mapping,
and a separate conservative fixed/delimiter/magic/length framing hypothesis
layer. `/api/reconstruct` and the browser's stream view expose those
limitations. Kaitai export, Wireshark Lua export, and additional capture
formats remain separate milestones.
Kaitai and Wireshark export are now implemented for supported reviewed fixed
ranges, with deterministic unit/HTTP/browser coverage. Additional formats and
full dependency-aware interoperability remain open.

## Phase 11 — Schema V2 engine

**Status: PARTIAL; first bounded vertical slice is complete.**

Implemented in commits `30c3c35`, `bcbad73`, `5213fcb`, and `d260a91`:

- V1 schemas still load, validate, apply, and export through the existing
  shape. `migrate_schema()` produces deterministic V2 stable field IDs without
  inventing dynamic semantics.
- V2 uses a declarative, non-executable expression model. Static values, field
  references, addition/subtraction, bounded multiplication, masks, boolean
  comparisons, min/max, and alignment are evaluated with deterministic graph
  ordering and explicit `RESOLVED`, `UNKNOWN`, `UNAVAILABLE`, `INVALID`,
  `CYCLIC`, `OUT_OF_BOUNDS`, and `LIMIT_EXCEEDED` states.
- Length-prefixed payloads, dynamic offsets and lengths, conditional presence,
  fixed/count arrays, nested fields, reusable definitions, provenance metadata,
  checksum relationship descriptors, and packet/field/expression/array
  budgets are represented. A false condition is a resolved absence; an
  unresolved condition remains `UNKNOWN`.
- V2 checksum relationships use the existing explicit CRC/checksum engine
  through an allow-list. CRC-8, CRC-16/CCITT-FALSE, CRC-16/MODBUS,
  CRC-32/ISO-HDLC, XOR-8, ADDITIVE-8, and ADDITIVE-16 support static,
  end-relative, field-targeted, include/exclude covered ranges, byte order,
  and deterministic `valid`, `invalid`, `insufficient`, `unsupported`, and
  `unresolved` results. Incomplete captures are not checksum mismatches.
- `/api/schema/validate` accepts V2 and returns per-packet field diagnostics.
  The browser applies V1 and V2 schemas, renders nested/array results and
  diagnostics, exports V2, and has real Chromium coverage for the first slice.

Remaining Phase 11 work includes richer nested-definition evaluation and
constraint enforcement for V2 values.

## Phase 12 — Browser Schema V2 workbench

**Status: PARTIAL.** The dependency-free editor now creates stable-ID V2
fields, accepts bounded JSON expressions for dynamic offsets, lengths and
conditions, configures fixed/count arrays and nested child fields, and shows
field status, byte ranges, values, array identities, and diagnostics. Undo/redo
continues to apply to human annotations. Full drag/drop ordering, reusable
definition editing, checksum configuration, byte-selection field creation,
and a dedicated independent-capture validation workspace remain open.

## Phase 13 — Capture interoperability

**Status: PARTIAL.** Kaitai and Wireshark exporters accept V2 static fields and
emit deterministic output. Dynamic, conditional, nested, array, and checksum
constructs are warned and omitted when the flat target format cannot preserve
their meaning. `packetscope/capture_formats.py` adds bounded normalized JSONL,
explicit UART lines, and explicit CAN lines while preserving timestamp,
direction, source identity, raw bytes, and CAN identifiers. USB captures can
use the normalized JSONL contract, but no dialect-specific USB parser exists.
No framing boundary is inferred.

## Exact continuation instruction

Next: add V2 constraint diagnostics, then complete the independent-capture
browser validation view and reusable nested-definition editor. Preserve the
experiment and stream workspaces and run `make test`, JavaScript syntax checks,
and `npm run e2e` after each thematic change.

## Release blockers

- Docker build and network-isolated image test: **BLOCKED/UNVERIFIED** until a
  Docker-capable host runs the documented commands.
- Hosted GitHub Actions: **UNVERIFIED** because no push or hosted run was
  authorized.
- No deployment or publication was performed.
