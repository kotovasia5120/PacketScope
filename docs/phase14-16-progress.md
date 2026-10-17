# PacketScope Phase 14–16 Progress

Starting HEAD: `22fc8ae`
Current HEAD: `998d347`
Workspace branch: `main`

This checkpoint records the locally verified continuation. Automatic detector
results remain hypotheses; Schema V2 validation reports evidence and status, not
proof that an interpretation is the protocol.

## Milestone status

### Milestone A — Schema V2 constraints: PARTIAL; core vertical slice COMPLETE

- COMPLETE: numeric minimum, maximum, exact, allowed, forbidden, signedness,
  width, and endianness checks with lossless wide-integer values.
- COMPLETE: enum diagnostics with strict and explicitly permissive policies.
- COMPLETE: masks, reserved bits, named flags, required/forbidden flags, and
  mutual exclusion diagnostics.
- COMPLETE: field-level diagnostics include field ID/path and byte location.
- COMPLETE: conditional absence, unresolved dependencies, truncation, invalid
  schemas, unsupported relationships, and resource limits retain distinct states.
- COMPLETE: browser evaluator covers the tested constraint subset and signed
  integer semantics.
- COMPLETE: browser structured constraint controls retain an advanced JSON escape
  hatch and submit the authored schema to authoritative server validation.
- COMPLETE: shared golden fixture compares Python and JavaScript values, paths,
  offsets, statuses, and diagnostic codes for the supported core subset. V1
  migration uses a canonical bounded FNV-1a identity in both engines.
- PARTIAL: browser-local checksum/length relationship evaluation and full
  reusable-definition instance scoping are not yet equivalent to Python; the
  independent validation path delegates authoritative results to Python.

### Milestone B — Independent-capture validation: COMPLETE locally

- COMPLETE: dedicated browser workflow accepts a separate capture and format
  selection for BIN/HEX/PCAP/PCAPNG/JSONL/UART/CAN.
- COMPLETE: whole-capture scope is explicit.
- COMPLETE: bounded summary, schema diagnostics, packet diagnostics, field
  diagnostics, and relationship diagnostics render through text content.
- COMPLETE: Chromium E2E covers valid, violated, and truncated independent JSONL
  records.

### Milestone C — Reusable definitions and editor usability: PARTIAL

- COMPLETE: backend definitions expand deterministically with scoped instance IDs,
  paths, provenance, nested references, sibling dependency ordering, cycle and
  missing-reference diagnostics, and depth/output limits.
- COMPLETE: browser bounded undo/redo covers field lifecycle and constraint edits.
- COMPLETE: HEX selection can create a field beyond the initially rendered
  window, preserving packet, coordinate, offset, width, and provenance metadata.
- PARTIAL: browser lacks a first-class reusable-definition hierarchy editor;
  nested JSON remains the advanced path for that uncommon construct.

### Milestone D — Capture integration: COMPLETE locally

- COMPLETE: normalized JSONL, explicit UART lines, and CAN/CAN-FD bounded
  records use the shared importer dispatcher for CLI, HTTP, jobs, analysis, and
  comparisons.
- COMPLETE: timestamps, direction, source identity, boundaries, metadata, CAN
  identifiers, malformed records, mixed formats, empty captures, and size limits
  have regression coverage.
- PARTIAL: UART framing is not inferred from an unframed byte stream; unsupported
  CAN dialects are rejected rather than reinterpreted.

### Milestone E — Interoperability/performance: PARTIAL

- COMPLETE: existing Kaitai and Wireshark exporters remain bounded and warn on
  unsupported dynamic constructs; regression tests pass.
- NOT_STARTED: full enum/bit-mask/nested dynamic exporter expansion.
- NOT_STARTED: dedicated 100/1,000/10,000/100,000 packet benchmark corpus and
  browser rendering/cancellation measurements.
- PARTIAL: deterministic synthetic phase corpora and inference quality scripts
  exist, but they do not measure the new Schema V2 validation path.

## Files changed in this continuation

- `packetscope/schema.py` — constraints, diagnostics, limits, relationships,
  reusable definitions, scoped expansion, and canonical V1 identity.
- `packetscope/static/schema-values.js` — browser constraint evaluator, bounded
  normalization, signed integers, expressions, reusable metadata, and parity
  migration.
- `packetscope/static/app.js`, `index.html`, `styles.css` — structured editor,
  independent validation, HEX field creation, and bounded undo/redo.
- `packetscope/importers/capture_importer.py`, `importers/base.py`, `models.py`,
  CLI/HTTP/analysis modules — unified normalized capture path.
- `tests/test_schema_v2.py`, `tests/test_schema_values.js`,
  `tests/fixtures/schema_v2_parity.json`, importer/CLI/HTTP tests, and E2E specs.

## Verification evidence

- `make test`: **PASS — 156 Python tests** on pinned Python 3.12.7.
- Node syntax checks for app, evaluator, and E2E files: **PASS**.
- `node --test tests/test_schema_values.js`: **PASS — 10 tests**.
- `npm run e2e`: **PASS — 12 Chromium tests**.
- `git diff --check`: **PASS**.
- Phase 6 evaluation: **PASS**, holdout precision 0.375, recall 1.000, F1 0.545.
- Phase 7 frozen holdout: exact F1 0.8 for byte-length and 0.4 for variable-width;
  alternative-group-aware F1 0.8 and 0.444. These are heuristic corpus metrics.
- Docker: **BLOCKED** — `docker` is not installed/available in this environment;
  image build, network-isolated test, and HTTP container smoke test are unverified.
- Hosted GitHub Actions: **UNVERIFIED** — no push or hosted run was authorized.

## Exact next action

Implement or explicitly defer a reusable-definition hierarchy editor, then add
bounded Schema V2 validation benchmarks and exporter coverage only after the
current committed checks remain green. Do not claim release readiness until the
Docker and hosted-CI gates are run by an authorized environment.
