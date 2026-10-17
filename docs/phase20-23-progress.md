# PacketScope Phase 20–23 Progress

Starting HEAD: `f14e4f1`

Current HEAD: `920aa91`

Current milestone: **Milestone A — PARTIAL**

## Acceptance criteria and status

### Milestone A — Visual Schema V2 Workbench: PARTIAL

- COMPLETE: dependency-free hierarchical tree for root fields and reusable
  definition fields.
- COMPLETE: create, inspect, duplicate, reorder, and delete fields while
  preserving stable IDs; deletion refuses fields with known references.
- COMPLETE: create, rename, duplicate, delete, and select reusable definitions;
  rename rewrites declarative definition references and deletion reports
  dangling references instead of silently corrupting the schema.
- COMPLETE: add nested structure children and inspect array element descriptors
  from the tree.
- COMPLETE: common GUI controls for reusable definitions, dynamic offset/length
  references, dynamic array counts, and conditional presence. Advanced JSON
  expressions remain available for constructs not covered by the compact form.
- COMPLETE: lightweight dependency inspector reports resolved, missing, and
  cyclic references without a graph dependency.
- COMPLETE: relationship editor for reviewed length/checksum descriptors with
  explicit server-authoritative validation messaging.
- COMPLETE: exact Schema V2 JSON save/restore and project save/restore preserve
  authored definitions, nested fields, arrays, conditions, and relationships.
- COMPLETE: HEX selection continues to attach packet/coordinate/offset/width
  provenance and works with the tree editor.
- COMPLETE: bounded schema undo/redo covers tree edits because all changes use
  the existing whole-document snapshot history.
- COMPLETE: Chromium coverage builds a reusable definition, nested structure,
  dynamic array, conditional field, checksum relationship, applies it, exports
  exact V2 JSON, and restores it from a saved project.
- PARTIAL: the compact inspector does not yet expose every Schema V2 property
  (signedness, encoding, provenance, and all constraint variants) as dedicated
  controls; the existing structured constraint panel and JSON escape hatch
  remain available.

### Milestone B — Cross-engine semantic consistency: PARTIAL

- COMPLETE: browser messaging and the existing API path disclose that Python
  is authoritative for reusable definitions and relationships.
- COMPLETE: `/api/schema/validate` now returns additive versioned evaluation
  contract metadata with canonical schema identity, raw capture identity,
  evaluator version/authority, server capability IDs, completeness status,
  bounded warnings/limitations, and explicit truncation reasons.
- COMPLETE: browser validation reports render the contract without changing
  the existing summary and packet diagnostic meaning; old responses without
  the contract remain supported.
- COMPLETE: HTTP integration tests assert V1/V2 contract identity, authority,
  capabilities, counts, and non-truncated normal evaluation.
- NOT_STARTED: versioned response metadata for evaluator version/capabilities
  and completeness has not yet been added.
- PARTIAL: the shared parity fixture still intentionally covers only the
  browser-supported local subset; reusable-instance and relationship parity
  remain server-authoritative.

### Milestone C — Interoperability: PARTIAL

- COMPLETE: current exporters remain bounded and warn about omitted dynamic or
  nested constructs.
- COMPLETE: `docs/interop-capability-matrix.md` documents SUPPORTED,
  PARTIALLY_SUPPORTED, and UNSUPPORTED semantics for integer types,
  endianness, enums, masks, arrays, nesting, dependencies, relationships,
  payload coordinates, and variable-size fields.
- NOT_STARTED: full semantic nested/dynamic Kaitai and Wireshark Lua generation
  and external-tool execution.

### Milestone D — Performance and reliability: PARTIAL

- COMPLETE: `scripts/benchmark_schema_v2.py` generates independent deterministic
  synthetic flat, nested-record, large-array, dependency, checksum, TCP
  reconstruction, and controlled-experiment workloads. `make benchmark` writes
  `benchmarks/schema-v2-results.json`.
- COMPLETE: machine-readable measurements record wall time, CPU time,
  tracemalloc peak allocation, throughput, serialized output size, environment,
  pinned Python version, warmup/repeat configuration, and explicit workload
  caps.
- BASELINE (one cold repeat, CPython 3.12.7, 12 CPUs, WSL2 x86_64): flat Schema
  V2 throughput was 761 packets/s at 100 packets, 771 packets/s at 1,000,
  789 packets/s at 10,000, and 747 packets/s at 100,000. The 100,000 run took
  133.846 s wall time, used 462,389,190 tracemalloc bytes, and serialized
  121,967,070 result bytes.
- BASELINE (explicit caps recorded in the JSON): nested records 217 packets/s
  at 2,000 evaluated packets, large arrays 43.5 packets/s at 1,000, complex
  dependencies 457.3 packets/s at 2,000, and checksum relationships 769.4
  packets/s at 2,000. No optimization is claimed yet; these are baselines.
- COMPLETE: existing schema and capture budgets continue to bound field,
  nesting, array, packet, output, and response work.

### Milestone E — Realistic end-to-end demonstration: PARTIAL

- COMPLETE: deterministic browser workflow now demonstrates construction,
  validation, exact schema export, and project restore for a nested synthetic
  protocol.
- NOT_STARTED: request/response, deliberate corruption, truncation, controlled
  experiment, and independent-capture walkthrough are not yet consolidated
  into one documented demonstration artifact.

### Milestone F — Release verification: UNVERIFIED

- COMPLETE locally: Python unit/integration suite, JavaScript evaluator tests,
  syntax checks, Chromium E2E, and `git diff --check` after the worktree change.
- BLOCKED: Docker is unavailable in the current environment.
- UNVERIFIED: hosted GitHub Actions; no push was authorized.

## Verification evidence for this checkpoint

Verified after commit with:

```text
make test
node --check packetscope/static/app.js
node --check packetscope/static/schema-values.js
node --check e2e/experiments.spec.js
node --check e2e/schema-v2.spec.js
node --check e2e/schema-v2-usability.spec.js
node --test tests/test_schema_values.js
npm run e2e
git diff --check
```

- `make test`: **PASS — 156 Python tests**.
- Node syntax checks and `node --test tests/test_schema_values.js`: **PASS — 10
  JavaScript tests**.
- `npm run e2e`: **PASS — 13 Chromium tests** (the workbench adds one test to
  the previous 12).
- `git diff --check`: **PASS**.
- Docker verification: **BLOCKED** — `docker` is not installed in this
  environment.
- Hosted GitHub Actions: **UNVERIFIED** — no push was authorized.

The new workbench E2E is in `e2e/schema-v2-usability.spec.js`.

## Modified files

- `packetscope/static/app.js` — hierarchical workbench, dependency inspector,
  relationship editor, exact schema/project persistence, and V2 export path.
- `packetscope/static/styles.css` — accessible bounded tree, dependency, and
  relationship layout styles.
- `e2e/schema-v2-usability.spec.js` — complete GUI construction/persistence
  workflow coverage.
- `docs/phase20-23-progress.md` — this checkpoint.

## Commits

- `6e5f81d feat: add hierarchical schema workbench`
- `837ae76 docs: checkpoint phase 20 workbench`
- `9432d87 feat: expose authoritative schema evaluation contract`
- `920aa91 feat: add reproducible schema performance corpus`
- pending `docs/interop-capability-matrix.md` capability matrix checkpoint
- A docs-only checkpoint commit is pending after this file is updated.

## Known regressions / gaps

- No known functional regression after the full required local test matrix.
- The browser tree is intentionally bounded to the existing field and output
  budgets and does not render unbounded imported schema content.
- Export syntax/semantics for complex nested/dynamic constructs remains
  explicitly warning-based until the interoperability milestone.

## Exact next implementation action

Run `make benchmark` with the pinned interpreter to refresh the corpus after
material code changes; then profile the largest measured allocation before
optimizing any bottleneck. Do not compare results from different Python
versions or workload caps without recording both configurations.
