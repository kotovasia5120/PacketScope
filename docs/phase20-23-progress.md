# PacketScope Phase 20–23 Progress

Starting HEAD: `f14e4f1`

Current HEAD: `6e5f81d`

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
- NOT_STARTED: versioned response metadata for evaluator version/capabilities
  and completeness has not yet been added.
- PARTIAL: the shared parity fixture still intentionally covers only the
  browser-supported local subset; reusable-instance and relationship parity
  remain server-authoritative.

### Milestone C — Interoperability: PARTIAL

- COMPLETE: current exporters remain bounded and warn about omitted dynamic or
  nested constructs.
- NOT_STARTED: full semantic nested/dynamic Kaitai and Wireshark Lua generation
  and external-tool execution.

### Milestone D — Performance and reliability: NOT_STARTED

- NOT_STARTED: dedicated Schema V2 100/1,000/10,000/100,000 packet corpus and
  machine-readable wall/CPU/memory/browser baselines.
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
- A docs-only checkpoint commit is pending after this file is updated.

## Known regressions / gaps

- No known functional regression after the full required local test matrix.
- The browser tree is intentionally bounded to the existing field and output
  budgets and does not render unbounded imported schema content.
- Export syntax/semantics for complex nested/dynamic constructs remains
  explicitly warning-based until the interoperability milestone.

## Exact next implementation action

Run the full required check matrix, fix any regression, commit the workbench
vertically, then add the versioned evaluator capability metadata and differential
server-authority coverage before starting performance benchmarks.
