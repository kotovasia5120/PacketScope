# PacketScope Phase 26–28 Progress

Starting HEAD: `118a07a`

Current HEAD: `eded146`

Current milestone: **Milestone F — release verification recorded; Docker BLOCKED**

## Status

- COMPLETE: repository instructions, Phase 20–23 checkpoint, Schema V2 evaluator,
  benchmark corpus, validation contract, and interoperability matrix inspected.
- COMPLETE: baseline benchmark reproduced with the pinned CPython 3.12.7
  interpreter using `make benchmark` (84 measurements, 100/1,000/10,000/100,000
  requested sizes, one warmup, three measured repeats).
- COMPLETE: cProfile and tracemalloc profiling identified repeated per-packet
  schema preparation as the dominant avoidable cost.
- COMPLETE: prepared Schema V2 evaluation metadata is built once per application
  and reused for packet-independent field expansion, dependency ordering,
  relationship descriptors, and safe static array element materialization.
- COMPLETE: packet runtime counters, decoded values, mutable diagnostics, and
  reference state remain isolated per packet.
- COMPLETE: authoritative reports now distinguish complete, partial, truncated,
  unsupported, schema-failure, resource-limit, and packet-constraint states.
- COMPLETE: Python, HTTP, and browser coverage includes incomplete fields,
  missing dependencies, result/output limits, unsupported field types, invalid
  schemas, and packet-budget truncation.
- PARTIAL: Kaitai and Wireshark exporters remain flat-static only; named integer
  enums are emitted when reviewed names are present, and Wireshark emits
  bounded one-byte named masks. External semantic execution is UNVERIFIED.
- COMPLETE: deterministic request/response corpus, separate reviewed schema and
  ground truth, backend workflow script, and Chromium workflow are present.
- PARTIAL: the JSONL demonstration intentionally reports no network flow count;
  transport-flow inspection remains covered by the Phase 6 PCAP workflow.
- BLOCKED: Docker verification is unavailable unless an authorized Docker host
  becomes accessible.
- UNVERIFIED: hosted GitHub Actions because no push was authorized.

## Milestone A baseline evidence

Pinned command:

```text
make benchmark
```

The current environment is CPython 3.12.7 on Linux x86_64. The reproduced
median rows across the three measured repeats include:

| Workload | Evaluated packets | Wall seconds | CPU seconds | Throughput | Peak tracemalloc bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| flat | 100,000 | 113.8613 | 113.8215 | 878.3 packets/s | 462,337,966 |
| nested records | 2,000 | 7.7457 | 7.7450 | 258.2 packets/s | 32,809,936 |
| large arrays | 1,000 | 19.5625 | 19.5599 | 51.1 packets/s | 97,651,934 |
| complex dependencies | 2,000 | 3.6316 | 3.6278 | 550.7 packets/s | 13,870,379 |
| CRC relationships | 2,000 | 2.2942 | 2.2917 | 871.8 packets/s | 12,461,955 |

The before/after comparison uses the same benchmark corpus and configuration;
the before file is the committed baseline from `04f6dde`, and the final after
file is the committed result from `eded146`:

| Workload | Packets | Wall before → after | Throughput before → after | Peak tracemalloc before → after |
| --- | ---: | ---: | ---: | ---: |
| flat | 100,000 | 113.8613 s → 71.2414 s (-37.4%) | 878.3 → 1,403.7/s (+59.8%) | 462,337,966 → 462,319,910 (-0.0%) |
| nested records | 2,000 | 7.7457 s → 6.1945 s (-20.0%) | 258.2 → 322.9/s (+25.0%) | 32,809,936 → 32,490,869 (-1.0%) |
| large arrays | 1,000 | 19.5625 s → 14.7936 s (-24.4%) | 51.1 → 67.6/s (+32.2%) | 97,651,934 → 97,632,446 (-0.0%) |
| complex dependencies | 2,000 | 3.6316 s → 2.5371 s (-30.1%) | 550.7 → 788.3/s (+43.1%) | 13,870,379 → 13,832,775 (-0.3%) |
| CRC relationships | 2,000 | 2.2942 s → 1.6558 s (-27.8%) | 871.8 → 1,208.0/s (+38.6%) | 12,461,955 → 12,432,359 (-0.2%) |

Peak memory above is **traced Python allocation**, not process RSS or peak
physical memory.

The focused cProfile runs used `apply_schema(validate_schema(schema), packets)`
with 1,000 flat packets and 100 large-array packets. Flat evaluation recorded
1,882,613 calls in 4.398 seconds under cProfile; large-array evaluation
recorded 3,663,582 calls in 9.310 seconds. The repeated avoidable work was:

1. `_v2_apply_packet` rebuilding expanded fields, field maps, dependency graphs,
   root dependency ordering, and relationship descriptors for every packet.
2. `_v2_parse_array` expanding the same element descriptor for every array item.
3. `deepcopy` and public result dictionaries are legitimate output costs, but
   were not treated as RSS and are not removed without changing output shape.

Top allocation locations were result construction at `schema.py:1727`,
definition/array expansion at `schema.py:913` and `schema.py:2037`, and
provenance copying. The first optimization targets item 1 while preserving
per-packet state isolation.

## Modified implementation and verification

- `packetscope/schema.py`: added `_v2_prepare_evaluation`, packet-local runtime
  state, and a conservative static-array fast path. Dynamic, nested, definition,
  and reference-bearing array elements retain the general expansion path.
- `tests/test_schema_v2.py`: added a regression test for packet state isolation
  and unchanged normalized schema metadata.
- `benchmarks/schema-v2-results.json`: regenerated with the pinned runtime after
  the optimization.
- `make test`: PASS — 164 Python tests.
- `make benchmark`: PASS — 84 measurements, one warmup, three measured repeats.
- Peak memory numbers remain tracemalloc allocation measurements, not RSS.

## Milestone B correctness evidence

The authoritative Python report now exposes `fully_validated_packets`,
`incomplete_packets`, `unsupported_packets`, `unsupported_fields`,
`validation_completeness`, `resource_limit_termination_reason`, and bounded
resource-limit reason lists. A constraint violation remains a fully evaluated
packet; truncation, unavailable bytes, unresolved dependencies, unsupported
constructs, and schema failures cannot become unconditional success.

The HTTP `evaluation_contract` now includes the same counts plus evaluator and
schema/capture identities, explicit schema-failure metadata, warnings,
limitations, and truncation reasons. The synchronous validation endpoint
discloses that cancellation is not supported rather than claiming it.

- `make test`: PASS — 164 Python tests.
- `node --check packetscope/static/app.js`: PASS.
- `node --check packetscope/static/schema-values.js`: PASS.
- `node --test tests/test_schema_values.js`: PASS — 10 JavaScript tests.
- Focused Chromium Schema V2/validation tests: PASS — 2 tests, including the
  authoritative completeness text in the browser report.

## Milestone C interoperability evidence

- COMPLETE for this vertical slice: named integer enum values with reviewed
  names are generated as Kaitai `enums`/field references and Wireshark Lua value
  tables.
- COMPLETE for this vertical slice: Wireshark one-byte numeric named flags are
  generated as bounded `ProtoField.bool` masks while preserving existing
  endian-specific `add_le` behavior for the primary field.
- PARTIAL: Kaitai named masks remain explicitly warned/omitted because the
  generated flat target has no equivalent field-level mask semantics.
- UNVERIFIED: `kaitai-struct-compiler`, Wireshark `tshark`, and Lua tooling are
  not installed in this environment; tests verify deterministic generation and
  warnings, not external execution.
- `make test`: PASS — 164 Python tests.

## Milestone E end-to-end evidence

- COMPLETE: `packetscope/demo_protocol.py` generates deterministic request and
  response messages with dynamic lengths, nested records, variable arrays,
  sequence values, CRC, corruption, and truncation.
- COMPLETE: `scripts/phase29_demo.py` runs import, bounded inference, controlled
  change comparison, authoritative validation, exports, and schema round-trip
  without passing reference facts into inference.
- COMPLETE: `tests/test_demo_protocol.py` verifies deterministic bytes,
  reference separation, and the expected `ok`/`violated`/`incomplete` states.
- COMPLETE: `e2e/phase29-demo.spec.js` performs the real browser load, schema
  application, independent validation, visible error/completeness review, and
  project restore. The full suite passed 14 Chromium tests.
- PARTIAL: JSONL messages have explicit direction but intentionally no IP/TCP/
  UDP identity; transport flow and independent scope coverage remains in the
  Phase 6 PCAP and experiment scenarios.

## Milestone F release verification

- COMPLETE: `make test` — PASS, 164 Python tests.
- COMPLETE: `node --check packetscope/static/app.js` — PASS.
- COMPLETE: `node --check packetscope/static/schema-values.js` — PASS.
- COMPLETE: `node --test tests/test_schema_values.js` — PASS, 10 JavaScript tests.
- COMPLETE: `npm run e2e` — PASS, 14 Chromium tests.
- COMPLETE: `git diff --check` — PASS.
- BLOCKED: Docker is unavailable in this environment; `docker build` and the
  network-isolated container test were not run.
- UNVERIFIED: hosted GitHub Actions; no push was authorized.
- UNVERIFIED: external Kaitai/Wireshark/Lua semantic execution; tools are not
  installed. Generated syntax and warnings are covered by unit/API tests only.

## Commits created in this phase

`029d104`, `04f6dde`, `680590d`, `2159d74`, `3129ab6`, `1e75272`, `a1a6b87`,
`40b021e`, `fe04c13`, and `eded146`.

## Exact continuation steps

If further work is authorized, install or provide an approved external Kaitai,
Wireshark, and Lua toolchain, run generated artifacts against synthetic
captures, and add semantic range comparisons before promoting matrix entries to
SUPPORTED. Separately, run the documented Docker commands on an authorized
Docker-capable host; do not change this checkpoint's BLOCKED/UNVERIFIED gates
from source-only evidence.
