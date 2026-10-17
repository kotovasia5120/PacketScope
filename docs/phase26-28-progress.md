# PacketScope Phase 26–28 Progress

Starting HEAD: `118a07a`

Current HEAD: `2159d74`

Current milestone: **Milestone A — COMPLETE; Milestone B NOT_STARTED**

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
- NOT_STARTED: authoritative partial/truncation contract expansion.
- PARTIAL: Kaitai and Wireshark exporters remain flat-static only; external
  semantic execution is UNVERIFIED.
- PARTIAL: the realistic request/response demonstration is not consolidated.
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
| flat | 100,000 | 113.8613 | 113.8215 | 878.3 packets/s | 462,345,070 |
| nested records | 2,000 | 7.7457 | 7.7450 | 258.2 packets/s | 32,816,672 |
| large arrays | 1,000 | 19.5625 | 19.5599 | 51.1 packets/s | 97,652,254 |
| complex dependencies | 2,000 | 3.6316 | 3.6278 | 550.7 packets/s | 13,871,195 |
| CRC relationships | 2,000 | 2.2942 | 2.2917 | 871.8 packets/s | 12,473,123 |

The before/after comparison uses the same benchmark corpus and configuration;
the before file is the committed baseline from `04f6dde`, and the after file is
the committed result from `2159d74`:

| Workload | Packets | Wall before → after | Throughput before → after | Peak tracemalloc before → after |
| --- | ---: | ---: | ---: | ---: |
| flat | 100,000 | 113.8613 s → 72.2298 s (-36.6%) | 878.3 → 1,384.5/s (+57.6%) | 462,337,966 → 462,319,910 (-0.0%) |
| nested records | 2,000 | 7.7457 s → 6.2017 s (-19.9%) | 258.2 → 322.5/s (+24.9%) | 32,809,936 → 32,490,869 (-1.0%) |
| large arrays | 1,000 | 19.5625 s → 14.8438 s (-24.1%) | 51.1 → 67.4/s (+31.8%) | 97,651,934 → 97,632,446 (-0.0%) |
| complex dependencies | 2,000 | 3.6316 s → 2.4856 s (-31.6%) | 550.7 → 804.7/s (+46.1%) | 13,870,379 → 13,832,775 (-0.3%) |
| CRC relationships | 2,000 | 2.2942 s → 1.6591 s (-27.7%) | 871.8 → 1,205.6/s (+38.3%) | 12,461,955 → 12,432,359 (-0.2%) |

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
- `make test`: PASS — 157 Python tests.
- `make benchmark`: PASS — 84 measurements, one warmup, three measured repeats.
- Peak memory numbers remain tracemalloc allocation measurements, not RSS.

## Exact next action

Expand the authoritative completeness contract and its Python/HTTP/browser
tests. Specifically cover evaluated versus fully validated packet counts,
output/array/schema-limit truncation, unsupported constructs, invalid schemas,
and cancellation or unavailable transport input without collapsing those states
into unconditional success.
