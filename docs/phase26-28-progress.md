# PacketScope Phase 26–28 Progress

Starting HEAD: `118a07a`

Current HEAD: `118a07a`

Current milestone: **Milestone A — profiling complete; optimization NOT_STARTED**

## Status

- COMPLETE: repository instructions, Phase 20–23 checkpoint, Schema V2 evaluator,
  benchmark corpus, validation contract, and interoperability matrix inspected.
- COMPLETE: baseline benchmark reproduced with the pinned CPython 3.12.7
  interpreter using `make benchmark` (84 measurements, 100/1,000/10,000/100,000
  requested sizes, one warmup, three measured repeats).
- COMPLETE: cProfile and tracemalloc profiling identified repeated per-packet
  schema preparation as the dominant avoidable cost.
- NOT_STARTED: prepared-schema evaluation optimization.
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

## Exact next action

Implement a reusable immutable prepared evaluation plan built once after Schema
V2 validation. Reuse only normalized metadata and dependency ordering; allocate
fresh packet runtime state and decoded values for every packet. Then run focused
correctness tests, `make test`, and the same benchmark command before moving to
authoritative completeness coverage.
