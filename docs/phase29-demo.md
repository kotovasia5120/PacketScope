# Phase 29 deterministic investigation demonstration

PacketScope now includes a deterministic request/response message corpus in
`packetscope/demo_protocol.py`. The generator is independent of the inference
engine. It produces six JSONL messages with forward/reverse direction, message
types, flags, sequence values, dynamic payload lengths, nested fixed-size
records, variable record counts, CRC-16, one deliberately corrupted checksum,
and one deliberately truncated message.

The reviewed schema and reference facts are separate functions:

- `protocol_reference_schema()` — supplied only after the capture has been
  analyzed.
- `protocol_reference_ground_truth()` — evaluation facts, never passed to
  inference.

## Reproduce the backend workflow

```bash
./.runtime/cpython-3.12.7-linux-x86_64-gnu/bin/python3.12 scripts/phase29_demo.py
```

The JSON summary covers import, bounded inference, controlled-change evidence,
authoritative validation, both exporters, and schema project round-trip. The
expected validation classification is four `ok`, one `violated` (CRC
mismatch), and one `incomplete` (missing checksum bytes). The JSONL corpus has
message direction but no network transport identity, so its flow count is
explicitly reported as unavailable; the existing Phase 6 PCAP workflow and
`e2e/experiments.spec.js` cover transport flows and independent baseline/change
scopes.

## Reproduce the browser workflow

The real Chromium scenario is:

```bash
npm run e2e -- --grep "deterministic request-response"
```

`e2e/phase29-demo.spec.js` loads the capture, performs local inspection,
applies the reviewed hierarchical schema, validates an independent copy,
checks the visible `VIOLATED` and `INCOMPLETE` diagnostics plus authoritative
completeness metadata, and saves/restores the project. The reference schema is
declared separately in the test and is not used during the initial analysis.

Transport-flow inspection and controlled baseline/changed experiments remain
covered by the existing Chromium scenarios in `e2e/experiments.spec.js` and
the Phase 6 synthetic PCAP fixture. PacketScope does not claim that JSONL
message direction is equivalent to a confirmed network flow.
