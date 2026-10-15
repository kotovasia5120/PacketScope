# Development plan

## P0 — usable local vertical slice

- Import BIN, HEX, classic PCAP, and basic PCAPNG packet blocks.
- Show packets as absolute-offset HEX/ASCII rows.
- Compare aligned messages and identify constant/variable regions.
- Emit deterministic candidates for magic bytes, counters, lengths, and common
  checksums, always with evidence and caveats.
- Add manual annotations, JSON export, upload limits, Docker, and offline tests.

**Completion criteria:** a synthetic capture can be uploaded in the browser,
inspected, annotated, and exported without network access; malformed and
oversized inputs return bounded errors; `make test` passes.

## P1 — stronger protocol investigation

- Add packet grouping and direction-aware views.
- Add field-width/endian alternatives and checksum range explanations.
- Add PCAP link-layer decoding for common Ethernet/IP/UDP/TCP payloads.
- Add saved local workspaces and import/export of annotation sets.

**Completion criteria:** a user can compare multiple message groups and trace
each candidate to source packets and byte ranges, with regression fixtures for
each supported link type.

## P2 — scale and collaboration ergonomics

- Stream large captures with indexed paging.
- Add reproducible analysis profiles and CLI batch reports.
- Add optional local plugin hooks with a documented, sandbox-free boundary.
- Improve keyboard navigation and visual filtering for large hypothesis sets.

**Completion criteria:** large bounded inputs remain responsive in documented
limits, outputs stay schema-compatible, and all behavior remains local and
telemetry-free.
