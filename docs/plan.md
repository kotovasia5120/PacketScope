# Development plan

## P0 — usable local vertical slice

- Import BIN, HEX, PCAP, and PCAPNG packet blocks.
- Show packets as absolute-offset HEX/ASCII rows.
- Compare aligned messages and identify constant/variable regions.
- Emit deterministic, explicitly hypothetical candidates.
- Add manual annotations, JSON export, upload limits, Docker, and offline tests.

**Status:** Implemented. The pinned-runtime, Docker, and hosted-CI gates remain unverified in the current environment because only Python 3.11.2 is available and Docker/GitHub CLI are absent.

## Phase 3 — explainable protocol reverse engineering

Implemented in the current branch:

- A unified `FieldHypothesis` model with byte-precise absolute and payload-relative offsets.
- Application-payload-first analysis with explicit raw-packet opt-in and decoder limitations.
- Constant prefixes/suffixes, variability statistics, entropy/frequency observations, length, sequence, bit-flag, and message-type candidates.
- Bounded alignment observations for inserted/deleted bytes and variable-length messages.
- CRC-8, CRC-16/CCITT-FALSE, CRC-16/MODBUS, CRC-32/ISO-HDLC, XOR-8, and additive checksum discovery with standard vectors and search/time limits.
- Deterministic synthetic corpora A–D, malformed/insufficient evidence/resource tests, JSON round-trip checks, and protocol-layer offset regression coverage.
- Overview/Compare/Fields/CRC tabs, safe DOM rendering, byte highlighting, evidence display, manual confirmation/rejection annotations, raw-analysis control, local annotation/project restoration, and request cancellation.

**Status:** Implemented and covered by the pinned-runtime CI/Docker verification
record in the README.

## Phase 4 — reliability, interactive reverse engineering, and demo

Implemented in the current branch:

- Deterministic, loadable multi-packet demo profiles for CRC-16 big-endian and
  CRC-32 little-endian with variable message lengths and counter overflow.
- Independent demo ground truth, explicit post-investigation evaluation, and
  precision/recall/F1 plus top-k ranking. Empty-ground-truth recall is N/A.
- Correct per-packet CRC locations for end-relative checksums, deterministic
  hypothesis IDs, and no automatic confirmation.
- Source-preserving importer/analyzer warnings and a bounded single-worker job
  lifecycle with progress and cooperative cancellation endpoints.
- Interactive packet comparison with two-or-more packet selection, raw versus
  application payloads, offset/sequence alignment, diff navigation, bounded
  HEX/ASCII rendering, field highlighting, search, and go-to-offset controls.
- Content-derived annotation identity, validated project restoration, manual
  annotation export, and accessible loading/empty/error states.

The browser client remains dependency-free. Large byte arrays are rendered as
bounded rows rather than one DOM element per byte. The analysis engine still
does not reassemble TCP segments or claim that a heuristic is protocol fact.

## Phase 5 — production reliability and browser acceptance

Implemented in the current working tree:

- Atomic, thread-safe job publication/terminal transitions, cooperative
  cancellation, bounded queues, safe worker errors, result snapshots, cleanup,
  shutdown handling, and HTTP conflict/timeout semantics.
- Normalized IPv4/IPv6 TCP/UDP flow grouping with selectable direction and
  packet-level TCP anomaly notes; TCP stream reassembly remains explicitly
  out of scope.
- Versioned reproducible profiles (`default`, `fast`, `deep`, and custom JSON),
  CLI validation/saving/loading, explicit search budgets, profile fingerprints,
  and report-level input identity/completeness metadata.
- Deterministic hypothesis ranking/grouping with heuristic labels and expanded
  evaluation metrics, plus a pinned Playwright/Chromium suite covering the
  real server and browser demo/persistence flows.

The local container used for this audit has Python 3.11.2 and no Docker daemon,
so the pinned Python 3.12.7, Docker, and hosted-CI gates require a later run.

## P2 — scale and collaboration ergonomics

- Stream large captures with indexed paging.
- Add indexed capture access and CLI batch reports beyond the bounded profiles.
- Add optional local plugin hooks with a documented, sandbox-free boundary.
- Improve keyboard navigation and visual filtering for large hypothesis sets.

## Phase 6 — release candidate hardening

Implemented in the current working tree:

- Fixed and regression-tested the reference-evaluation HTTP endpoint, including
  bounded malformed, incomplete, oversized, unavailable, and internal-error
  handling.
- Reused the existing single-worker jobs to reanalyze uploaded captures for a
  validated flow/direction scope. The browser hides stale hypotheses while a
  scoped result is pending and labels display-only restored-project filtering.
- Added deterministic multi-flow PCAP/manifest coverage for IPv4, IPv6, UDP,
  TCP, duplicate/out-of-order segments, unsupported input, and incomplete
  records.
- Expanded real Chromium acceptance to five tests and bounded packet navigation
  to a searchable 200-option window.
- Added job raw-payload retention and result-size limits with cancellation and
  recovery tests.

Remaining release gates are environmental rather than silently assumed:
Python 3.12.7 execution, Docker build/offline test, and a hosted GitHub Actions
run on this HEAD must be recorded before claiming a complete competition
release. External importer validation is documented separately and does not
claim application-protocol reverse engineering.

## Phase 7 — evidence quality and final release candidate

Implemented locally in the current working tree:

- Ambiguity-aware scalar interpretations with overlap groups, evidence-quality
  metadata, deterministic heuristic ranking, and explicit next-observation
  guidance. The independent holdout's 16-bit little-endian length is retained
  alongside its viable 8-bit projection rather than being arbitrarily forced.
- Root-cause-driven false-positive reductions for nested counters, flag/type
  aliases, and the previous length-candidate generation bug.
- Exact and alternative-group-aware evaluation metrics plus fixed-seed
  development, validation, and frozen-holdout generators.
- Server-owned built-in-demo evaluation identities, explicit untrusted client
  comparison mode, and tamper/wrong-profile regression coverage.
- Versioned non-executable protocol schema export/import/application with
  overlap, variable-length, invalid-schema, manual-origin, and review-status
  coverage, plus browser schema export and apply controls.

Docker and a hosted CI run on the final release commit remain release gates;
see [`docs/phase7-progress.md`](phase7-progress.md).

## Phase 8 — integrated experimental reverse engineering

The first P0 browser milestone is implemented in the current continuation:

- A dedicated dependency-free Experiments workspace accepts independent
  baseline and changed BIN, HEX, PCAP, and PCAPNG captures.
- The existing bounded single-worker job lifecycle now supports controlled
  experiment jobs with progress, cooperative cancellation, aggregate two-file
  retention accounting, independent flow/direction scopes, exact upload hashes,
  and a retained JSON report download.
- The browser renders server-produced changed ranges, distributions, bounded
  synchronized HEX evidence, contradictions, limitations, deterministic
  follow-up suggestions, manual annotations, export, and report-only restore.
- Real Chromium coverage exercises the complete run/review/annotate/export/
  restore flow and independent PCAP flow scopes.

**Status:** Phase 8.1 P0 is complete locally. Phase 8.2/8.3 evidence-model
extensions are partial; repeated-experiment identity and richer statistics are
not yet implemented. See [`docs/phase8-progress.md`](phase8-progress.md).

The first Phase 9 slice is also implemented: the browser can add reviewed
fixed-range fields to a version 1 schema, apply them to the current capture,
and request per-packet validation diagnostics. Dependency-aware structures,
arrays, conditionals, and length/CRC relationships remain future work.

## Phase 10 — bounded TCP reconstruction slice

Implemented as an independent transport-layer slice:

- `packetscope/reassembly.py` reconstructs direction-aware TCP payload streams
  with bounded sequence ordering, wraparound-aware offsets, overlap and gap
  records, packet/timestamp provenance, and no synthetic bytes.
- A separate framing helper reports fixed-length, delimiter, magic-byte, and
  length-prefixed candidates as hypotheses with ambiguity limitations.
- `/api/reconstruct` and the browser stream panel expose the derived view for
  an uploaded capture without changing the immutable packet records.

**Status:** Partial. The backend and browser evidence view are implemented and
covered by unit, HTTP, and Chromium tests. Reviewed fixed-range schemas also
export to Kaitai/Lua with explicit unsupported warnings. Additional capture
formats and full dependency-aware interoperability are not started.

## Continuation plan — reliability and investigation workspace

This is the actionable plan for the post-Phase-7 continuation. Work is
ordered by user impact and each item is complete only when its acceptance
criteria and regression checks are present.

### P0 — correctness and safe deployment

- **Coordinate contract:** every offset-bearing field declares either
  `raw_packet` or `application_payload`; Python schema application and the
  browser use the same transform and return unavailable rather than partial
  values. Acceptance: Ethernet/IPv4/TCP/UDP and raw BIN fixtures highlight and
  apply at identical byte ranges in both views.
- **Lossless scalars:** UINT32, UINT64, and INT64 values are represented as
  JSON-safe decimal strings when needed, with explicit encoding metadata.
  Acceptance: zero, maximum, signed boundary, and both endian orders match
  between Python and JavaScript without `Number.parseInt` precision loss.
- **Deployment truthfulness:** local/private and public-demo modes disclose
  different data handling, and public health/UI text never claims uploads stay
  local. Acceptance: HTTP tests cover both modes and malformed/oversized/slow
  requests do not echo payloads or exhaust the bounded worker.
- **Release consistency:** package, server, upload, retained-job, and report
  metadata agree on version and limits. Acceptance: configuration, wheel, HTTP
  smoke, and adversarial-input tests pass.

### P1 — explainable comparison and investigation UX

- Add a bounded baseline-versus-controlled-change comparison that reports
  correlated byte ranges, group/distribution changes, evidence, contradictions,
  and suggested follow-up experiments without claiming causation.
- Improve non-unit counter and length-convention evidence while retaining
  competing interpretations; add held-out synthetic metrics and runtime/memory
  budget assertions.
- Keep packet, field, and evidence selection synchronized; add keyboard and
  bounded virtualized navigation checks for large packets and stale-scope
  responses.

### P2 — protocol interoperability and transport coverage

- Add explicit reviewed-field exports for Kaitai Struct, Wireshark Lua, and a
  deterministic machine-readable report. Generated definitions remain data-only
  and are never executed by PacketScope.
- Add bounded TCP stream reconstruction as a transport layer with sequence,
  retransmission, overlap, missing-data, and ambiguity records, keeping
  application framing separate.

### Verification gates

After every thematic change run `make test`, then run the applicable Node
syntax/E2E and evaluation commands. Docker build/offline container tests and a
hosted GitHub Actions run remain **UNVERIFIED** until an environment with those
capabilities performs them; no local source-only result may promote either gate.
