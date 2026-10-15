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

## P2 — scale and collaboration ergonomics

- Stream large captures with indexed paging.
- Add reproducible analysis profiles and CLI batch reports.
- Add optional local plugin hooks with a documented, sandbox-free boundary.
- Improve keyboard navigation and visual filtering for large hypothesis sets.
