# PacketScope architecture

## Data flow

```text
BIN / HEX / PCAP / PCAPNG / NORMALIZED JSONL / UART / CAN
          |
          v
   bounded import layer
          |
          v
  immutable Packet records
          |
          v
  bounded protocol metadata decoder
          |
          v
 deterministic observations
          |
          v
  explicit hypotheses + evidence
          |
   normalized flow/direction view
          |
          +--> versioned JSON export / protocol schema
          +--> baseline/control experiment report
          +--> localhost HTTP API --> vanilla browser UI
```

## Boundaries

- `packetscope/importers/` validates file formats and produces packets. It does
  not decide what a field means. `capture_importer.py` adapts the bounded
  message-oriented parsers below into this same `ImportResult`/`Packet` path;
  CLI, HTTP, and analysis jobs therefore share one dispatch boundary.
- `packetscope/capture_formats.py` is a separate bounded message-oriented
  importer for captures that already provide message boundaries. Its
  normalized JSON-lines contract has one object per message and preserves a
  finite timestamp, explicit direction, source identity, exact raw bytes
  (canonical padded base64), capture order, and an `explicit-record` boundary
  marker. It never sorts by timestamp, splits a byte stream, or infers a
  missing UART/USB frame boundary. Duplicate JSON keys, non-canonical base64,
  malformed records, packet/message/input limits, and oversized output are
  rejected with the existing `FormatError`/`InputLimitError` types.
- The isolated UART text representation is one UTF-8 line per explicit
  message: `timestamp<TAB>direction<TAB>source<TAB>base64`. The isolated CAN
  representation uses `timestamp<TAB>direction<TAB>source<TAB>can_id#payload_hex`;
  payload bytes remain raw and the bounded numeric CAN identifier is retained
  as `metadata.can_id`. CAN data is capped at 64 bytes, and neither helper
  guesses direction, classic-vs-FD mode, or message boundaries. A USB bulk or
  interrupt capture can use the normalized JSONL contract with a source such
  as `usb:1-2`; USB descriptor and transfer framing are intentionally outside
  this importer.

The canonical JSONL record is compact and stable, for example:

```json
{"boundary":"explicit-record","direction":"rx","index":0,"metadata":{},"raw":"AAEC","raw_encoding":"base64","source":"uart0","timestamp":12.5}
```

`index` is capture order rather than a timestamp sort key. `metadata` is a
bounded scalar object for transport attributes such as `can_id`; it is empty
for ordinary UART/USB records. Re-serializing an imported collection emits
the same key ordering and base64 spelling. A continuous stream must be
framed by the capture producer before it can be represented by this format.
- `packetscope/analysis/` compares aligned bytes and emits cautious,
  evidence-backed hypotheses. It never mutates source data.
- `packetscope/protocols.py` decodes bounded Ethernet, IPv4/IPv6, TCP, and UDP
  header metadata. It reports truncation and fragmentation and does not
  reassemble packets. Unknown link types remain raw and are marked
  `unsupported_link_type`.
- `packetscope/export.py` owns the stable JSON shape and annotation merge.
- `packetscope/schema.py` validates and applies versioned, non-executable
  protocol schemas. V1 fixed-range schemas remain compatible; V2 adds stable
  IDs, declarative dependency expressions, dynamic offsets/lengths, conditions,
  arrays, nested structures, reusable definitions, and explicit evaluation
  budgets/statuses. It only reads bounded imported bytes and never generates
  or executes parser code. V2 checksum relationships use the existing
  allow-listed CRC/checksum engine with explicit ranges, byte order, and
  valid/invalid/insufficient/unsupported/unresolved results. Capture
  validation separates unavailable/incomplete data from protocol violations.
- `packetscope/web.py` exposes bounded HTTP operations and serves static assets.
  It defaults to private local mode; an explicit `public-demo` mode changes the
  health/UI privacy contract so hosted uploads are disclosed to users.
- `packetscope/static/` is a dependency-free presentation layer.
- `packetscope/flows.py` groups decoded IPv4/IPv6 TCP/UDP packets into
  bidirectional endpoint-normalized flows. It preserves packet IDs and raw
  offsets, labels A→B/B→A directions, and records retransmission/out-of-order
  observations as limitations rather than facts. It does not reassemble TCP.
- `packetscope/profiles.py` validates versioned, bounded analysis configuration,
  applies explicit budgets, and computes a profile fingerprint for reports.
- `packetscope/experiments.py` compares two bounded captures in an explicitly
  declared coordinate system. It pairs comparable messages by capture order,
  reports associated ranges and distribution changes, and records limitations
  and follow-up experiments; it does not claim causation or replace framing.
- `packetscope/jobs.py` owns both single-capture analysis jobs and controlled
  experiment jobs. Experiment jobs retain two uploads only until each import
  completes, apply independent flow/direction scopes server-side, and publish
  bounded progress, cancellation, provenance, and report snapshots through the
  same single-worker lifecycle.
- `packetscope/reassembly.py` reconstructs bounded TCP payload directions as a
  derived evidence view. It keeps sequence, timestamp, source-packet mapping,
  overlap, retransmission, and gap records, and its separate framing helper
  emits only conservative hypotheses.
- `packetscope/interop.py` generates data-only Kaitai and Wireshark Lua text
  from reviewed fixed-range schemas. Unsupported coordinates, overlaps, and
  non-representable constraints become warnings rather than silently wrong
  parser definitions.

The first iteration intentionally uses standard-library parsing and a small
detector set. Link-layer stream reassembly and advanced CRC families are
planned extensions, not hidden behavior.

## Safety model

Uploads and direct analysis iterables are bounded before parsing or
materialization. PCAP and PCAPNG length fields are checked against the bounded
source, including block trailers and section/interface state. Packet bytes are
treated only as data. Results say
`candidate` or `hypothesis` and include a confidence plus evidence; users can
add manual annotations that remain distinct from automatic findings.

## Phase 3 analysis contract

`FieldHypothesis` keeps the packet id, absolute raw-packet offset, optional application-payload-relative offset, width, endian, candidate value, confidence, evidence, contradictions, sample count, status, and alternatives together. Automatically generated objects use `hypothesis`; only a browser or API user action may create a confirmed annotation.

By default, decoded Ethernet/IP/transport headers are excluded from discovery. The response records protocol status and limitations for packets whose application payload cannot be decoded. `analyze_raw=True` (the CLI `--raw` option or the upload `raw` field) explicitly switches to raw packet bytes.

The CRC detector has fixed algorithm and range budgets and supports variable-length messages when the checksum is in an end-relative location. Its confidence includes sample count and search-space size; it is not a match percentage.

## Direction and reproducibility contract

Flow IDs are deterministic functions of IP version, transport, and canonical
endpoint tuples. Packet order remains capture/index order within a flow. A
direction-scoped analysis only passes packets from that direction to the
detectors, so counters from opposite directions cannot be merged. For TCP,
sequence overlap and out-of-order observations are packet-level hints; no
application-message or stream reassembly is claimed.

Every report carries `reproducibility` metadata: PacketScope/analyzer versions,
input SHA-256, profile JSON and fingerprint, completeness, tested algorithms,
candidate count, and constraints that stopped bounded searches. The confidence
and ranking fields are explicitly labelled heuristic and are not calibrated
probabilities.

Controlled experiment reports additionally retain exact baseline and changed
upload SHA-256 values, effective formats, packet counts, independent
flow/direction selections, bounded changed-byte evidence, message
distributions, contradictions, limitations, and deterministic follow-up
suggestions. The browser experiment workspace stores only the report and
manual annotations when exporting/restoring; it never embeds original capture
buffers.

Scalar detector candidates may share an `interpretation_group` when their byte
ranges overlap. The group records viable widths and endianness without choosing
one as fact. Each candidate also carries an evidence basis, observed sample
count, caveats, and deterministic “what would help” observations. Manual
schema fields are separate, reviewable records with origin and review status.
