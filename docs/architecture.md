# PacketScope architecture

## Data flow

```text
BIN / HEX / PCAP / PCAPNG
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
          +--> versioned JSON export
          +--> localhost HTTP API --> vanilla browser UI
```

## Boundaries

- `packetscope/importers/` validates file formats and produces packets. It does
  not decide what a field means.
- `packetscope/analysis/` compares aligned bytes and emits cautious,
  evidence-backed hypotheses. It never mutates source data.
- `packetscope/protocols.py` decodes bounded Ethernet, IPv4/IPv6, TCP, and UDP
  header metadata. It reports truncation and fragmentation and does not
  reassemble packets. Unknown link types remain raw and are marked
  `unsupported_link_type`.
- `packetscope/export.py` owns the stable JSON shape and annotation merge.
- `packetscope/web.py` exposes only local, bounded HTTP operations and serves
  static assets.
- `packetscope/static/` is a dependency-free presentation layer.

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
