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
- `packetscope/export.py` owns the stable JSON shape and annotation merge.
- `packetscope/web.py` exposes only local, bounded HTTP operations and serves
  static assets.
- `packetscope/static/` is a dependency-free presentation layer.

The first iteration intentionally uses standard-library parsing and a small
detector set. Link-layer stream reassembly and advanced CRC families are
planned extensions, not hidden behavior.

## Safety model

Uploads are bounded before parsing. PCAP and PCAPNG length fields are checked
against the bounded source. Packet bytes are treated only as data. Results say
`candidate` or `hypothesis` and include a confidence plus evidence; users can
add manual annotations that remain distinct from automatic findings.
