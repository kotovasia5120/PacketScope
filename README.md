# PacketScope

PacketScope is a local-first, open-source workbench for reverse-engineering
unknown binary protocols. Load synthetic or real packet captures, compare bytes,
inspect HEX/ASCII, and record evidence-backed hypotheses without sending data to
cloud AI or external APIs.

> **Status:** Phase 3 analysis engine and local evidence UI. Automatic findings are
> hypotheses, not confirmed protocol facts.

## What works in this iteration

- BIN, whitespace-oriented HEX, classic PCAP, and basic PCAPNG imports.
- Local HTTP server and vanilla HTML/CSS/JavaScript interface.
- Absolute-offset HEX/ASCII packet viewer.
- Byte-level comparison across two or more messages.
- Constant and variable aligned regions.
- Cautious candidates for magic bytes, counters, lengths, bit flags, message types, alignment, and checksums/CRCs.
- Unified field evidence with separate raw-packet and application-payload offsets.
- Manual field annotations and versioned JSON export.
- Bounded uploads and no telemetry, cloud AI, or execution of packet contents.
- Basic Ethernet, IPv4/IPv6, TCP, and UDP metadata decoding without fragment
  reassembly; unsupported link types remain raw and explicitly unsupported.

## Quick start

The supported runtime is Python **3.12.7**. The repository pins it in
`.python-version`. No third-party runtime packages are required.

```bash
cp .env.example .env
make test
make serve
```

Open <http://127.0.0.1:8765>. Upload a `.bin`, `.hex`, `.pcap`, or `.pcapng`
file. The default upload limit is 256 MiB; individual packets are limited to
16 MiB and the capture to 100,000 packets.

## Docker

Docker is the reproducible Linux x86-64 path:

```bash
docker build -t packetscope:local .
docker run --rm --network none -p 127.0.0.1:8765:8765 packetscope:local
```

The image runs the offline test suite during `docker build`. Use
`--network none` when running it to verify the application makes no network
requests.

Offline test and HTTP demonstration are separate operations. The container
listens on `0.0.0.0` so port forwarding works, while the documented host
mapping binds only `127.0.0.1`. Do not publish the port to a wider interface
unless that exposure is intentional.

## CLI

```bash
python3 -m packetscope.cli analyze sample.bin --format auto --pretty
python3 -m packetscope.cli serve --host 127.0.0.1 --port 8765
python3 -m packetscope.cli evaluate result.json ground-truth.json --pretty
```

`evaluate` is intentionally a separate post-analysis step: it compares exported
hypotheses against a truth file without exposing the truth during analysis and
reports accuracy, missing fields, and false positives.

All JSON findings include evidence and caveats. A field is never described as
confirmed merely because a heuristic matched.

## Architecture and priorities

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/plan.md`](docs/plan.md). Contributor behavior is documented in
[`AGENTS.md`](AGENTS.md).

## Verification record

The current container has Python 3.11.2, while the supported runtime is pinned to Python 3.12.7. Docker and the GitHub CLI are not installed, so those gates are explicitly blocked/unverified rather than reported as passing.

| Command or gate | Result |
| --- | --- |
| `python -m unittest discover -s tests -p 'test_*.py' -v` | **PASS** — 34 tests under Python 3.11.2; useful functional evidence, not pinned-runtime verification |
| `make test` | **BLOCKED** — correctly refused Python 3.11.2 |
| `python -m compileall -q packetscope tests` | **PASS** |
| `node --check packetscope/static/app.js` | **PASS** — when Node is available in the verification container |
| `docker version` / `docker build` | **BLOCKED** — Docker CLI unavailable |
| GitHub Actions run | **UNVERIFIED** — `gh` CLI unavailable and no run receipt is present in this checkout |

The mandatory tests are offline and use only deterministic synthetic fixtures. CRC reference values and parameters are documented in [`docs/crc.md`](docs/crc.md).

## Phase 3 usage

The CLI can explicitly inspect raw packet bytes with `--raw`; otherwise decoded PCAP/PCAPNG application payloads are analyzed when the link/network/transport decoder can identify them. The browser exposes the same choice as “Analyze raw packet headers too”. Exported JSON can be restored through the browser’s saved-project control.


## License

MIT. See [`LICENSE`](LICENSE).
