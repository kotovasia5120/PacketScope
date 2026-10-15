# PacketScope

PacketScope is a local-first, open-source workbench for reverse-engineering
unknown binary protocols. Load synthetic or real packet captures, compare bytes,
inspect HEX/ASCII, and record evidence-backed hypotheses without sending data to
cloud AI or external APIs.

> **Status:** P0 first working iteration. Automatic findings are candidates,
> not confirmed protocol facts.

## What works in this iteration

- BIN, whitespace-oriented HEX, classic PCAP, and basic PCAPNG imports.
- Local HTTP server and vanilla HTML/CSS/JavaScript interface.
- Absolute-offset HEX/ASCII packet viewer.
- Byte-level comparison across two or more messages.
- Constant and variable aligned regions.
- Cautious candidates for magic bytes, counters, length fields, and checksums.
- Manual field annotations and versioned JSON export.
- Bounded uploads and no telemetry, cloud AI, or execution of packet contents.

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

## CLI

```bash
python3 -m packetscope.cli analyze sample.bin --format auto --pretty
python3 -m packetscope.cli serve --host 127.0.0.1 --port 8765
```

All JSON findings include evidence and caveats. A field is never described as
confirmed merely because a heuristic matched.

## Architecture and priorities

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/plan.md`](docs/plan.md). Contributor behavior is documented in
[`AGENTS.md`](AGENTS.md).

## Verification record

This file is updated with actual commands and results after each working
stage. The initial environment used for development did not have Docker and
reported Python 3.11.2, while the project requires Python 3.12.7; the local
test run is therefore explicitly recorded in the final session summary and
must be repeated in the pinned Docker image when Docker is available.

## License

MIT. See [`LICENSE`](LICENSE).
