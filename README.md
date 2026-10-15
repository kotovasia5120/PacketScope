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
```

All JSON findings include evidence and caveats. A field is never described as
confirmed merely because a heuristic matched.

## Architecture and priorities

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/plan.md`](docs/plan.md). Contributor behavior is documented in
[`AGENTS.md`](AGENTS.md).

## Verification record

The initial build environment reported Python 3.11.2 and did not have Docker,
while the project pins Python 3.12.7. Verification on 2026-10-15 therefore
records both the successful standard-library checks and the unavailable Docker
check:

| Command | Result |
| --- | --- |
| `python3 -m unittest discover -s tests -p 'test_*.py' -v` | **PASS** — 21 tests under the available Python 3.11.2 (useful functional evidence, but not the pinned runtime) |
| `make test` | **BLOCKED** — correctly refused Python 3.11.2; the project requires exactly Python 3.12.7 |
| `python3 -m compileall -q packetscope tests` | **PASS** |
| `python3 -m pip wheel --no-deps --no-build-isolation . --wheel-dir /tmp/packetscope-wheel` | **BLOCKED** — the available Python 3.11.2 is outside the declared 3.12 range |
| `docker version` | **BLOCKED** — Docker CLI is unavailable in the build environment |
| `docker build -t packetscope:local .` | **UNVERIFIED** — not executed; no Docker CLI was available |
| `.github/workflows/ci.yml` Docker build/offline test | **UNVERIFIED** — workflow added, but no GitHub Actions run result is available from this checkout |

Commits containing the P0 work:

| Commit | Change |
| --- | --- |
| `9972dab` | Enforce Python 3.12.7 in Makefile, add dependency-free build backend, Docker checks, and CI workflow |
| `676b855` | Harden PCAP/PCAPNG parsing, add bounded analysis, HTTP failure handling, protocol decoding, and 21-test coverage |
| `2c7d262` | Record verification limits, reference-corpus rights/hashes, and next-phase planning |
| `a5d69fd` | Preserve unsigned PCAP link-type values |
| `a10d981` | Avoid a host-specific Debian package pin in the Docker build |

The Docker build must still be run on a clean Linux host or GitHub Actions
before Docker can be marked **PASS**. The CI workflow deliberately records the
offline container test separately from the port-forwarded HTTP smoke test.

Independent corpus licensing and hashes are recorded in
[`docs/reference-corpora.md`](docs/reference-corpora.md); no external fixture
is part of the mandatory offline suite.

## License

MIT. See [`LICENSE`](LICENSE).
