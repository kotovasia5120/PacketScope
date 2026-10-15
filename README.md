# PacketScope

PacketScope is a local-first, open-source workbench for reverse-engineering
unknown binary protocols. Load synthetic or real packet captures, compare bytes,
inspect HEX/ASCII, and record evidence-backed hypotheses without sending data to
cloud AI or external APIs.

> **Status:** Phase 5 reliability slice. Automatic findings remain heuristic
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
- One-click deterministic demo captures for CRC-16/big-endian and
  CRC-32/little-endian (including counter overflow), with a separate reference
  evaluation that is shown only after the investigation is requested.
- Comparison workspace with packet selection, offset/sequence alignment,
  bounded HEX/ASCII panes, difference navigation, and synchronized scrolling.
- Content-hashed annotation persistence, source-preserving diagnostics, and a
  bounded single-worker server job lifecycle (`QUEUED` → `IMPORTING` →
  `ANALYZING` → `COMPLETE`/`FAILED`/`CANCELLED`).
- Bounded uploads and no telemetry, cloud AI, or execution of packet contents.
- Basic Ethernet, IPv4/IPv6, TCP, and UDP metadata decoding without fragment
  reassembly; unsupported link types remain raw and explicitly unsupported.
- Direction-aware IPv4/IPv6 TCP/UDP flow grouping with packet identity,
  retransmission/out-of-order notes, and explicit no-TCP-reassembly limits.
- Versioned `default`, `fast`, `deep`, and custom analysis profiles with bounded
  budgets, SHA-256 input identity, profile fingerprints, and reproducibility
  metadata in every analysis report.

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
docker run --rm --network none packetscope:local make test
docker run --rm -p 127.0.0.1:8765:8765 packetscope:local
```

The image runs the offline test suite during `docker build`. The first command
is the isolated offline-test check. The second command is the HTTP
demonstration; it must not use `--network none` because the exposed port is the
browser's local connection to the application.

Offline test and HTTP demonstration are separate operations. The container
listens on `0.0.0.0` so port forwarding works, while the documented host
mapping binds only `127.0.0.1`. Do not publish the port to a wider interface
unless that exposure is intentional.

## CLI

```bash
python3 -m packetscope.cli analyze sample.bin --format auto --pretty
python3 -m packetscope.cli analyze sample.pcap --direction forward --profile fast --pretty
python3 -m packetscope.cli profile save deep --output deep-profile.json
python3 -m packetscope.cli profile validate deep-profile.json
python3 -m packetscope.cli serve --host 127.0.0.1 --port 8765
python3 -m packetscope.cli evaluate result.json ground-truth.json --pretty
```

`evaluate` is intentionally a separate post-analysis step: it compares exported
hypotheses against a truth file without exposing the truth during analysis and
reports precision, recall, F1, top-k ranking, missing fields, and unmatched
hypotheses. Recall is reported as not applicable for an empty truth set.

All JSON findings include evidence and caveats. A field is never described as
confirmed merely because a heuristic matched.

## Architecture and priorities

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/plan.md`](docs/plan.md). Contributor behavior is documented in
[`AGENTS.md`](AGENTS.md).

## Verification record

The pre-Phase-4 baseline `HEAD` was `57f44270bce993f6c8b52d97cf66d54bab00ffee`,
matching the verified commit for the recorded GitHub Actions run
`38736191414`. That run completed successfully for both `tests` and `docker`.
The Phase-4 changes below are new work and must receive a new CI run; the
baseline PASS is not attributed to this changed tree.

| Command or gate | Result |
| --- | --- |
| `python -m unittest discover -s tests -p 'test_*.py' -v` | **PASS** — 40 tests in the local development environment |
| `make test` | **PASS for the pre-Phase-4 baseline in the pinned CI/Docker environment; rerun required for this tree** |
| `python -m compileall -q packetscope tests` | **PASS** |
| `node --check packetscope/static/app.js` | **PASS** |
| `docker run --rm --network none packetscope:local make test` | **PASS for the pre-Phase-4 baseline; rerun required for this tree** |
| GitHub Actions run `38736191414` at `57f4427` | **PASS** — `tests` and `docker` jobs for the baseline commit |

The mandatory tests are offline and use only deterministic synthetic fixtures. CRC reference values and parameters are documented in [`docs/crc.md`](docs/crc.md).

## Browser E2E

Chromium is a development/test dependency only. Install the pinned Node
lockfile and browser once, then run the real browser acceptance suite:

```bash
npm ci
npx playwright install chromium
npm run e2e
```

The suite starts the real local server, exercises both CRC demos, navigation,
HEX interaction, annotations, undo/redo, project export/import, and invalid
project handling. Failure screenshots, traces, and console text are written
under `test-artifacts/` (ignored by Git); packet contents are not written to
the console artifact. CI installs Chromium with Linux dependencies and uploads
those artifacts only on failure.

## Interactive demonstration

Start the server, open the browser, and click **Load demo**. Choose two or more
packets in **Compare**, switch between offset and bounded sequence alignment,
inspect the field and CRC tabs, add a manual annotation, export the JSON, and
restore it with **Restore saved project**. The **Evaluate reference** action is
deliberately separate from analysis so the analyzer never consumes its ground
truth.

## Phase 4 usage

The CLI can explicitly inspect raw packet bytes with `--raw`; otherwise decoded PCAP/PCAPNG application payloads are analyzed when the link/network/transport decoder can identify them. The browser exposes the same choice as “Analyze raw packet headers too”. Exported JSON can be restored through the browser’s saved-project control.

Flow selectors in the browser operate on the normalized flow metadata returned
by the analysis. `forward` and `reverse` are relative to canonical endpoint A
and B; selecting a direction changes the visible packet scope without reloading
the capture. TCP segments remain packet-scoped because stream reassembly is not
implemented.


## License

MIT. See [`LICENSE`](LICENSE).
