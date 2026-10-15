# PacketScope

PacketScope is a local-first, open-source workbench for reverse-engineering
unknown binary protocols. Load synthetic or real packet captures, compare bytes,
inspect HEX/ASCII, and record evidence-backed hypotheses without sending data to
cloud AI or external APIs.

> **Status:** Phase 7 release-candidate slice. Automatic findings remain heuristic
> hypotheses, not confirmed protocol facts.

## Demo

- **Live demo:** <https://packetscope-demo.onrender.com>
- **Video walkthrough:** <https://youtu.be/kQIqGE6kvfc>

The hosted instance is provided for evaluation and demonstration. Do not upload
confidential captures there; use the local server or the Docker workflow below
for private evidence.

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
- Scoped server-side reanalysis for selected flows and directions, with stale
  browser responses ignored and display-only filtering clearly labeled when a
  restored project has no source capture.
- Bounded job payload retention (64 MiB total by default), terminal result
  retention limits, prompt raw-payload release, and safe oversized-result
  rejection.
- Versioned `default`, `fast`, `deep`, and custom analysis profiles with bounded
  budgets, SHA-256 input identity, profile fingerprints, and reproducibility
  metadata in every analysis report.
- Overlapping interpretation groups, deterministic evidence-quality ranking,
  and field-specific “What would help confirm this?” guidance. Widths are not
  promoted merely because they match a corpus.
- Versioned, non-executable protocol schema export with inferred/manual origin,
  review status, evidence references, constraints, limitations, overlapping
  fields, and bounded byte validation.
- Server-owned built-in-demo evaluation identities; arbitrary client-submitted
  comparisons are clearly labeled untrusted.

## Quick start

The supported runtime is Python **3.12.7** exactly. The repository pins it in
`.python-version`, the package metadata, the build backend, the Makefile gate,
and the Docker image. No third-party runtime packages are required.

```bash
cp .env.example .env
make test
make serve
```

Open <http://127.0.0.1:8765>. Upload a `.bin`, `.hex`, `.pcap`, or `.pcapng`
file. The default upload limit is 256 MiB; individual packets are limited to
16 MiB and the capture to 100,000 packets.

## Clean Linux build and installation

Install Python **3.12.7** before running these commands; the repository does
not silently substitute another interpreter. Verify the executable first:

```bash
python3.12 --version                 # must print Python 3.12.7
python3.12 -m venv .venv
. .venv/bin/activate
make PYTHON=python3.12 test
make PYTHON=python3.12 wheel
python -m venv /tmp/packetscope-wheel-check
/tmp/packetscope-wheel-check/bin/python -m pip install --no-index --no-deps dist/packetscope-0.1.0-py3-none-any.whl
/tmp/packetscope-wheel-check/bin/packetscope --help
```

The wheel has no runtime dependencies. `requirements.lock` records that empty
runtime set. The browser test dependency is separate and is pinned by
`package.json`, `package-lock.json`, and `.nvmrc`:

```bash
nvm use                              # uses Node 22.14.0 from .nvmrc
npm ci
npx playwright install chromium
npm run e2e
```

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

The Docker base image is pinned to the Linux x86-64 digest for
`python:3.12.7-slim`. The initial `docker build` still needs access to the
Docker registry and Debian package mirror unless those inputs are already
cached by the machine; after the image exists, the test-container command is
network-isolated.

## Render deployment

The live demo is deployed as a Render **Web Service** from the repository's
`main` branch using the checked-in `Dockerfile`. To reproduce that setup:

1. Create a Web Service connected to this repository and select the `main`
   branch.
2. Choose **Docker** as the runtime. Leave **Root Directory** empty so the
   repository root is used.
3. Set **Dockerfile Path** to `./Dockerfile` and **Docker Build Context
   Directory** to `.`.
4. Leave **Docker Command** empty so Render uses the `CMD` in the Dockerfile.
5. Enable **Auto-Deploy: On Commit** if deployments should follow updates to
   `main`.
6. After deployment, verify the service with:

   ```bash
   curl https://packetscope-demo.onrender.com/api/health
   ```

   A healthy service returns JSON containing `"status": "ok"` and
   `"local_only": true`.

The container listens on `0.0.0.0:8765`, exposes `/api/health` for a health
check, and has no required secrets or external services. Render's public URL
is useful for the demo, but the local-only privacy model still means that
private packet captures should be analyzed locally.

The same values are collected in [`docs/render-deploy.md`](docs/render-deploy.md)
for deployment reviews or service recreation.

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

Historical phase results are retained for context only. The current evidence
and unresolved gates are recorded in [`docs/phase7-progress.md`](docs/phase7-progress.md).

| Command or gate | Result |
| --- | --- |
| `make PYTHON=./.runtime/cpython-3.12.7-linux-x86_64-gnu/bin/python3.12 test` | **PASS** — 85 tests |
| `python3 -m unittest discover -s tests -p 'test_*.py'` | **BLOCKED** — host Python 3.11.2 fails the pinned-runtime gate |
| `node --check packetscope/static/app.js` plus E2E JS files | **PASS** |
| `npm run e2e` with local Chromium server | **PASS** — 5 browser tests, including schema apply and field editing |
| HTTP `/api/health` smoke test | **PASS** — real local server |
| `make test` with default host `python3` | **BLOCKED** — host is 3.11.2; use the explicit pinned-runtime command above |
| Docker build/offline container | **BLOCKED** — Docker daemon is unavailable in this environment |
| New GitHub Actions run | **UNVERIFIED** — no push was authorized |
| Clean wheel build, install, and reproducibility | **PASS** — local build-backend test; CI repeats isolated wheel install/hash checks |

The mandatory tests are offline and use only deterministic synthetic fixtures. CRC reference values and parameters are documented in [`docs/crc.md`](docs/crc.md).

The independent holdout corpus is not available to the analyzer at runtime.
Run `python3 -m tests.phase6_evaluate` for exact metrics and
`python3 -m tests.phase7_evaluate` for fixed-seed development, validation, and
frozen-holdout exact and alternative-group-aware metrics. These are heuristic
metrics, not probabilities. Results are recorded in
[`docs/phase7-progress.md`](docs/phase7-progress.md); historical limitations
remain in [`docs/phase6-evaluation.md`](docs/phase6-evaluation.md).

## Browser E2E

Chromium is a development/test dependency only. Install the pinned Node
lockfile and browser once, then run the real browser acceptance suite:

```bash
npm ci
npx playwright install chromium
npm run e2e
```

The suite starts the real local server, exercises both CRC demos, navigation,
HEX interaction, schema export/application, editable annotations, undo/redo,
project export/import, and invalid project handling. Failure screenshots,
traces, and console text are written under `test-artifacts/` (ignored by Git);
packet contents are not written to the console artifact. CI installs Chromium
with Linux dependencies and uploads those artifacts only on failure.

## Interactive demonstration

Start the server, open the browser, and click **Load demo**. Choose two or more
packets in **Compare**, switch between offset and bounded sequence alignment,
inspect the field and CRC tabs, compare an interpretation group, add and edit a
manual annotation, export and re-apply the protocol schema, export the JSON and
restore it with **Restore saved project**. Built-in **Evaluate reference** uses
a server-owned analysis identity; arbitrary client-submitted metrics are
explicitly untrusted. The timed script and screenshot paths are in
[`docs/demo-guide.md`](docs/demo-guide.md).

## Troubleshooting

- **`PacketScope requires Python 3.12.7`**: select the exact interpreter and
  pass it explicitly, for example `make PYTHON=/path/to/python3.12 test`.
- **`pip` tries to reach the network during a wheel check**: use
  `--no-index --no-deps`; PacketScope itself has no Python package downloads.
- **Chromium is missing**: run `npm ci` followed by
  `npx playwright install chromium`. Linux CI additionally uses
  `npx playwright install --with-deps chromium`.
- **Docker cannot connect to the daemon**: start Docker and rerun the build;
  do not mark the Docker gates passed from a source-only test run.
- **The browser server port is busy**: set `PACKETSCOPE_PORT` for the manual
  server; the E2E suite uses its dedicated port from Playwright configuration.

## Phase 4 usage

The CLI can explicitly inspect raw packet bytes with `--raw`; otherwise decoded PCAP/PCAPNG application payloads are analyzed when the link/network/transport decoder can identify them. The browser exposes the same choice as “Analyze raw packet headers too”. Exported JSON can be restored through the browser’s saved-project control.

Flow selectors in the browser operate on the normalized flow metadata returned
by the analysis. `forward` and `reverse` are relative to canonical endpoint A
and B. For an uploaded capture, selecting a flow or direction submits the same
source through the bounded analysis job with validated scope parameters; packet
presentation, hypotheses, CRC evidence, and packet IDs then come from that
scope. Stale scoped responses cannot overwrite a newer selection. A restored
JSON project has no source capture, so its selectors are explicitly marked
display-only. TCP segments remain packet-scoped because stream reassembly is
not implemented. The deterministic Phase-6 corpus and manifest are under
`tests/fixtures/phase6_multiflow*`.

## External fixtures and release evidence

Importer-only validation against small public tcpdump, PcapPlusPlus,
Wireshark, and Kaitai samples is recorded in
[`docs/external-fixture-validation.md`](docs/external-fixture-validation.md).
The files are not vendored. Browser screenshots, traces, and performance JSON
are generated under the ignored `test-artifacts/` directory by the real
Chromium suite. Phase-7 acceptance status and remaining Docker/CI blockers are
tracked in [`docs/phase7-progress.md`](docs/phase7-progress.md).


## License

MIT. See [`LICENSE`](LICENSE).
