# PacketScope contributor guidelines

## Mission

PacketScope is a local-only workbench for reverse-engineering unknown binary
protocols. It must help a person inspect evidence without presenting a
heuristic as a confirmed protocol fact.

## Design rules

- Keep import/parsing, analysis, export, HTTP, and browser code in separate
  modules. The analysis engine must remain usable without the web server.
- Prefer Python's standard library. Any new dependency must be justified,
  pinned in the lockfile, and available during an offline Docker test.
- Treat every detector result as a hypothesis. Include evidence, offsets,
  confidence, and caveats. Never silently upgrade a guess to a fact.
- Bound input bytes, packet count, packet size, block size, response size, and
  generated hypotheses before allocating or iterating over untrusted data.
- Never execute packet contents or invoke external decoders on imported data.
- Do not log raw payloads by default. Do not add telemetry or cloud calls.
- Use deterministic ordering and JSON-safe values in exported results.
- Keep the browser UI dependency-free and accessible from the local server.

## Checks

Run the single project check from the repository root:

```bash
make test
```

The same command is run during the Docker image build. Add regression tests for
each parser or detector rule, including malformed and limit-boundary inputs.

## Workflow

1. State the observable behavior and its limits before editing.
2. Make the smallest complete change in the correct layer.
3. Run `make test` after each working step.
4. Review `git diff` and commit a focused, thematic change.

## Privacy and safety

Sample captures belong to users. Do not commit real captures, secrets, private
payloads, generated result dumps, or machine-specific absolute paths. Fixtures
must be synthetic and minimal.
