# Phase 3 reproducible demonstration

This scenario uses only the deterministic corpora under `tests/fixtures`; no capture is downloaded. The truth file is kept separate from the analysis input and is used only after analysis.

1. Run `make serve` on the pinned Python 3.12.7 runtime and open `http://127.0.0.1:8765`.
2. Load a capture containing at least three messages. The browser starts in application-payload scope; enable **Analyze raw packet headers too** only when raw analysis is intentional.
3. Use **Compare** to inspect constant/variable regions, entropy/frequency observations, and alignment.
4. Select a hypothesis to highlight its bytes and inspect evidence, alternatives, contradictions, packet count, and decoder limitations.
5. Review the **CRC** tab. CRC candidates show algorithm parameters, byte order, end-relative or absolute location, covered ranges, and mismatch counts.
6. Confirm or reject a candidate, or add a manually adjusted field annotation. Automatic hypotheses remain non-confirmed.
7. Export `packetscope-project.json`, then restore it through **Restore saved project** to verify annotations and selection data survive a round trip.
8. For a post-analysis accuracy report, convert one set's `expected` list from `tests/fixtures/phase3_ground_truth.json` to `ground-truth.json` and run:

   ```bash
   python3 -m packetscope.cli evaluate packetscope-project.json ground-truth.json --pretty
   ```

The report includes matched fields, missing fields, false-positive ids, and any automatically confirmed results. The synthetic regression tests exercise the same checks automatically and currently report zero automatically confirmed hypotheses.
