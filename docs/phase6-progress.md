# Phase 6 release-candidate progress

This is the task-specific release gate record for Phase 6. It records observed
behavior on the current local checkout; historical Phase 5 results are not
used as evidence for this phase.

## Acceptance criteria

- [x] `/api/demo/evaluate` returns metrics for both built-in profiles.
- [x] Invalid evaluation requests return bounded 4xx/5xx JSON responses and
      the server remains healthy.
- [x] Flow and direction selections reach the analyzer, not only the packet
      display.
- [x] Scoped evidence and packet IDs are tested at engine, job, HTTP, and
      Chromium levels.
- [x] A deterministic IPv4/IPv6 multi-flow PCAP and separate manifest exist
      under `tests/fixtures/`.
- [x] Cooperative cancellation, payload-retention bounds, result-size bounds,
      active-job retention, and recovery after rejection are tested.
- [x] Real Chromium acceptance covers demos, reference evaluation, downloads,
      reimports, scoped flow switching, annotations, Undo/Redo, and restore.
- [x] Packet navigation is searchable and bounded to at most 200 options.
- [x] Exact Python 3.12.7 `make test` run on this container.
- [ ] Docker build and offline Docker test.
- [ ] Hosted GitHub Actions run on this HEAD.
- [x] External public fixture imports were run without vendoring the fixtures.

## Verified evidence

Commands run from the repository root:

```text
python3 -m unittest discover -s tests -p 'test_*.py'   PASS — 77 tests
node --check packetscope/static/app.js                    PASS
npm run e2e                                                PASS — 5 Chromium tests
```

The host Python is 3.11.2, so the default `make test` correctly stops at its
pinned-runtime check. The exact `.runtime/cpython-3.12.7-linux-x86_64-gnu/bin/python3.12`
gate was then run and passed all 77 tests.

The real browser run produced screenshots and traces in the ignored
`test-artifacts/` directory. The suite records console text without packet
payloads and fails on page errors, failed requests, or HTTP 5xx responses.

The scoped corpus contains two UDP conversations, two TCP endpoint pairs,
IPv4, IPv6, distinct message types with CRC-bearing payloads, duplicate and
out-of-order TCP segments, an unsupported Ethernet type, and an incomplete
record. The manifest explicitly says that TCP stream reassembly was not
performed.

## Resource policy

`AnalysisManager` now bounds total raw payload bytes retained by queued and
importing jobs to `Limits.max_job_payload_bytes` (64 MiB by default), bounds
retained job records to 32, releases raw request bytes after importing and on
terminal cancellation/failure, rejects oversized completed results at the
configured response limit, and expires only terminal jobs. Cleanup is still
triggered by normal job access/submission; it does not create a background
cleanup thread. The tests exercise importer cancellation, shutdown, terminal
cleanup, result snapshots, rejection, and recovery.

The current measurements are behavioral retention bounds, not a substitute for
an OS-level heap profiler. A final peak-RSS measurement remains a release
follow-up before claiming memory safety as fully verified.

Representative local measurement (host Python 3.11.2, four distinct 8 MiB
queued/importing payloads) recorded `retained_payload_bytes=33,554,432` and a
process peak-RSS increase of approximately 42,000,384 bytes; after shutdown the
manager reported zero retained payload bytes. This is a bounded workload
measurement, not a universal memory-safety proof.

The Chromium performance artifact measured bounded packet navigation at 402
DOM nodes for 100 packets, 502 nodes for 1,000 and 10,000 packets, and 5.6 ms
render time for the 10,000-packet load on the local run. The 300-hypothesis,
128 KiB-packet workload measured 5,390 DOM nodes and 58 ms. These figures are
machine-specific; the important regression result is that 10,000 packets no
longer create 10,000 `<option>` nodes.

## Inference evaluation

The false-positive breakdown and holdout table remain reproducible with:

```bash
  python3 -m tests.phase6_evaluate
```

The current detector deliberately retains alternative heuristic explanations;
no ground truth is passed into the analyzer. The measured table is recorded in
`docs/phase6-evaluation.md`. No ranking change is claimed until an improvement
survives new unseen seeds rather than only A–D.

## Next actions and blockers

1. Run the final Python suite with Python 3.12.7 and record the exact command.
2. Run Docker build, offline container test, and localhost health smoke test;
   if Docker is unavailable, keep the gate **BLOCKED**.
3. Run the reproducible evaluation script and final Chromium suite after the
   documentation changes; retain successful screenshots and failure traces.
4. Review `git diff`, create the documentation/release commit, and leave the
   working tree clean. Do not push without explicit authorization.
