# Phase 7 release-candidate progress

This record describes the current local checkout. It does not treat the older
Phase 3 CI result or the Phase 6 report as evidence for the current HEAD.

## Baseline verified before inference changes

| Gate | Result |
| --- | --- |
| HEAD at start | `477bdb17732efac2ef475882bb24e140bf5133a2` |
| Pinned Python 3.12.7 test suite | **PASS** — 77 tests |
| Default `make test` on host Python 3.11.2 | **BLOCKED** by the intentional runtime gate |
| `python3 -m tests.phase6_evaluate` | **PASS** — holdout precision 0.222 / recall 0.667 / F1 0.333 |
| Real Chromium E2E | **PASS** — 5 tests |
| Docker | **BLOCKED** — `docker` is not installed |
| Hosted GitHub Actions for this HEAD | **UNVERIFIED** — no push was authorized and `gh` is unavailable |

The working tree was clean before this phase. The branch was 15 commits ahead
of `origin/main`; this phase still does not push or publish.

## Implemented in this phase

- Fixed length-detector loop control so a later wider/little-endian candidate
  is not hidden by an earlier narrow candidate.
- Retained viable overlapping scalar alternatives and added deterministic
  interpretation groups with widths and endianness.
- Added evidence quality metadata, explicit caveats, deterministic ranking
  factors, and field-specific “What would help confirm this?” guidance.
- Reduced known false positives by suppressing flag-like message-type aliases,
  flag interpretations of exact unit-step counters, duplicate one-byte length
  endian aliases, and nested sequence projections. These are conservative
  rules, not corpus-specific offsets.
- Added alternative-group-aware evaluation alongside exact field metrics. The
  exact metrics remain directly comparable with Phase 6.
- Added server-owned demo evaluation identities. The built-in button now uses
  a server-stored analysis result and labels client-submitted comparisons as
  untrusted.
- Added a versioned, non-executable protocol schema module with validation,
  overlapping/variable-range support, byte application, and round-trip tests.
  The browser exposes “Export protocol schema”; inferred fields remain marked
  as hypotheses and manual annotations retain their review status.
- Added frozen development, validation, and holdout generators with fixed
  seeds covering width/endian/start/increment, flags/types, variable lengths,
  length conventions, CRC placement, corruption, missing/reordered messages,
  and unrelated bytes.

## Inference results after changes

`python3 -m tests.phase6_evaluate` now reports:

| Dataset | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| Corpus A | 0.500 | 1.000 | 0.667 |
| Corpus B | 0.600 | 1.000 | 0.750 |
| Independent holdout | 0.375 | 1.000 | 0.545 |

The holdout now finds the 16-bit little-endian length at offset 4. The narrow
8-bit interpretation is retained in the same ambiguity group and ranked lower;
it is not silently discarded or promoted to a fact. The Phase 7 frozen
generalization report is generated with:

```bash
./.runtime/cpython-3.12.7-linux-x86_64-gnu/bin/python3.12 -m tests.phase7_evaluate
```

Its cases intentionally include inconclusive/reordered/non-unit-counter
conditions. They are reported as exact and alternative-group-aware metrics;
they are not used as hidden tuning feedback.

## False-positive root causes and limits

- **Sequence counters:** the old detector emitted every nested byte projection
  and treated any constant progression as equally persuasive. The current
  detector emits the widest unit-step interpretation per offset, records the
  packet-order assumption, and warns about duplicates, gaps, direction mixing,
  and projected subfields. Non-unit progressions are intentionally reported as
  unsupported rather than silently called counters.
- **Length fields:** the old loop stopped after seeing any previous length at
  the same offset, so a one-byte big-endian match could prevent a later
  two-byte little-endian candidate from being generated. The loop now retains
  compatible width/endian alternatives and ranks a wider explanation above
  its narrower projection only when the bytes support it. Total, payload-only,
  and bytes-after-field remain explicitly ambiguous.
- **Message types:** low-cardinality bytes were too easily labeled as message
  types. A byte whose varying mask is fully explained by packed flags is now
  kept as a flag interpretation rather than duplicated as a type. Remaining
  low-cardinality candidates still carry an enum/flag/counter caveat.
- **Bit flags:** monotonic counter bytes were also accepted as flags. Exact
  unit-step counter evidence suppresses that redundant semantic label while
  preserving the counter explanation and its caveat.

These rules improve ranking and evidence presentation, but do not prove
protocol semantics. Reordered or non-unit-counter cases in the Phase 7 frozen
corpus remain deliberately inconclusive where the observed bytes cannot
distinguish competing models.

## Current checks

| Command | Result |
| --- | --- |
| Pinned `make test` | **PASS** — 85 tests on Python 3.12.7 |
| CRC reference vectors | **PASS** — existing `tests/test_crc.py` suite |
| `node --check` for browser/E2E JavaScript | **PASS** |
| Real Chromium E2E with real Python server | **PASS** — 5 tests, including schema application and field editing |
| Schema round-trip, overlap, variable-range, invalid-schema tests | **PASS** — manual range application also asserted |
| Demo valid/tampered/wrong-profile/invalid evaluation tests | **PASS** |
| External fixtures | **PASS** for existing importer-only validation; application inference remains unsupported/not claimed |
| Docker build and offline image test | **BLOCKED** — Docker unavailable |
| GitHub Actions on final release commit | **UNVERIFIED** — requires publication/CI run |

## Release blockers and next actions

1. Keep Docker **BLOCKED** until a Linux machine with Docker runs the Dockerfile
   build, offline test container, and HTTP smoke test.
2. Keep hosted CI **UNVERIFIED** until the exact release commit is published or
   otherwise run by an authorized maintainer. Do not call the release validated
   before that run passes.
3. Review the generated real-application screenshots in `test-artifacts/` and
   attach only approved screenshots to the submission package.
4. Run the exact final commands below after the last documentation change:

```bash
make PYTHON=./.runtime/cpython-3.12.7-linux-x86_64-gnu/bin/python3.12 test
node --check packetscope/static/app.js
node --check e2e/phase5.spec.js
npm run e2e
python3 -m tests.phase6_evaluate
python3 -m tests.phase7_evaluate
git diff --check
```

Competition readiness is **NOT COMPLETE** while Docker and hosted CI remain
unresolved.
