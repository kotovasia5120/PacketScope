# Phase 6 reproducible evaluation report

Run `python3 -m tests.phase6_evaluate` from the repository root. The script
uses only deterministic local fixtures and evaluates hypotheses after analysis;
the analyzer never imports the truth data.

| Corpus | Precision | Recall | F1 | False positives | Missed | Top-1 recall | Top-3 recall | Top-5 recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 0.400 | 1.000 | 0.571 | 6 | 0 | 0.250 | 0.250 | 0.500 |
| B | 0.429 | 1.000 | 0.600 | 4 | 0 | 0.000 | 0.333 | 0.667 |
| C | 0.000 | N/A | N/A | 3 | 0 | N/A | N/A | N/A |
| D | 1.000 | N/A | N/A | 0 | 0 | N/A | N/A | N/A |
| independent holdout | 0.222 | 0.667 | 0.333 | 7 | 1 | 0.000 | 0.333 | 0.333 |

## False-positive breakdown

- A: `sequence_counter` 3, `magic_bytes` 1, `length_field` 1,
  `bit_flags` 1.
- B: `sequence_counter` 2, `message_type` 1, `crc` 1.
- C: `magic_bytes` 2, `message_type` 1.
- D: no candidates.
- Holdout: `sequence_counter` 4, `length_field` 1, `message_type` 1,
  `bit_flags` 1. The missed field is the little-endian 16-bit length at
  offset 4.

These results are **heuristic detector metrics, not calibrated probabilities**.
The false positives show that the current ranking is not release-grade enough
to claim a precision improvement. Phase 6 retains the prior behavior rather
than tuning to the built-in corpora or discarding useful alternatives. A future
ranking change must be tested against new unseen seeds and report its
regressions as well as any gain.
