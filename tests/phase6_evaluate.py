"""Reproduce the Phase 6 heuristic evaluation table without network access."""
from __future__ import annotations

import json

from packetscope.analysis import analyze_packets
from packetscope.evaluation import evaluate_result
from packetscope.models import Packet
from tests.fixtures.phase3_corpus import corpus_a, corpus_b, corpus_c, corpus_d
from tests.fixtures.phase5_holdout import TRUTH as HOLDOUT_TRUTH
from tests.fixtures.phase5_holdout import corpus as holdout


def main() -> None:
    truth = json.loads(open("tests/fixtures/phase3_ground_truth.json", encoding="utf-8").read())
    corpora = {
        "A": (corpus_a(), truth["set_a"]["expected"]),
        "B": (corpus_b(), truth["set_b"]["expected"]),
        "C": (corpus_c(), []),
        "D": (corpus_d(), []),
        "holdout": (holdout(), HOLDOUT_TRUTH),
    }
    report = {}
    for name, (payloads, expected) in corpora.items():
        result = analyze_packets([Packet(index, payload) for index, payload in enumerate(payloads)])
        evaluation = evaluate_result(result, expected)
        report[name] = {
            key: evaluation[key]
            for key in (
                "precision", "recall", "f1", "false_positive_count",
                "false_positive_breakdown", "top_k_metrics", "missed",
            )
        }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
