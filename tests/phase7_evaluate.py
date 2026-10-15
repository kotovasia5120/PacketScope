"""Report exact and alternative-group-aware metrics for frozen Phase 7 cases."""
from __future__ import annotations

import json

from packetscope.analysis import analyze_packets
from packetscope.evaluation import evaluate_result
from packetscope.models import Packet
from tests.fixtures.phase7_generalization import DEVELOPMENT, HOLDOUT, VALIDATION, generate


def evaluate(settings_group):
    report = {}
    for settings in settings_group:
        payloads, truth = generate(settings)
        result = analyze_packets([Packet(index, payload) for index, payload in enumerate(payloads)])
        evaluation = evaluate_result(result, truth)
        report[settings.name] = {
            "exact": {key: evaluation[key] for key in ("precision", "recall", "f1", "false_positive_count", "missed")},
            "alternative_group_aware": evaluation["alternative_group_aware"],
            "false_positive_breakdown": evaluation["false_positive_breakdown"],
        }
    return report


def main() -> None:
    print(json.dumps({"development": evaluate(DEVELOPMENT), "validation": evaluate(VALIDATION), "frozen_holdout": evaluate(HOLDOUT)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
