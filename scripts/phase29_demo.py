#!/usr/bin/env python3
"""Run the deterministic Phase 29 investigation without a browser.

This is a backend smoke demonstration, not a replacement for the Chromium
workflow.  The capture is analyzed before the reviewed schema is supplied.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packetscope.analysis.engine import analyze_packets
from packetscope.demo_protocol import protocol_capture, protocol_reference_schema
from packetscope.experiments import compare_controlled_change
from packetscope.flows import group_flows
from packetscope.importers.base import import_bytes
from packetscope.interop import export_kaitai, export_wireshark_lua
from packetscope.models import Limits, Packet
from packetscope.schema import dumps_schema, validate_capture_against_schema, validate_schema


def main() -> int:
    limits = Limits(max_input_bytes=64 * 1024)
    imported = import_bytes("phase29.jsonl", protocol_capture(), "jsonl", limits)
    packets = imported.packets
    analysis = analyze_packets(packets, limits=limits)
    changed = import_bytes("phase29-changed.jsonl", protocol_capture(changed=True), "jsonl", limits).packets
    experiment = compare_controlled_change(packets, changed, limits=limits)
    reviewed = validate_schema(protocol_reference_schema())
    validation = validate_capture_against_schema(reviewed, packets)
    restored = validate_schema(json.loads(dumps_schema(reviewed)))
    report = {
        "import": {"format": imported.format, "packet_count": len(packets), "warnings": imported.warnings},
        "flows": {"count": len(group_flows(packets, limits=limits)), "limitation": "JSONL carries message direction but no IP/TCP/UDP transport identity"},
        "inference": {"status": analysis.get("analysis", {}).get("status", analysis.get("status")), "hypothesis_count": len(analysis.get("hypotheses", []))},
        "controlled_experiment": {"operation": experiment.get("comparison_type"), "correlated_ranges": len(experiment.get("correlated_ranges", []))},
        "authoritative_validation": validation["summary"],
        "exports": {
            "kaitai": {"warning_count": len(export_kaitai(reviewed)["warnings"])},
            "wireshark_lua": {"warning_count": len(export_wireshark_lua(reviewed)["warnings"])},
        },
        "project_restore": {"schema_identity": json.loads(dumps_schema(restored)) == json.loads(dumps_schema(reviewed))},
        "ground_truth": "held separately in protocol_reference_ground_truth; not supplied to inference",
    }
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
