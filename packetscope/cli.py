from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from packetscope.analysis import analyze_packets
from packetscope.errors import InputLimitError
from packetscope.experiments import compare_controlled_change
from packetscope.evaluation import evaluate_result
from packetscope.export import dumps_result
from packetscope.importers import import_bytes
from packetscope.models import Limits
from packetscope.profiles import dump_profile, limits_for_profile, resolve_profile
from packetscope.web import _merge_warnings, serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="packetscope")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze a packet file")
    analyze.add_argument("input", type=Path)
    capture_formats = (
        "auto", "bin", "hex", "pcap", "pcapng", "jsonl",
        "uart", "uart-lines", "can", "can-lines",
    )
    analyze.add_argument("--format", choices=capture_formats, default="auto")
    analyze.add_argument("--pretty", action="store_true")
    analyze.add_argument("--raw", action="store_true", help="analyze raw packet bytes instead of decoded application payloads")
    analyze.add_argument("--direction", choices=("both", "forward", "reverse"), default="both",
                         help="limit analysis to one normalized flow direction")
    analyze.add_argument("--output", type=Path)
    analyze.add_argument("--profile", default="default", help="built-in profile name or JSON profile path")
    compare = subparsers.add_parser("compare", help="compare a baseline capture with a controlled-change capture")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("changed", type=Path)
    compare.add_argument("--baseline-format", choices=capture_formats, default="auto")
    compare.add_argument("--changed-format", choices=capture_formats, default="auto")
    compare.add_argument("--raw", action="store_true", help="compare raw packet bytes instead of decoded application payloads")
    compare.add_argument("--change-label", default="controlled change")
    compare.add_argument("--pretty", action="store_true")
    compare.add_argument("--output", type=Path)
    compare.add_argument("--profile", default="default", help="built-in profile name or JSON profile path")
    profile = subparsers.add_parser("profile", help="validate or save an analysis profile")
    profile.add_argument("action", choices=("save", "validate"))
    profile.add_argument("source", help="built-in profile name or JSON profile path")
    profile.add_argument("--output", type=Path)
    evaluate = subparsers.add_parser("evaluate", help="compare an exported result with a separate truth JSON file")
    evaluate.add_argument("result", type=Path)
    evaluate.add_argument("truth", type=Path)
    evaluate.add_argument("--pretty", action="store_true")
    server = subparsers.add_parser("serve", help="start the local browser server")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    server.add_argument("--deployment-mode", choices=("local", "public-demo"), default=None,
                        help="privacy/deployment contract; defaults to PACKETSCOPE_DEPLOYMENT_MODE or local")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        serve(args.host, args.port, deployment_mode=args.deployment_mode)
        return 0
    if args.command == "profile":
        selected = resolve_profile(args.source)
        if args.action == "save":
            if args.output is None:
                raise ValueError("profile save requires --output")
            dump_profile(selected, args.output)
            return 0
        sys.stdout.write(dumps_result(selected.as_dict(), pretty=True) + "\n")
        return 0
    if args.command == "evaluate":
        result = json.loads(args.result.read_text(encoding="utf-8"))
        truth = json.loads(args.truth.read_text(encoding="utf-8"))
        expected = truth.get("expected", truth) if isinstance(truth, dict) else truth
        sys.stdout.write(dumps_result(evaluate_result(result, expected), args.pretty) + "\n")
        return 0
    if args.command == "compare":
        profile = resolve_profile(args.profile)
        limits = limits_for_profile(Limits(), profile)
        baseline_imported, baseline_bytes = _read_capture(args.baseline, args.baseline_format, limits)
        changed_imported, changed_bytes = _read_capture(args.changed, args.changed_format, limits)
        result = compare_controlled_change(
            baseline_imported.packets,
            changed_imported.packets,
            limits=limits,
            analyze_raw=args.raw,
            change_label=args.change_label,
        )
        result["baseline"].update({
            "name": args.baseline.name,
            "format": baseline_imported.format,
            "byte_count": len(baseline_bytes),
        })
        result["changed"].update({
            "name": args.changed.name,
            "format": changed_imported.format,
            "byte_count": len(changed_bytes),
        })
        result["warnings"] = _merge_warnings(
            [], baseline_imported.warnings + changed_imported.warnings
        )
        rendered = dumps_result(result, args.pretty) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    profile = resolve_profile(args.profile)
    limits = limits_for_profile(Limits(), profile)
    imported, data = _read_capture(args.input, args.format, limits)
    result = analyze_packets(imported.packets, limits=limits, analyze_raw=args.raw,
                             selected_direction=args.direction, profile=profile,
                             input_sha256=hashlib.sha256(data).hexdigest())
    result["source"] = {
        "name": args.input.name,
        "format": imported.format,
        "packet_count": len(imported.packets),
        "byte_count": len(data),
    }
    result["warnings"] = _merge_warnings(result.get("warnings", []), imported.warnings)
    rendered = dumps_result(result, args.pretty) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


def _read_capture(path: Path, format_name: str, limits: Limits):
    file_size = path.stat().st_size
    if file_size > limits.max_input_bytes:
        raise InputLimitError(
            f"input is {file_size} bytes; limit is {limits.max_input_bytes}"
        )
    data = path.read_bytes()
    if len(data) > limits.max_input_bytes:
        raise InputLimitError(
            f"input is {len(data)} bytes; limit is {limits.max_input_bytes}"
        )
    return import_bytes(path.name, data, format_name, limits), data


if __name__ == "__main__":
    raise SystemExit(main())
