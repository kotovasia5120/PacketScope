from __future__ import annotations

import argparse
import sys
from pathlib import Path

from packetscope.analysis import analyze_packets
from packetscope.errors import InputLimitError
from packetscope.export import dumps_result
from packetscope.importers import import_bytes
from packetscope.models import Limits
from packetscope.web import serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="packetscope")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze a packet file")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--format", choices=("auto", "bin", "hex", "pcap", "pcapng"), default="auto")
    analyze.add_argument("--pretty", action="store_true")
    analyze.add_argument("--raw", action="store_true", help="analyze raw packet bytes instead of decoded application payloads")
    analyze.add_argument("--output", type=Path)
    server = subparsers.add_parser("serve", help="start the local browser server")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        serve(args.host, args.port)
        return 0
    limits = Limits()
    file_size = args.input.stat().st_size
    if file_size > limits.max_input_bytes:
        raise InputLimitError(
            f"input is {file_size} bytes; limit is {limits.max_input_bytes}"
        )
    data = args.input.read_bytes()
    if len(data) > limits.max_input_bytes:
        raise InputLimitError(
            f"input is {len(data)} bytes; limit is {limits.max_input_bytes}"
        )
    imported = import_bytes(args.input.name, data, args.format, limits)
    result = analyze_packets(imported.packets, limits=limits, analyze_raw=args.raw)
    result["source"] = {
        "name": args.input.name,
        "format": imported.format,
        "packet_count": len(imported.packets),
        "byte_count": len(data),
    }
    result["warnings"] = imported.warnings
    rendered = dumps_result(result, args.pretty) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
