#!/usr/bin/env python3
"""Reproducible, synthetic Schema V2 and workflow performance corpus.

This benchmark intentionally generates packets independently of the inference
engine. It measures bounded authoritative evaluation and two adjacent pure
workloads without logging payload bytes. Results are JSON so another machine
can repeat the same configuration and compare like-for-like measurements.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
import tracemalloc
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packetscope.experiments import compare_controlled_change
from packetscope.models import Limits, Packet
from packetscope.reassembly import reconstruct_tcp_streams
from packetscope.schema import apply_schema, validate_schema


DEFAULT_SIZES = (100, 1_000, 10_000, 100_000)
SEED = 0x50534350
WORKLOAD_CAPS = {"nested_records": 2_000, "large_arrays": 1_000, "complex_dependencies": 2_000, "crc_relationship": 2_000}


def _byte(index: int, salt: int = 0) -> int:
    return (SEED + index * 37 + salt * 101) & 0xFF


def make_packets(count: int, width: int = 24, changed: bool = False) -> list[Packet]:
    packets: list[Packet] = []
    for index in range(count):
        payload = bytearray(_byte(index + offset, salt=offset) for offset in range(width))
        payload[0] = 1
        payload[1] = index & 0xFF
        payload[2] = (index >> 8) & 0xFF
        if changed:
            payload[4] ^= 0x01
        packets.append(Packet(index=index, payload=bytes(payload), source_name="synthetic"))
    return packets


def schema_for(workload: str) -> dict:
    if workload == "flat":
        return {"schema_version": 2, "name": "benchmark-flat", "coordinate_system": "raw_packet", "fields": [
            {"id": "kind", "type": "uint8", "offset": 0, "length": 1},
            {"id": "counter", "type": "uint16", "offset": 1, "length": 2, "endian": "little"},
            {"id": "payload", "type": "bytes", "offset": 3, "length": 21},
        ]}
    if workload == "nested_records":
        return {"schema_version": 2, "name": "benchmark-nested", "coordinate_system": "raw_packet", "fields": [
            {"id": "header", "type": "struct", "offset": 0, "length": 4, "fields": [
                {"id": "kind", "type": "uint8", "offset": 0, "length": 1},
                {"id": "count", "type": "uint8", "offset": 1, "length": 1},
                {"id": "sequence", "type": "uint16", "offset": 2, "length": 2, "endian": "little"},
            ]},
            {"id": "records", "type": "array", "offset": 4, "array": {"count": 2, "max_items": 4, "element": {"type": "struct", "fields": [
                {"id": "tag", "type": "uint8", "offset": 0, "length": 1},
                {"id": "value", "type": "uint8", "offset": 1, "length": 1},
            ]}}},
        ]}
    if workload == "large_arrays":
        return {"schema_version": 2, "name": "benchmark-array", "coordinate_system": "raw_packet", "budgets": {"max_array_items": 128, "max_total_array_items": 128}, "fields": [
            {"id": "count", "type": "uint8", "offset": 0, "length": 1},
            {"id": "items", "type": "array", "offset": 1, "array": {"count": 64, "max_items": 64, "element": {"type": "uint8", "offset": 0, "length": 1}}},
        ]}
    if workload == "complex_dependencies":
        return {"schema_version": 2, "name": "benchmark-dependencies", "coordinate_system": "raw_packet", "fields": [
            {"id": "base", "type": "uint8", "offset": 0, "length": 1},
            {"id": "offset", "type": "uint8", "offset": 1, "length": 1},
            {"id": "length", "type": "uint8", "offset": 2, "length": 1},
            {"id": "body", "type": "bytes", "offset": {"field": "offset", "add": 3}, "length": {"field": "length"}},
            {"id": "optional", "type": "uint8", "offset": {"field": "offset", "add": 4}, "length": 1, "presence": {"op": "eq", "args": [{"field": "base"}, 1]}},
        ]}
    if workload == "crc_relationship":
        return {"schema_version": 2, "name": "benchmark-crc", "coordinate_system": "raw_packet", "fields": [
            {"id": "body", "type": "bytes", "offset": 0, "length": 23},
            {"id": "crc", "type": "crc", "offset": 23, "length": 1},
        ], "relationships": [{"id": "body-crc", "kind": "checksum", "field_id": "crc", "algorithm": "CRC-8", "byte_order": "big", "covered_ranges": {"include": [[0, 24]], "exclude": [[23, 24]]}}]}
    raise ValueError(f"unknown schema workload: {workload}")


def workload_packets(workload: str, count: int, changed: bool = False) -> list[Packet]:
    width = 64 if workload == "large_arrays" else 24
    packets = make_packets(count, width=width, changed=changed)
    if workload == "complex_dependencies":
        packets = [Packet(p.index, bytes([1, 1, 3]) + p.payload[3:], source_name="synthetic") for p in packets]
    return packets


def measure(label: str, operation, input_count: int) -> dict:
    tracemalloc.start()
    start_wall = time.perf_counter()
    start_cpu = time.process_time()
    result = operation()
    wall = time.perf_counter() - start_wall
    cpu = time.process_time() - start_cpu
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if result is not None else ""
    return {"label": label, "input_count": input_count, "wall_seconds": wall, "cpu_seconds": cpu, "peak_tracemalloc_bytes": peak, "throughput_per_second": input_count / wall if wall else None, "result_bytes": len(encoded), "result_status": result.get("status") if isinstance(result, dict) else None}


def run_schema_benchmark(workload: str, count: int, warmups: int, repeats: int, limits: Limits) -> list[dict]:
    actual_count = min(count, WORKLOAD_CAPS.get(workload, count))
    schema = validate_schema(schema_for(workload))
    packets = workload_packets(workload, actual_count)
    for _ in range(warmups):
        apply_schema(schema, packets, max_packets=limits.max_packets)
    rows = []
    for repeat in range(repeats):
        row = measure(f"schema_{workload}", lambda: apply_schema(schema, packets, max_packets=limits.max_packets), actual_count)
        row["workload"] = workload
        row["requested_count"] = count
        row["capped"] = actual_count != count
        row["repeat"] = repeat
        rows.append(row)
    return rows


def run_adjacent_benchmark(name: str, count: int, repeats: int, limits: Limits) -> list[dict]:
    if name == "tcp_reconstruction":
        packets = [Packet(index, bytes([0] * 40), metadata={"tcp": {"sequence": index * 40, "src": "a", "dst": "b"}}, source_name="synthetic") for index in range(count)]
        operation = lambda: reconstruct_tcp_streams(packets, limits=limits)
    elif name == "controlled_experiment":
        baseline = make_packets(count, changed=False)
        changed = make_packets(count, changed=True)
        operation = lambda: compare_controlled_change(baseline, changed, limits=limits)
    else:
        raise ValueError(f"unknown adjacent workload: {name}")
    rows = []
    for repeat in range(repeats):
        row = measure(name, operation, count)
        row["workload"] = name
        row["repeat"] = repeat
        rows.append(row)
    return rows


def build_report(sizes: tuple[int, ...], warmups: int, repeats: int) -> dict:
    limits = Limits(max_packets=max(sizes), max_packet_bytes=16 * 1024 * 1024)
    workloads = ["flat", "nested_records", "large_arrays", "complex_dependencies", "crc_relationship"]
    rows: list[dict] = []
    for count in sizes:
        for workload in workloads:
            rows.extend(run_schema_benchmark(workload, count, warmups, repeats, limits))
        # Adjacent workloads use a smaller cap to keep the benchmark practical
        # while retaining the required 100k packet Schema V2 boundary.
        adjacent_count = min(count, 10_000)
        for workload in ("tcp_reconstruction", "controlled_experiment"):
            rows.extend(run_adjacent_benchmark(workload, adjacent_count, repeats, limits))
    return {
        "benchmark": "packetscope-schema-v2",
        "version": 1,
        "seed": SEED,
        "configuration": {"sizes": list(sizes), "warmups": warmups, "repeats": repeats, "limits": asdict(limits)},
        "environment": {"python": sys.version, "implementation": platform.python_implementation(), "platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor() or "unknown", "cpu_count": os.cpu_count()},
        "measurements": rows,
        "notes": [
            "Synthetic payloads are generated independently of inference heuristics.",
            "Peak memory is tracemalloc Python allocation, not total RSS.",
            "Rows are raw repeats; compare medians by workload and input_count.",
            "The flat Schema V2 workload includes the 100,000 boundary; recursive/array workloads use explicit caps recorded as requested_count and capped.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("benchmarks/schema-v2-results.json"))
    parser.add_argument("--sizes", type=int, nargs="+", default=list(DEFAULT_SIZES))
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if any(size <= 0 for size in args.sizes) or args.warmups < 0 or args.repeats <= 0:
        parser.error("sizes must be positive, warmups must be non-negative, and repeats must be positive")
    report = build_report(tuple(args.sizes), args.warmups, args.repeats)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "measurements": len(report["measurements"]), "sizes": report["configuration"]["sizes"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
