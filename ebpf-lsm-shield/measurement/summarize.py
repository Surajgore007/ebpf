#!/usr/bin/env python3
import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

METRICS = [
    "unique_files_opened", "unique_files_written", "unique_files_modified",
    "unique_files_renamed", "unique_files_deleted", "writes_per_second",
    "bytes_written_per_second", "truncate_operations", "ftruncate_operations",
    "fallocate_operations", "unique_files_truncated", "unique_files_ftruncated",
    "unique_files_fallocated", "modified_files_per_second", "writes_per_modified_file",
    "write_open_ratio", "rename_write_ratio",
    "max_processes_per_file", "mean_processes_per_file", "multi_process_files_count",
    "max_modifying_processes_per_file", "multi_process_modified_files_count",
    "total_distinct_processes", "read_write_entropy_ratio",
    "decoy_touch_count", "decoy_operations"
]


def quantile(values, q):
    if not values:
        return None
    xs = sorted(values)
    pos = (len(xs) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    return xs[lo] if lo == hi else xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def mad(values):
    if not values:
        return None
    med = statistics.median(values)
    return statistics.median([abs(x - med) for x in values])


def main():
    parser = argparse.ArgumentParser(description="Summarize telemetry measurement distributions")
    parser.add_argument("--results-dir", default=None, help="Directory containing .jsonl results")
    args = parser.parse_args()

    default_root = Path(__file__).resolve().parents[1] / "experiments" / "results_phase1"
    if args.results_dir:
        root = Path(args.results_dir)
    elif default_root.exists():
        root = default_root
    else:
        root = Path(__file__).resolve().parents[1] / "experiments" / "results_v2"

    rows = []
    for p in sorted(root.glob("*.jsonl")):
        if p.name.endswith(".files.jsonl"):
            continue
        for line in p.read_text().splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    lines = ["workload,metric,n,median,standard_deviation,p95,p99,mad"]
    for workload in sorted({r["workload"] for r in rows if "workload" in r}):
        for metric in METRICS:
            vals = [
                float(r[metric]) for r in rows
                if r.get("workload") == workload and r.get(metric) is not None and math.isfinite(float(r[metric]))
            ]
            sd = statistics.stdev(vals) if len(vals) > 1 else None
            med_val = f"{statistics.median(vals):.4f}" if vals else ""
            sd_val = f"{sd:.4f}" if sd is not None else ""
            p95_val = f"{quantile(vals, 0.95):.4f}" if vals else ""
            p99_val = f"{quantile(vals, 0.99):.4f}" if vals else ""
            mad_val = f"{mad(vals):.4f}" if vals else ""
            lines.append(f"{workload},{metric},{len(vals)},{med_val},{sd_val},{p95_val},{p99_val},{mad_val}")

    output = "\n".join(lines) + "\n"
    print(output, end="")
    (root / "distributions.csv").write_text(output)
    (root / "distributions.txt").write_text(output)


if __name__ == "__main__":
    main()