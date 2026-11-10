#!/usr/bin/env python3
import csv
from pathlib import Path

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
phase1_path = ROOT / "experiments" / "results_phase1" / "distributions.csv"
phase3_path = ROOT / "experiments" / "results_phase3" / "distributions.csv"


def read_dist(path):
    d = {}
    if not path.exists():
        return d
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            d[(row["workload"], row["metric"])] = row
    return d


p1 = read_dist(phase1_path)
p3 = read_dist(phase3_path)

workloads = sorted({k[0] for k in (p3.keys() or p1.keys())})
metrics = [
    "unique_files_modified", "modified_files_per_second", "writes_per_second",
    "rename_write_ratio", "read_write_entropy_ratio",
    "max_processes_per_file", "multi_process_files_count",
    "max_modifying_processes_per_file", "multi_process_modified_files_count"
]

header = f"{'Workload':<15} | {'Metric':<34} | {'Phase 1 Med':<12} | {'Phase 3 Med':<12} | {'Phase 3 P95':<12}"
print(header)
print("-" * len(header))
for w in workloads:
    for m in metrics:
        p1_val = p1.get((w, m), {}).get("median", "N/A")
        p3_row = p3.get((w, m), {})
        p3_med = p3_row.get("median", "N/A")
        p3_p95 = p3_row.get("p95", "N/A")
        print(f"{w:<15} | {m:<34} | {p1_val:<12} | {p3_med:<12} | {p3_p95:<12}")
    print("-" * len(header))
