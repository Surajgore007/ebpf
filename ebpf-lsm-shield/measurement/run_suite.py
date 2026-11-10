#!/usr/bin/env python3
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "experiments" / os.environ.get("RESULTS_DIR_NAME", "results_phase4")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

WORKLOADS = [
    "idle",
    "editing",
    "archive",
    "copy",
    "git-checkout",
    "compile",
    "backup",
    "create",
]

SUDO_PW = os.environ.get("SUDO_PASSWORD", "toor")


def run_workload(workload, iteration):
    log_file = RESULTS_DIR / f"{workload}-{iteration}.log"
    print(f"[{time.strftime('%H:%M:%S')}] Running {workload} iteration {iteration}...")
    cmd = [
        "python3",
        str(ROOT / "measurement" / "collector.py"),
        "--workload", workload,
        "--output-dir", str(RESULTS_DIR),
        "--sudo-password", SUDO_PW,
        "--",
        "python3", str(ROOT / "measurement" / "workloads.py"), workload
    ]
    with log_file.open("w") as out:
        res = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        print(f"  WARNING: {workload} iteration {iteration} exited with {res.returncode}")
    else:
        print(f"  Completed {workload} iteration {iteration}")
    time.sleep(1)


def run_simulator(iteration=1):
    log_file = RESULTS_DIR / f"simulator-{iteration}.log"
    print(f"[{time.strftime('%H:%M:%S')}] Running simulator iteration {iteration}...")
    subprocess.run(["rm", "-rf", "/tmp/ebpf_shield_lab"], check=False)
    cmd = [
        "python3",
        str(ROOT / "measurement" / "collector.py"),
        "--workload", "simulator",
        "--output-dir", str(RESULTS_DIR),
        "--sudo-password", SUDO_PW,
        "--",
        "python3", str(ROOT / "simulator.py")
    ]
    with log_file.open("w") as out:
        res = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        print(f"  WARNING: simulator iteration {iteration} exited with {res.returncode}")
    else:
        print(f"  Completed simulator iteration {iteration}")
    time.sleep(1)


def run_multiprocess(iteration=1):
    log_file = RESULTS_DIR / f"multiprocess-{iteration}.log"
    print(f"[{time.strftime('%H:%M:%S')}] Running multiprocess iteration {iteration}...")
    subprocess.run(["rm", "-rf", "/tmp/ebpf_shield_lab"], check=False)
    cmd = [
        "python3",
        str(ROOT / "measurement" / "collector.py"),
        "--workload", "multiprocess",
        "--output-dir", str(RESULTS_DIR),
        "--sudo-password", SUDO_PW,
        "--",
        "python3", str(ROOT / "simulator_multiprocess.py")
    ]
    with log_file.open("w") as out:
        res = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        print(f"  WARNING: multiprocess iteration {iteration} exited with {res.returncode}")
    else:
        print(f"  Completed multiprocess iteration {iteration}")
    time.sleep(1)


def run_canary(iteration=1):
    log_file = RESULTS_DIR / f"canary-{iteration}.log"
    print(f"[{time.strftime('%H:%M:%S')}] Running canary iteration {iteration}...")
    cmd = [
        "python3",
        str(ROOT / "measurement" / "collector.py"),
        "--workload", "canary_test",
        "--output-dir", str(RESULTS_DIR),
        "--sudo-password", SUDO_PW,
        "--",
        "python3", str(ROOT / "simulator_canary.py")
    ]
    with log_file.open("w") as out:
        res = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        print(f"  WARNING: canary iteration {iteration} exited with {res.returncode}")
    else:
        print(f"  Completed canary iteration {iteration}")
    time.sleep(1)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1, help="Iterations per workload (default 1 for quick, 3 for full)")
    args = parser.parse_args()

    print(f"Starting Phase 4 regression suite ({args.iterations} iterations) into {RESULTS_DIR}")
    for workload in WORKLOADS:
        for it in range(1, args.iterations + 1):
            run_workload(workload, it)
    for it in range(1, args.iterations + 1):
        run_simulator(it)
    for it in range(1, args.iterations + 1):
        run_multiprocess(it)
    for it in range(1, args.iterations + 1):
        run_canary(it)

    print("\nRunning summarize.py on new results...")
    sum_cmd = [
        "python3",
        str(ROOT / "measurement" / "summarize.py"),
        "--results-dir", str(RESULTS_DIR)
    ]
    res = subprocess.run(sum_cmd, capture_output=True, text=True)
    summary_csv = RESULTS_DIR / "summary.csv"
    summary_csv.write_text(res.stdout)
    print(res.stdout)
    print(f"\nSuite completed successfully! Summary saved to {summary_csv}")


if __name__ == "__main__":
    main()
