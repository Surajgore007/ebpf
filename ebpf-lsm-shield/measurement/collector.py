#!/usr/bin/env python3
import argparse
import csv
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath

from decoys import DecoyManager
from entropy import (
    SAMPLE_SIZE,
    compute_entropy_ratio,
    is_lab_path,
    sample_file_prefix,
    shannon_entropy_fixed,
)
from file_identity import resolve_path

WINDOW_NS = 2_000_000_000


def norm_path(value):
    if not value or value == "-":
        return None
    value = value.replace("\\t", " ").replace("\\n", " ")
    if value.startswith("/"):
        return os.path.normpath(value)
    return value


def ext(path):
    suffix = PurePosixPath(path).suffix.lower()
    return suffix if suffix else "[no-extension]"


def parent(path):
    p = PurePosixPath(path).parent
    return str(p) if str(p) else "."


def identity_key(path, identity):
    if identity is not None:
        return identity.key()
    return f"path:{path}"


def new_file_window(file_key, path, identity=None):
    return {
        "file_key": file_key,
        "identity": identity,
        "path": path,
        "paths": {path} if path else set(),
        "pids": set(),
        "modifying_pids": set(),
        "comm_by_pid": {},
        "opens": 0,
        "reads": 0,
        "writes": 0,
        "bytes_read": 0,
        "bytes_written": 0,
        "renames": 0,
        "deletes": 0,
        "truncates": 0,
        "ftruncates": 0,
        "fallocates": 0,
        "read_entropy_samples": [],
        "write_entropy_samples": [],
        "is_fallback": identity is None,
        "is_decoy": False,
        "decoy_touched": False,
        "decoy_operations": 0,
    }


def get_file_window(window_files, file_key, path, identity, decoy_mgr=None):
    if file_key not in window_files:
        window_files[file_key] = new_file_window(file_key, path, identity)
    fw = window_files[file_key]
    if path:
        fw["path"] = path
        fw["paths"].add(path)
    if identity is not None and fw["identity"] is None:
        fw["identity"] = identity
        fw["is_fallback"] = False
    if decoy_mgr and not fw["is_decoy"]:
        if decoy_mgr.is_decoy(fkey=file_key, path=path):
            fw["is_decoy"] = True
    return fw


def sample_fw_prefix(fw, path, max_len=SAMPLE_SIZE):
    if path and is_lab_path(path):
        buf = sample_file_prefix(path, max_len)
        if buf:
            return buf
    curr = fw.get("path")
    if curr and curr != path and is_lab_path(curr):
        buf = sample_file_prefix(curr, max_len)
        if buf:
            return buf
    for p in fw.get("paths", ()):
        if p and p != path and p != curr and is_lab_path(p):
            buf = sample_file_prefix(p, max_len)
            if buf:
                return buf
    return None


def finalize_window(file_dict, workload, start_ns, end_ns, all_names):
    seconds = max((end_ns - start_ns) / 1_000_000_000, 0.001)
    files = list(file_dict.values())

    files_opened = [f for f in files if f["opens"] > 0]
    files_written = [f for f in files if f["writes"] > 0]
    files_modified = [f for f in files if f["writes"] > 0 or f["truncates"] > 0 or f["ftruncates"] > 0 or f["fallocates"] > 0]
    files_renamed = [f for f in files if f["renames"] > 0]
    files_deleted = [f for f in files if f["deletes"] > 0]
    files_truncated = [f for f in files if f["truncates"] > 0]
    files_ftruncated = [f for f in files if f["ftruncates"] > 0]
    files_fallocated = [f for f in files if f["fallocates"] > 0]

    unique_files_opened = len(files_opened)
    unique_files_written = len(files_written)
    unique_files_modified = len(files_modified)
    unique_files_renamed = len(files_renamed)
    unique_files_deleted = len(files_deleted)
    unique_files_truncated = len(files_truncated)
    unique_files_ftruncated = len(files_ftruncated)
    unique_files_fallocated = len(files_fallocated)

    opens = sum(f["opens"] for f in files)
    reads = sum(f.get("reads", 0) for f in files)
    writes = sum(f["writes"] for f in files)
    bytes_read = sum(f.get("bytes_read", 0) for f in files)
    bytes_written = sum(f["bytes_written"] for f in files)
    renames = sum(f["renames"] for f in files)
    deletes = sum(f["deletes"] for f in files)
    truncates = sum(f["truncates"] for f in files)
    ftruncates = sum(f["ftruncates"] for f in files)
    fallocates = sum(f["fallocates"] for f in files)

    reads_per_second = reads / seconds
    bytes_read_per_second = bytes_read / seconds
    writes_per_second = writes / seconds
    bytes_written_per_second = bytes_written / seconds
    modified_files_per_second = unique_files_modified / seconds
    writes_per_modified_file = (writes / unique_files_modified) if unique_files_modified else None
    write_open_ratio = (writes / opens) if opens else None
    rename_write_ratio = (renames / writes) if writes else None

    all_read_entropy = [s for f in files for s in f.get("read_entropy_samples", [])]
    all_write_entropy = [s for f in files for s in f.get("write_entropy_samples", [])]
    mean_read_entropy = (sum(all_read_entropy) / len(all_read_entropy)) if all_read_entropy else None
    mean_write_entropy = (sum(all_write_entropy) / len(all_write_entropy)) if all_write_entropy else None
    entropy_ratio = (
        compute_entropy_ratio(int(mean_read_entropy), int(mean_write_entropy))
        if (mean_read_entropy is not None and mean_write_entropy is not None and mean_write_entropy > 0)
        else None
    )

    modified_paths = {f["path"] for f in files_modified if f["path"]}
    directory_breadth = len({parent(p) for p in modified_paths})
    file_type_diversity = len({ext(p) for p in modified_paths})
    identity_fallbacks = sum(1 for f in files if f["is_fallback"])

    # Multi-Process Tracking (General & Modifying)
    process_counts = [len(f["pids"]) for f in files]
    max_processes_per_file = max(process_counts) if process_counts else 0
    mean_processes_per_file = (sum(process_counts) / len(process_counts)) if process_counts else 0.0
    multi_process_files_count = sum(1 for c in process_counts if c > 1)
    multi_process_file_ratio = (multi_process_files_count / len(files)) if files else 0.0

    mod_counts = [len(f["modifying_pids"]) for f in files_modified]
    max_modifying_processes_per_file = max(mod_counts) if mod_counts else 0
    multi_process_modified_files_count = sum(1 for c in mod_counts if c > 1)

    all_pids = set.union(*(f["pids"] for f in files)) if files else set()
    pid_ops = defaultdict(int)
    for f in files:
        ops = f["writes"] + f["opens"] + f["renames"] + f["deletes"] + f["truncates"] + f["ftruncates"] + f["fallocates"]
        for p in f["pids"]:
            pid_ops[p] += ops
    primary_pid = max(pid_ops, key=pid_ops.get) if pid_ops else 0
    primary_process = all_names.get(primary_pid, "?")
    pids_list = "; ".join(f"{p}/{all_names.get(p, '?')}" for p in sorted(all_pids))
    # Phase 4 Decoy / Canary Tracking
    decoy_touched_files = [f for f in files if f.get("is_decoy") and f.get("decoy_touched")]
    decoy_touch_count = len(decoy_touched_files)
    decoy_operations = sum(f.get("decoy_operations", 0) for f in files)

    return {
        "workload": workload,
        "pid": primary_pid,
        "process": primary_process,
        "pid_processes": pids_list,
        "total_distinct_processes": len(all_pids),
        "window_start_ns": start_ns,
        "window_end_ns": end_ns,
        "window_seconds": seconds,
        "unique_files_opened": unique_files_opened,
        "unique_files_written": unique_files_written,
        "unique_files_modified": unique_files_modified,
        "unique_files_renamed": unique_files_renamed,
        "unique_files_deleted": unique_files_deleted,
        "open_operations": opens,
        "read_operations": reads,
        "write_operations": writes,
        "rename_operations": renames,
        "delete_operations": deletes,
        "bytes_read": bytes_read,
        "bytes_written": bytes_written,
        "bytes_read_per_second": bytes_read_per_second,
        "bytes_written_per_second": bytes_written_per_second,
        "truncate_operations": truncates,
        "ftruncate_operations": ftruncates,
        "fallocate_operations": fallocates,
        "unique_files_truncated": unique_files_truncated,
        "unique_files_ftruncated": unique_files_ftruncated,
        "unique_files_fallocated": unique_files_fallocated,
        "reads_per_second": reads_per_second,
        "writes_per_second": writes_per_second,
        "modified_files_per_second": modified_files_per_second,
        "writes_per_modified_file": writes_per_modified_file,
        "write_open_ratio": write_open_ratio,
        "rename_write_ratio": rename_write_ratio,
        "mean_read_entropy_millibits": round(mean_read_entropy, 1) if mean_read_entropy is not None else None,
        "mean_write_entropy_millibits": round(mean_write_entropy, 1) if mean_write_entropy is not None else None,
        "read_write_entropy_ratio": entropy_ratio,
        "directory_breadth": directory_breadth,
        "file_type_diversity": file_type_diversity,
        "max_processes_per_file": max_processes_per_file,
        "mean_processes_per_file": round(mean_processes_per_file, 4),
        "multi_process_files_count": multi_process_files_count,
        "multi_process_file_ratio": round(multi_process_file_ratio, 4),
        "max_modifying_processes_per_file": max_modifying_processes_per_file,
        "multi_process_modified_files_count": multi_process_modified_files_count,
        "decoy_touch_count": decoy_touch_count,
        "decoy_operations": decoy_operations,
        "identity_fallbacks": identity_fallbacks,
        "paths_are_observation_keys": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Measurement-only two-second file-centric process telemetry collector")
    parser.add_argument("--workload", required=True)
    parser.add_argument("--output-dir", default="experiments/results")
    parser.add_argument("--sudo-password", default=os.environ.get("SUDO_PASSWORD"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.sudo_password:
        parser.error("SUDO_PASSWORD or --sudo-password is required to attach bpftrace")
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a workload command is required")

    root = Path(args.output_dir)
    root.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    jsonl_path = root / f"{args.workload}-{stamp}.jsonl"
    csv_path = root / f"{args.workload}-{stamp}.csv"
    files_jsonl_path = root / f"{args.workload}-{stamp}.files.jsonl"
    bt_path = Path(__file__).with_name("file_activity.bt")
    proc = subprocess.Popen(
        ["sudo", "-S", "-p", "", "stdbuf", "-o0", "-e0", "bpftrace", str(bt_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1)
    proc.stdin.write(args.sudo_password + "\n")
    proc.stdin.flush()
    start = time.monotonic_ns()

    import threading
    stderr_lines = []
    def _drain_stderr():
        try:
            for l in proc.stderr:
                stderr_lines.append(l)
        except Exception:
            pass
    threading.Thread(target=_drain_stderr, daemon=True).start()

    config_file = Path(__file__).resolve().parent.parent / "config" / "detector.json"
    decoy_mgr = DecoyManager(str(config_file))
    decoy_mgr.deploy()

    collector_pid = os.getpid()
    windows = defaultdict(dict)
    names = {}
    fd_identities = {}
    path_identities = {}
    known_file_entropy = {}
    pending_operations = {}
    first_ns = None
    last_ns = None
    measurement_start_ns = None
    ready = False

    def consume(line):
        nonlocal first_ns, last_ns, ready
        line = line.rstrip("\r\n")
        if line == "READY":
            ready = True
            return
        fields = line.split("\t")
        if not fields:
            return
        if fields[0] == "TICK" and len(fields) >= 2:
            tick = int(fields[1])
            if first_ns is None:
                first_ns = tick - WINDOW_NS
            last_ns = tick
            return
        if fields[0] != "EV" or len(fields) < 6:
            return
        ts = int(fields[1]); pid = int(fields[2]); comm = fields[3]; kind = fields[4]
        if comm == "bpftrace" or pid == collector_pid or (measurement_start_ns is not None and ts < measurement_start_ns):
            return
        if first_ns is None:
            first_ns = (ts // WINDOW_NS) * WINDOW_NS
        index = (ts - first_ns) // WINDOW_NS
        names[pid] = comm
        last_ns = max(last_ns or ts, ts)

        if kind == "P" and len(fields) >= 9:
            pending_tid = int(fields[5])
            if len(pending_operations) >= 4096:
                pending_operations.pop(next(iter(pending_operations)))
            pending_operations[(pid, pending_tid)] = (
                fields[6], int(fields[7]), norm_path("\t".join(fields[8:])))
            return

        if kind == "S" and len(fields) >= 7:
            pending_tid = int(fields[5])
            pending = pending_operations.pop((pid, pending_tid), None)
            if pending is None:
                return
            subtype, fd, path = pending
            identity = fd_identities.get((pid, fd)) if fd >= 0 else None
            if identity is None and path:
                identity = path_identities.get((pid, path)) or resolve_path(path)
            fkey = identity_key(path, identity)
            fw = get_file_window(windows[index], fkey, path, identity, decoy_mgr)
            fw["pids"].add(pid)
            fw["comm_by_pid"][pid] = comm

            if subtype == "RD":
                bytes_read = max(int(fields[6]), 0)
                fw["reads"] += 1
                fw["bytes_read"] += bytes_read
                if is_lab_path(path) and len(fw["read_entropy_samples"]) < 5:
                    ent = known_file_entropy.get(fkey)
                    if ent is None:
                        buf = sample_file_prefix(path)
                        if buf:
                            ent = shannon_entropy_fixed(buf)
                            known_file_entropy[fkey] = ent
                    if ent is not None:
                        fw["read_entropy_samples"].append(ent)
            elif subtype == "W":
                bytes_written = max(int(fields[6]), 0)
                fw["writes"] += 1
                fw["bytes_written"] += bytes_written
                fw["modifying_pids"].add(pid)
                if fw.get("is_decoy") or decoy_mgr.is_decoy(fkey, path):
                    fw["is_decoy"] = True
                    fw["decoy_touched"] = True
                    fw["decoy_operations"] += 1
                if is_lab_path(path) and len(fw["write_entropy_samples"]) < 5:
                    buf = sample_fw_prefix(fw, path)
                    if buf:
                        ent = shannon_entropy_fixed(buf)
                        fw["write_entropy_samples"].append(ent)
                        known_file_entropy[fkey] = ent
            elif subtype == "T":
                fw["truncates"] += 1
                fw["modifying_pids"].add(pid)
                if fw.get("is_decoy") or decoy_mgr.is_decoy(fkey, path):
                    fw["is_decoy"] = True
                    fw["decoy_touched"] = True
                    fw["decoy_operations"] += 1
            elif subtype == "F":
                fw["ftruncates"] += 1
                fw["modifying_pids"].add(pid)
                if fw.get("is_decoy") or decoy_mgr.is_decoy(fkey, path):
                    fw["is_decoy"] = True
                    fw["decoy_touched"] = True
                    fw["decoy_operations"] += 1
            elif subtype == "A":
                fw["fallocates"] += 1
                fw["modifying_pids"].add(pid)
                if fw.get("is_decoy") or decoy_mgr.is_decoy(fkey, path):
                    fw["is_decoy"] = True
                    fw["decoy_touched"] = True
                    fw["decoy_operations"] += 1
            return

        if kind == "O":
            if len(fields) >= 7:
                fd = int(fields[5])
                path = norm_path("\t".join(fields[6:]))
            else:
                fd = None
                path = norm_path("\t".join(fields[5:]))
            identity = resolve_path(path) if path else None
            if identity is None and path:
                identity = path_identities.get((pid, path))
            if fd is not None:
                fd_identities[(pid, fd)] = identity
            if path and identity is not None:
                path_identities[(pid, path)] = identity
            fkey = identity_key(path, identity)
            fw = get_file_window(windows[index], fkey, path, identity, decoy_mgr)
            fw["pids"].add(pid)
            fw["comm_by_pid"][pid] = comm
            fw["opens"] += 1
            if is_lab_path(path) and fkey not in known_file_entropy:
                buf = sample_file_prefix(path)
                if buf:
                    known_file_entropy[fkey] = shannon_entropy_fixed(buf)

        elif kind == "W":
            if len(fields) >= 8:
                fd = int(fields[5])
                bytes_written = max(int(fields[6]), 0)
                path = norm_path("\t".join(fields[7:]))
            else:
                fd = None
                bytes_written = 0
                path = norm_path("\t".join(fields[5:]))
            identity = fd_identities.get((pid, fd)) if fd is not None and fd >= 0 else None
            if identity is None and path:
                identity = path_identities.get((pid, path)) or resolve_path(path)
            fkey = identity_key(path, identity)
            fw = get_file_window(windows[index], fkey, path, identity, decoy_mgr)
            fw["pids"].add(pid)
            fw["comm_by_pid"][pid] = comm
            fw["writes"] += 1
            fw["bytes_written"] += bytes_written
            fw["modifying_pids"].add(pid)
            if fw.get("is_decoy") or decoy_mgr.is_decoy(fkey, path):
                fw["is_decoy"] = True
                fw["decoy_touched"] = True
                fw["decoy_operations"] += 1
            if is_lab_path(path) and len(fw["write_entropy_samples"]) < 5:
                buf = sample_fw_prefix(fw, path)
                if buf:
                    ent = shannon_entropy_fixed(buf)
                    fw["write_entropy_samples"].append(ent)
                    known_file_entropy[fkey] = ent

        elif kind == "R" and len(fields) >= 7:
            old = norm_path(fields[5])
            new = norm_path("\t".join(fields[6:]))
            identity = path_identities.get((pid, old)) if old else None
            if identity is None and new:
                identity = resolve_path(new)
            if identity is None and old:
                identity = resolve_path(old)
            target = new or old
            fkey = identity_key(target, identity)
            fw = get_file_window(windows[index], fkey, target, identity, decoy_mgr)
            fw["pids"].add(pid)
            fw["comm_by_pid"][pid] = comm
            fw["renames"] += 1
            if old:
                fw["paths"].add(old)
                old_ident = path_identities.pop((pid, old), None)
                old_fkey = identity_key(old, old_ident)
                if old_fkey in known_file_entropy and fkey not in known_file_entropy:
                    known_file_entropy[fkey] = known_file_entropy[old_fkey]
            if new and identity:
                fw["paths"].add(new)
                fw["path"] = new
                path_identities[(pid, new)] = identity
            if fw.get("is_decoy") or decoy_mgr.is_decoy(fkey, target) or (old and decoy_mgr.is_decoy(path=old)):
                fw["is_decoy"] = True
                fw["decoy_touched"] = True
                fw["decoy_operations"] += 1
            if is_lab_path(target) and not fw["write_entropy_samples"]:
                buf = sample_fw_prefix(fw, target)
                if buf:
                    ent = shannon_entropy_fixed(buf)
                    fw["write_entropy_samples"].append(ent)
                    known_file_entropy[fkey] = ent

        elif kind == "D":
            path = norm_path("\t".join(fields[5:]))
            identity = path_identities.pop((pid, path), None) if path else None
            if identity is None and path:
                identity = resolve_path(path)
            fkey = identity_key(path, identity)
            fw = get_file_window(windows[index], fkey, path, identity, decoy_mgr)
            fw["pids"].add(pid)
            fw["comm_by_pid"][pid] = comm
            fw["deletes"] += 1
            if fw.get("is_decoy") or decoy_mgr.is_decoy(fkey, path):
                fw["is_decoy"] = True
                fw["decoy_touched"] = True
                fw["decoy_operations"] += 1

        elif kind in ("T", "F", "A"):
            fd = int(fields[5]) if kind in ("F", "A") and len(fields) >= 7 else None
            path = norm_path("\t".join(fields[6:] if fd is not None else fields[5:]))
            identity = fd_identities.get((pid, fd)) if fd is not None else None
            if identity is None:
                identity = path_identities.get((pid, path)) if path else None
            if identity is None and path:
                identity = resolve_path(path)
            fkey = identity_key(path, identity)
            fw = get_file_window(windows[index], fkey, path, identity, decoy_mgr)
            fw["pids"].add(pid)
            fw["comm_by_pid"][pid] = comm
            fw["modifying_pids"].add(pid)
            if fw.get("is_decoy") or decoy_mgr.is_decoy(fkey, path):
                fw["is_decoy"] = True
                fw["decoy_touched"] = True
                fw["decoy_operations"] += 1
            if kind == "T":
                fw["truncates"] += 1
            elif kind == "F":
                fw["ftruncates"] += 1
            else:
                fw["fallocates"] += 1

    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and not ready:
            line = proc.stdout.readline()
            if line:
                consume(line)
            elif proc.poll() is not None:
                break
        if not ready:
            raise RuntimeError("bpftrace did not become ready")
        workload = subprocess.Popen(command)
        measurement_start_ns = time.monotonic_ns()
        while workload.poll() is None:
            line = proc.stdout.readline()
            if line:
                consume(line)
            else:
                time.sleep(0.01)
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=8)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            consume(line)
    finally:
        decoy_mgr.cleanup()
        if 'workload' in locals() and workload.poll() is None:
            workload.terminate()
            workload.wait(timeout=5)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if first_ns is None:
        first_ns = start
    if last_ns is None:
        last_ns = first_ns + WINDOW_NS

    results = []
    file_records = []
    for index in sorted(windows.keys()):
        file_dict = windows[index]
        if not file_dict:
            continue
        ws = first_ns + index * WINDOW_NS
        we = ws + WINDOW_NS
        results.append(finalize_window(file_dict, args.workload, ws, we, names))
        for f in file_dict.values():
            file_records.append({
                "workload": args.workload,
                "window_index": index,
                "window_start_ns": ws,
                "window_end_ns": we,
                "file_key": f["file_key"],
                "path": f["path"],
                "pids": sorted(list(f["pids"])),
                "modifying_pids": sorted(list(f["modifying_pids"])),
                "processes": [f["comm_by_pid"].get(p, "?") for p in sorted(list(f["pids"]))],
                "distinct_process_count": len(f["pids"]),
                "distinct_modifying_process_count": len(f["modifying_pids"]),
                "opens": f["opens"],
                "reads": f.get("reads", 0),
                "writes": f["writes"],
                "bytes_read": f.get("bytes_read", 0),
                "bytes_written": f["bytes_written"],
                "renames": f["renames"],
                "deletes": f["deletes"],
                "truncates": f["truncates"],
                "ftruncates": f["ftruncates"],
                "fallocates": f["fallocates"],
                "read_entropy": round(sum(f["read_entropy_samples"]) / len(f["read_entropy_samples"]), 1) if f.get("read_entropy_samples") else None,
                "write_entropy": round(sum(f["write_entropy_samples"]) / len(f["write_entropy_samples"]), 1) if f.get("write_entropy_samples") else None,
                "entropy_ratio": compute_entropy_ratio(
                    int(sum(f["read_entropy_samples"]) / len(f["read_entropy_samples"])),
                    int(sum(f["write_entropy_samples"]) / len(f["write_entropy_samples"]))
                ) if f.get("read_entropy_samples") and f.get("write_entropy_samples") else None,
                "modified": f["writes"] > 0 or f["truncates"] > 0 or f["ftruncates"] > 0 or f["fallocates"] > 0,
                "is_decoy": f.get("is_decoy", False),
                "decoy_touched": f.get("decoy_touched", False),
                "decoy_operations": f.get("decoy_operations", 0),
            })

    with jsonl_path.open("w", encoding="utf-8") as out:
        for row in results:
            out.write(json.dumps(row, sort_keys=True) + "\n")
    with files_jsonl_path.open("w", encoding="utf-8") as out:
        for row in file_records:
            out.write(json.dumps(row, sort_keys=True) + "\n")
    if results:
        with csv_path.open("w", newline="", encoding="utf-8") as out:
            fields = [k for k, v in results[0].items() if not isinstance(v, bool)]
            writer = csv.DictWriter(out, fieldnames=fields)
            writer.writeheader()
            for row in results:
                writer.writerow({k: v for k, v in row.items() if k in fields})

    print(json.dumps({
        "workload": args.workload,
        "windows": len(results),
        "total_file_windows": len(file_records),
        "jsonl": str(jsonl_path),
        "files_jsonl": str(files_jsonl_path),
        "csv": str(csv_path),
        "bpftrace_ready": ready
    }, sort_keys=True))
    for row in results:
        print(json.dumps(row, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())