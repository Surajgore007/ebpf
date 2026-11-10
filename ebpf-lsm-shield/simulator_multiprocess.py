#!/usr/bin/env python3
import multiprocessing
import os
import shutil
import time
from pathlib import Path

LAB = Path("/tmp/ebpf_shield_lab")


def worker_task(file_batch):
    for p in file_batch:
        try:
            data = p.read_bytes()
            p.write_bytes(data[::-1] + b"\nLAB_TRANSFORM\n")
            renamed = p.with_name(p.stem + ".transformed." + p.suffix.lstrip("."))
            p.rename(renamed)
        except OSError:
            pass


def main():
    if LAB.exists():
        shutil.rmtree(LAB)
    LAB.mkdir(mode=0o700)
    files = []
    types = ["doc", "txt", "jpg", "pdf", "csv", "log"]
    print("Generating 150 test files for multi-process distributed workload...")
    for i in range(150):
        p = LAB / f"document-{i:04d}.{types[i % len(types)]}"
        p.write_bytes((f"deterministic laboratory input {i}\n" * 8).encode())
        files.append(p)
    print("[*] Corpus ready. Commencing distributed execution across worker processes...")
    time.sleep(2.2)

    for batch in range(3):
        print(f"[*] Distributed cycle {batch + 1}/3: 5 cooperating processes, 10 files each...")
        batch_files = files[batch * 50 : (batch + 1) * 50]
        chunks = [batch_files[i * 10 : (i + 1) * 10] for i in range(5)]
        processes = [multiprocessing.Process(target=worker_task, args=(chunk,)) for chunk in chunks]
        for p in processes:
            p.start()
        for p in processes:
            p.join()
        time.sleep(2.2)

    shutil.rmtree(LAB)
    print("[*] Multi-process workload completed. Lab directory removed.")


if __name__ == "__main__":
    main()
