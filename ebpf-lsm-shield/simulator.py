#!/usr/bin/env python3
import shutil
import time
from pathlib import Path

LAB = Path("/tmp/ebpf_shield_lab")


def main():
    if LAB.exists():
        shutil.rmtree(LAB)
    LAB.mkdir(mode=0o700)
    files = []
    types = ["doc", "txt", "jpg", "pdf", "csv", "log"]
    print("\033[96m┌──────────────────────────────────────────────────────────────────────────────┐\033[0m")
    print("\033[96m│\033[0m             eBPF LSM SHIELD SYNTHETIC WORKLOAD SIMULATOR                     \033[96m│\033[0m")
    print("\033[96m├──────────────────────────────────────────────────────────────────────────────┤\033[0m")
    print(f"\033[96m│\033[0m Target Directory: {str(LAB):<59}\033[96m│\033[0m")
    print("\033[96m└──────────────────────────────────────────────────────────────────────────────┘\033[0m")
    print("Generating synthetic workload corpus (150 files across 6 extensions)...")
    for i in range(150):
        p = LAB / f"document-{i:04d}.{types[i % len(types)]}"
        p.write_bytes((f"deterministic laboratory input {i}\n" * 8).encode())
        files.append(p)
    print("[*] Corpus initialized. Commencing transformation sequence...")
    time.sleep(2.2)
    for batch in range(3):
        print(f"[*] Transformation cycle {batch + 1}/3: Processing 50 files...")
        for p in files[batch * 50 : (batch + 1) * 50]:
            data = p.read_bytes()
            p.write_bytes(data[::-1] + b"\nLAB_TRANSFORM\n")
            renamed = p.with_name(p.stem + ".transformed." + p.suffix.lstrip("."))
            p.rename(renamed)
            files[files.index(p)] = renamed
        time.sleep(2.2)
    shutil.rmtree(LAB)
    print("[*] Workload execution completed. Lab directory removed.")


if __name__ == "__main__":
    main()