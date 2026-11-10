#!/usr/bin/env python3
"""Adversarial decoy and canary access test harness.

Simulates unauthorized discovery, payload overwrite, and extension alteration
against configured honeypot files to test kernel-level tripwire response.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

CANARY_DIR = Path("/tmp/ebpf_shield_canaries")


def main():
    print("\033[96m┌──────────────────────────────────────────────────────────────────────────────┐\033[0m")
    print("\033[96m│\033[0m                 CANARY HONEYPOT ADVERSARIAL TEST HARNESS                     \033[96m│\033[0m")
    print("\033[96m├──────────────────────────────────────────────────────────────────────────────┤\033[0m")
    print(f"\033[96m│\033[0m Target Directory: {str(CANARY_DIR):<59}\033[96m│\033[0m")
    print("\033[96m└──────────────────────────────────────────────────────────────────────────────┘\033[0m")

    if not CANARY_DIR.exists():
        CANARY_DIR.mkdir(parents=True, exist_ok=True)
        test_file = CANARY_DIR / "passwords_backup.xlsx"
        test_file.write_bytes(b"PK\x03\x04\x14\x00CANARY_SIMULATOR_TEST_DATA")

    canary_files = list(CANARY_DIR.glob("*"))
    if not canary_files:
        test_file = CANARY_DIR / "passwords_backup.xlsx"
        test_file.write_bytes(b"PK\x03\x04\x14\x00CANARY_SIMULATOR_TEST_DATA")
        canary_files = [test_file]

    print(f"[*] Located {len(canary_files)} canary targets in {CANARY_DIR}")
    for f in canary_files:
        print(f"    - {f.name} (inode: {f.stat().st_ino})")

    time.sleep(1.0)
    target = canary_files[0]
    print(f"[*] Accessing target: {target.name}")

    data = target.read_bytes()
    encrypted = bytes([b ^ 0xAA for b in data]) + b"\nENCRYPTED_PAYLOAD\n"
    target.write_bytes(encrypted)
    print(f"[*] Overwrote payload ({len(encrypted)} bytes)")

    locked = target.with_name(target.name + ".locked")
    target.rename(locked)
    print(f"[*] Renamed file: {target.name} -> {locked.name}")
    print("[*] Tripwire access cycle complete.")
    time.sleep(2.0)

    # Revert modification
    if locked.exists():
        locked.rename(target)
        target.write_bytes(data)


if __name__ == "__main__":
    main()
