"""Fixed-point Shannon entropy computation and bounded prefix sampling."""

from __future__ import annotations

import math
import os
from typing import Optional

SAMPLE_SIZE = 4096
SCALE = 1000  # Millibits: 0 to 8000

LOG2_MILLIBITS = [0] * (SAMPLE_SIZE + 1)
for i in range(1, SAMPLE_SIZE + 1):
    LOG2_MILLIBITS[i] = int(round(math.log2(i) * SCALE))


def shannon_entropy_fixed(buffer: bytes, max_len: int = SAMPLE_SIZE) -> int:
    """Compute Shannon entropy in millibits (0 to 8000) using fixed-point integer arithmetic."""
    if not buffer:
        return 0
    data = buffer[:max_len]
    n = len(data)
    if n == 0:
        return 0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    sum_c_log_c = sum(c * LOG2_MILLIBITS[c] for c in counts if c > 0)
    entropy_millibits = LOG2_MILLIBITS[n] - (sum_c_log_c // n)
    return max(0, min(8000, entropy_millibits))


def is_lab_path(path: Optional[str]) -> bool:
    """Confine buffer sampling strictly to lab paths for privacy and zero overhead outside."""
    if not path:
        return False
    return (
        path.startswith("/tmp/ebpf_shield_lab")
        or path.startswith("/tmp/ebpf_shield_canaries")
        or path.startswith("/tmp/shield-")
        or "\\tmp\\ebpf_shield_lab" in path
        or "\\tmp\\ebpf_shield_canaries" in path
        or "\\tmp\\shield-" in path
    )


def sample_file_prefix(path: str, max_len: int = SAMPLE_SIZE) -> Optional[bytes]:
    """Sample up to max_len bytes from file if within lab scope."""
    if not is_lab_path(path):
        return None
    try:
        with open(path, "rb") as f:
            return f.read(max_len)
    except OSError:
        return None


def compute_entropy_ratio(read_millibits: int, write_millibits: int) -> Optional[float]:
    """Compute read/write entropy ratio. Center near 1.0 for benign, low for encryption."""
    if write_millibits <= 0 or read_millibits <= 0:
        return None
    return round(read_millibits / write_millibits, 4)
