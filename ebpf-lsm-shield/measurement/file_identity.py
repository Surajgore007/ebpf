"""Bounded file identity resolution for Linux telemetry events."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - the collector runs on Linux.
    fcntl = None


FS_IOC_GETVERSION = 0x80087601


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    generation: Optional[int]

    def key(self) -> str:
        generation = "unknown" if self.generation is None else str(self.generation)
        return f"{self.device}:{self.inode}:{generation}"


def resolve_path(path: str) -> Optional[FileIdentity]:
    """Resolve a path without following symlinks and best-effort generation."""
    if not path or not os.path.isabs(path):
        return None
    try:
        stat_result = os.stat(path, follow_symlinks=False)
    except OSError:
        return None

    generation = None
    if fcntl is not None:
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            value = bytearray(struct.calcsize("L"))
            fcntl.ioctl(fd, FS_IOC_GETVERSION, value, True)
            generation = struct.unpack("L", value)[0]
        except (OSError, ValueError, struct.error):
            generation = None
        finally:
            if fd is not None:
                os.close(fd)
    return FileIdentity(stat_result.st_dev, stat_result.st_ino, generation)
