"""Config-driven decoy (canary) file deployment and identity tracking for Phase 4."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    from measurement.file_identity import FileIdentity, resolve_path
except ModuleNotFoundError:
    from file_identity import FileIdentity, resolve_path

DEFAULT_CANARY_FILENAMES = [
    ".credentials_2026.docx",
    "passwords_backup.xlsx",
    "private_keys.pem",
    "client_database.db",
    "financial_ledger.csv",
]

# Realistic decoy file headers to simulate genuine high-value targets
CANARY_PAYLOADS = {
    "docx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00CANARY_DOCUMENT_HEADER_DO_NOT_MODIFY",
    "xlsx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00CANARY_SPREADSHEET_HEADER_DO_NOT_MODIFY",
    "pem": b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0CANARYKEYNOTREAL\n-----END RSA PRIVATE KEY-----\n",
    "db": b"SQLite format 3\x00\x10\x00\x01\x01\x00@  \x00\x00\x00\x01CANARY_DB",
    "csv": b"account_id,username,password_hash,role\n1001,admin,CANARY_HASH_DO_NOT_TOUCH,superuser\n",
}


def get_canary_payload(filename: str) -> bytes:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return CANARY_PAYLOADS.get(ext, b"[CONFIDENTIAL CANARY DATA - DO NOT ACCESS]\n")


class DecoyManager:
    """Manages deployment, identity registry, and lifecycle of decoy/canary files."""

    def __init__(self, config_path: Optional[str] = None):
        self.deployed_files: List[Path] = []
        self.decoy_identities: Dict[str, Path] = {}  # fkey -> Path
        self.decoy_paths: Set[str] = set()           # normalized path -> True
        self.config = self._load_config(config_path)

    def _load_config(self, config_path: Optional[str]) -> dict:
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("decoys", {})
            except Exception:
                pass
        return {}

    def deploy(self, target_dirs: Optional[List[str]] = None, filenames: Optional[List[str]] = None) -> List[Path]:
        """Deploy canary files into specified directories and register their identities."""
        if filenames is None:
            filenames = self.config.get("patterns", DEFAULT_CANARY_FILENAMES)
        if target_dirs is None:
            target_dirs = self.config.get("directories", ["/tmp/ebpf_shield_canaries"])

        deployed = []
        for d in target_dirs:
            dp = Path(d)
            if not dp.exists():
                try:
                    dp.mkdir(parents=True, exist_ok=True)
                except OSError:
                    continue
            try:
                os.chmod(dp, 0o777)
            except OSError:
                pass
            for fname in filenames:
                file_path = dp / fname
                try:
                    payload = get_canary_payload(fname)
                    file_path.write_bytes(payload)
                    os.chmod(file_path, 0o666)
                    ident = resolve_path(str(file_path))
                    norm = os.path.normpath(str(file_path))
                    self.decoy_paths.add(norm)
                    if ident:
                        self.decoy_identities[ident.key()] = file_path
                    self.deployed_files.append(file_path)
                    deployed.append(file_path)
                except OSError:
                    continue
        return deployed

    def register_existing(self, path: str):
        """Register an existing file path as a decoy without recreating it."""
        norm = os.path.normpath(path)
        self.decoy_paths.add(norm)
        ident = resolve_path(norm)
        if ident:
            self.decoy_identities[ident.key()] = Path(norm)

    def is_decoy(self, fkey: Optional[str] = None, path: Optional[str] = None) -> bool:
        """Check if a file identity or path belongs to an active decoy."""
        if fkey and fkey in self.decoy_identities:
            return True
        if path:
            norm = os.path.normpath(path)
            if norm in self.decoy_paths:
                return True
            for d in self.config.get("directories", ["/tmp/ebpf_shield_canaries"]):
                norm_d = os.path.normpath(d)
                if norm.startswith(norm_d):
                    return True
            name = Path(norm).name
            patterns = self.config.get("patterns", DEFAULT_CANARY_FILENAMES)
            if any(name.startswith(p.split(".")[0]) for p in patterns) or name.startswith(".canary"):
                if "/tmp/ebpf_shield" in norm or "\\tmp\\ebpf_shield" in norm:
                    return True
        return False

    def get_decoy_name(self, fkey: Optional[str] = None, path: Optional[str] = None) -> Optional[str]:
        """Get the human-readable name of the matched decoy."""
        if fkey and fkey in self.decoy_identities:
            return self.decoy_identities[fkey].name
        if path:
            return Path(path).name
        return None

    def cleanup(self):
        """Remove only deployed decoy files safely."""
        for p in list(self.deployed_files):
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass
        # Clean up empty parent directories if created in /tmp/ebpf_shield_canaries
        for d in self.config.get("directories", ["/tmp/ebpf_shield_canaries"]):
            dp = Path(d)
            try:
                if dp.exists() and not any(dp.iterdir()):
                    dp.rmdir()
            except OSError:
                pass
        self.deployed_files.clear()
        self.decoy_identities.clear()
        self.decoy_paths.clear()
