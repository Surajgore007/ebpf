# eBPF LSM Shield

Audit-only Linux behavioral detection prototype for ransomware-like filesystem activity.

## Overview

eBPF LSM Shield observes filesystem behavior with eBPF-backed kernel tracepoints and analyzes it in userspace. It looks for combinations of:

- broad file modification
- write activity
- rename activity
- write/rename relationships
- file-type and directory diversity
- persistence across consecutive observation windows

The monitor reports:

```text
LOW / BENIGN → SUSPICIOUS → HIGH RISK
```

This is a research and demonstration prototype, not a production ransomware
classifier. It does not claim universal accuracy.

## Architecture

```text
Filesystem activity
        ↓
bpftrace/eBPF tracepoint telemetry
        ↓
Compact event stream
        ↓
Python userspace feature extraction
        ↓
Explainable behavioral classification
        ↓
Terminal dashboard and audit alert
```

The current live filesystem path uses **bpftrace plus Python**. The repository
also contains a separate BPF LSM execution-hook example. That hook is
audit-only and is not currently used to block filesystem operations.

## Safety and scope

- The project is audit-only: it does not block, kill, quarantine, or encrypt.
- The included simulator works only inside `/tmp/ebpf_shield_lab`.
- The simulator creates dummy files, rewrites deterministic dummy data, and
  renames those files.
- It does not access user documents, home-directory data, or real secrets.
- Entropy sampling is bounded to explicitly named laboratory paths.
- Canary files, when enabled, are deployed under `/tmp/ebpf_shield_canaries`.

Do not run experimental workloads against real user data.

## Current telemetry

The probe observes successful filesystem operations including:

- `openat` and `openat2`
- `write`, `pwrite64`, `writev`, `pwritev`, and `pwritev2`
- `copy_file_range`
- `truncate`, `ftruncate`, and `fallocate`
- `rename`, `renameat`, and `renameat2`
- `unlink` and `unlinkat`
- `close`

Write-family and truncate-family events use entry/completion correlation.
Failed operations are not counted. Larger unique-file sets are maintained in
userspace rather than as unbounded kernel state.

File observations use `(device, inode, generation)` where generation is
available. Unsupported generation lookup is reported as a fallback rather than
silently treated as definitive identity.

## Detection behavior

The prototype does not classify a process from write volume alone. Legitimate
archive extraction, copying, backups, builds, and high-volume file creation can
modify many files.

The current demonstration emphasizes:

```text
broad file coverage
+ transformation evidence
+ persistence across multiple windows
= HIGH RISK prototype alert
```

Thresholds are configurable engineering parameters derived from measurements
on the development environment. They are not universal ransomware thresholds.

## Repository layout

```text
config/
  detector.json             Prototype configuration
measurement/
  file_activity.bt          eBPF-backed bpftrace telemetry
  collector.py              Structured JSON/CSV collection
  file_identity.py          File identity resolution
  entropy.py                Bounded lab-only entropy sampling
  decoys.py                 Canary deployment and tracking
  summarize.py              Measurement summaries
  workloads.py              Benign workload definitions
shield                       Live terminal dashboard
simulator.py                 Safe isolated transformation simulator
simulator_canary.py          Canary demonstration workload
simulator_multiprocess.py    Multi-process demonstration workload
demo.sh                      Interactive demonstration runner
src/shield.bpf.c             Audit-only BPF LSM hook example
src/vmlinux.h                Generated kernel type definitions
```

## Requirements

The project is intended for a Linux system with:

- Linux kernel with BPF and tracepoint support
- Python 3
- `bpftrace`
- `sudo` permission to attach tracing programs

The BPF LSM example additionally requires a kernel configured with BPF LSM
support. Exact kernel, compiler, and bpftrace versions are environment-specific.

## Running the live demonstration

From the project directory:

### Terminal 1: start the monitor

```bash
sudo ./shield
```

### Terminal 2: run the safe simulator

```bash
python3 simulator.py
```

Expected behavior:

```text
LOW / BENIGN
      ↓
SUSPICIOUS
      ↓
HIGH RISK
      ↓
SECURITY ALERT
```

The dashboard displays live PID/process information, window statistics,
behavioral evidence, state transitions, and the audit-only policy status.

To run the interactive demonstration menu:

```bash
./demo.sh
```

The menu includes benign workload, transformation, multiprocess, canary, and
live-monitor demonstrations.

## Structured measurements

Run a controlled workload and write results to a local output directory:

```bash
python3 measurement/collector.py \
  --workload copy \
  --output-dir experiments/local \
  -- python3 measurement/workloads.py copy
```

Summarize collected observations with:

```bash
python3 measurement/summarize.py experiments/local
```

Use the project’s supported privilege method for your environment. Do not put
passwords in commands, scripts, configuration, or committed files.

## Limitations

- The live telemetry path is text-based bpftrace, not a typed libbpf ring buffer.
- The BPF LSM hook is audit-only.
- The classifier is explainable prototype logic, not machine learning.
- Entropy is experimental and is not currently a universal classification gate.
- Results were collected on a limited environment and workload set.
- The simulator is deterministic and does not represent every ransomware family.
- No production prevention, recovery, quarantine, or self-protection mechanism
  is implemented.

## Planned work

- migrate live telemetry to a compiled libbpf/CO-RE loader
- use a typed ring buffer for compact events
- improve identity handling across filesystem edge cases
- validate entropy and adaptive baselines with larger datasets
- evaluate TP, TN, FP, FN, precision, recall, F1, and detection latency
- design and test carefully gated enforcement after audit validation

## Project status

This repository contains a working academic prototype and safe interactive
demonstration. It should be presented as **behavioral ransomware-like activity
detection in audit mode**, not as a finished endpoint protection product.

## License

No license has been selected yet. Add a license before accepting external
contributions or redistributing the project.
