# eBPF LSM Shield

## Kernel-Level Behavioral Threat Detection and Response using eBPF and Linux Security Modules

eBPF LSM Shield is a Linux security prototype that watches what processes do to files and looks for suspicious combinations that may resemble ransomware-like transformation.

It is currently **audit-only**. It does not encrypt real files, block processes, kill processes, quarantine processes, or claim universal ransomware detection.

---

## 1. What are we building?

The prototype watches for a process that may suddenly:

- modify many different files;
- write to many files quickly;
- rename files rapidly; and
- repeat the pattern across multiple windows.

This is behavioral detection: the system combines several signals instead of treating one system call as proof of ransomware.

It does **not** use a rule such as:

```text
100 writes = ransomware
```

Archive extraction, copying, backups, builds, and legitimate file creation can all produce high filesystem activity. The project measured those workloads before designing the current demonstration logic.

---

## 2. Simple project flow

```text
Application / Process
        ↓
Linux Kernel
        ↓
eBPF Tracepoint Telemetry
        ↓
Filesystem Events
        ↓
Two-Second Window
        ↓
Userspace Feature Extraction
        ↓
Behavioral Detection Logic
        ↓
LOW / BENIGN → SUSPICIOUS → HIGH RISK
        ↓
Audit Alert
```

1. A process performs filesystem operations.
2. Linux produces kernel tracepoint events.
3. The bpftrace probe observes selected events.
4. Events contain timestamp, PID, process name, operation, and path information where available.
5. Python groups events into two-second per-process windows.
6. Python maintains unique-path sets and derives rates, ratios, directory breadth, and file-type diversity.
7. The detector displays an explainable state.
8. HIGH RISK produces an alert, but no process is blocked.

---

## 3. What is actually implemented?

| Component | Status | Current behavior |
|---|---|---|
| Ubuntu/eBPF environment | ✅ IMPLEMENTED / VERIFIED | Ubuntu 24.04.5, kernel 6.8.0-146, clang 18.1.3, libbpf 1.3.0, bpftool 7.4.0, bpftrace 0.20.2, BTF, tracefs, debugfs, BPF filesystem, and BPF LSM were verified. |
| Live filesystem telemetry | ✅ IMPLEMENTED / VERIFIED | `measurement/file_activity.bt` uses bpftrace-backed kernel tracepoints. |
| Python live monitor | ✅ IMPLEMENTED / VERIFIED | `shield` parses events, maintains windows, extracts features, classifies states, and renders the dashboard. |
| Configuration | ✅ IMPLEMENTED | `config/detector.json` contains measured references and prototype parameters. |
| Unique-file tracking | ✅ IMPLEMENTED | Larger path sets are maintained in userspace, not indefinitely in BPF maps. |
| Persistence detection | ✅ IMPLEMENTED | Broad transformation must persist for three consecutive windows for HIGH RISK. |
| Safe simulator | ✅ IMPLEMENTED / VERIFIED | Uses only `/tmp/ebpf_shield_lab`. |
| Benign measurements | ✅ IMPLEMENTED / VERIFIED | Required workload measurements are stored under `experiments/`. |
| Explainable alerts | ✅ IMPLEMENTED / VERIFIED | Live values and evidence are shown for each state. |
| Existing BPF LSM hook | ✅ IMPLEMENTED / VERIFIED | `src/shield.bpf.c` contains an audit-only process-execution hook. |
| Final enforcement | 🔵 FUTURE | Nothing is blocked or killed. |
| Final libbpf/CO-RE detector | 🔵 FUTURE | The live filesystem path currently uses bpftrace plus Python. |

Important: the live filesystem detector is **bpftrace telemetry plus Python analysis**. The existing BPF LSM source/object is a separate audit-hook demonstration and is not the live filesystem detector loader.

---

## 4. Actual project structure

```text
ebpf-lsm-shield/
├── config/
│   └── detector.json
├── measurement/
│   ├── collector.py
│   ├── file_activity.bt
│   ├── summarize.py
│   └── workloads.py
├── experiments/
│   ├── measurement_comparison.csv
│   ├── measurement_comparison_primary.csv
│   ├── measurement_distributions.csv
│   └── measurement_windows.csv
├── src/
│   ├── shield.bpf.c
│   ├── shield.bpf.o
│   └── vmlinux.h
├── shield
├── simulator.py
└── README_REVIEW2.md
```

### Important files

- **`shield`** — executable Python live monitor. It starts bpftrace, parses events, calculates features, classifies states, and renders the dashboard.
- **`measurement/file_activity.bt`** — current bpftrace telemetry probe.
- **`measurement/collector.py`** — measurement collector that writes structured JSONL and CSV observations.
- **`measurement/workloads.py`** — controlled idle, editing, archive, copy, Git, compile, backup-like, and file-creation workloads.
- **`measurement/summarize.py`** — calculates median, standard deviation, P95, P99, and MAD for available measurements.
- **`config/detector.json`** — window, persistence, measured references, and prototype parameters.
- **`simulator.py`** — isolated deterministic laboratory workload; it is not ransomware.
- **`src/shield.bpf.c`** — existing `lsm/bprm_check_security` process-execution hook.
- **`src/vmlinux.h`** — kernel type definitions for the existing BPF source.
- **`src/shield.bpf.o`** — existing compiled BPF object; the current dashboard does not load it.
- **`experiments/*.csv`** — measured windows and summaries from the VM.

Python `__pycache__` files may appear after execution and are runtime artifacts.

---

## 5. How the current system works

### Kernel telemetry

`measurement/file_activity.bt` emits records shaped like:

```text
EV  <timestamp>  <pid>  <process>  <operation>  <path>
```

The actual separator is a tab. Rename events contain old and new path fields. A `TICK` record is emitted every two seconds.

### File descriptor association

For an open:

```text
PID 1234 opens /tmp/example.txt
        ↓
openat returns FD 7
        ↓
(PID 1234, FD 7) → /tmp/example.txt
        ↓
PID 1234 writes to FD 7
        ↓
write event is associated with /tmp/example.txt
        ↓
close removes the mapping
```

The kernel-side state is deliberately small. Python stores the larger unique-path sets.

### Current identity handling and window aggregation (Phase 1)

The measurement and live-monitor paths resolve absolute paths to a bounded
file identity of `(device, inode, generation)`. `generation` is obtained with
`FS_IOC_GETVERSION` when the filesystem and permissions support it. When it is
not available, the identity is explicitly marked as an unknown-generation
identity and the path is used as a bounded fallback. This fallback is reported
in structured output through `identity_fallbacks`.

**File-Centric Aggregation:**
Window aggregation in `shield` and `measurement/collector.py` is keyed by
file identity `(device, inode, generation)` rather than `(pid, idx)`.
A window represents "what happened to this file during the time slice," with
the set of PIDs operating on that file tracked as an attribute.

**Multi-Process Evasion Defense (Minerva):**
To defeat cooperating multi-process ransomware that splits file operations
across multiple processes to stay under per-process thresholds, the detector
tracks:
- `distinct_process_count`: count of unique PIDs operating on each file;
- `max_processes_per_file`: highest PID count on any file in the window;
- `multi_process_modified_files_count`: count of files modified by $> 1$ distinct processes; and
- `total_distinct_processes`: total cooperating PIDs observed in the window.

Filesystem operations across multiple cooperating processes are aggregated into the
same time window, ensuring multi-process attacks cannot evade detection.

---

## 6. Events currently monitored

Only events present in `measurement/file_activity.bt` are listed here.

| Event | Meaning | Why it matters |
|---|---|---|
| `openat`, `openat2` | Open a path | Establish path and file-descriptor association. |
| `write` | Successful write through a descriptor | Indicates content modification and reports returned bytes. Failed/zero-byte writes are excluded. |
| `pwrite64`, `writev`, `pwritev`, `pwritev2` | Successful positional/vector writes | Counted in the write family and report returned bytes. |
| `copy_file_range` | Successful kernel-assisted copy | Captures copy/backup destinations and reports returned bytes. |
| `truncate`, `ftruncate`, `fallocate` | Successful file-size/allocation operations | Tracked separately; they do not increment write-operation or byte counters. |
| `rename`, `renameat`, `renameat2` | Successful rename | Failed rename attempts are excluded. |
| `unlink`, `unlinkat` | Successful removal of a directory entry | Failed deletion attempts are excluded. |
| `close` | Close a descriptor | Removes the descriptor mapping. |
| Two-second interval | Window timer | Finalizes windows; it is not a filesystem operation. |

Entropy is not implemented.

---

## 7. Behavioral features

| Feature | Meaning | Use |
|---|---|---|
| Unique files opened | Distinct opened paths | Access breadth. |
| Unique files written | Distinct paths associated with writes | Separates many-file writing from repeated writes. |
| Unique files modified | Distinct modified paths | Main breadth feature. |
| Unique files renamed | Distinct old/new rename paths | Rename breadth. |
| Unique files deleted | Distinct deleted paths | Delete breadth. |
| Writes/sec | Writes divided by two seconds | Write intensity. |
| Bytes written/sec | Successful returned write bytes divided by two seconds | Volume of data changed, distinct from write-operation count. |
| Modified files/sec | Unique modified paths divided by two seconds | Modification breadth over time. |
| Writes/modified file | Writes divided by modified paths | Repeated editing versus one-pass transformation. |
| Write/open ratio | Writes divided by opens | Operation relationship. |
| Rename/write ratio | Renames divided by writes | Transformation relationship. |
| Directory breadth | Distinct parent directories | Directory coverage. |
| File-type diversity | Distinct extensions | Cross-type coverage. |
| Suspicious streak | Consecutive broad-transformation windows | Persistence evidence. |

The dashboard renders zero for an undefined ratio; the structured collector records unavailable ratios as null.

---

## 8. Current detection logic

High activity alone is not HIGH RISK. The current high-risk concept is:

```text
BROAD FILE COVERAGE
+
TRANSFORMATION EVIDENCE
+
PERSISTENCE
```

Transformation evidence means:

```text
rapid rename activity
AND
rename/write ratio meets the configured prototype parameter
```

The indicators calculated by `shield` are:

- **Broad file coverage** — unique modified paths are at least `broad_modified_minimum`, currently 20.
- **High write rate** — writes/sec reach the configured fraction of the measured write reference.
- **Rapid rename activity** — at least `rename_minimum`, currently 1, renamed path is observed.
- **Rename/write transformation relationship** — ratio reaches `rename_write_ratio_minimum`, currently 0.50.
- **Broad file-type coverage** — at least `type_diversity_minimum`, currently 3, file types are observed.

The exact current classifier is:

```text
transformation = rapid_rename AND rename_write_relationship

if broad_file_coverage AND transformation
   AND suspicious_streak >= confirmation_windows:
       HIGH RISK
elif broad_file_coverage AND transformation:
       SUSPICIOUS
elif broad_file_coverage AND indicator_count >= suspicious_indicator_minimum:
       SUSPICIOUS
else:
       LOW / BENIGN
```

The streak resets when broad transformation evidence is absent. The current persistence value is three windows.

`high_risk_indicator_minimum` and `broad_modified_fraction_of_reference` exist in configuration, but the current classifier uses the explicit broad-plus-transformation-plus-streak rule for HIGH RISK. Do not describe unused or secondary configuration fields as universal thresholds.

### Beginner pseudocode

```text
Every two seconds:
    collect events for each process
    calculate unique files, rates, ratios, breadth, and types

    broad = modified files >= configured minimum
    rapid_rename = renamed paths >= configured minimum
    relationship = rename/write ratio >= configured minimum
    transformation = rapid_rename AND relationship

    if broad AND transformation:
        streak += 1
    else:
        streak = 0

    if broad AND transformation AND streak >= 3:
        HIGH RISK
    elif suspicious behavior exists:
        SUSPICIOUS
    else:
        LOW / BENIGN
```

---

## 9. Why we rejected a simple threshold

The first prototype alerted when a PID opened more than a fixed number of files in a short period. Legitimate services exceeded that number, and a benign file-creation test opened 20 files and generated an alert.

The project therefore moved from:

```text
single syscall threshold
        ↓
false positives
        ↓
measure real benign activity
        ↓
combine file breadth, transformation behavior, and persistence
```

This is why a process modifying many files is not automatically considered malicious.

---

## 10. Measured benign workloads

The VM measurements included idle, editing, archive extraction, large copy, Git checkout, compilation, backup-like activity, and high-volume creation.

Primary-process median comparison:

| Workload | Windows | Unique modified | Modified/sec | Writes/sec | Writes/modified | Rename/write |
|---|---:|---:|---:|---:|---:|---:|
| Idle | 3 | 0 | 0.0 | 0.0 | unavailable | unavailable |
| Editing | 11 | 1 | 0.5 | 11.0 | 24.0 | 0.000 |
| Archive extraction | 7 | 121 | 60.5 | 68.0 | 1.252 | 0.000 |
| Large copy | 6 | 80.5 | 40.25 | 40.25 | 1.000 | 0.000 |
| Git checkout | 9 | 10 | 5.0 | 5.0 | 1.287 | 0.000 in primary-process summary |
| Compilation | 6 | 13.5 | 6.75 | 6.75 | 1.000 | 0.000 |
| Backup-like | 6 | 80.5 | 40.25 | 40.25 | 1.000 | 0.000 |
| High-volume creation | 7 | 85 | 42.5 | 42.5 | 1.000 | 0.000 |

The detailed per-process data includes child Git processes and reports a Git rename/write P95 of approximately `0.429`.

Important observations:

- archive extraction reached approximately 60.5 modified files/sec;
- large copy reached approximately 40.25 modified files/sec;
- backup-like activity reached approximately 40.25 modified files/sec;
- high-volume creation reached approximately 42.5 modified files/sec;
- editing touched few files but had many writes per modified file; and
- high modified-files/sec alone is not enough.

These values came from this VM and this workload set. They are not universal Linux or ransomware thresholds. `measurement_distributions.csv` contains median, standard deviation, P95, P99, and MAD where values were available. The dataset is prototype-scale.

---

## 11. Current configuration

File: `config/detector.json`

### Measured baseline references

| Field | Value | Meaning |
|---|---:|---|
| `source` | measured VM benign workload distributions, 2026-10-07 | Provenance. |
| `modified_files_per_second_p95_high_activity` | 121.0 | Measured high-activity modified-files/sec P95 reference. |
| `writes_per_second_p95_high_activity` | 151.5 | Measured high-activity writes/sec P95 reference. |
| `rename_write_ratio_p95_git` | 0.4286 | Measured Git rename/write P95 reference. |

### Prototype engineering parameters

| Field | Value | Meaning |
|---|---:|---|
| `window_seconds` | 2 | Observation window. |
| `confirmation_windows` | 3 | Required persistent windows. |
| `mode` | audit | No enforcement. |
| `broad_modified_fraction_of_reference` | 0.75 | Prototype value retained for future baseline-relative work. |
| `broad_modified_minimum` | 20 | Explicit broad-coverage minimum currently used. |
| `high_write_fraction_of_reference` | 0.75 | Prototype high-write indicator fraction. |
| `rename_minimum` | 1 | Rapid-rename minimum. |
| `rename_write_ratio_minimum` | 0.50 | Transformation ratio minimum. |
| `type_diversity_minimum` | 3 | File-type breadth minimum. |
| `suspicious_indicator_minimum` | 2 | Indicator count for broad suspicious classification. |
| `high_risk_indicator_minimum` | 3 | Present in config; not a separate current HIGH RISK gate. |

Measured references and engineering parameters must not be confused. These settings make the demo reproducible; they are not universal thresholds.

---

## 12. Safe simulator

`simulator.py` is a deterministic laboratory workload, not real ransomware.

It uses only:

```text
/tmp/ebpf_shield_lab
```

It creates 150 dummy files across six extensions, reads them, reverses bytes and adds a marker, rewrites them, rapidly renames them, repeats the pattern in three batches, and removes only its own lab directory.

It never encrypts real files, deletes user files, accesses the home directory, or touches data outside the lab. It exists to produce a repeatable ransomware-like filesystem pattern for a safe demonstration.

---

## 13. Live demonstration

### Terminal 1

```bash
cd /home/vboxuser/ebpf-lsm-shield
sudo ./shield
```

### Terminal 2

```bash
cd /home/vboxuser/ebpf-lsm-shield
python3 simulator.py
```

Expected flow:

```text
Monitor starts
    ↓
Simulator creates isolated lab
    ↓
SUSPICIOUS
    ↓
SUSPICIOUS
    ↓
HIGH RISK
    ↓
SECURITY ALERT
```

The dashboard displays PID, process, timestamp, two-second statistics, evidence, state transition, streak, and:

```text
POLICY: AUDIT-ONLY — NO BLOCKING
```

### Benign copy demonstration

Terminal 1:

```bash
cd /home/vboxuser/ebpf-lsm-shield
sudo ./shield
```

Terminal 2:

```bash
cd /home/vboxuser/ebpf-lsm-shield
python3 measurement/workloads.py copy
```

The copy test produced approximately 161 modified files at 80.5 modified files/sec and remained LOW / BENIGN. This shows the intended distinction between high legitimate activity and high activity plus transformation and persistence. It does not prove zero false positives generally.

---

## 14. What BPF LSM does now

The layers are different:

- **Tracepoint telemetry** observes filesystem activity.
- **Python analysis** extracts features and classifies behavior.
- **BPF LSM** provides a Linux security-policy hook.

The existing `src/shield.bpf.c` contains:

```c
SEC("lsm/bprm_check_security")
int BPF_PROG(shield_exec_monitor, struct linux_binprm *bprm)
```

It reads the execution filename, prints a kernel debug message, and returns `0`. Returning `0` allows the operation.

Current architecture:

```text
observe → analyze → alert
```

Not current:

```text
observe → block process
```

The live filesystem detector does not currently use BPF LSM to block file operations.

---

## 15. Future / not yet implemented

- **libbpf/CO-RE migration** — replace the live bpftrace path with a compiled libbpf loader.
- **BPF ring buffer** — send typed compact events instead of parsing bpftrace text.
- **Inode-based identity** — track files robustly across renames and aliases.
- **Entropy analysis** — add content evidence if it can be measured safely and efficiently.
- **Stronger process-tree tracking** — associate child processes more completely.
- **Adaptive/per-process baselines** — compare a process with its own normal behavior.
- **Improved risk scoring** — validate a stronger statistical model.
- **Larger evaluation dataset** — repeat labeled workloads across more runs and environments.
- **Statistical evaluation** — calculate prototype TP/TN/FP/FN, precision, recall, F1, and false-positive rate on a larger dataset.
- **Actual BPF LSM enforcement** — add carefully gated policy decisions after audit validation.
- **Quarantine/blocking response** — add a safe response mechanism.

---

## 16. Current limitations

- Live telemetry uses bpftrace and text parsing.
- The live path is not yet a typed libbpf ring buffer.
- File identity is path-based, not inode-based.
- Entropy is absent.
- The simulator is deterministic and limited.
- Detector values are prototype engineering parameters.
- Measurements come from one VM and a controlled workload set.
- The detector is not a universal ransomware classifier.
- BPF LSM is audit-only.
- No process is blocked or killed.
- System-wide observation can show ordinary system processes.
- Temporary-directory cleanup can generate delete events.

---

## 17. Explanation for a presentation

### Project explanation in 30 seconds

> eBPF LSM Shield is a Linux kernel-level behavioral detection prototype. It uses eBPF tracepoint telemetry to observe filesystem activity, groups events into two-second windows, extracts features such as unique files modified, write rate, and rename behavior, and combines these signals to identify suspicious transformation patterns. A safe simulator demonstrates ransomware-like behavior only inside an isolated temporary directory, while legitimate high-volume workloads were measured to avoid simple-threshold false positives. The current BPF LSM component is audit-only, so it reports execution activity but does not block processes. libbpf/CO-RE migration and enforcement are future work.

### Questions a professor may ask

**What exactly did you build?**  
A measurement-backed prototype that observes per-process filesystem activity and produces explainable three-state alerts.

**Where does eBPF come in?**  
The bpftrace program uses eBPF-backed kernel tracepoints for open, write, copy, rename, unlink, and close activity.

**Where does LSM come in?**  
The project contains a BPF LSM process-execution hook. It is audit-only and returns `0`.

**How do you detect ransomware?**  
The prototype looks for broad file coverage plus write/rename transformation evidence persisting across three windows.

**Why not hardcode one threshold?**  
Legitimate services and workloads exceeded simple open/write thresholds. We measured benign behavior and combined multiple signals.

**Why two seconds?**  
It is a short, visible burst window chosen for this prototype, not a universal optimum.

**Why three windows?**  
A one-window burst can be legitimate. Three is the current reproducible engineering parameter.

**How do you identify a file?**  
The probe maps `(PID, file descriptor)` to an opened path and associates later writes with that path. Rename/unlink paths are observed directly. Inode identity is future work.

**Can it block ransomware?**  
Not currently. The project observes and alerts only.

**What if a legitimate program modifies 1000 files?**  
That alone is not HIGH RISK. Transformation evidence and persistence are also required, though broader testing remains future work.

---

## 18. Things teammates should not say

| Do not say | Correct statement |
|---|---|
| “It uses AI.” | No AI model is implemented; the current rules are explainable prototype logic. |
| “It has 100% accuracy.” | The dataset is prototype-scale and no universal accuracy claim is valid. |
| “It blocks ransomware.” | It observes and alerts; BPF LSM is audit-only. |
| “The simulator is real ransomware.” | It is deterministic, non-encrypting laboratory behavior. |
| “Thresholds are universal.” | Values are measured references and prototype parameters for this VM. |
| “libbpf/CO-RE is implemented.” | The live filesystem path currently uses bpftrace and Python. |
| “High modified-files/sec means ransomware.” | High activity can be legitimate; combined transformation and persistence matter. |
| “The LSM hook monitors all filesystem writes.” | The current LSM hook monitors process execution; bpftrace observes filesystem activity. |

---

## 19. Quick commands

```bash
# Start live detector
cd /home/vboxuser/ebpf-lsm-shield
sudo ./shield

# Start safe simulator
cd /home/vboxuser/ebpf-lsm-shield
python3 simulator.py

# Run benign copy
cd /home/vboxuser/ebpf-lsm-shield
python3 measurement/workloads.py copy

# Stop
Ctrl+C

# Check simulator cleanup
test -e /tmp/ebpf_shield_lab && echo PRESENT || echo CLEAN

# Check environment
uname -a
clang --version
bpftrace --version
bpftool version
pkg-config --modversion libbpf
cat /sys/kernel/security/lsm
stat /sys/kernel/btf/vmlinux
```

For structured collection:

```bash
cd /home/vboxuser/ebpf-lsm-shield
SUDO_PASSWORD=toor python3 measurement/collector.py \
  --workload copy \
  --output-dir experiments/results \
  -- python3 measurement/workloads.py copy
```

No pip dependency is required by the current scripts; they use Python's standard library.

---

## 20. Troubleshooting

### `sudo` asks for a password

The monitor needs privileges to attach bpftrace:

```bash
sudo ./shield
```

The current collector demonstration uses `SUDO_PASSWORD=toor`; do not commit passwords to source files.

### bpftrace does not start

```bash
cd /home/vboxuser/ebpf-lsm-shield
sudo bpftrace measurement/file_activity.bt
```

The probe should print `READY`.

### Check BPF LSM

```bash
cat /sys/kernel/security/lsm
```

The verified VM output includes `bpf`.

### Simulator does not trigger detection

1. Start `sudo ./shield` first.
2. Run both commands from `/home/vboxuser/ebpf-lsm-shield`.
3. Confirm the probe prints `READY`.
4. Remove only a stale lab directory:

```bash
rm -rf /tmp/ebpf_shield_lab
```

### No HIGH RISK alert appears

The current classifier requires broad transformation evidence for three consecutive windows. A copy or archive workload may modify many files without producing the required rename/write relationship.

---

## 21. Final project status

| Area | Status |
|---|---|
| Verified Ubuntu/eBPF environment | ✅ IMPLEMENTED / VERIFIED |
| eBPF tracepoint telemetry | ✅ IMPLEMENTED / VERIFIED |
| Filesystem monitoring | ✅ IMPLEMENTED / VERIFIED |
| Userspace feature extraction | ✅ IMPLEMENTED / VERIFIED |
| Two-second windows | ✅ IMPLEMENTED / VERIFIED |
| Baseline measurements | ✅ IMPLEMENTED / VERIFIED, prototype-scale |
| Behavioral detector | 🟡 PROTOTYPE / UNDER DEVELOPMENT |
| Explainable live alerting | ✅ IMPLEMENTED / VERIFIED |
| Safe simulator | ✅ IMPLEMENTED / VERIFIED |
| BPF LSM execution hook | ✅ IMPLEMENTED / VERIFIED, audit-only |
| File-centric identity & aggregation (Phase 1) | ✅ IMPLEMENTED / VERIFIED |
| Telemetry completeness (Phase 2) | ✅ IMPLEMENTED / VERIFIED |
| Entropy mismatch (Phase 3) | 🔵 FUTURE |
| Decoy files / canaries (Phase 4) | 🔵 FUTURE |
| Multi-tier time windows (Phase 5) | 🔵 FUTURE |
| Formal evaluation harness (Phase 6) | 🔵 FUTURE |
| libbpf/LSM live detection & enforcement (Phase 7) | 🔵 FUTURE |
| Self-defense / tamper resistance (Phase 8) | 🔵 FUTURE |

This README describes the current verified VM implementation. It separates implemented behavior, verified behavior, prototype parameters, and future work. The current end-to-end path is:

```text
real kernel telemetry
    ↓
file-centric two-second observations (with cooperating PID tracking)
    ↓
userspace feature extraction
    ↓
explainable state
    ↓
live audit alert
```

It does not yet prove universal ransomware detection or automatic prevention.
