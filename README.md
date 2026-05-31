# GTFOGuard

GTFOGuard is a point-in-time behavioral posture scanner for Linux. It takes a
single snapshot of the running process table and flags
[GTFOBins](https://gtfobins.github.io/)-style abuse and Living-Off-the-Land
(LOTL) behavior: shell escapes, inline code execution, binaries running from
world-writable staging paths, anomalous process ancestry, and network activity
from commonly-abused tools.

Every finding is assigned a severity, a numeric score, and a plain-language
explanation of *why* it was flagged, so an analyst can triage results without
reverse-engineering the tool's logic.

GTFOGuard performs **read-only detection**. It does not kill or modify
processes, change system state, install hooks, or transmit data anywhere.

> **GTFOGuard is not an EDR.** It does not monitor continuously, correlate
> events over time, or catch short-lived processes that start and exit between
> scans. It is a triage and posture-assessment tool that answers one question:
> *"At this instant, what on this host looks like LOTL abuse?"* See
> [Known Limitations](#known-limitations) before relying on it operationally.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Architecture Overview](#architecture-overview)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Example Output](#example-output)
7. [Detector Descriptions](#detector-descriptions)
8. [Validation Results](#validation-results)
9. [Known Limitations](#known-limitations)
10. [Security Philosophy](#security-philosophy)
11. [Roadmap](#roadmap)
12. [License](#license)

---

## Project Overview

Attackers frequently avoid dropping custom malware and instead abuse binaries
that already ship with the operating system — `bash`, `python`, `find`, `tar`,
`nc`, `awk`, and dozens more. Used with the right arguments, these trusted tools
provide shell escapes, arbitrary code execution, file read/write primitives, and
network exfiltration. The [GTFOBins](https://gtfobins.github.io/) project
catalogs these techniques.

GTFOGuard inspects the current process table for the *behavioral signatures* of
this abuse. Rather than matching file hashes, it looks at how trusted binaries
are actually being invoked and where they are running from. The result is a
ranked, explainable list of suspicious processes intended to accelerate human
triage — not to replace it.

GTFOGuard is built for security practitioners: incident responders doing
point-in-time host triage, blue teamers validating detections, CTF and lab
exercises, and engineers who want a transparent, auditable, dependency-light
posture check they can read end-to-end in a few minutes.

## Features

- **Five independent behavioral detectors** covering GTFOBins name matches,
  command-line abuse patterns, path anomalies, process ancestry, and network
  activity.
- **Explainable risk scoring.** Each finding carries a `HIGH` / `MEDIUM` / `LOW`
  severity, a numeric score, and a human-readable reason.
- **Informational vs. actionable distinction.** Low-confidence, name-only
  matches are explicitly scored `LOW` so they never masquerade as confirmed
  abuse (see [Security Philosophy](#security-philosophy)).
- **Ranked terminal output.** Findings are sorted highest-score-first in a
  [Rich](https://github.com/Textualize/rich) table for fast scanning.
- **Read-only and side-effect-free.** No process termination, no system
  modification, no network egress, no telemetry.
- **Minimal dependency surface.** Two runtime dependencies (`psutil`, `rich`).
- **Tested.** 37 automated unit tests and a 10-scenario operational validation
  harness, all passing.

## Architecture Overview

GTFOGuard is a linear, single-pass pipeline. Each stage has one responsibility
and a narrow interface, which keeps the detectors independent and the data flow
easy to audit.

```
ProcessCollector  →  Detectors (×5)  →  RiskScorer  →  Rich Terminal UI
   (psutil)            (heuristics)      (severity)      (ranked table)
```

| Stage | Responsibility |
|-------|----------------|
| **ProcessCollector** | Enumerates the process table via `psutil` and produces an immutable `ProcessSnapshot` per process (pid, ppid, name, exe, cmdline, username, create_time, status). Inaccessible or vanished processes are skipped, not faked. |
| **Detectors** | Five independent detectors each consume the full snapshot list and emit `DetectionResult` records. Detectors share a common `Detector` protocol and hold no cross-detector state. |
| **RiskScorer** | Maps each `DetectionResult` to a `RiskScore` (severity, numeric score, reason) via a per-detection-type scoring table. |
| **Terminal UI** | Renders scored findings as a ranked table, or prints a clean "no findings" message. |

Detection rules and data are deliberately separated from detection logic
(`detectors/catalog.py`, `detectors/*_rules.py`), so the catalog and heuristics
can be reviewed and extended without touching control flow.

## Installation

**Requirements:**

- Linux
- Python 3.11 or newer

GTFOGuard relies on Python 3.11 language features (e.g. `StrEnum`) and will not
run on older interpreters.

**Install runtime dependencies:**

```bash
pip install -r requirements.txt
```

**For development** (adds the test framework):

```bash
pip install -r requirements-dev.txt
```

Runtime dependencies are limited to `psutil` (process and connection
enumeration) and `rich` (terminal rendering).

## Usage

Scan the current process table:

```bash
python -m gtfoguard
```

For the most complete results — including network connections owned by other
users' processes — run with elevated privileges:

```bash
sudo python -m gtfoguard
```

### Linux & root permission considerations

GTFOGuard sees only what the operating system lets the invoking user see:

- **As an unprivileged user**, it scans every process visible to that user.
  Metadata (`exe`, `cmdline`) for processes owned by other users may be
  restricted, and the kernel will not attribute network connections owned by
  other users to their PIDs. Those network findings are simply **absent** — not
  reported as safe.
- **As root**, process metadata and network-connection-to-PID attribution are
  far more complete, which materially improves the network and path detectors.

Because reduced visibility silently shrinks what can be detected, treat an
unprivileged scan as a partial view. For host triage, run as root.

## Example Output

When suspicious activity is found, GTFOGuard prints a ranked table, highest
score first:

```
                          GTFOGuard — 3 detection(s)
┏━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  PID ┃ User ┃ Binary ┃ Detection Type        ┃ Severity ┃ Score ┃ Explanation                  ┃
┡━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1337 │ root │ bash   │ cmdline_pattern_match │   HIGH   │     8 │ Command-line pattern 'bash   │
│      │      │        │                       │          │       │ -c' is a known GTFOBins      │
│      │      │        │                       │          │       │ shell escape or code         │
│      │      │        │                       │          │       │ execution technique          │
│ 4290 │ www  │ python │ ancestry_anomaly      │   HIGH   │     8 │ Suspicious process ancestry  │
│      │      │        │                       │          │       │ 'nginx -> python' — a        │
│      │      │        │                       │          │       │ service or daemon spawning   │
│      │      │        │                       │          │       │ this child is a common       │
│      │      │        │                       │          │       │ post-exploitation pattern    │
│ 2048 │ www  │ nc     │ network_activity      │  MEDIUM  │     5 │ Suspicious executable 'nc'   │
│      │      │        │                       │          │       │ currently has an active      │
│      │      │        │                       │          │       │ network connection           │
└──────┴──────┴────────┴───────────────────────┴──────────┴───────┴──────────────────────────────┘
```

When nothing is flagged:

```
No suspicious activity detected.
```

## Detector Descriptions

GTFOGuard runs five independent detectors against every process snapshot. Each
finding is scored by detection type.

### 1. GTFOBins name match — `gtfobins_name_match` · LOW (score 3)

Flags any process whose binary name appears in the bundled GTFOBins catalog
(206 entries). This detector **does not inspect arguments** — a match means only
that a commonly-abusable binary is present. It is deliberately **informational**
and noisy by design: a routine `bash`, `curl`, or `find` will match. Use it as
context, not as evidence of compromise.

### 2. Command-line pattern match — `cmdline_pattern_match` · HIGH / MEDIUM

The primary high-confidence detector. It inspects argument vectors for known
abuse patterns using three matching modes to avoid naïve substring false
positives:

- **Exact token** — e.g. `bash -c`, `sh -c`, `python -c`, `perl -e`, `ruby -e`,
  `php -r`, `find -exec` / `-execdir`, `vim -c`, `env -i`, `xargs -I`.
- **Argument fragment** — e.g. `awk 'system(...)'`, `nmap --script`,
  `tar --checkpoint-action`, `socat EXEC:`.
- **Pipe-to-shell** — e.g. `curl … | sh`, `wget … | bash`.

Patterns mapping to direct code execution or shell escape are scored **HIGH
(8)** (e.g. `bash -c`, `python -c`, `find -exec`, `curl pipe`, `socat exec`,
`nmap --script`, `tar -checkpoint-action`). Patterns more often associated with
file access or privilege manipulation are scored **MEDIUM (5)** (e.g. `vim -c`,
`node -e`, `lua -e`, `env -i`, `xargs -I`, `openssl`).

### 3. Path anomaly — `path_anomaly` · MEDIUM (score 6)

Flags executables running from world-writable staging locations
(`/tmp/`, `/var/tmp/`, `/dev/shm/`) while explicitly trusting standard system
locations (`/bin/`, `/usr/bin/`, `/usr/sbin/`, `/sbin/`, `/usr/local/bin/`, and
`/nix/store/`). Running from a writable temp path is a common malware staging
behavior, though it also occurs with legitimate build and installer tooling.

### 4. Process ancestry — `ancestry_anomaly` · HIGH (score 8)

Flags parent→child relationships that are characteristic of post-exploitation —
for example a web server (`nginx`, `apache2`, `httpd`) or scheduler (`cron`)
spawning a shell or interpreter, or `sshd` spawning `find`. Ancestry is resolved
within the snapshot using each process's reported parent PID.

### 5. Network activity — `network_activity` · MEDIUM (score 5)

Flags processes that (a) have an active inbound/outbound `inet` connection and
(b) are commonly-abused networking or scripting tools (`nc`, `netcat`, `ncat`,
`socat`, `python`, `python3`, `perl`, `ruby`, `bash`, `sh`). Connection
attribution depends on privilege level; see
[permission considerations](#linux--root-permission-considerations).

## Validation Results

GTFOGuard ships with two complementary test layers.

- **Unit tests** (`tests/`) — **37 tests** covering the detection-type model,
  the risk scorer, all five detectors, the engine pipeline, and command-line
  matching regressions.
- **Operational validation harness** (`validation/`) — **10 controlled LOTL
  scenarios** (6 positive, 4 negative). Positive scenarios confirm each detector
  fires at the expected severity and score; negative scenarios confirm that
  benign activity produces **no actionable (MEDIUM/HIGH) finding**, measuring
  false positives and false negatives directly.

Run them:

```bash
python -m pytest        # unit tests
python -m validation    # operational validation harness
```

Current status: **37/37 unit tests passing** and **10/10 validation scenarios
passing**, with 0 actionable false positives and 0 false negatives across the
scenario set.

These results characterize behavior against the bundled synthetic scenarios.
They demonstrate that the implemented heuristics behave as specified — they are
not a measure of real-world detection rates against live adversaries.

## Known Limitations

GTFOGuard is intentionally narrow. Understand these limitations before relying
on it.

- **Point-in-time, not continuous.** GTFOGuard captures one snapshot and exits.
  It is **not an EDR** and does not monitor, hook, or correlate over time.
- **Short-lived processes are missed.** Many real LOTL payloads (e.g. a
  `bash -c` reverse shell) execute in milliseconds. If such a process is not
  alive at the moment of the scan, GTFOGuard cannot see it. This is the single
  most important limitation: GTFOGuard is best at finding *persistent or
  long-running* abuse, not transient execution.
- **Heuristics, not ground truth.** Findings indicate *suspicious patterns*, not
  confirmed compromise. Every finding requires human triage.
- **Privilege-dependent visibility.** Without root, some process metadata and
  cross-user network attribution are unavailable, and the corresponding findings
  are silently absent rather than reported.
- **Name-based GTFOBins matches are noisy by design.** `gtfobins_name_match`
  flags catalog binaries by name regardless of usage; expect benign `LOW`
  findings for everyday tools.
- **Ancestry resolves within the snapshot only.** Re-parented processes (e.g.
  adopted by PID 1 after the real parent exits) lose the ancestry signal.
- **No cross-detector correlation.** Detectors run independently; GTFOGuard does
  not currently combine weak signals across detectors into a single
  higher-confidence verdict.
- **Detection is signature/heuristic-bounded.** An attacker aware of these rules
  can stage outside the watched paths, rename binaries, or use patterns not in
  the catalog to evade detection.
- **Linux only.**

## Security Philosophy

**Read-only by design.** GTFOGuard observes; it never acts. It does not kill
processes, modify the system, or send data off-host. This keeps it safe to run
during an active incident and makes its behavior trivial to audit.

**Honest about confidence.** Findings are separated into *informational* and
*actionable* tiers, and the tool does not pretend a weak signal is a strong one:

- **Informational (`LOW`)** — context worth knowing, but not on its own evidence
  of abuse. The `gtfobins_name_match` detector lives here: a binary that *can* be
  abused is present, but nothing about its usage is confirmed.
- **Actionable (`MEDIUM` / `HIGH`)** — a specific suspicious behavior was
  observed (an abuse argument pattern, a write-path execution, an anomalous
  parent/child relationship, or active network use by an abusable tool). These
  warrant triage.

The validation harness measures the tool against this contract directly:
benign activity must not generate actionable findings.

**Fail visible, not silent-safe.** Where the operating system withholds
visibility (e.g. network attribution without root), GTFOGuard omits the finding
rather than asserting the host is clean. Absence of a finding is not proof of
absence of abuse — interpret results with the privilege level in mind.

**Triage aid, not an oracle.** GTFOGuard exists to make a human analyst faster
and better-informed. It is not a decision-maker and should not be the only
control on a host.

## Roadmap

Planned and candidate work, roughly in priority order. Items are aspirational
and subject to change.

**Near-term (v1.1)**

- Command-line flags: `--help`, `--version`, `--json`, `--min-severity`.
- Machine-readable JSON output for automation and log pipelines.
- Non-zero exit code when actionable findings are present, so scheduled scans
  can drive alerting.
- A surfaced warning when running without root (degraded visibility).
- Packaging: `pyproject.toml`, a `gtfoguard` console entry point, a pinned
  dependency set, and CI running both test layers.

**Later**

- Detection tuning: corroborating signals to reduce `gtfobins_name_match` and
  network-detector noise.
- Cross-detector correlation to combine weak signals into higher-confidence
  findings.
- Optional repeated-sampling mode to narrow (not close) the short-lived-process
  gap, while remaining explicitly distinct from a continuous EDR.

## License

Released under the [MIT License](LICENSE).
