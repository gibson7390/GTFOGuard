# GTFOGuard

GTFOGuard is a terminal-based behavioral security scanner for Linux. It takes a
point-in-time snapshot of running processes and flags
[GTFOBins](https://gtfobins.github.io/)-style abuse and Living-Off-The-Land
(LOTL) behavior — shell escapes, inline code execution, suspicious binary
locations, anomalous process ancestry, and network activity from
commonly-abused tools. Every finding is scored and accompanied by a plain-language
explanation of *why* it was flagged.

GTFOGuard performs **read-only detection**. It does not kill processes, modify
the system, or send data anywhere.

## Installation

Requirements:

- Linux
- Python 3.11+

Install runtime dependencies:

```bash
pip install -r requirements.txt
```

For development (adds the test framework):

```bash
pip install -r requirements-dev.txt
```

## Usage

Run a scan of the current process table:

```bash
python -m gtfoguard
```

For the most complete results — including network activity from other users'
processes — run with elevated privileges:

```bash
sudo python -m gtfoguard
```

Without root, GTFOGuard still scans every process it can see, but network
connection enumeration for processes owned by other users is unavailable.

## Example Output

When suspicious activity is found, GTFOGuard prints a ranked table (highest
score first):

```
                     GTFOGuard — 2 detection(s)
┏━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━┓
┃  PID ┃ User   ┃ Binary ┃ Detection Type        ┃ Severity ┃ Score ┃ Explanation  ┃
┡━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━┩
│ 1337 │ root   │ bash   │ cmdline_pattern_match │   HIGH   │     8 │ 'bash -c' …  │
│ 2048 │ www    │ nc     │ network_activity      │  MEDIUM  │     5 │ active conn… │
└──────┴────────┴────────┴───────────────────────┴──────────┴───────┴──────────────┘
```

When nothing is flagged:

```
No suspicious activity detected.
```

## Detector Overview

GTFOGuard runs five independent detectors against each process snapshot:

| Detector | Detection type | Severity | What it flags |
|----------|----------------|----------|---------------|
| GTFOBins name match | `gtfobins_name_match` | LOW | Binary name appears in the GTFOBins catalog (informational, no arguments confirmed) |
| Command-line pattern | `cmdline_pattern_match` | HIGH / MEDIUM | Known shell-escape or code-execution argument patterns (e.g. `bash -c`, `python -c`, `find -exec`) |
| Path anomaly | `path_anomaly` | MEDIUM | Executable running from a world-writable staging location (e.g. `/tmp`, `/dev/shm`) |
| Process ancestry | `ancestry_anomaly` | HIGH | A service/daemon spawning a shell child (common post-exploitation pattern) |
| Network activity | `network_activity` | MEDIUM | A commonly-abused tool (e.g. `nc`, `socat`) with an active network connection |

Findings are passed to a risk scorer that assigns a severity, a numeric score,
and a human-readable reason.

## Validation

GTFOGuard ships with two test layers:

- **Unit tests** (`tests/`) — 37 tests covering detection types, the risk
  scorer, all five detectors, the engine, and command-line matching regressions.
- **Operational validation harness** (`validation/`) — 10 controlled LOTL
  scenarios (6 positive, 4 negative). Positive scenarios confirm each detector
  fires at the expected severity/score; negative scenarios confirm benign
  activity produces no actionable (MEDIUM/HIGH) finding.

Run them:

```bash
python -m pytest        # unit tests
python -m validation    # operational validation harness
```

Both suites pass (37/37 unit tests; 10/10 validation scenarios).

## Limitations

- **Point-in-time scan, not a daemon.** GTFOGuard takes a single snapshot and
  exits. It does not continuously monitor or correlate events over time.
- **Behavioral heuristics, not ground truth.** Detections indicate
  *suspicious patterns*, not confirmed compromise. Triage every finding.
- **Privilege-dependent visibility.** Without root, some process metadata and
  network connections owned by other users are not visible.
- **Name-based GTFOBins matches are noisy by design.** The `gtfobins_name_match`
  detector flags any catalog binary by name (LOW severity) regardless of how it
  is used; benign use of tools like `bash` or `curl` will produce LOW findings.
- **Linux only.**

## License

Released under the [MIT License](LICENSE).
