import time
from gtfoguard.models import ProcessSnapshot, DetectionResult, DetectionType


_PATTERNS: list[tuple[str, set[str], list[str]]] = [
    # (pattern_label, binary_names, suspicious_args)
    ("bash -c",       {"bash"},                      ["-c"]),
    ("sh -c",         {"sh", "dash", "ash"},         ["-c"]),
    ("python -c",     {"python", "python2", "python3"}, ["-c"]),
    ("perl -e",       {"perl"},                      ["-e"]),
    ("ruby -e",       {"ruby"},                      ["-e"]),
    ("php -r",        {"php"},                       ["-r"]),
    ("lua -e",        {"lua"},                       ["-e"]),
    ("node -e",       {"node"},                      ["-e"]),
    ("find -exec",    {"find"},                      ["-exec"]),
    ("find -execdir", {"find"},                      ["-execdir"]),
    ("awk system",    {"awk", "gawk", "mawk", "nawk"}, ["system("]),
    ("awk exec",      {"awk", "gawk", "mawk", "nawk"}, ["exec("]),
    ("nmap --script", {"nmap"},                      ["--script"]),
    ("curl pipe",     {"curl"},                      ["|", "sh", "bash"]),
    ("wget pipe",     {"wget"},                      ["|", "sh", "bash"]),
    ("tar -checkpoint-action", {"tar"},              ["--checkpoint-action"]),
    ("socat exec",    {"socat"},                     ["EXEC:"]),
    ("openssl",       {"openssl"},                   ["enc", "s_client"]),
    ("vim -c",        {"vim", "vi", "view", "rvim", "rview", "vimdiff"}, ["-c"]),
    ("env -i",        {"env"},                       ["-i"]),
    ("xargs -I",      {"xargs"},                     ["-I"]),
]


def _cmdline_contains(cmdline: list[str], args: list[str]) -> bool:
    joined = " ".join(cmdline)
    return any(arg in cmdline or arg in joined for arg in args)


class CommandLineDetector:
    def detect(self, snapshots: list[ProcessSnapshot]) -> list[DetectionResult]:
        results = []
        detection_time = time.time()
        for snapshot in snapshots:
            if not snapshot.cmdline:
                continue
            binary = snapshot.name
            for pattern_label, binary_names, suspicious_args in _PATTERNS:
                if binary not in binary_names:
                    continue
                if _cmdline_contains(snapshot.cmdline, suspicious_args):
                    results.append(
                        DetectionResult(
                            snapshot=snapshot,
                            matched_name=pattern_label,
                            detection_type=DetectionType.CMDLINE_PATTERN_MATCH,
                            timestamp=detection_time,
                        )
                    )
                    break
        return results
