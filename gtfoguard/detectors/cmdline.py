import time
from gtfoguard.models import ProcessSnapshot, DetectionResult, DetectionType


_TOKEN_PATTERNS: list[tuple[str, set[str], list[str]]] = [
    ("bash -c",       {"bash"},                                      ["-c"]),
    ("sh -c",         {"sh", "dash", "ash"},                         ["-c"]),
    ("python -c",     {"python", "python2", "python3"},              ["-c"]),
    ("perl -e",       {"perl"},                                      ["-e"]),
    ("ruby -e",       {"ruby"},                                      ["-e"]),
    ("php -r",        {"php"},                                       ["-r"]),
    ("lua -e",        {"lua"},                                       ["-e"]),
    ("node -e",       {"node"},                                      ["-e"]),
    ("find -exec",    {"find"},                                      ["-exec"]),
    ("find -execdir", {"find"},                                      ["-execdir"]),
    ("openssl",       {"openssl"},                                   ["enc", "s_client"]),
    ("vim -c",        {"vim", "vi", "view", "rvim", "rview", "vimdiff"}, ["-c"]),
    ("env -i",        {"env"},                                       ["-i"]),
    ("xargs -I",      {"xargs"},                                     ["-I"]),
]

_FRAGMENT_PATTERNS: list[tuple[str, set[str], list[str]]] = [
    ("awk system",            {"awk", "gawk", "mawk", "nawk"}, ["system("]),
    ("awk exec",              {"awk", "gawk", "mawk", "nawk"}, ["exec("]),
    ("nmap --script",         {"nmap"},                        ["--script"]),
    ("tar -checkpoint-action", {"tar"},                        ["--checkpoint-action"]),
    ("socat exec",            {"socat"},                       ["EXEC:"]),
]

_PIPE_PATTERNS: list[tuple[str, set[str]]] = [
    ("curl pipe", {"curl"}),
    ("wget pipe", {"wget"}),
]

_PIPE_SHELLS: frozenset[str] = frozenset({"sh", "bash", "dash", "ash", "zsh"})


def _has_exact_token(cmdline: list[str], tokens: list[str]) -> bool:
    return any(token in cmdline for token in tokens)


def _has_fragment_in_arg(cmdline: list[str], fragments: list[str]) -> bool:
    return any(fragment in arg for arg in cmdline for fragment in fragments)


def _is_pipe_to_shell(cmdline: list[str]) -> bool:
    return "|" in cmdline and any(shell in cmdline for shell in _PIPE_SHELLS)


class CommandLineDetector:
    def detect(self, snapshots: list[ProcessSnapshot]) -> list[DetectionResult]:
        results = []
        detection_time = time.time()
        for snapshot in snapshots:
            if not snapshot.cmdline:
                continue
            label = self._match(snapshot.name, snapshot.cmdline)
            if label is not None:
                results.append(
                    DetectionResult(
                        snapshot=snapshot,
                        matched_name=label,
                        detection_type=DetectionType.CMDLINE_PATTERN_MATCH,
                        timestamp=detection_time,
                    )
                )
        return results

    def _match(self, binary: str, cmdline: list[str]) -> str | None:
        for label, binaries, tokens in _TOKEN_PATTERNS:
            if binary in binaries and _has_exact_token(cmdline, tokens):
                return label
        for label, binaries, fragments in _FRAGMENT_PATTERNS:
            if binary in binaries and _has_fragment_in_arg(cmdline, fragments):
                return label
        for label, binaries in _PIPE_PATTERNS:
            if binary in binaries and _is_pipe_to_shell(cmdline):
                return label
        return None
