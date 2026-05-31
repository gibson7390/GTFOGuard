from typing import Callable
from gtfoguard.models import DetectionResult, DetectionType, RiskScore


_HIGH_CMDLINE_PATTERNS: set[str] = {
    "bash -c",
    "sh -c",
    "python -c",
    "perl -e",
    "ruby -e",
    "php -r",
    "find -exec",
    "find -execdir",
    "awk system",
    "awk exec",
    "curl pipe",
    "wget pipe",
    "socat exec",
    "nmap --script",
    "tar -checkpoint-action",
}

_MEDIUM_CMDLINE_PATTERNS: set[str] = {
    "vim -c",
    "node -e",
    "lua -e",
    "env -i",
    "xargs -I",
    "openssl",
}


def _score_gtfobins(detection: DetectionResult) -> tuple[str, int, str]:
    return (
        "LOW",
        3,
        "Binary name matches GTFOBins catalog — no suspicious arguments confirmed",
    )


def _score_cmdline(detection: DetectionResult) -> tuple[str, int, str]:
    pattern = detection.matched_name
    if pattern in _HIGH_CMDLINE_PATTERNS:
        return (
            "HIGH",
            8,
            f"Command-line pattern '{pattern}' is a known GTFOBins shell escape or code execution technique",
        )
    if pattern in _MEDIUM_CMDLINE_PATTERNS:
        return (
            "MEDIUM",
            5,
            f"Command-line pattern '{pattern}' can be used for privilege escalation or file access",
        )
    return (
        "MEDIUM",
        5,
        f"Command-line pattern '{pattern}' matched a suspicious execution pattern",
    )


def _score_path_anomaly(detection: DetectionResult) -> tuple[str, int, str]:
    location = detection.matched_name
    return (
        "MEDIUM",
        6,
        f"Executable runs from suspicious location '{location}' — a world-writable path commonly used to stage malware",
    )


def _score_ancestry(detection: DetectionResult) -> tuple[str, int, str]:
    relationship = detection.matched_name
    return (
        "HIGH",
        8,
        f"Suspicious process ancestry '{relationship}' — a service or daemon spawning this child is a common post-exploitation pattern",
    )


def _score_network(detection: DetectionResult) -> tuple[str, int, str]:
    name = detection.matched_name
    return (
        "MEDIUM",
        5,
        f"Suspicious executable '{name}' currently has an active network connection",
    )


_SEVERITY_MAP: dict[DetectionType, Callable[[DetectionResult], tuple[str, int, str]]] = {
    DetectionType.GTFOBINS_NAME_MATCH: _score_gtfobins,
    DetectionType.CMDLINE_PATTERN_MATCH: _score_cmdline,
    DetectionType.PATH_ANOMALY: _score_path_anomaly,
    DetectionType.ANCESTRY_ANOMALY: _score_ancestry,
    DetectionType.NETWORK_ACTIVITY: _score_network,
}


class RiskScorer:
    def score(self, detections: list[DetectionResult]) -> list[RiskScore]:
        results = []
        for detection in detections:
            severity, numeric_score, reason = self._evaluate(detection)
            results.append(
                RiskScore(
                    detection=detection,
                    severity=severity,
                    score=numeric_score,
                    reason=reason,
                )
            )
        return results

    def _evaluate(self, detection: DetectionResult) -> tuple[str, int, str]:
        handler = _SEVERITY_MAP.get(detection.detection_type)
        if handler is None:
            return (
                "LOW",
                2,
                f"Unknown detection type '{detection.detection_type}'",
            )
        return handler(detection)
