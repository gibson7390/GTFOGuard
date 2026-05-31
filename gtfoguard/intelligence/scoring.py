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

_SEVERITY_MAP: dict[DetectionType, tuple[str, int, str]] = {
    DetectionType.GTFOBINS_NAME_MATCH: (
        "LOW",
        3,
        "Binary name matches GTFOBins catalog — no suspicious arguments confirmed",
    ),
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
        if detection.detection_type == DetectionType.GTFOBINS_NAME_MATCH:
            return (
                "LOW",
                3,
                "Binary name matches GTFOBins catalog — no suspicious arguments confirmed",
            )

        if detection.detection_type == DetectionType.CMDLINE_PATTERN_MATCH:
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

        if detection.detection_type == DetectionType.PATH_ANOMALY:
            location = detection.matched_name
            return (
                "MEDIUM",
                6,
                f"Executable runs from suspicious location '{location}' — a world-writable path commonly used to stage malware",
            )

        if detection.detection_type == DetectionType.ANCESTRY_ANOMALY:
            relationship = detection.matched_name
            return (
                "HIGH",
                8,
                f"Suspicious process ancestry '{relationship}' — a service or daemon spawning this child is a common post-exploitation pattern",
            )

        if detection.detection_type == DetectionType.NETWORK_ACTIVITY:
            name = detection.matched_name
            return (
                "MEDIUM",
                5,
                f"Suspicious executable '{name}' currently has an active network connection",
            )

        return (
            "LOW",
            2,
            f"Unknown detection type '{detection.detection_type}'",
        )
