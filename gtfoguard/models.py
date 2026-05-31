from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable


class DetectionType(StrEnum):
    GTFOBINS_NAME_MATCH = "gtfobins_name_match"
    CMDLINE_PATTERN_MATCH = "cmdline_pattern_match"
    PATH_ANOMALY = "path_anomaly"
    ANCESTRY_ANOMALY = "ancestry_anomaly"
    NETWORK_ACTIVITY = "network_activity"


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: list[str]
    username: str
    create_time: float
    status: str


@dataclass(frozen=True)
class DetectionResult:
    snapshot: ProcessSnapshot
    matched_name: str
    detection_type: DetectionType
    timestamp: float


@dataclass(frozen=True)
class RiskScore:
    detection: DetectionResult
    severity: str
    score: int
    reason: str


@runtime_checkable
class Detector(Protocol):
    def detect(self, snapshots: list[ProcessSnapshot]) -> list[DetectionResult]:
        ...
