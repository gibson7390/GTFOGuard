from __future__ import annotations
from dataclasses import dataclass


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
    detection_type: str
    timestamp: float


@dataclass(frozen=True)
class RiskScore:
    detection: DetectionResult
    severity: str
    score: int
    reason: str
