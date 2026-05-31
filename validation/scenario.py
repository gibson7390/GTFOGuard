from dataclasses import dataclass, field
from gtfoguard.models import ProcessSnapshot


def snapshot(
    pid: int,
    name: str,
    exe: str,
    cmdline: list[str],
    ppid: int = 1,
) -> ProcessSnapshot:
    return ProcessSnapshot(
        pid=pid,
        ppid=ppid,
        name=name,
        exe=exe,
        cmdline=cmdline,
        username="user",
        create_time=0.0,
        status="running",
    )


@dataclass(frozen=True)
class ExpectedFinding:
    detector: str
    severity: str
    score: int


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    kind: str
    snapshots: list[ProcessSnapshot]
    expected: list[ExpectedFinding] = field(default_factory=list)
    connected_pids: frozenset[int] = frozenset()
