from dataclasses import dataclass, field


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
