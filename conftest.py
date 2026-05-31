import pytest
from gtfoguard.models import ProcessSnapshot


def _make_snapshot(
    pid=1000,
    ppid=1,
    name="proc",
    exe="/usr/bin/proc",
    cmdline=None,
    username="user",
    create_time=0.0,
    status="running",
):
    return ProcessSnapshot(
        pid=pid,
        ppid=ppid,
        name=name,
        exe=exe,
        cmdline=cmdline if cmdline is not None else [name],
        username=username,
        create_time=create_time,
        status=status,
    )


@pytest.fixture
def make_snapshot():
    return _make_snapshot
