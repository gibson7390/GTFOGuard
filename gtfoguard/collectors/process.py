import psutil
from gtfoguard.models import ProcessSnapshot


class ProcessCollector:
    def collect(self) -> list[ProcessSnapshot]:
        snapshots = []
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "status"]
        ):
            try:
                info = proc.info
                snapshots.append(
                    ProcessSnapshot(
                        pid=info["pid"],
                        ppid=info["ppid"] or 0,
                        name=info["name"] or "",
                        exe=info["exe"] or "",
                        cmdline=info["cmdline"] or [],
                        username=info["username"] or "",
                        create_time=info["create_time"] or 0.0,
                        status=info["status"] or "",
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return snapshots
