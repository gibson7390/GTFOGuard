import time
import psutil
from gtfoguard.models import ProcessSnapshot, DetectionResult
from gtfoguard.detectors.network_rules import NETWORK_SUSPICIOUS_NAMES


def _active_connection_pids() -> set[int]:
    pids = set()
    try:
        for connection in psutil.net_connections(kind="inet"):
            if connection.pid is not None:
                pids.add(connection.pid)
    except (psutil.AccessDenied, PermissionError):
        pass
    return pids


class NetworkDetector:
    def __init__(self, connection_pids_provider=_active_connection_pids) -> None:
        self._connection_pids_provider = connection_pids_provider

    def detect(self, snapshots: list[ProcessSnapshot]) -> list[DetectionResult]:
        results = []
        detection_time = time.time()
        connected_pids = self._connection_pids_provider()
        for snapshot in snapshots:
            if snapshot.pid in connected_pids and snapshot.name in NETWORK_SUSPICIOUS_NAMES:
                results.append(
                    DetectionResult(
                        snapshot=snapshot,
                        matched_name=snapshot.name,
                        detection_type="network_activity",
                        timestamp=detection_time,
                    )
                )
        return results
