import time
from gtfoguard.models import ProcessSnapshot, DetectionResult, DetectionType
from gtfoguard.detectors.ancestry_rules import SUSPICIOUS_PARENT_CHILD


class AncestryDetector:
    def detect(self, snapshots: list[ProcessSnapshot]) -> list[DetectionResult]:
        results = []
        detection_time = time.time()
        name_by_pid = {snapshot.pid: snapshot.name for snapshot in snapshots}
        for snapshot in snapshots:
            parent_name = name_by_pid.get(snapshot.ppid)
            if parent_name is None:
                continue
            suspicious_children = SUSPICIOUS_PARENT_CHILD.get(parent_name)
            if suspicious_children and snapshot.name in suspicious_children:
                results.append(
                    DetectionResult(
                        snapshot=snapshot,
                        matched_name=f"{parent_name} -> {snapshot.name}",
                        detection_type=DetectionType.ANCESTRY_ANOMALY,
                        timestamp=detection_time,
                    )
                )
        return results
