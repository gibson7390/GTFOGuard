import time
from gtfoguard.models import ProcessSnapshot, DetectionResult
from gtfoguard.detectors.path_rules import TRUSTED_PREFIXES, SUSPICIOUS_PREFIXES


def _has_hidden_segment(path: str) -> bool:
    return any(segment.startswith(".") and segment not in (".", "..")
              for segment in path.split("/"))


class PathAnomalyDetector:
    def detect(self, snapshots: list[ProcessSnapshot]) -> list[DetectionResult]:
        results = []
        detection_time = time.time()
        for snapshot in snapshots:
            exe = snapshot.exe
            if not exe:
                continue
            if exe.startswith(TRUSTED_PREFIXES):
                continue
            for prefix in SUSPICIOUS_PREFIXES:
                if exe.startswith(prefix):
                    results.append(
                        DetectionResult(
                            snapshot=snapshot,
                            matched_name=prefix,
                            detection_type="path_anomaly",
                            timestamp=detection_time,
                        )
                    )
                    break
        return results
