import time
from gtfoguard.models import ProcessSnapshot, DetectionResult
from gtfoguard.detectors.catalog import GTFOBINS_CATALOG


class GTFOBinsDetector:
    def detect(self, snapshots: list[ProcessSnapshot]) -> list[DetectionResult]:
        results = []
        detection_time = time.time()
        for snapshot in snapshots:
            if snapshot.name in GTFOBINS_CATALOG:
                results.append(
                    DetectionResult(
                        snapshot=snapshot,
                        matched_name=snapshot.name,
                        detection_type="gtfobins_name_match",
                        timestamp=detection_time,
                    )
                )
        return results
