from gtfoguard.collectors.process import ProcessCollector
from gtfoguard.detectors.gtfobins import GTFOBinsDetector
from gtfoguard.detectors.cmdline import CommandLineDetector
from gtfoguard.detectors.path import PathAnomalyDetector
from gtfoguard.detectors.ancestry import AncestryDetector
from gtfoguard.detectors.network import NetworkDetector
from gtfoguard.intelligence.scoring import RiskScorer
from gtfoguard.models import DetectionResult, RiskScore, Detector


class Engine:
    def __init__(self) -> None:
        self.collector = ProcessCollector()
        self.detectors: list[Detector] = [
            GTFOBinsDetector(),
            CommandLineDetector(),
            PathAnomalyDetector(),
            AncestryDetector(),
            NetworkDetector(),
        ]
        self.scorer = RiskScorer()

    def run(self) -> list[RiskScore]:
        snapshots = self.collector.collect()
        detections: list[DetectionResult] = []
        for detector in self.detectors:
            detections.extend(detector.detect(snapshots))
        return self.scorer.score(detections)
