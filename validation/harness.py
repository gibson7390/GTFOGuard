from collections import Counter
from dataclasses import dataclass, field

from gtfoguard.detectors.gtfobins import GTFOBinsDetector
from gtfoguard.detectors.cmdline import CommandLineDetector
from gtfoguard.detectors.path import PathAnomalyDetector
from gtfoguard.detectors.ancestry import AncestryDetector
from gtfoguard.detectors.network import NetworkDetector
from gtfoguard.intelligence.scoring import RiskScorer
from validation.scenario import Scenario, ExpectedFinding


ACTIONABLE_SEVERITIES: frozenset[str] = frozenset({"MEDIUM", "HIGH"})


@dataclass(frozen=True)
class ActualFinding:
    detector: str
    severity: str
    score: int
    detection_type: str
    matched_name: str


@dataclass
class ScenarioResult:
    scenario: Scenario
    actual: list[ActualFinding]
    actionable: list[ActualFinding]
    informational: list[ActualFinding]
    false_negatives: list[ExpectedFinding]
    false_positives: list[ActualFinding]
    passed: bool


def _run_detectors(scenario: Scenario) -> list[tuple[str, object]]:
    connected = set(scenario.connected_pids)
    detectors = [
        ("GTFOBinsDetector", GTFOBinsDetector()),
        ("CommandLineDetector", CommandLineDetector()),
        ("PathAnomalyDetector", PathAnomalyDetector()),
        ("AncestryDetector", AncestryDetector()),
        ("NetworkDetector", NetworkDetector(connection_pids_provider=lambda: connected)),
    ]
    pairs = []
    for name, detector in detectors:
        for detection in detector.detect(scenario.snapshots):
            pairs.append((name, detection))
    return pairs


def run_scenario(scenario: Scenario) -> ScenarioResult:
    pairs = _run_detectors(scenario)
    scores = RiskScorer().score([detection for _, detection in pairs])

    actual = [
        ActualFinding(
            detector=name,
            severity=score.severity,
            score=score.score,
            detection_type=str(score.detection.detection_type),
            matched_name=score.detection.matched_name,
        )
        for (name, _), score in zip(pairs, scores)
    ]

    actionable = [f for f in actual if f.severity in ACTIONABLE_SEVERITIES]
    informational = [f for f in actual if f.severity not in ACTIONABLE_SEVERITIES]

    expected_counts = Counter((e.detector, e.severity, e.score) for e in scenario.expected)
    actual_counts = Counter((f.detector, f.severity, f.score) for f in actionable)

    false_negatives = [
        ExpectedFinding(*key)
        for key, count in (expected_counts - actual_counts).items()
        for _ in range(count)
    ]
    missing_keys = expected_counts - actual_counts
    unexpected_keys = actual_counts - expected_counts
    false_positives = [f for f in actionable if (f.detector, f.severity, f.score) in unexpected_keys]

    passed = not missing_keys and not unexpected_keys

    return ScenarioResult(
        scenario=scenario,
        actual=actual,
        actionable=actionable,
        informational=informational,
        false_negatives=false_negatives,
        false_positives=false_positives,
        passed=passed,
    )


def run_all(scenarios: list[Scenario]) -> list[ScenarioResult]:
    return [run_scenario(scenario) for scenario in scenarios]
