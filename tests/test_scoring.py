import pytest
from gtfoguard.models import DetectionResult, DetectionType
from gtfoguard.intelligence.scoring import RiskScorer


@pytest.fixture
def score(make_snapshot):
    def _score(matched_name, detection_type):
        detection = DetectionResult(make_snapshot(), matched_name, detection_type, 0.0)
        return RiskScorer().score([detection])[0]

    return _score


def test_gtfobins_scores_low(score):
    result = score("python", DetectionType.GTFOBINS_NAME_MATCH)
    assert (result.severity, result.score) == ("LOW", 3)


def test_cmdline_high_pattern_scores_high(score):
    result = score("bash -c", DetectionType.CMDLINE_PATTERN_MATCH)
    assert (result.severity, result.score) == ("HIGH", 8)


def test_cmdline_medium_pattern_scores_medium(score):
    result = score("vim -c", DetectionType.CMDLINE_PATTERN_MATCH)
    assert (result.severity, result.score) == ("MEDIUM", 5)
    assert "privilege escalation" in result.reason


def test_cmdline_unlisted_pattern_uses_default_branch(score):
    result = score("some-unlisted-pattern", DetectionType.CMDLINE_PATTERN_MATCH)
    assert (result.severity, result.score) == ("MEDIUM", 5)
    assert "matched a suspicious execution pattern" in result.reason


def test_path_anomaly_scores_medium(score):
    result = score("/tmp/", DetectionType.PATH_ANOMALY)
    assert (result.severity, result.score) == ("MEDIUM", 6)


def test_ancestry_scores_high(score):
    result = score("apache2 -> sh", DetectionType.ANCESTRY_ANOMALY)
    assert (result.severity, result.score) == ("HIGH", 8)


def test_network_scores_medium(score):
    result = score("nc", DetectionType.NETWORK_ACTIVITY)
    assert (result.severity, result.score) == ("MEDIUM", 5)


def test_unknown_type_falls_back_to_low(score):
    result = score("whatever", "totally_unknown_type")
    assert (result.severity, result.score) == ("LOW", 2)
    assert "Unknown detection type" in result.reason


def test_scorer_preserves_detection_count(make_snapshot):
    detections = [
        DetectionResult(make_snapshot(), "python", DetectionType.GTFOBINS_NAME_MATCH, 0.0),
        DetectionResult(make_snapshot(), "bash -c", DetectionType.CMDLINE_PATTERN_MATCH, 0.0),
    ]
    scored = RiskScorer().score(detections)
    assert len(scored) == 2
