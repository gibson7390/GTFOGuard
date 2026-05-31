from gtfoguard.engine import Engine
from gtfoguard.models import RiskScore, DetectionType
from gtfoguard.detectors.gtfobins import GTFOBinsDetector
from gtfoguard.detectors.cmdline import CommandLineDetector
from gtfoguard.detectors.path import PathAnomalyDetector
from gtfoguard.detectors.ancestry import AncestryDetector
from gtfoguard.detectors.network import NetworkDetector


EXPECTED_ORDER = [
    GTFOBinsDetector,
    CommandLineDetector,
    PathAnomalyDetector,
    AncestryDetector,
    NetworkDetector,
]


def _disable_live_network(engine):
    for detector in engine.detectors:
        if isinstance(detector, NetworkDetector):
            detector._connection_pids_provider = lambda: set()


def test_detector_execution_order():
    engine = Engine()
    assert [type(detector) for detector in engine.detectors] == EXPECTED_ORDER


def test_engine_run_returns_riskscores(make_snapshot):
    engine = Engine()
    _disable_live_network(engine)
    engine.collector.collect = lambda: [
        make_snapshot(pid=100, name="apache2", exe="/usr/sbin/apache2"),
        make_snapshot(pid=200, ppid=100, name="sh", exe="/usr/bin/sh", cmdline=["sh", "-c", "id"]),
    ]
    scored = engine.run()
    assert isinstance(scored, list)
    assert len(scored) >= 1
    assert all(isinstance(item, RiskScore) for item in scored)


def test_detector_output_reaches_scorer(make_snapshot):
    engine = Engine()
    _disable_live_network(engine)
    engine.collector.collect = lambda: [
        make_snapshot(pid=200, ppid=100, name="sh", exe="/usr/bin/sh", cmdline=["sh", "-c", "id"]),
    ]
    scored = engine.run()
    produced_types = {item.detection.detection_type for item in scored}
    assert DetectionType.CMDLINE_PATTERN_MATCH in produced_types


def test_engine_run_with_no_findings_returns_empty(make_snapshot):
    engine = Engine()
    _disable_live_network(engine)
    engine.collector.collect = lambda: [
        make_snapshot(pid=300, name="my_benign_app_xyz", exe="/usr/bin/my_benign_app_xyz", cmdline=["my_benign_app_xyz"]),
    ]
    assert engine.run() == []
