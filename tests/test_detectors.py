from gtfoguard.models import DetectionType
from gtfoguard.detectors.gtfobins import GTFOBinsDetector
from gtfoguard.detectors.cmdline import CommandLineDetector
from gtfoguard.detectors.path import PathAnomalyDetector
from gtfoguard.detectors.ancestry import AncestryDetector
from gtfoguard.detectors.network import NetworkDetector


def test_gtfobins_matches_catalog_binary(make_snapshot):
    snapshot = make_snapshot(name="python", exe="/usr/bin/python")
    results = GTFOBinsDetector().detect([snapshot])
    assert len(results) == 1
    assert results[0].matched_name == "python"
    assert results[0].detection_type == DetectionType.GTFOBINS_NAME_MATCH


def test_gtfobins_ignores_unknown_binary(make_snapshot):
    snapshot = make_snapshot(name="my_custom_app_xyz")
    assert GTFOBinsDetector().detect([snapshot]) == []


def test_cmdline_detects_bash_dash_c(make_snapshot):
    snapshot = make_snapshot(name="bash", cmdline=["bash", "-c", "id"])
    results = CommandLineDetector().detect([snapshot])
    assert len(results) == 1
    assert results[0].matched_name == "bash -c"
    assert results[0].detection_type == DetectionType.CMDLINE_PATTERN_MATCH


def test_cmdline_ignores_benign_invocation(make_snapshot):
    snapshot = make_snapshot(name="bash", cmdline=["bash", "deploy_script.sh"])
    assert CommandLineDetector().detect([snapshot]) == []


def test_cmdline_skips_empty_cmdline(make_snapshot):
    snapshot = make_snapshot(name="bash", cmdline=[])
    assert CommandLineDetector().detect([snapshot]) == []


def test_path_flags_suspicious_prefix(make_snapshot):
    snapshot = make_snapshot(name="evil", exe="/tmp/evil")
    results = PathAnomalyDetector().detect([snapshot])
    assert len(results) == 1
    assert results[0].matched_name == "/tmp/"
    assert results[0].detection_type == DetectionType.PATH_ANOMALY


def test_path_ignores_trusted_prefix(make_snapshot):
    snapshot = make_snapshot(name="python", exe="/usr/bin/python")
    assert PathAnomalyDetector().detect([snapshot]) == []


def test_path_skips_empty_exe(make_snapshot):
    snapshot = make_snapshot(name="x", exe="")
    assert PathAnomalyDetector().detect([snapshot]) == []


def test_ancestry_flags_suspicious_parent_child(make_snapshot):
    parent = make_snapshot(pid=100, name="apache2")
    child = make_snapshot(pid=200, ppid=100, name="sh")
    results = AncestryDetector().detect([parent, child])
    assert len(results) == 1
    assert results[0].matched_name == "apache2 -> sh"
    assert results[0].detection_type == DetectionType.ANCESTRY_ANOMALY


def test_ancestry_ignores_benign_parent_child(make_snapshot):
    parent = make_snapshot(pid=100, name="bash")
    child = make_snapshot(pid=200, ppid=100, name="ls")
    assert AncestryDetector().detect([parent, child]) == []


def test_network_flags_suspicious_connected_process(make_snapshot):
    snapshot = make_snapshot(pid=4242, name="nc")
    detector = NetworkDetector(connection_pids_provider=lambda: {4242})
    results = detector.detect([snapshot])
    assert len(results) == 1
    assert results[0].matched_name == "nc"
    assert results[0].detection_type == DetectionType.NETWORK_ACTIVITY


def test_network_ignores_unconnected_process(make_snapshot):
    snapshot = make_snapshot(pid=4242, name="nc")
    detector = NetworkDetector(connection_pids_provider=lambda: set())
    assert detector.detect([snapshot]) == []


def test_network_ignores_connected_but_benign_name(make_snapshot):
    snapshot = make_snapshot(pid=4242, name="firefox")
    detector = NetworkDetector(connection_pids_provider=lambda: {4242})
    assert detector.detect([snapshot]) == []
