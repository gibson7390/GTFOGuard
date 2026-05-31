from gtfoguard.models import DetectionType


EXPECTED_MEMBERS = {
    "GTFOBINS_NAME_MATCH": "gtfobins_name_match",
    "CMDLINE_PATTERN_MATCH": "cmdline_pattern_match",
    "PATH_ANOMALY": "path_anomaly",
    "ANCESTRY_ANOMALY": "ancestry_anomaly",
    "NETWORK_ACTIVITY": "network_activity",
}


def test_all_enum_members_exist():
    actual = {member.name: member.value for member in DetectionType}
    assert actual == EXPECTED_MEMBERS


def test_exactly_five_members():
    assert len(list(DetectionType)) == 5


def test_backward_compat_equals_string():
    assert DetectionType.PATH_ANOMALY == "path_anomaly"
    assert DetectionType.GTFOBINS_NAME_MATCH == "gtfobins_name_match"


def test_backward_compat_is_str_instance():
    for member in DetectionType:
        assert isinstance(member, str)


def test_backward_compat_str_renders_value():
    assert str(DetectionType.NETWORK_ACTIVITY) == "network_activity"


def test_lookup_by_value_returns_member():
    assert DetectionType("cmdline_pattern_match") is DetectionType.CMDLINE_PATTERN_MATCH
