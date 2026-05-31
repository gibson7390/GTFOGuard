from validation.scenario import Scenario, ExpectedFinding, snapshot


POSITIVE_SCENARIOS: list[Scenario] = [
    Scenario(
        name="bash -c",
        description="Shell spawned with an inline command string (classic LOTL execution)",
        kind="positive",
        snapshots=[snapshot(1001, "bash", "/usr/bin/bash", ["bash", "-c", "id"])],
        expected=[ExpectedFinding("CommandLineDetector", "HIGH", 8)],
    ),
    Scenario(
        name="python -c",
        description="Python one-liner executing inline code",
        kind="positive",
        snapshots=[snapshot(1002, "python", "/usr/bin/python", ["python", "-c", "import os; os.system('id')"])],
        expected=[ExpectedFinding("CommandLineDetector", "HIGH", 8)],
    ),
    Scenario(
        name="find -exec",
        description="find used to execute a command via -exec (GTFOBins technique)",
        kind="positive",
        snapshots=[snapshot(1003, "find", "/usr/bin/find", ["find", "/", "-exec", "sh", ";"])],
        expected=[ExpectedFinding("CommandLineDetector", "HIGH", 8)],
    ),
    Scenario(
        name="suspicious /tmp execution",
        description="Unknown binary executing from a world-writable staging directory",
        kind="positive",
        snapshots=[snapshot(1004, "stage0_payload", "/tmp/stage0_payload", ["/tmp/stage0_payload"])],
        expected=[ExpectedFinding("PathAnomalyDetector", "MEDIUM", 6)],
    ),
    Scenario(
        name="apache2 -> sh ancestry",
        description="Web server spawning a shell child (post-exploitation pattern)",
        kind="positive",
        snapshots=[
            snapshot(1005, "apache2", "/usr/sbin/apache2", ["/usr/sbin/apache2", "-k", "start"]),
            snapshot(1006, "sh", "/usr/bin/sh", ["sh"], ppid=1005),
        ],
        expected=[ExpectedFinding("AncestryDetector", "HIGH", 8)],
    ),
    Scenario(
        name="nc network activity",
        description="netcat listener with an active network connection",
        kind="positive",
        snapshots=[snapshot(1007, "nc", "/usr/bin/nc", ["nc", "-lvnp", "4444"])],
        expected=[ExpectedFinding("NetworkDetector", "MEDIUM", 5)],
        connected_pids=frozenset({1007}),
    ),
]


NEGATIVE_SCENARIOS: list[Scenario] = [
    Scenario(
        name="normal bash shell",
        description="Interactive bash shell with no inline command",
        kind="negative",
        snapshots=[snapshot(2001, "bash", "/usr/bin/bash", ["bash"])],
        expected=[],
    ),
    Scenario(
        name="normal python execution",
        description="Python running a script file normally",
        kind="negative",
        snapshots=[snapshot(2002, "python", "/usr/bin/python", ["python", "app.py"])],
        expected=[],
    ),
    Scenario(
        name="benign curl download",
        description="curl downloading a file with no shell pipe",
        kind="negative",
        snapshots=[snapshot(2003, "curl", "/usr/bin/curl", ["curl", "-O", "https://example.com/archive.tar.gz"])],
        expected=[],
    ),
    Scenario(
        name="benign file operations",
        description="cat reading a normal configuration file",
        kind="negative",
        snapshots=[snapshot(2004, "cat", "/usr/bin/cat", ["cat", "/etc/hostname"])],
        expected=[],
    ),
]


VALIDATION_SCENARIOS: list[Scenario] = POSITIVE_SCENARIOS + NEGATIVE_SCENARIOS
