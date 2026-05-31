SUSPICIOUS_PARENT_CHILD: dict[str, frozenset[str]] = {
    "apache2": frozenset({"sh", "bash", "python", "python3"}),
    "httpd": frozenset({"sh", "bash", "python", "python3"}),
    "nginx": frozenset({"sh", "bash", "python", "python3"}),
    "cron": frozenset({"curl", "wget", "sh", "bash"}),
    "crond": frozenset({"curl", "wget", "sh", "bash"}),
    "curl": frozenset({"sh", "bash"}),
    "wget": frozenset({"sh", "bash"}),
    "sshd": frozenset({"find"}),
}
