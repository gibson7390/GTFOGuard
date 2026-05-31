TRUSTED_PREFIXES: tuple[str, ...] = (
    "/bin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/usr/local/bin/",
    "/nix/store/",
)

SUSPICIOUS_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)
