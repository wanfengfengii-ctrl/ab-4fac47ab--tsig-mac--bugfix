"""Runtime configuration sourced from environment variables."""
from __future__ import annotations

import os


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


class Config:
    # Storage
    DB_PATH = os.environ.get("DB_PATH", "/data/dns.db")

    # HTTP
    API_PORT = _int("API_PORT", 8080)
    API_HOST = os.environ.get("API_HOST", "0.0.0.0")

    # DNS
    DNS_PORT = _int("DNS_PORT", 53)
    DNS_HOST = os.environ.get("DNS_HOST", "0.0.0.0")

    # Instance identity (used to attribute transfer references)
    INSTANCE_ID = os.environ.get("INSTANCE_ID", f"instance-{os.getpid()}")

    # Limits (overridable for tests; defaults are the enforced production policy)
    MAX_RECORDS_PER_ZONE = _int("MAX_RECORDS_PER_ZONE", 10000)
    MAX_CHANGES_PER_PUBLISH = _int("MAX_CHANGES_PER_PUBLISH", 1000)
    MAX_NAME_LEN = _int("MAX_NAME_LEN", 255)          # wire-format octets
    MAX_LABEL_LEN = _int("MAX_LABEL_LEN", 63)
    MAX_RDATA_LEN = _int("MAX_RDATA_LEN", 65535)
    MAX_UDP_PAYLOAD = 512                              # RFC 1035 plain DNS
    MAX_TCP_MESSAGE = 65535

    # Transfer behaviour
    XFER_IDLE_TIMEOUT = _int("XFER_IDLE_TIMEOUT", 30)
    # Maximum wire size of a transfer response message before TSIG room.
    XFER_MESSAGE_BUDGET = _int("XFER_MESSAGE_BUDGET", 65000)
    # Per-connection TCP send buffer: small enough that a slow secondary
    # applies real back-pressure (keeping the transfer pin genuinely alive),
    # large enough not to fragment normal responses.
    XFER_SNDBUF = _int("XFER_SNDBUF", 16384)
