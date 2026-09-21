"""Stable machine-readable error codes.

Every error surfaced over HTTP or DNS maps to one of these codes so that
clients can programmatically distinguish failure classes (bad input, version
conflict, idempotency-key reuse, unknown zone, key failure, ...).
"""
from __future__ import annotations


class ErrorCode:
    # Generic / transport
    INTERNAL = "INTERNAL"
    MALFORMED_JSON = "MALFORMED_JSON"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    NOT_FOUND = "NOT_FOUND"

    # Zones
    ZONE_NOT_FOUND = "ZONE_NOT_FOUND"
    ZONE_ALREADY_EXISTS = "ZONE_ALREADY_EXISTS"
    NAME_OUT_OF_ZONE = "NAME_OUT_OF_ZONE"

    # Publish / versioning
    VERSION_CONFLICT = "VERSION_CONFLICT"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    SERIAL_INVALID = "SERIAL_INVALID"
    SERIAL_UNDECIDABLE = "SERIAL_UNDECIDABLE"
    ZONE_INVALID = "ZONE_INVALID"          # apex SOA/NS/CNAME invariants
    CHANGESET_INVALID = "CHANGESET_INVALID"

    # Keys
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    NO_ACTIVE_KEY = "NO_ACTIVE_KEY"
    KEY_STATE_INVALID = "KEY_STATE_INVALID"
    REQUEST_NOT_FOUND = "REQUEST_NOT_FOUND"

    # DNS / transfer
    DNS_FORMERR = "DNS_FORMERR"
    DNS_SERVFAIL = "DNS_SERVFAIL"
    DNS_NOTIMP = "DNS_NOTIMP"
    DNS_REFUSED = "DNS_REFUSED"
    TRANSFER_DENIED = "TRANSFER_DENIED"     # TSIG auth failure (generic)
    TRANSFER_PROTOCOL = "TRANSFER_PROTOCOL"


class ApiError(Exception):
    """An error that carries a stable machine code and an HTTP status."""

    def __init__(self, code: str, message: str, http_status: int = 400,
                 details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = details or {}

    def to_dict(self) -> dict:
        body = {"error": {"code": self.code, "message": self.message}}
        if self.details:
            body["error"]["details"] = self.details
        return body
