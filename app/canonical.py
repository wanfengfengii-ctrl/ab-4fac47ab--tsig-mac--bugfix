"""Deterministic canonicalization and validation for names and RDATA.

Names are compared case-insensitively; every stored/returned form is a single
canonical absolute lowercase presentation name ending in '.'. RDATA has a
canonical JSON shape per type and a precomputed DNS wire encoding.
"""
from __future__ import annotations

import ipaddress
import json
import re

from . import dnswire
from .config import Config
from .errors import ApiError

_LABEL_RE = re.compile(r"^[a-z0-9_-]{1,63}$")


def canonical_zone(name: str) -> str:
    """Canonicalize a zone apex (must be absolute)."""
    if not isinstance(name, str) or not name:
        raise ApiError("VALIDATION_ERROR", "zone name required", 400)
    raw = name.lower().strip()
    if not raw.endswith("."):
        raise ApiError("VALIDATION_ERROR",
                       "zone name must be absolute (end with '.')")
    return _check_name(raw)


def canonical_zone_arg(raw: str) -> str:
    """Canonicalize a zone name supplied in a URL path. Accepts both
    ``example.com.`` and ``example.com``."""
    if not isinstance(raw, str) or not raw.strip():
        raise ApiError("VALIDATION_ERROR", "zone name required")
    raw = raw.lower().strip()
    if not raw.endswith("."):
        raw += "."
    return _check_name(raw)


def _check_name(abs_name: str) -> str:
    labels = abs_name[:-1].split(".") if abs_name != "." else []
    wire_len = 1
    for lab in labels:
        if len(lab) > Config.MAX_LABEL_LEN:
            raise ApiError("LIMIT_EXCEEDED",
                           f"label too long ({len(lab)} > "
                           f"{Config.MAX_LABEL_LEN} octets)", 413,
                           {"limit": Config.MAX_LABEL_LEN})
        if not _LABEL_RE.match(lab):
            raise ApiError("VALIDATION_ERROR", f"invalid label: {lab!r}")
        wire_len += 1 + len(lab)
    if wire_len > Config.MAX_NAME_LEN:
        raise ApiError("LIMIT_EXCEEDED",
                       f"name wire length {wire_len} exceeds {Config.MAX_NAME_LEN}",
                       413, {"limit": Config.MAX_NAME_LEN})
    return abs_name


def canonical_name(raw: str, zone: str) -> str:
    """Canonicalize an RR owner name. Relative names get the zone appended.
    Raises NAME_OUT_OF_ZONE when outside the zone."""
    if not isinstance(raw, str) or not raw:
        raise ApiError("VALIDATION_ERROR", "record name required")
    name = raw.lower().strip()
    if name == "@":
        return zone
    if name in ("", "."):
        raise ApiError("VALIDATION_ERROR", "root name not allowed in a zone")
    if not name.endswith("."):
        name = f"{name}.{zone}"
    if not name.endswith(zone):
        raise ApiError("NAME_OUT_OF_ZONE",
                       f"{raw!r} is outside zone {zone}", 422,
                       {"name": raw, "zone": zone})
    # ensure label boundary: e.g. name evil-example.com. must not be treated
    # as being in zone example.com.
    if name != zone and not name.endswith("." + zone):
        raise ApiError("NAME_OUT_OF_ZONE",
                       f"{raw!r} is not within zone {zone}", 422)
    return _check_name(name)


def name_labels(name: str) -> tuple[str, ...]:
    return tuple(name[:-1].split(".")) if name != "." else ()


def is_subname(name: str, zone: str) -> bool:
    n, z = name_labels(name), name_labels(zone)
    return len(n) >= len(z) and n[-len(z):] == z


def canonical_target(raw: str, zone: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ApiError("VALIDATION_ERROR", "target name required")
    t = raw.lower().strip()
    if not t.endswith("."):
        t = f"{t}.{zone}"
    return _check_name(t)


def _check_ttl(ttl) -> int:
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        raise ApiError("VALIDATION_ERROR", "ttl must be an integer")
    if not 0 <= ttl <= 0xFFFFFFFF:
        raise ApiError("VALIDATION_ERROR", "ttl must be 0..4294967295")
    return ttl


def canonical_rdata(rtype: str, value, zone: str) -> tuple[str, bytes]:
    """Return (canonical JSON text, wire bytes) for one RDATA value."""
    if not isinstance(value, dict):
        raise ApiError("VALIDATION_ERROR", f"{rtype} rdata must be an object")
    try:
        if rtype == "A":
            addr = str(value.get("address", ""))
            try:
                ip = ipaddress.IPv4Address(addr)  # validates
            except (ValueError, ipaddress.AddressValueError):
                raise ApiError("VALIDATION_ERROR", f"bad IPv4 address: {addr!r}")
            canon = {"address": str(ip)}
        elif rtype == "AAAA":
            addr = str(value.get("address", ""))
            try:
                ip = ipaddress.IPv6Address(addr)
            except (ValueError, ipaddress.AddressValueError):
                raise ApiError("VALIDATION_ERROR", f"bad IPv6 address: {addr!r}")
            canon = {"address": ip.compressed.lower()}
        elif rtype in ("NS", "CNAME"):
            canon = {"target": canonical_target(value.get("target", ""), zone)}
        elif rtype == "MX":
            exchange = canonical_target(value.get("exchange", ""), zone)
            try:
                pref = int(value.get("preference"))
            except (TypeError, ValueError):
                raise ApiError("VALIDATION_ERROR", "MX preference must be int")
            if not 0 <= pref <= 0xFFFF:
                raise ApiError("VALIDATION_ERROR",
                               "MX preference must be 0..65535")
            canon = {"preference": pref, "exchange": exchange}
        elif rtype == "TXT":
            text = value.get("text", "")
            if not isinstance(text, str):
                raise ApiError("VALIDATION_ERROR", "TXT text must be string")
            encoded = text.encode("utf-8")
            if len(encoded) > Config.MAX_RDATA_LEN:
                raise ApiError("LIMIT_EXCEEDED", "TXT rdata too large", 413)
            canon = {"text": text}
        elif rtype == "SOA":
            canon = {
                "mname": canonical_target(value.get("mname", ""), zone),
                "rname": canonical_target(value.get("rname", ""), zone),
                "serial": _u32(value.get("serial"), "SOA serial"),
                "refresh": _i32_nonneg(value.get("refresh"), "refresh"),
                "retry": _i32_nonneg(value.get("retry"), "retry"),
                "expire": _i32_nonneg(value.get("expire"), "expire"),
                "minimum": _u32(value.get("minimum"), "minimum"),
            }
        else:
            raise ApiError("VALIDATION_ERROR", f"unsupported type {rtype}")
        wire = dnswire.encode_rdata(rtype, canon)
    except dnswire.WireError as exc:
        raise ApiError("VALIDATION_ERROR", f"bad {rtype} rdata: {exc}")
    if len(wire) > Config.MAX_RDATA_LEN:
        raise ApiError("LIMIT_EXCEEDED",
                       f"{rtype} rdata length {len(wire)} exceeds limit", 413)
    return json.dumps(canon, sort_keys=True, separators=(",", ":")), wire


def _u32(v, field: str) -> int:
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ApiError("VALIDATION_ERROR", f"{field} must be an integer")
    if not 0 <= v <= 0xFFFFFFFF:
        raise ApiError("SERIAL_INVALID" if "serial" in field else "VALIDATION_ERROR",
                       f"{field} must be 0..4294967295")
    return v


def _i32_nonneg(v, field: str) -> int:
    return _u32(v, field)


def rr_fits_message(name: str, rtype: str, rdata_wire: bytes) -> None:
    """Reject records before persistence that cannot fit in a signed DNS TCP
    transfer message: 65535 minus the 2-byte TCP length, header/question, and
    ample room for the first/last TSIG RR. This guarantees every record can
    always be streamed (never an illegal >65535 framed message)."""
    rr_len = len(dnswire.encode_name(name)) + 10 + len(rdata_wire)
    hard_limit = Config.MAX_TCP_MESSAGE - 700
    if rr_len > hard_limit:
        raise ApiError("LIMIT_EXCEEDED",
                       f"{rtype} RR would not fit a signed DNS message "
                       f"({rr_len} bytes)",
                       413, {"rrLength": rr_len, "limit": hard_limit})


def parse_rdata_json(rtype: str, text: str) -> dict:
    return json.loads(text)
