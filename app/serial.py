"""RFC 1982 serial number arithmetic for the 32-bit unsigned serial space."""
from __future__ import annotations

MOD = 1 << 32
HALF = 1 << 31


class SerialRelation:
    EQUAL = "EQUAL"
    GREATER = "GREATER"          # s2 is a forward successor of s1
    LESS = "LESS"                # s2 is behind s1
    UNDECIDABLE = "UNDECIDABLE"  # distance exactly 2^31


def compare(s1: int, s2: int) -> str:
    """Compare two uint32 serials using RFC 1982 half-range ordering."""
    s1 &= 0xFFFFFFFF
    s2 &= 0xFFFFFFFF
    if s1 == s2:
        return SerialRelation.EQUAL
    delta = (s2 - s1) % MOD
    if 0 < delta < HALF:
        return SerialRelation.GREATER
    if HALF < delta < MOD:
        return SerialRelation.LESS
    return SerialRelation.UNDECIDABLE


def is_forward(base: int, nxt: int) -> tuple[bool, str | None]:
    """A valid update strictly advances inside the decidable half window."""
    rel = compare(base, nxt)
    if rel == SerialRelation.GREATER:
        return True, None
    if rel == SerialRelation.EQUAL:
        return False, "nextSerial must be greater than baseSerial"
    if rel == SerialRelation.UNDECIDABLE:
        return False, "serial distance is exactly 2^31 (undecidable per RFC 1982)"
    return False, "nextSerial is behind baseSerial in serial-number arithmetic"


def valid_u32(v) -> int | None:
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    if 0 <= v <= 0xFFFFFFFF:
        return v
    return None
