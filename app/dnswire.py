"""DNS wire protocol: names, records, messages and TSIG-style authentication.

Only the subset required by an authoritative distribution node is implemented:
queries carrying a single question, SOA/record answers, AXFR/IXFR responses and
a TSIG (RFC 2845 style) additional record authenticated with HMAC-SHA256.
"""
from __future__ import annotations

import hmac
import hashlib
import struct
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_IXFR = 251
TYPE_AXFR = 252
TYPE_ANY = 255
TYPE_TSIG = 250

CLASS_IN = 1
CLASS_ANY = 255

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

# TSIG error codes (RFC 2845 §5)
TSIG_BADSIG = 16
TSIG_BADKEY = 17
TSIG_BADTIME = 18

ALGORITHM_NAME = "hmac-sha256."  # TSIG-style name, HMAC-SHA256 per RFC 4635
_ALGORITHM_WIRE = b"\x0bhmac-sha256\x00"

FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200

TYPES_BY_VALUE = {
    TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_SOA: "SOA",
    TYPE_MX: "MX", TYPE_TXT: "TXT", TYPE_AAAA: "AAAA",
    TYPE_IXFR: "IXFR", TYPE_AXFR: "AXFR",
}
TYPES_BY_NAME = {v: k for k, v in TYPES_BY_VALUE.items()}

SUPPORTED_TYPES = {"SOA", "NS", "A", "AAAA", "CNAME", "TXT", "MX"}


class WireError(ValueError):
    """Raised when a DNS message cannot be parsed safely."""


# ---------------------------------------------------------------------------
# Domain names
# ---------------------------------------------------------------------------

def encode_name(name: str) -> bytes:
    """Encode a presentation name (absolute or relative root '') to wire."""
    out = b""
    if name in ("", "."):
        return b"\x00"
    for label in name.rstrip(".").split("."):
        if not label:
            raise WireError("empty label")
        lab = label.encode("ascii", errors="strict").lower()
        if len(lab) > 63:
            raise WireError("label too long")
        out += bytes((len(lab),)) + lab
    return out + b"\x00"


def decode_name(buf: bytes, off: int) -> tuple[str, int]:
    """Decode a possibly compressed name; returns (presentation, new_offset)."""
    labels, seen = [], set()
    cur = off
    jumped = False
    next_off = None
    while True:
        if cur >= len(buf):
            raise WireError("name overruns message")
        n = buf[cur]
        if n == 0:
            cur += 1
            if not jumped:
                next_off = cur
            break
        if n & 0xC0 == 0xC0:
            if cur + 1 >= len(buf):
                raise WireError("truncated pointer")
            ptr = ((n & 0x3F) << 8) | buf[cur + 1]
            if ptr in seen or ptr >= cur:
                raise WireError("bad compression pointer")
            seen.add(ptr)
            if not jumped:
                next_off = cur + 2
            cur = ptr
            jumped = True
            continue
        if n & 0xC0:
            raise WireError("reserved label bits")
        cur += 1
        if cur + n > len(buf):
            raise WireError("label overruns message")
        labels.append(buf[cur:cur + n].decode("ascii", errors="strict").lower())
        cur += n
    return ".".join(labels) + ".", next_off  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# RDATA encode / decode
# ---------------------------------------------------------------------------

def _u32(v) -> int:
    v = int(v)
    if not 0 <= v <= 0xFFFFFFFF:
        raise WireError("u32 out of range")
    return v


def encode_rdata(rtype: str, rdata: dict) -> bytes:
    """Encode canonical rdata (as stored in JSON) to wire bytes."""
    if rtype == "A":
        parts = rdata["address"].split(".")
        if len(parts) != 4:
            raise WireError("bad IPv4")
        return bytes(int(p) for p in parts)
    if rtype == "AAAA":
        import ipaddress
        return ipaddress.IPv6Address(rdata["address"]).packed
    if rtype in ("NS", "CNAME"):
        return encode_name(rdata["target"])
    if rtype == "MX":
        pref = int(rdata["preference"])
        if not 0 <= pref <= 0xFFFF:
            raise WireError("MX preference out of range")
        return struct.pack(">H", pref) + encode_name(rdata["exchange"])
    if rtype == "TXT":
        text = rdata["text"].encode("utf-8")
        out = b""
        for i in range(0, len(text), 255):
            chunk = text[i:i + 255]
            out += bytes((len(chunk),)) + chunk
        if not out:
            out = b"\x00"
        return out
    if rtype == "SOA":
        out = encode_name(rdata["mname"]) + encode_name(rdata["rname"])
        out += struct.pack(">IIIII", _u32(rdata["serial"]), _u32(rdata["refresh"]),
                           _u32(rdata["retry"]), _u32(rdata["expire"]),
                           _u32(rdata["minimum"]))
        return out
    raise WireError("unsupported type %r" % rtype)


def rdata_wire_len(rtype: str, rdata: dict) -> int:
    return len(encode_rdata(rtype, rdata))


# ---------------------------------------------------------------------------
# RR / message building
# ---------------------------------------------------------------------------

def pack_rr(name: str, rtype: int, rclass: int, ttl: int, rdata: bytes,
            rr_type_name: str | None = None) -> bytes:
    return (encode_name(name) + struct.pack(">HHIH", rtype, rclass, _u32(ttl),
                                            len(rdata)) + rdata)


def build_header(qid: int, flags: int, qd: int, an: int, ns: int, ar: int) -> bytes:
    return struct.pack(">HHHHHH", qid, flags, qd, an, ns, ar)


def patch_arcount(msg_without_tsig: bytes, arcount: int) -> bytes:
    return msg_without_tsig[:10] + struct.pack(">H", arcount) + msg_without_tsig[12:]


def _tsig_rdata(alg_wire: bytes, when: int, fudge: int, mac: bytes,
                orig_id: int, error: int, other: bytes = b"") -> bytes:
    return (alg_wire
            + struct.pack(">HIH", (when >> 32) & 0xFFFF, when & 0xFFFFFFFF,
                          fudge)
            + struct.pack(">H", len(mac)) + mac
            + struct.pack(">HHH", orig_id, error, len(other)) + other)


def tsig_variables(key_name: str, alg_wire: bytes, when: int, fudge: int,
                   error: int, other: bytes) -> bytes:
    """The digest-variable block appended to the signed message (RFC 2845
    §3.4.2): the TSIG RR with MAC Size and MAC omitted."""
    rdata_no_mac = (alg_wire
                    + struct.pack(">HIH", (when >> 32) & 0xFFFF,
                                  when & 0xFFFFFFFF, fudge)
                    + struct.pack(">H", error) + struct.pack(">H", len(other))
                    + other)
    return (encode_name(key_name)
            + struct.pack(">HHIH", TYPE_TSIG, CLASS_ANY, 0, len(rdata_no_mac))
            + rdata_no_mac)


def append_tsig(msg: bytes, key_name: str, when: int, fudge: int, mac: bytes,
                orig_id: int, error: int = 0, arcount_before: int | None = None,
                other: bytes = b"") -> bytes:
    """Append a TSIG RR to a message (which must currently end after ARs)."""
    if arcount_before is None:
        arcount_before = struct.unpack(">H", msg[10:12])[0]
    rdata = _tsig_rdata(_ALGORITHM_WIRE, when, fudge, mac, orig_id, error, other)
    rr = encode_name(key_name) + struct.pack(">HHIH", TYPE_TSIG, CLASS_ANY, 0,
                                             len(rdata)) + rdata
    head = patch_arcount(msg, arcount_before + 1)
    return head + rr


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------

def _skip_rr(buf: bytes, off: int) -> int:
    _, off = decode_name(buf, off)
    if off + 10 > len(buf):
        raise WireError("RR header truncated")
    rdlen = struct.unpack(">H", buf[off + 8:off + 10])[0]
    off += 10
    if off + rdlen > len(buf):
        raise WireError("RRDATA truncated")
    return off + rdlen


def parse_tsig_rdata(buf: bytes, off: int, rdlen: int) -> dict:
    end = off + rdlen
    alg, off = decode_name(buf, off)
    if off + 8 > end:
        raise WireError("TSIG time truncated")
    hi, lo, fudge = struct.unpack(">HIH", buf[off:off + 8])
    when = (hi << 32) | lo
    off += 8
    if off + 2 > end:
        raise WireError("TSIG mac size truncated")
    (maclen,) = struct.unpack(">H", buf[off:off + 2])
    off += 2
    if off + maclen + 6 > end:
        raise WireError("TSIG mac/tail truncated")
    mac = buf[off:off + maclen]
    off += maclen
    orig_id, error, otherlen = struct.unpack(">HHH", buf[off:off + 6])
    off += 6
    if off + otherlen != end:
        raise WireError("TSIG other length mismatch")
    other = buf[off:off + otherlen]
    return {"algorithm": alg, "time": when, "fudge": fudge, "mac": mac,
            "orig_id": orig_id, "error": error, "other": other}


def parse_query(buf: bytes) -> dict:
    """Parse a DNS query. Raises WireError on anything malformed.

    An IXFR request (RFC 1995) carries the client's current SOA in the
    authority section; its serial is extracted as ``client_soa_serial``."""
    if len(buf) < 12:
        raise WireError("message shorter than header")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    if flags & FLAG_QR:
        raise WireError("query QR bit set")
    if qd != 1 or an != 0:
        raise WireError("query must have exactly one question and no answers")
    off = 12
    qname, off = decode_name(buf, off)
    if off + 4 > len(buf):
        raise WireError("question tail truncated")
    qtype, qclass = struct.unpack(">HH", buf[off:off + 4])
    off += 4
    question_end = off

    client_soa_serial = None
    for _ in range(ns):
        _, off2 = decode_name(buf, off)
        if off2 + 10 > len(buf):
            raise WireError("authority RR truncated")
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off2:off2 + 10])
        rstart = off2 + 10
        if rstart + rdlen > len(buf):
            raise WireError("authority RDATA truncated")
        if rtype == TYPE_SOA and rdlen >= 22:
            try:
                _, p = decode_name(buf, rstart)
                _, p = decode_name(buf, p)
                if p + 20 <= rstart + rdlen:
                    client_soa_serial = struct.unpack(">I", buf[p:p + 4])[0]
            except WireError:
                pass
        off = rstart + rdlen

    tsig = None
    for _ in range(ar):
        start = off
        tname, off2 = decode_name(buf, off)
        if off2 + 10 > len(buf):
            raise WireError("additional RR truncated")
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off2:off2 + 10])
        rstart = off2 + 10
        if rstart + rdlen > len(buf):
            raise WireError("additional RDATA truncated")
        if rtype == TYPE_TSIG:
            if tsig is not None:
                raise WireError("duplicate TSIG")
            tsig = {"name": tname, **parse_tsig_rdata(buf, rstart, rdlen)}
            tsig_offset = start
        off = rstart + rdlen
    if off != len(buf):
        raise WireError("trailing garbage")

    return {
        "id": qid, "flags": flags, "qname": qname, "qtype": qtype,
        "qclass": qclass, "raw_question": buf[12:question_end],
        "tsig": tsig, "tsig_offset": tsig_offset if tsig else None,
        "arcount": ar, "raw": buf,
        "client_soa_serial": client_soa_serial,
    }


# ---------------------------------------------------------------------------
# TSIG signing / verification (HMAC-SHA256, server UTC only)
# ---------------------------------------------------------------------------

def _digest_block(msg: bytes, tsig_offset: int, final_arcount: int,
                  key_name: str, when: int, fudge: int, error: int,
                  other: bytes) -> bytes:
    # RFC 2845 §3.4.2: the signed base is the message *before* the TSIG RR,
    # with ARCOUNT adjusted to the value it has after the TSIG is appended.
    base = msg[:tsig_offset]
    base = patch_arcount(base, final_arcount)
    return base + tsig_variables(key_name, _ALGORITHM_WIRE, when, fudge, error,
                                 other)


def expected_request_mac(key: bytes, q: dict) -> bytes:
    t = q["tsig"]
    block = _digest_block(q["raw"], q["tsig_offset"], q["arcount"], t["name"],
                          t["time"], t["fudge"], t["error"], t["other"])
    return hmac.new(key, block, hashlib.sha256).digest()


def sign_response(key: bytes, response_no_tsig: bytes, key_name: str,
                  prior_mac: bytes, when: int, fudge: int, orig_id: int,
                  arcount_before: int) -> tuple[bytes, bytes]:
    """Sign and append TSIG. Returns (wire, mac). prior_mac is request MAC
    for the first signed response, or the previous signed response's MAC."""
    base = patch_arcount(response_no_tsig, arcount_before + 1)
    block = (prior_mac + base
             + tsig_variables(key_name, _ALGORITHM_WIRE, when, fudge, 0, b""))
    mac = hmac.new(key, block, hashlib.sha256).digest()
    return append_tsig(response_no_tsig, key_name, when, fudge, mac, orig_id,
                       arcount_before=arcount_before), mac


def verify_tsig_time(tsig_time: int, fudge: int, now: int, max_fudge: int = 300
                     ) -> bool:
    if not (1 <= fudge <= max_fudge):
        return False
    return abs(now - tsig_time) <= fudge


def utcnow() -> int:
    return int(time.time())


def make_error_response(q: dict, rcode: int, tsig_error: int | None) -> bytes:
    """Build a REFUSED/FORMERR response, optionally echoing a TSIG error with
    an empty MAC (no data is ever included). For BADTIME (RFC 2845 §5.4) the
    6-byte other-data carries the server's current 48-bit time."""
    flags = FLAG_QR | FLAG_AA | rcode
    msg = build_header(q["id"], flags, 1, 0, 0, 1 if tsig_error is not None else 0)
    msg += q["raw_question"]
    if tsig_error is not None and q["tsig"] is not None:
        other = b""
        if tsig_error == TSIG_BADTIME:
            now = utcnow()
            other = struct.pack(">HI", (now >> 32) & 0xFFFF,
                                now & 0xFFFFFFFF)  # 6 bytes, server time
        msg = append_tsig(msg, q["tsig"]["name"], utcnow(), 300, b"",
                          q["id"], error=tsig_error, arcount_before=0,
                          other=other)
    return msg


def make_simple_response(qid: int, question: bytes, rcode: int,
                         answers: list[bytes] | None = None,
                         aa: bool = True, tc: bool = False) -> bytes:
    flags = FLAG_QR | rcode
    if aa:
        flags |= FLAG_AA
    if tc:
        flags |= FLAG_TC
    ancount = 0 if tc else len(answers or [])
    msg = build_header(qid, flags, 1, ancount, 0, 0) + question
    if not tc:
        for rr in answers or []:
            msg += rr
    return msg
