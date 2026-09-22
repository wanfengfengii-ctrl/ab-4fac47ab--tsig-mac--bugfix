"""Deterministic RFC 2845 TSIG conformance probe.

Runnable inside an edge container with no network listeners, no preexisting
zone and no modification of the serving database::

    python -m app.rfc_tsig_probe

The fixed MAC probe (scenario 1) needs no zone and touches no database at all.
The transfer scenarios (single/multi-message AXFR and IXFR) run the real
business transfer pipeline (:func:`app.dns_server.transfer_envelopes`:
authorize transaction, pin, WAL snapshot, streaming RR cursor, batching and
signing) against a *throwaway* temporary database file, producing one
envelope at a time -- the full zone is never cached.

Every expected MAC is recomputed here from the RFC 2845 text alone
(§3.4.1/§3.4.2/§3.4.3 and §4.4); the product's own signer/verifier is never
used to judge the result. When the third-party ``dnspython`` library happens
to be importable it is additionally used as an independent oracle; in the
standard-library-only runtime image that cross-check is simply skipped.

Exits 0 only if every assertion holds. A mismatch raises AssertionError
(non-zero exit); this module never prints ``RFC_TSIG_MISMATCH``.
"""
from __future__ import annotations

import hashlib
import hmac
import inspect
import os
import struct
import tempfile
import time

from . import dnsclient as dc
from . import dnswire as w
from .config import Config
from .dns_server import DNSLogic, transfer_envelopes
from .storage import Database

# ---------------------------------------------------------------------------
# Independent RFC 2845 primitives (no product authentication code is reused)
# ---------------------------------------------------------------------------

ALG_WIRE = b"\x0bhmac-sha256\x00"
TYPE_TSIG = 250
CLASS_ANY = 255
FLAG_QR = 0x8000
FLAG_AA = 0x0400
TYPE_AXFR, TYPE_IXFR, TYPE_SOA = 252, 251, 6
CLASS_IN = 1


def _name(name: str) -> bytes:
    if name in ("", "."):
        return b"\x00"
    out = b""
    for label in name.rstrip(".").split("."):
        lab = label.encode("ascii")
        out += bytes((len(lab),)) + lab
    return out + b"\x00"


def _timers(when: int, fudge: int) -> bytes:
    return struct.pack(">HIH", (when >> 32) & 0xFFFF, when & 0xFFFFFFFF, fudge)


def rfc_tsig_variables(key_name: str, when: int, fudge: int,
                       error: int = 0, other: bytes = b"") -> bytes:
    """RFC 2845 §3.4.2: NAME, CLASS(ANY), TTL(0), Algorithm, Time Signed,
    Fudge, Error, Other Len, Other -- with no TYPE and no RDLENGTH field."""
    return (_name(key_name)
            + struct.pack(">HI", CLASS_ANY, 0)
            + ALG_WIRE + _timers(when, fudge)
            + struct.pack(">HH", error, len(other)) + other)


def _patch_arcount(msg: bytes, arcount: int) -> bytes:
    return msg[:10] + struct.pack(">H", arcount) + msg[12:]


def _strip_tsig(raw: bytes, tsig_offset: int, arcount_with_tsig: int) -> bytes:
    """Message before the TSIG RR, ARCOUNT rewound to its pre-TSIG value
    (RFC 2845 §3.4.1)."""
    return _patch_arcount(raw[:tsig_offset], arcount_with_tsig - 1)


def rfc_request_mac(key: bytes, q: dict) -> bytes:
    """Request MAC (RFC 2845 §3.4.2, no prior digest):
    u16(original ID) | message[2:] pre-TSIG/pre-ARCOUNT-increment | vars."""
    t = q["tsig"]
    base = _strip_tsig(q["raw"], q["tsig_offset"], q["arcount"])
    h = hmac.new(key, b"", hashlib.sha256)
    h.update(struct.pack(">H", t["orig_id"]))
    h.update(base[2:])
    h.update(rfc_tsig_variables(t["name"], t["time"], t["fudge"],
                                t["error"], t["other"]))
    return h.digest()


class RFCChainVerifier:
    """Reference RFC 2845 §4.4 verifier for a sequence of TCP envelopes."""

    def __init__(self, key: bytes, request_mac: bytes):
        self.key = key
        self.n_signed = 0
        self._seed(request_mac)

    def _seed(self, prior: bytes) -> None:
        self.h = hmac.new(self.key, b"", hashlib.sha256)
        self.h.update(struct.pack(">H", len(prior)))  # §3.4.3 MAC Length
        self.h.update(prior)

    def unsigned(self, raw: bytes) -> None:
        """A complete unsigned envelope enters the running digest as sent."""
        self.h.update(raw)

    def signed(self, raw: bytes) -> bytes:
        """Verify a TSIG-bearing envelope; returns its MAC (new running MAC)."""
        m = dc.parse_message(raw)
        t = m["tsig"]
        assert t is not None, "expected a TSIG-bearing envelope"
        base = _strip_tsig(raw, m["tsig_offset"], m["arcount"])
        self.h.update(struct.pack(">H", t["orig_id"]))
        self.h.update(base[2:])
        if self.n_signed == 0:
            # First envelope: full TSIG variables (§3.4.2).
            self.h.update(rfc_tsig_variables(t["name"], t["time"], t["fudge"],
                                             t["error"], t["other"]))
        else:
            # Subsequent envelopes: TSIG timers only (§4.4).
            self.h.update(_timers(t["time"], t["fudge"]))
        calc = self.h.digest()
        assert hmac.compare_digest(calc, t["mac"]), (
            f"TSIG MAC mismatch at signed envelope #{self.n_signed}\n"
            f"  expected(indep.): {calc.hex()}\n"
            f"  actual(product) : {t['mac'].hex()}")
        self._seed(calc)
        self.n_signed += 1
        return calc


def _rfc_verify_transfer(envelopes: list[bytes], key: bytes,
                         request_mac: bytes, *, expect_periodic: bool
                         ) -> dict:
    """Run the independent verifier over a complete transfer and assert the
    §4.4 structural rules (first + last signed, no 100-envelope unsigned run,
    every envelope consumed by the continuous chain)."""
    assert envelopes, "transfer produced no envelopes"
    parsed = [dc.parse_message(e) for e in envelopes]
    signed_idx = [i for i, m in enumerate(parsed) if m["tsig"] is not None]
    assert signed_idx and signed_idx[0] == 0, "first envelope must be signed"
    assert signed_idx[-1] == len(parsed) - 1, "last envelope must be signed"
    assert all(b - a <= 100 for a, b in zip(signed_idx, signed_idx[1:])), \
        "TSIG must appear at least every 100 envelopes (RFC 2845 4.4)"
    if expect_periodic:
        assert len(signed_idx) > 2, "expected a periodic intermediate TSIG"
        assert any(0 < i < len(parsed) - 1 for i in signed_idx), \
            "no periodic TSIG present"
    verifier = RFCChainVerifier(key, request_mac)
    for i, raw in enumerate(envelopes):
        if parsed[i]["tsig"] is None:
            verifier.unsigned(raw)
        else:
            verifier.signed(raw)
    return {"messages": len(parsed), "signed": signed_idx}


# ---------------------------------------------------------------------------
# Optional third-party oracle (dnspython); absent in the slim runtime image
# ---------------------------------------------------------------------------

def _dnspython_crosscheck():
    try:
        import dns.message  # type: ignore
        import dns.name  # type: ignore
        import dns.rdataclass  # type: ignore
        import dns.rdatatype  # type: ignore
        import dns.renderer  # type: ignore
        import dns.tsig  # type: ignore
    except Exception:
        print("  dnspython not importable; third-party oracle cross-check skipped")
        return
    key = b"k" * 32
    kname = dns.name.from_text("k.example.")
    keyring = {kname: key}
    when, fudge = 1700000000, 300
    dns.renderer.time.time = lambda: when  # pin the library clock

    # Product-signed fixed response must be accepted by dnspython too.
    plain = (_fixed_header() + _name("z.")
             + struct.pack(">HH", TYPE_AXFR, CLASS_IN))
    wire, _mac = w.sign_response(key, plain, "k.example.", b"p" * 32,
                                 when, fudge, 1, arcount_before=0)
    dns.message.from_wire(wire, keyring=keyring, request_mac=b"p" * 32)

    # Product-built query must be accepted by dnspython.
    qwire = dc.build_tsig_query(1, "z.", TYPE_AXFR, "k.example.", key,
                                when=when, fudge=fudge)
    parsed = dns.message.from_wire(qwire, keyring=keyring)
    req_mac = parsed.tsig[0].mac

    # A 4-envelope sequence signed by dnspython must pass OUR independent
    # verifier (signed, unsigned, periodic, last).
    def make(qid, nans):
        m = dns.message.Message(id=qid)
        m.flags = FLAG_QR | FLAG_AA
        m.find_rrset(m.question, dns.name.from_text("z."), dns.rdataclass.IN,
                     dns.rdatatype.AXFR, create=True, force_unique=True)
        for i in range(nans):
            m.answer.append(dns.rrset.from_text(
                "z.", 60, "IN", "A", f"192.0.2.{i + 1}"))
        return m

    def lib_sign(m, ctx, request_mac=b""):
        m.request_mac = request_mac
        m.use_tsig(keyring, kname, fudge=fudge, original_id=m.id,
                   algorithm=dns.tsig.HMAC_SHA256)
        out = m.to_wire(multi=True, tsig_ctx=ctx)
        return out, m.tsig_ctx

    e0, ctx = lib_sign(make(1, 1), None, request_mac=req_mac)
    e1 = make(1, 2).to_wire()
    ctx.update(e1)
    e2, ctx = lib_sign(make(1, 3), ctx)
    e3, ctx = lib_sign(make(1, 1), ctx)
    _rfc_verify_transfer([e0, e1, e2, e3], key, req_mac, expect_periodic=True)
    print("  dnspython oracle cross-check: OK (both directions)")


# ---------------------------------------------------------------------------
# Fixed deterministic response (id=1, z., AXFR/IN)
# ---------------------------------------------------------------------------

def _fixed_header(arcount: int = 0) -> bytes:
    return struct.pack(">HHHHHH", 1, FLAG_QR | FLAG_AA, 1, 0, 0, arcount)


def fixed_response_no_tsig() -> bytes:
    return (_fixed_header() + _name("z.")
            + struct.pack(">HH", TYPE_AXFR, CLASS_IN))


def scenario_fixed_mac() -> None:
    """The issue's deterministic probe: fixed inputs, product MAC vs the
    independent RFC formula. Must end in an EQUALITY assertion; on failure the
    process exits non-zero and RFC_TSIG_MISMATCH is never printed."""
    key = b"k" * 32
    prior = b"p" * 32
    key_name = "k.example."
    when, fudge = 1700000000, 300
    plain = fixed_response_no_tsig()

    wire, product_mac = w.sign_response(
        key, plain, key_name, prior, when, fudge, 1, arcount_before=0)

    # Independent reference (RFC 2845 §3.4.3 + §3.4.1 + §3.4.2).
    h = hmac.new(key, b"", hashlib.sha256)
    h.update(struct.pack(">H", len(prior)))
    h.update(prior)
    h.update(struct.pack(">H", 1))  # original ID substituted for message ID
    h.update(_patch_arcount(plain, 0)[2:])  # ARCOUNT is 0 before TSIG is added
    h.update(rfc_tsig_variables(key_name, when, fudge))
    reference_mac = h.digest()

    assert product_mac == reference_mac, (
        "fixed response MAC disagrees with the independent RFC 2845 result\n"
        f"  product:   {product_mac.hex()}\n"
        f"  rfc ref:   {reference_mac.hex()}")
    # The transmitted RR must carry exactly that MAC too.
    parsed = dc.parse_message(wire)
    assert parsed["tsig"]["mac"] == reference_mac
    print("  fixed MAC probe (id=1 z. AXFR/IN, t=1700000000): MATCH")


def scenario_request_and_response_standard() -> None:
    """An inbound request signed with the independent standard value is
    accepted; the resulting standalone response signature is itself verified
    with independent standard logic (never product-sign-vs-product-verify)."""
    key = b"k" * 32
    key_name = "k.example."

    # Independently construct a standard request MAC and a TSIG query carrying
    # it (build the RR without the product signer).
    when, fudge = int(time.time()), 300
    qid = 0x5151
    arcount_before = 0
    base = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    base += _name("z.") + struct.pack(">HH", TYPE_AXFR, CLASS_IN)
    h = hmac.new(key, b"", hashlib.sha256)
    h.update(struct.pack(">H", qid))
    h.update(_patch_arcount(base, 0)[2:])  # ARCOUNT 0 (pre-TSIG)
    h.update(rfc_tsig_variables(key_name, when, fudge))
    mac = h.digest()
    rdata = (ALG_WIRE + _timers(when, fudge)
             + struct.pack(">H", len(mac)) + mac
             + struct.pack(">HHH", qid, 0, 0))
    query = base + _name(key_name) + struct.pack(
        ">HHIH", TYPE_TSIG, CLASS_ANY, 0, len(rdata)) + rdata

    # Product parses it and its request authentication must accept the
    # independently computed request MAC.
    q = w.parse_query(query)
    assert hmac.compare_digest(w.expected_request_mac(key, q), mac)
    # And re-deriving independently from the parsed wire yields the same value.
    assert hmac.compare_digest(rfc_request_mac(key, q), mac)

    # Product signs a standalone response; verify it strictly independently.
    plain = fixed_response_no_tsig()
    wire, resp_mac = w.sign_response(
        key, plain, key_name, mac, when, fudge, qid, arcount_before=0)
    verifier = RFCChainVerifier(key, mac)
    got = verifier.signed(wire)
    assert got == resp_mac
    print("  independent request MAC accepted; response MAC verified")


# ---------------------------------------------------------------------------
# Transfer scenarios over the real (temp-DB) business pipeline
# ---------------------------------------------------------------------------

def _soa_ops(serial: int, hosts: list[str] | None = None):
    ops = [{"action": "replace", "name": "@", "type": "SOA", "ttl": 3600,
            "records": [{"mname": "ns1.t.", "rname": "admin.t.",
                         "serial": serial, "refresh": 7200, "retry": 3600,
                         "expire": 1209600, "minimum": 3600}]}]
    for i, addr in enumerate(hosts or []):
        ops.append({"action": "replace", "name": f"h{i:03d}", "type": "A",
                    "ttl": 60, "records": [{"address": addr}]})
    return ops


def _publish(db: Database, zone: str, rid: str, base: int, nxt: int,
             ops: list[dict]) -> None:
    from .api import canonical_fingerprint
    db.publish(zone, rid, base, nxt, ops,
               canonical_fingerprint(base, nxt, ops, zone))


def _fresh_world(hosts_at_11: int, hosts_at_12: int):
    """Create an isolated throwaway database with zone t. at serial 12 and
    install TSIG key k.example. Returns (db, logic, zone, key_name, key)."""
    fd, path = tempfile.mkstemp(prefix="tsigprobe-", suffix=".db")
    os.close(fd)
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except FileNotFoundError:
            pass
    db = Database(path)
    zone = "t."
    db.create_zone(zone, 10,
                   {"mname": "ns1.t.", "rname": "admin.t.",
                    "refresh": 7200, "retry": 3600, "expire": 1209600,
                    "minimum": 3600},
                   ["ns1.t."], retain_versions=50)
    _publish(db, zone, "p11", 10, 11, _soa_ops(
        11, [f"192.0.11.{i}" for i in range(hosts_at_11)]))
    _publish(db, zone, "p12", 11, 12, _soa_ops(
        12, [f"192.0.12.{i}" for i in range(hosts_at_12)]))
    db.install_key(zone, "probe-key", "k.example.", None)
    row = db.conn.execute(
        "SELECT secret FROM keys WHERE key_name='k.example.'").fetchone()
    key = row["secret"]  # stored as raw 32 bytes (base64 is applied at the API)
    return db, path, zone, "k.example.", key


def _run_transfer(db: Database, zone: str, key_name: str, key: bytes,
                  qtype: int, ixfr_serial: int | None, budget: int,
                  interval: int):
    """Drive the real streaming pipeline lazily and return (query, list of
    envelopes). The generator yields one envelope at a time (no full-zone
    buffering); we preserve that behaviour while collecting for verification."""
    Config.INSTANCE_ID = "tsig-probe"
    Config.XFER_MESSAGE_BUDGET = budget
    authority = b""
    if ixfr_serial is not None:
        authority = dc.soa_authority(zone, ixfr_serial)
    query = dc.build_tsig_query(0x7777, zone, qtype, key_name, key,
                                authority=authority)
    q = w.parse_query(query)
    logic = DNSLogic(db)
    gen = transfer_envelopes(logic, q, interval=interval)
    assert inspect.isgenerator(gen), "transfer pipeline must stream lazily"
    envelopes = list(gen)  # exhaust: releases snapshot + pin
    return query, q["tsig"]["mac"], envelopes


def scenario_transfers() -> None:
    # Enough records that a 400-byte budget forces many envelopes.
    db, path, zone, kname, key = _fresh_world(hosts_at_11=0, hosts_at_12=60)
    try:
        # ---- single-message AXFR (large budget -> one envelope) ----
        _q, req_mac, env = _run_transfer(
            db, zone, kname, key, TYPE_AXFR, None, 65000, 100)
        assert len(env) == 1, f"expected 1 envelope, got {len(env)}"
        info = _rfc_verify_transfer(env, key, req_mac, expect_periodic=False)
        assert dc.parse_message(env[0])["tsig"] is not None
        print(f"  single-message AXFR: 1 envelope, chain OK")

        # ---- single-message IXFR (client up to date -> one SOA) ----
        _q, req_mac, env = _run_transfer(
            db, zone, kname, key, TYPE_IXFR, 12, 65000, 100)
        assert len(env) == 1
        _rfc_verify_transfer(env, key, req_mac, expect_periodic=False)
        answers = dc.parse_message(env[0])["answers"]
        assert len(answers) == 1 and answers[0]["type"] == TYPE_SOA
        print("  single-message IXFR (equal serial): 1 envelope, chain OK")

        # ---- multi-message AXFR: unsigned middles + periodic signature ----
        _q, req_mac, env = _run_transfer(
            db, zone, kname, key, TYPE_AXFR, None, 400, 2)
        assert len(env) > 3, f"expected multi-envelope transfer, got {len(env)}"
        parsed = [dc.parse_message(e) for e in env]
        assert any(m["tsig"] is None for m in parsed), \
            "expected unsigned intermediate envelopes"
        info = _rfc_verify_transfer(env, key, req_mac, expect_periodic=True)
        answers = [a for m in parsed for a in m["answers"]]
        assert answers[0]["type"] == answers[-1]["type"] == TYPE_SOA
        assert dc.soa_serial(answers[0]["rdata"]) == 12
        assert dc.soa_serial(answers[-1]["rdata"]) == 12
        assert sum(1 for r in answers if r["type"] == 1) == 60
        print(f"  multi-message AXFR: {len(env)} envelopes, "
              f"signed at {info['signed']}; continuous chain OK")

        # ---- multi-message IXFR (serial 10 -> 12), same guarantees ----
        _q, req_mac, env = _run_transfer(
            db, zone, kname, key, TYPE_IXFR, 10, 400, 2)
        assert len(env) > 3, f"expected multi-envelope IXFR, got {len(env)}"
        parsed = [dc.parse_message(e) for e in env]
        assert any(m["tsig"] is None for m in parsed)
        info = _rfc_verify_transfer(env, key, req_mac, expect_periodic=True)
        answers = [a for m in parsed for a in m["answers"]]
        soa_serials = [dc.soa_serial(r["rdata"]) for r in answers
                       if r["type"] == TYPE_SOA]
        assert soa_serials[0] == 12 and soa_serials[-1] == 12
        print(f"  multi-message IXFR: {len(env)} envelopes, "
              f"signed at {info['signed']}; continuous chain OK")

        # ---- streaming, not cached: first envelope arrives before the rest
        # are generated and the pin is OPEN while the generator is paused. ----
        Config.XFER_MESSAGE_BUDGET = 400
        logic = DNSLogic(db)
        q = w.parse_query(dc.build_tsig_query(0x7778, zone, TYPE_AXFR,
                                              kname, key))
        gen = transfer_envelopes(logic, q, interval=2)
        first = next(gen)
        assert dc.parse_message(first)["tsig"] is not None
        open_while_streaming = db.conn.execute(
            "SELECT COUNT(*) AS c FROM transfer_refs WHERE state='OPEN'"
        ).fetchone()["c"]
        assert open_while_streaming >= 1, "pin must be live mid-stream"
        rest = list(gen)
        assert rest, "streaming transfer stopped after first envelope"
        after = db.conn.execute(
            "SELECT COUNT(*) AS c FROM transfer_refs WHERE state='OPEN'"
        ).fetchone()["c"]
        assert after == 0, "pin must be released after the generator exhausts"
        print("  envelopes produced lazily one at a time; pin released at end")
    finally:
        db.conn.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(path + suffix)
            except FileNotFoundError:
                pass


def main() -> int:
    print("RFC 2845 TSIG conformance probe")
    print("[1] fixed deterministic MAC vs independent standard formula")
    scenario_fixed_mac()
    print("[2] inbound request auth + response signature, independent logic")
    scenario_request_and_response_standard()
    print("[3] single-message AXFR/IXFR through the streaming pipeline")
    print("[4] multi-message AXFR/IXFR (unsigned middles, periodic TSIG, "
          "continuous chain, streaming)")
    scenario_transfers()
    print("[5] third-party oracle cross-check (best effort)")
    _dnspython_crosscheck()
    print("ALL RFC 2845 TSIG CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
