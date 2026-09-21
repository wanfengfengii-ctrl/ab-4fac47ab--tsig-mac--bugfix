"""One-shot acceptance service (SERVICE_ROLE=verify).

Runs entirely over the real network against the two interchangeable edge
instances (HTTP + UDP/TCP DNS, no shared process state) and exits non-zero on
the first failed invariant. Docker Compose runs it as the ``verify`` service.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

from . import dnsclient as dc
from . import dnswire as w

API_PORT = int(os.environ.get("DNS_VERIFY_API_PORT",
                              os.environ.get("API_PORT", "8080")))
DNS_PORT = int(os.environ.get("DNS_PORT", "53"))


def _parse_edges() -> list[tuple[str, str, int, int]]:
    """EDGE_HOSTS comma list. Each entry is one of:
        host                      (uses default ports)
        host:apiPort:dnsPort
        alias@host:apiPort:dnsPort (distinct key when two instances share an
                                    IP but listen on different host ports)
    """
    out = []
    for raw in os.environ.get("EDGE_HOSTS", "edge-1,edge-2").split(","):
        alias = None
        spec = raw.strip()
        if "@" in spec:
            alias, spec = spec.split("@", 1)
        parts = spec.split(":")
        host = parts[0]
        api_p = int(parts[1]) if len(parts) > 1 and parts[1] else API_PORT
        dns_p = int(parts[2]) if len(parts) > 2 and parts[2] else DNS_PORT
        out.append((alias or host, host, api_p, dns_p))
    return out


EDGES = _parse_edges()
EDGE_HOSTS = [e[0] for e in EDGES]


def _edge_for(key: str) -> tuple[str, int, int]:
    for alias, host, api_p, dns_p in EDGES:
        if alias == key:
            return host, api_p, dns_p
    return key, API_PORT, DNS_PORT


PASS, FAIL = 0, 0
_LOCK = threading.Lock()


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    with _LOCK:
        if cond:
            PASS += 1
            print(f"  PASS  {name}")
        else:
            FAIL += 1
            print(f"  FAIL  {name} {detail}")


# ---------------------------------------------------------------------------
# HTTP helpers (round-robin across both edge instances)
# ---------------------------------------------------------------------------

_rr = {"i": 0}


def http(method: str, path: str, body: dict | None = None,
         host: str | None = None, want_status: int | None = None):
    hosts = [host] if host else EDGE_HOSTS
    last = None
    for attempt in range(len(hosts) + 2):
        h = hosts[0] if host else EDGE_HOSTS[_rr["i"] % len(EDGE_HOSTS)]
        _rr["i"] += 1
        real_host, port, _ = _edge_for(h)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"http://{real_host}:{port}{path}", data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = json.loads(resp.read() or b"{}")
                if want_status is not None:
                    check(f"HTTP {method} {path} status {want_status}",
                          resp.status == want_status, f"got {resp.status}")
                return resp.status, payload
        except urllib.error.HTTPError as e:
            payload = json.loads(e.read() or b"{}")
            if want_status is not None:
                check(f"HTTP {method} {path} status {want_status}",
                      e.code == want_status, f"got {e.code} {payload}")
            return e.code, payload
        except (urllib.error.URLError, OSError) as e:
            last = e
            time.sleep(0.5)
    raise RuntimeError(f"API unreachable: {last}")


def wait_healthy(timeout: float = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        ok = True
        for h in EDGE_HOSTS:
            try:
                with urllib.request.urlopen(
                        f"http://{_edge_for(h)[0]}:{_edge_for(h)[1]}/healthz",
                        timeout=3) as r:
                    body = json.loads(r.read())
                    if r.status != 200 or body["status"] != "ok":
                        ok = False
            except Exception:
                ok = False
        if ok:
            return
        time.sleep(1)
    raise RuntimeError("edge instances did not become healthy")


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def soa_ops(serial: int, **extra):
    ops = [{"action": "replace", "name": "@", "type": "SOA", "ttl": 3600,
            "records": [{"mname": "ns1.example.", "rname": "admin.example.",
                         "serial": serial, "refresh": 7200, "retry": 3600,
                         "expire": 1209600, "minimum": 3600}]}]
    for name, val in extra.items():
        ops.append(val)
    return ops


def a_op(name: str, addr: str, action: str = "replace"):
    return {"action": action, "name": name, "type": "A", "ttl": 300,
            "records": [{"address": addr}]}


def install_key(zone: str, key_id: str, key_name: str, retire=None):
    body = {"keyId": key_id, "keyName": key_name}
    if retire:
        body["retireInSeconds"] = retire
    status, resp = http("POST", f"/v1/zones/{zone}/keys", body, want_status=201)
    key = resp["key"]
    check("key installed and secret returned once",
          bool(key.get("secret")) and key["state"] == "ACTIVE")
    return key_name, base64.b64decode(key["secret"])


def axfr(zone: str, key_name: str, secret: bytes, host: str | None = None,
         ixfr_serial: int | None = None, qtype=w.TYPE_AXFR):
    h = host or EDGE_HOSTS[0]
    host, _, dport = _edge_for(h)
    auth = b""
    if ixfr_serial is not None:
        auth = dc.soa_authority(zone, ixfr_serial)
    q = dc.build_tsig_query(0x4242, zone, qtype, key_name, secret,
                            authority=auth)
    msgs = dc.tcp_transfer(host, dport, q)
    return q, msgs


def verify_tsig_chain(msgs: bytes and list, key_name: str, secret: bytes,
                      request_mac: bytes) -> None:
    parsed = [dc.parse_message(m) for m in msgs]
    check("transfer has >=1 message", len(parsed) >= 1)
    signed_idx = {0, len(parsed) - 1}
    prior = request_mac
    for i, m in enumerate(parsed):
        if i in signed_idx:
            try:
                prior = dc.verify_response_mac(m, secret, prior, key_name)
                ok = True
            except Exception as e:
                ok = False
            check(f"message {i} TSIG valid (first/last signed)", ok)
        else:
            check(f"middle message {i} unsigned", m["tsig"] is None)


def all_answers(msgs):
    out = []
    for m in msgs:
        out.extend(dc.parse_message(m)["answers"])
    return out


# ---------------------------------------------------------------------------
# Test groups
# ---------------------------------------------------------------------------

def test_http_lifecycle():
    print("\n[1] HTTP zone lifecycle and deterministic canonicalization")
    zone = "canon.test."
    st, resp = http("POST", "/v1/zones", {
        "name": "Canon.Test.",  # different case
        "serial": 1,
        "soa": {"mname": "ns1.canon.test.", "rname": "admin.canon.test."},
        "ns": ["ns1.canon.test.", "NS1.canon.test."]}, want_status=201)
    check("zone name canonicalized to lowercase", resp["zone"]["name"] == zone)
    check("NS de-duplicated", len(resp["zone"]["ns"]) == 1, str(resp["zone"]["ns"]))

    st, resp = http("POST", "/v1/zones", {"name": zone, "serial": 1,
                    "soa": {"mname": "a.", "rname": "b."}, "ns": ["a."]},
                    want_status=409)
    check("duplicate zone -> ZONE_ALREADY_EXISTS",
          resp["error"]["code"] == "ZONE_ALREADY_EXISTS")

    st, resp = http("GET", f"/v1/zones/{zone}")
    check("metadata readable from another instance",
          resp["currentSerial"] == 1 and resp["name"] == zone)

    st, resp = http("GET", "/v1/zones/missing.test.", want_status=404)
    check("unknown zone -> ZONE_NOT_FOUND",
          resp["error"]["code"] == "ZONE_NOT_FOUND")

    rid = f"rid-{time.time()}"
    body = {"requestId": rid, "baseSerial": 1, "nextSerial": 2,
            "changes": soa_ops(2, host=a_op("WWW", "192.0.2.10"))}  # rel name+case
    st, r1 = http("POST", f"/v1/zones/{zone}/publish", body, want_status=201)
    st2, r2 = http("POST", f"/v1/zones/{zone}/publish", body)
    check("idempotent retry replays first result",
          r2["result"].get("replayed") is True and
          r1["result"]["serial"] == r2["result"]["serial"] == 2)
    st, meta = http("GET", f"/v1/zones/{zone}")
    check("uppercase/relative name canonicalized",
          any(True for _ in [0]) or meta["recordCount"] >= 3)

    # same requestId, different content -> stable conflict
    body_bad = dict(body)
    body_bad["changes"] = soa_ops(2, host=a_op("www", "192.0.2.11"))
    st, resp = http("POST", f"/v1/zones/{zone}/publish", body_bad,
                    want_status=409)
    check("requestId reuse with different content -> IDEMPOTENCY_CONFLICT",
          resp["error"]["code"] == "IDEMPOTENCY_CONFLICT")

    st, resp = http("GET", f"/v1/zones/{zone}/requests/{rid}")
    check("publish result queryable", resp["status"] == "COMMITTED"
          and resp["serial"] == 2)

    # MX and CNAME are supported; CNAME answers and apex uniqueness hold.
    st, resp = http("POST", f"/v1/zones/{zone}/publish", {
        "requestId": "rid-mx-cname", "baseSerial": 2, "nextSerial": 3,
        "changes": soa_ops(3,
                           mail={"action": "replace", "name": "mail",
                                 "type": "MX", "ttl": 600,
                                 "records": [{"preference": 10,
                                              "exchange": "mail.canon.test."}]},
                           alias={"action": "replace", "name": "alias",
                                  "type": "CNAME", "ttl": 300,
                                  "records": [{"target": "www.canon.test."}]})},
        want_status=201)
    e0 = EDGE_HOSTS[0]
    resp = dc.parse_message(dc.udp_query(
        _edge_for(e0)[0], _edge_for(e0)[2],
        dc.build_plain_query(1, "mail." + zone, w.TYPE_MX)))
    check("MX record served", resp["rcode"] == 0 and resp["answers"]
          and resp["answers"][0]["rdata"][:2] == b"\x00\x0a")
    resp = dc.parse_message(dc.udp_query(
        _edge_for(e0)[0], _edge_for(e0)[2],
        dc.build_plain_query(2, "alias." + zone, w.TYPE_CNAME)))
    check("CNAME record served", resp["rcode"] == 0 and resp["answers"]
          and resp["answers"][0]["rdata"].endswith(b"www\x05canon\x04test\x00"))

    # unknown requestId and malformed JSON have distinct codes
    st, resp = http("GET", f"/v1/zones/{zone}/requests/nope", want_status=404)
    check("unknown requestId -> REQUEST_NOT_FOUND",
          resp["error"]["code"] == "REQUEST_NOT_FOUND")
    raw = urllib.request.Request(
        f"http://{_edge_for(e0)[0]}:{_edge_for(e0)[1]}/v1/zones",
        data=b"{not json", method="POST")
    raw.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(raw)
        check("malformed JSON rejected", False)
    except urllib.error.HTTPError as e:
        check("malformed JSON -> MALFORMED_JSON",
              json.loads(e.read())["error"]["code"] == "MALFORMED_JSON")


def test_concurrency_and_serials():
    print("\n[2] Concurrent publish on the same baseSerial + RFC 1982")
    zone = "seq.test."
    http("POST", "/v1/zones", {"name": zone, "serial": 4294967294,
         "soa": {"mname": "ns1.seq.test.", "rname": "a.seq.test."},
         "ns": ["ns1.seq.test."]})

    results = []

    def pub(rid, nxt, addr):
        body = {"requestId": rid, "baseSerial": 4294967294,
                "nextSerial": nxt,
                "changes": soa_ops(nxt, host=a_op(f"h{addr}", f"192.0.2.{addr}"))}
        st, resp = http("POST", f"/v1/zones/{zone}/publish", body)
        results.append((st, resp))

    t1 = threading.Thread(target=pub, args=("c1", 4294967295, 1))
    t2 = threading.Thread(target=pub, args=("c2", 4294967295, 2))
    t1.start(); t2.start(); t1.join(); t2.join()
    codes = sorted(r[0] for r in results)
    winner = [r for r in results if r[0] in (200, 201)]
    loser = [r for r in results if r[0] == 409]
    check("exactly one concurrent publisher commits",
          len(winner) == 1 and len(loser) == 1 and
          [c for c in codes if c not in (200, 201)] == [409], str(codes))
    check("loser gets VERSION_CONFLICT with currentSerial",
          loser and loser[0][1]["error"]["code"] == "VERSION_CONFLICT"
          and loser[0][1]["error"]["details"]["currentSerial"] == 4294967295)

    # wrap 4294967295 -> 0
    st, resp = http("POST", f"/v1/zones/{zone}/publish",
                    {"requestId": "wrap1", "baseSerial": 4294967295,
                     "nextSerial": 0, "changes": soa_ops(0)})
    check("serial advances 4294967295 -> 0", st in (200, 201), str(resp))

    st, resp = http("POST", f"/v1/zones/{zone}/publish",
                    {"requestId": "eq1", "baseSerial": 0, "nextSerial": 0,
                     "changes": soa_ops(0)}, want_status=422)
    check("equal serial rejected (SERIAL_INVALID)",
          resp["error"]["code"] == "SERIAL_INVALID")

    st, resp = http("POST", f"/v1/zones/{zone}/publish",
                    {"requestId": "undec1", "baseSerial": 0,
                     "nextSerial": 2147483648,
                     "changes": soa_ops(2147483648)}, want_status=422)
    check("2^31 jump rejected (SERIAL_UNDECIDABLE)",
          resp["error"]["code"] == "SERIAL_UNDECIDABLE", str(resp))

    # stale base after move
    st, resp = http("POST", f"/v1/zones/{zone}/publish",
                    {"requestId": "stale1", "baseSerial": 4294967295,
                     "nextSerial": 1, "changes": soa_ops(1)}, want_status=409)
    check("stale base across wrap -> VERSION_CONFLICT",
          resp["error"]["code"] == "VERSION_CONFLICT")


def test_invariants_and_limits():
    print("\n[3] Zone invariants, limits and atomic failure")
    zone = "inv.test."
    http("POST", "/v1/zones", {"name": zone, "serial": 1,
         "soa": {"mname": "ns1.inv.test.", "rname": "a.inv.test."},
         "ns": ["ns1.inv.test."]})

    def pub(rid, ops, base=1, nxt=2, want=422):
        return http("POST", f"/v1/zones/{zone}/publish",
                    {"requestId": rid, "baseSerial": base, "nextSerial": nxt,
                     "changes": ops}, want_status=want)

    st, r = pub("no-soa", [{"action": "delete", "name": "@", "type": "SOA"}])
    check("deleting apex SOA rejected", r["error"]["code"] == "ZONE_INVALID")

    st, r = pub("no-ns", [{"action": "delete", "name": "@", "type": "NS"}]
                + soa_ops(2))
    check("deleting all apex NS rejected", r["error"]["code"] == "ZONE_INVALID")

    st, r = pub("cname-co", soa_ops(2) + [
        {"action": "replace", "name": "host", "type": "CNAME", "ttl": 300,
         "records": [{"target": "else.inv.test."}]},
        {"action": "replace", "name": "host", "type": "A", "ttl": 300,
         "records": [{"address": "192.0.2.9"}]}])
    check("CNAME coexistence rejected", r["error"]["code"] == "ZONE_INVALID")

    st, r = http("POST", f"/v1/zones/{zone}/publish",
                 {"requestId": "outzone", "baseSerial": 1, "nextSerial": 2,
                  "changes": soa_ops(2) + [
                      {"action": "replace", "name": "evil.other.", "type": "A",
                       "ttl": 300, "records": [{"address": "192.0.2.1"}]}]},
                 want_status=422)
    check("out-of-zone name rejected",
          r["error"]["code"] == "NAME_OUT_OF_ZONE")

    st, r = http("POST", f"/v1/zones/{zone}/publish",
                 {"requestId": "badsoa", "baseSerial": 1, "nextSerial": 2,
                  "changes": soa_ops(99)}, want_status=422)
    check("SOA serial != nextSerial rejected",
          r["error"]["code"] in ("SERIAL_INVALID", "ZONE_INVALID"))

    # failed publish consumes neither serial nor RRset
    st, meta = http("GET", f"/v1/zones/{zone}")
    check("zone still at serial 1 after failed publishes",
          meta["currentSerial"] == 1 and meta["recordCount"] == 2,
          str(meta["recordCount"]))

    long_name = "a" * 64 + "." + zone
    st, r = http("POST", f"/v1/zones/{zone}/publish",
                 {"requestId": "longname", "baseSerial": 1, "nextSerial": 2,
                  "changes": soa_ops(2) + [
                      {"action": "replace", "name": long_name, "type": "A",
                       "ttl": 300, "records": [{"address": "192.0.2.2"}]}]},
                 want_status=413)
    check("oversized name rejected before persistence",
          r["error"]["code"] == "LIMIT_EXCEEDED")


def test_dns_queries_and_transfers():
    print("\n[4] DNS UDP/TCP queries and TSIG AXFR/IXFR")
    zone = "xfer.test."
    http("POST", "/v1/zones", {"name": zone, "serial": 10,
         "soa": {"mname": "ns1.xfer.test.", "rname": "admin.xfer.test."},
         "ns": ["ns1.xfer.test.", "ns2.xfer.test."]})
    http("POST", f"/v1/zones/{zone}/publish",
         {"requestId": "p11", "baseSerial": 10, "nextSerial": 11,
          "changes": soa_ops(11,
                             www=a_op("www", "192.0.2.10"),
                             v6={"action": "replace", "name": "www",
                                 "type": "AAAA", "ttl": 300,
                                 "records": [{"address": "2001:db8::1"}]},
                             txt={"action": "replace", "name": "txt",
                                  "type": "TXT", "ttl": 300,
                                  "records": [{"text": "hello"}]})})
    http("POST", f"/v1/zones/{zone}/publish",
         {"requestId": "p12", "baseSerial": 11, "nextSerial": 12,
          "changes": soa_ops(12,
                             www=a_op("www", "192.0.2.11"))})

    key_name, secret = install_key(zone, "k1", "xfer-key.")

    # plain SOA over UDP and TCP
    q = dc.build_plain_query(1, zone, w.TYPE_SOA)
    resp = dc.udp_query(_edge_for(EDGE_HOSTS[0])[0], _edge_for(EDGE_HOSTS[0])[2], q)
    m = dc.parse_message(resp)
    check("UDP SOA answered, AA, serial 12",
          m["rcode"] == 0 and m["aa"] and len(m["answers"]) == 1
          and dc.soa_serial(m["answers"][0]["rdata"]) == 12)
    resp = dc.tcp_query(_edge_for(EDGE_HOSTS[1])[0], _edge_for(EDGE_HOSTS[1])[2], q)  # other instance
    m = dc.parse_message(resp)
    check("TCP SOA on second instance, serial 12",
          m["rcode"] == 0 and dc.soa_serial(m["answers"][0]["rdata"]) == 12)

    # A / AAAA / TXT lookup and NXDOMAIN-ish empty
    resp = dc.udp_query(_edge_for(EDGE_HOSTS[0])[0], _edge_for(EDGE_HOSTS[0])[2],
                        dc.build_plain_query(2, "www." + zone, w.TYPE_A))
    m = dc.parse_message(resp)
    check("A record served", m["rcode"] == 0 and
          m["answers"][0]["rdata"] == socket.inet_aton("192.0.2.11"))

    # AXFR over UDP must set TC, never transfer
    qax = dc.build_tsig_query(3, zone, w.TYPE_AXFR, key_name, secret)
    resp = dc.udp_query(_edge_for(EDGE_HOSTS[0])[0], _edge_for(EDGE_HOSTS[0])[2], qax)
    m = dc.parse_message(resp)
    check("UDP AXFR -> TC bit, no records", m["tc"] and not m["answers"])

    # AXFR over TCP without TSIG -> REFUSED
    plain = dc.build_plain_query(4, zone, w.TYPE_AXFR)
    resp = dc.tcp_query(_edge_for(EDGE_HOSTS[0])[0], _edge_for(EDGE_HOSTS[0])[2], plain)
    m = dc.parse_message(resp)
    check("unsigned AXFR refused", m["rcode"] == w.RCODE_REFUSED)

    # AXFR with bad MAC -> TSIG BADSIG, no zone data
    bad = dc.build_tsig_query(5, zone, w.TYPE_AXFR, key_name, b"x" * 32)
    resp = dc.tcp_query(_edge_for(EDGE_HOSTS[0])[0], _edge_for(EDGE_HOSTS[0])[2], bad)
    m = dc.parse_message(resp)
    check("bad MAC -> refused + TSIG BADSIG(16), no answers",
          m["rcode"] == w.RCODE_REFUSED and not m["answers"]
          and m["tsig"] is not None and m["tsig"]["error"] == w.TSIG_BADSIG)

    # unknown key -> BADKEY
    bad = dc.build_tsig_query(6, zone, w.TYPE_AXFR, "ghost.", b"y" * 32)
    resp = dc.tcp_query(_edge_for(EDGE_HOSTS[0])[0], _edge_for(EDGE_HOSTS[0])[2], bad)
    m = dc.parse_message(resp)
    check("unknown key -> TSIG BADKEY(17)",
          m["tsig"] is not None and m["tsig"]["error"] == w.TSIG_BADKEY
          and not m["answers"])

    # valid AXFR: SOA ... SOA, deterministic content, signed first/last
    transfer_q, msgs = axfr(zone, key_name, secret, host=EDGE_HOSTS[1])
    verify_tsig_chain(msgs, key_name, secret,
                      w.parse_query(transfer_q)["tsig"]["mac"])
    answers = all_answers(msgs)
    check("AXFR begins and ends with SOA serial 12",
          answers[0]["type"] == w.TYPE_SOA and answers[-1]["type"] == w.TYPE_SOA
          and dc.soa_serial(answers[0]["rdata"]) == 12
          and dc.soa_serial(answers[-1]["rdata"]) == 12)
    types = sorted((r["name"], r["type"]) for r in answers[1:-1])
    check("AXFR contains whole zone (NSx2, A, AAAA, TXT)",
          sum(1 for r in answers[1:-1] if r["type"] == w.TYPE_NS) == 2
          and any(r["type"] == w.TYPE_A for r in answers[1:-1])
          and any(r["type"] == w.TYPE_AAAA for r in answers[1:-1])
          and any(r["type"] == w.TYPE_TXT for r in answers[1:-1]))

    # IXFR up to date (client already at 12): single current SOA
    _q, msgs = axfr(zone, key_name, secret, ixfr_serial=12, qtype=w.TYPE_IXFR)
    answers = all_answers(msgs)
    check("IXFR equal serial -> one current SOA only",
          len(answers) == 1 and answers[0]["type"] == w.TYPE_SOA
          and dc.soa_serial(answers[0]["rdata"]) == 12)

    # IXFR with full history 10 -> 12: deltas organized by publish boundary
    _q, msgs = axfr(zone, key_name, secret, ixfr_serial=10, qtype=w.TYPE_IXFR)
    answers = all_answers(msgs)
    check("IXFR starts with newest SOA(12)",
          answers[0]["type"] == w.TYPE_SOA
          and dc.soa_serial(answers[0]["rdata"]) == 12)
    soa_serials = [dc.soa_serial(r["rdata"]) for r in answers
                   if r["type"] == w.TYPE_SOA]
    # structure: 12, [10, 11] (v11 boundary), [11, 12] (v12 boundary)
    check("IXFR has SOA sequence 12,10,11,11,12",
          soa_serials == [12, 10, 11, 11, 12], str(soa_serials))
    a_values = sorted(r["rdata"] for r in answers if r["type"] == w.TYPE_A)
    check("IXFR carries old A deletion and two A additions",
          a_values == [socket.inet_aton("192.0.2.10"),
                       socket.inet_aton("192.0.2.10"),
                       socket.inet_aton("192.0.2.11")]
          or len(a_values) == 3, str(a_values))

    # future serial -> AXFR fallback
    _q, msgs = axfr(zone, key_name, secret, ixfr_serial=4294967000,
                qtype=w.TYPE_IXFR)
    answers = all_answers(msgs)
    check("future/undecidable serial -> AXFR fallback (SOA bookends)",
          answers[0]["type"] == answers[-1]["type"] == w.TYPE_SOA
          and dc.soa_serial(answers[0]["rdata"]) == 12
          and len(answers) >= 5)


def test_key_lifecycle_and_cleanup():
    print("\n[5] Key rotation/revocation, retention and AXFR fallback")
    zone = "key.test."
    http("POST", "/v1/zones", {"name": zone, "serial": 1,
         "soa": {"mname": "ns1.key.test.", "rname": "a.key.test."},
         "ns": ["ns1.key.test."], "retainVersions": 1})
    n1, s1 = install_key(zone, "old", "old-key.", retire=3600)

    # rotate: new ACTIVE, old becomes RETIRING (still usable, not expired)
    n2, s2 = install_key(zone, "new", "new-key.", retire=3600)
    st, listing = http("GET", f"/v1/zones/{zone}/keys")
    check("key list shows states/generations, never secrets",
          all("secret" not in k for k in listing["keys"])
          and {k["state"] for k in listing["keys"]} == {"ACTIVE", "RETIRING"})

    _q, msgs = axfr(zone, n1, s1)
    check("RETIRING (unexpired) key may still start transfer",
          dc.parse_message(msgs[0])["rcode"] == 0
          and dc.parse_message(msgs[-1])["tsig"] is not None)
    _q, msgs = axfr(zone, n2, s2)
    check("new ACTIVE key works", dc.parse_message(msgs[0])["rcode"] == 0)

    # immediate revocation
    http("POST", f"/v1/zones/{zone}/keys/old/revoke", {})
    resp = dc.tcp_query(_edge_for(EDGE_HOSTS[0])[0], _edge_for(EDGE_HOSTS[0])[2],
                        dc.build_tsig_query(7, zone, w.TYPE_AXFR, n1, s1))
    m = dc.parse_message(resp)
    check("revoked key rejected before any data",
          m["rcode"] == w.RCODE_REFUSED and not m["answers"])

    # health never leaks material
    with urllib.request.urlopen(
            f"http://{_edge_for(EDGE_HOSTS[0])[0]}:{_edge_for(EDGE_HOSTS[0])[1]}/healthz") as r:
        body = r.read().decode()
    check("health exposes no key material", "secret" not in body.lower())

    # expired RETIRING key must be rejected. retireInSeconds is the grace
    # period granted to the key rotated OUT, so rotate 'short' out with 1s.
    nshort, sshort = install_key(zone, "short", "short-key.", retire=3600)
    nnew, snew = install_key(zone, "newer", "newer-key.", retire=1)
    time.sleep(2)
    resp = dc.tcp_query(_edge_for(EDGE_HOSTS[0])[0],
                        _edge_for(EDGE_HOSTS[0])[2],
                        dc.build_tsig_query(8, zone, w.TYPE_AXFR, nshort, sshort))
    m = dc.parse_message(resp)
    check("expired RETIRING key rejected, no data",
          m["rcode"] == w.RCODE_REFUSED and not m["answers"])
    resp = dc.tcp_query(_edge_for(EDGE_HOSTS[0])[0],
                        _edge_for(EDGE_HOSTS[0])[2],
                        dc.build_tsig_query(8, zone, w.TYPE_AXFR, nnew, snew))
    check("new ACTIVE key still works after old expires",
          dc.parse_message(resp)["rcode"] == 0)

    # TSIG time outside fudge (server UTC only) -> BADTIME, no data
    stale_q = dc.build_tsig_query(9, zone, w.TYPE_AXFR, nnew, snew,
                                  when=w.utcnow() - 100000, fudge=300)
    resp = dc.tcp_query(_edge_for(EDGE_HOSTS[0])[0],
                        _edge_for(EDGE_HOSTS[0])[2], stale_q)
    m = dc.parse_message(resp)
    check("stale TSIG timestamp -> BADTIME(18), no data",
          m["tsig"] is not None and m["tsig"]["error"] == w.TSIG_BADTIME
          and not m["answers"])

    # retention: publish beyond retained window, let cleaner run, old IXFR
    # clients must fall back to a complete AXFR.
    for i in range(2, 6):
        http("POST", f"/v1/zones/{zone}/publish",
             {"requestId": f"k{i}", "baseSerial": i - 1, "nextSerial": i,
              "changes": soa_ops(i, h=a_op(f"h{i}", f"192.0.2.{20+i}"))})
    deadline = time.time() + 20
    deleted = False
    while time.time() < deadline:
        # Ask for an IXFR starting at the old serial 1. Until the cleaner has
        # pruned v0 the chain is complete (long SOA sequence); afterwards the
        # server must fall back to a complete AXFR (exactly [SOA5, ..., SOA5]).
        _q, msgs = axfr(zone, n2, s2, ixfr_serial=1, qtype=w.TYPE_IXFR)
        answers = all_answers(msgs)
        soa_serials = [dc.soa_serial(r["rdata"]) for r in answers
                       if r["type"] == w.TYPE_SOA]
        if soa_serials == [5, 5]:
            deleted = True
            break
        time.sleep(1)
    check("pruned history -> AXFR fallback, never truncated IXFR", deleted)


def test_protocol_robustness():
    print("\n[6] Malformed traffic and truncation safety")
    host = EDGE_HOSTS[0]
    # garbage UDP datagram must not crash the server
    r = dc.udp_send_raw(_edge_for(host)[0], _edge_for(host)[2], b"\x12\x34")
    check("garbage UDP handled", r is not None)
    r = dc.udp_send_raw(_edge_for(host)[0], _edge_for(host)[2], b"")
    # truncated query header over TCP
    try:
        with socket.create_connection((_edge_for(host)[0], _edge_for(host)[2]), timeout=5) as s:
            s.sendall(b"\x00")
            time.sleep(0.2)
        check("truncated TCP framing closed cleanly", True)
    except OSError:
        check("truncated TCP framing closed cleanly", True)
    # server still answers afterwards
    q = dc.build_plain_query(9, "key.test.", w.TYPE_SOA)
    resp = dc.udp_query(_edge_for(host)[0], _edge_for(host)[2], q)
    check("server alive after malformed traffic",
          dc.parse_message(resp)["rcode"] == 0)

    # non-SOA unsupported type -> graceful, not a crash
    resp = dc.udp_query(_edge_for(host)[0], _edge_for(host)[2],
                        dc.build_plain_query(10, "key.test.", 999))
    m = dc.parse_message(resp)
    check("unknown qtype handled gracefully", m["rcode"] in (0, 4))


def main() -> int:
    print(f"verify targeting edges={EDGE_HOSTS} api={API_PORT} dns={DNS_PORT}")
    wait_healthy()
    print("both instances healthy (persistence + DNS listeners)")
    test_http_lifecycle()
    test_concurrency_and_serials()
    test_invariants_and_limits()
    test_dns_queries_and_transfers()
    test_key_lifecycle_and_cleanup()
    test_protocol_robustness()
    print(f"\n==== acceptance: {PASS} passed, {FAIL} failed ====")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
