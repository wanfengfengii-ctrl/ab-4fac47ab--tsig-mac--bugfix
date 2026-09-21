"""Real DNS network endpoints: UDP/TCP SOA service and TSIG-authenticated
AXFR/IXFR zone transfers over TCP.

Transfer consistency
--------------------
Every transfer performs authentication, target selection and the in-flight
*pin* in one IMMEDIATE transaction, then streams from a dedicated connection
that holds a stable WAL snapshot. The pin records the target version, the
oldest version the IXFR delta chain needs and the authorized key generation.
Publishes, key rotation and history cleanup therefore cannot alter what an
already-started connection outputs, while later connections observe the new
state.
"""
from __future__ import annotations

import hmac
import json
import socket
import socketserver
import struct
import threading

from . import dnswire
from .config import Config
from .errors import ErrorCode
from .storage import Database, utcnow

def _transfer_budget() -> int:
    # Read at call time so tests (and operators, via env) can tune it.
    # Capped to leave room for the 2-byte TCP length and TSIG RR inside 65535.
    return min(Config.XFER_MESSAGE_BUDGET, 65000)


def _rr_wire(row, rtype: int | None = None) -> bytes:
    rt = rtype or dnswire.TYPES_BY_NAME[row["rtype"]]
    return dnswire.pack_rr(row["name"], rt, dnswire.CLASS_IN, row["ttl"],
                           row["rdata_wire"])


def _soa_row(db: Database, zone: str, version_id: int):
    return db.get_soa(zone, version_id)


def _question_for(zone: str, qtype: int) -> bytes:
    return dnswire.encode_name(zone) + struct.pack(">HH", qtype,
                                                   dnswire.CLASS_IN)


def _frame(msg: bytes) -> bytes:
    return struct.pack(">H", len(msg)) + msg


class _ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# Message assembly
# ---------------------------------------------------------------------------

def _rr_batches(qid: int, question: bytes, rr_iter, budget: int,
                tsig_space: int):
    """Greedy streaming packer: pull RRs from *rr_iter* and yield plain (still
    unsigned) DNS messages. Only one message plus a small RR buffer is held in
    memory at a time, so a whole zone is never resident per transfer."""
    base_header = 12 + len(question)
    room = budget - tsig_space
    cur, cur_len = [], base_header

    def flush():
        return _wrap(qid, question, cur)

    for rr in rr_iter:
        if cur and cur_len + len(rr) > room:
            yield flush()
            cur, cur_len = [], base_header
        cur.append(rr)
        cur_len += len(rr)
    yield flush()


def _wrap(qid: int, question: bytes, answers: list[bytes]) -> bytes:
    flags = dnswire.FLAG_QR | dnswire.FLAG_AA | dnswire.RCODE_NOERROR
    msg = dnswire.build_header(qid, flags, 1, len(answers), 0, 0) + question
    msg += b"".join(answers)
    return msg


# ---------------------------------------------------------------------------
# Query answering (non-transfer)
# ---------------------------------------------------------------------------

class DNSLogic:
    def __init__(self, db: Database):
        self.db = db

    def answer_question(self, q: dict) -> tuple[int, bytes | None]:
        """Return (rcode, optional response-without-question)."""
        if q["qclass"] not in (dnswire.CLASS_IN, dnswire.CLASS_ANY):
            return dnswire.RCODE_REFUSED, None
        z = self.db.find_zone_by_name(q["qname"])
        if z is None:
            return dnswire.RCODE_REFUSED, None
        zone = z["name"]
        if q["qname"] != zone and not q["qname"].endswith("." + zone):
            return dnswire.RCODE_REFUSED, None
        qt = q["qtype"]
        if qt in (dnswire.TYPE_AXFR, dnswire.TYPE_IXFR):
            return -1, None  # signals: TC on UDP, transfer handling on TCP
        version = z["current_version"]
        if qt == dnswire.TYPE_ANY:
            rows = list(self.db.conn.execute(
                "SELECT * FROM records WHERE zone=? AND version_id=? AND name=? "
                "ORDER BY rtype,rdata", (zone, version, q["qname"])))
        else:
            tname = dnswire.TYPES_BY_VALUE.get(qt)
            if tname is None:
                return dnswire.RCODE_NOTIMP, None
            rows = list(self.db.conn.execute(
                "SELECT * FROM records WHERE zone=? AND version_id=? AND name=? "
                "AND rtype=? ORDER BY rdata",
                (zone, version, q["qname"], tname)))
        if not rows:
            exists = self.db.conn.execute(
                "SELECT 1 FROM records WHERE zone=? AND version_id=? AND name=? "
                "LIMIT 1", (zone, version, q["qname"])).fetchone()
            return (dnswire.RCODE_NOERROR if exists else dnswire.RCODE_NXDOMAIN), \
                b""
        return dnswire.RCODE_NOERROR, b"".join(_rr_wire(r) for r in rows)

    # ------------------------------------------------------------- transfers
    def authorize_transfer(self, q: dict) -> dict:
        """One IMMEDIATE transaction: key policy + MAC + version decision + pin.

        Returns a plan dict; raises _TransferDenied with a TSIG error code on
        any authentication/authorization failure (before zone data is read for
        output)."""
        db = self.db
        conn = db.conn
        t = q.get("tsig")
        if t is None:
            raise _TransferDenied(None)
        conn.execute("BEGIN IMMEDIATE")
        try:
            z = conn.execute("SELECT * FROM zones WHERE name=?",
                             (q["qname"],)).fetchone()
            if z is None:
                raise _TransferDenied(dnswire.TSIG_BADKEY)
            zone = z["name"]
            key = self._resolve_in_tx(conn, zone, t)
            if "error" in key:
                raise _TransferDenied(key["error"],
                                      server_time=key.get("serverTime"))
            expected = dnswire.expected_request_mac(key["secret"], q)
            if not hmac.compare_digest(expected, t["mac"]):
                raise _TransferDenied(dnswire.TSIG_BADSIG)

            target_version = z["current_version"]
            target_serial = z["current_serial"]
            mode = "AXFR" if q["qtype"] == dnswire.TYPE_AXFR else None
            min_version = target_version
            client_serial = q.get("client_soa_serial")

            if q["qtype"] == dnswire.TYPE_IXFR:
                mode = self._decide_ixfr(conn, zone, target_version,
                                         target_serial, client_serial)
                if mode == "IXFR":
                    start = conn.execute(
                        "SELECT version_id FROM versions WHERE zone=? AND serial=?",
                        (zone, client_serial)).fetchone()
                    min_version = start["version_id"]
                # AXFR fallback pins only the target version.
            ref_id = db.pin_transfer(zone, Config.INSTANCE_ID, target_version,
                                     min_version, key["generation"])
            conn.commit()
        except _TransferDenied:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            raise
        return {"mode": mode, "zone": zone, "targetVersion": target_version,
                "targetSerial": target_serial, "minVersion": min_version,
                "refId": ref_id, "keyName": t["name"],
                "secret": key["secret"], "qid": q["id"]}

    @staticmethod
    def _resolve_in_tx(conn, zone: str, t: dict) -> dict:
        rows = conn.execute("SELECT * FROM keys WHERE zone=? AND key_name=?",
                            (zone, t["name"])).fetchall()
        live = [r for r in rows if r["state"] != "REVOKED"]
        if not live:
            return {"error": dnswire.TSIG_BADKEY}
        if not dnswire.verify_tsig_time(t["time"], t["fudge"], utcnow()):
            return {"error": dnswire.TSIG_BADTIME, "serverTime": utcnow()}
        # expires_at is epoch milliseconds; TSIG time and "now" here are seconds.
        now_ms = utcnow() * 1000
        usable = [r for r in live
                  if r["state"] == "ACTIVE"
                  or r["expires_at"] is None or now_ms < r["expires_at"]]
        if not usable:
            return {"error": dnswire.TSIG_BADKEY}
        key = max(usable, key=lambda r: r["gen"])
        return {"keyId": key["key_id"], "generation": key["gen"],
                "secret": key["secret"], "state": key["state"]}

    @staticmethod
    def _decide_ixfr(conn, zone, target_version, target_serial,
                     client_serial) -> str:
        """All failure/ambiguity cases deliberately fall back to AXFR of the
        fixed target version: unknown serial, pruned history, future serial,
        undecidable RFC 1982 relation. Only a complete contiguous history from
        the client's serial yields IXFR."""
        from .serial import compare, SerialRelation
        if client_serial is None:
            return "AXFR"
        rel = compare(client_serial, target_serial)
        if rel == SerialRelation.EQUAL:
            return "IXFR"  # zero deltas: single current SOA
        if rel != SerialRelation.GREATER:
            return "AXFR"  # future / undecidable
        start = conn.execute(
            "SELECT version_id FROM versions WHERE zone=? AND serial=?",
            (zone, client_serial)).fetchone()
        if start is None:
            return "AXFR"  # unknown / pruned
        v0 = start["version_id"]
        if v0 >= target_version:
            return "AXFR"
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM versions WHERE zone=? AND version_id>? "
            "AND version_id<=?", (zone, v0, target_version)).fetchone()["c"]
        if count != target_version - v0:
            return "AXFR"  # history gap (cleaned): never a truncated chain
        return "IXFR"

    # -------------------------------------------------------- stream builders
    def axfr_rr_stream(self, snap, plan: dict):
        """Yield AXFR RRs straight from a streaming snapshot cursor:
        SOA(first), all other records in deterministic order, SOA(last)."""
        zone, v = plan["zone"], plan["targetVersion"]
        soa = snap.execute(
            "SELECT * FROM records WHERE zone=? AND version_id=? AND name=? "
            "AND rtype='SOA'", (zone, v, zone)).fetchone()
        yield _rr_wire(soa)
        cur = snap.execute(
            "SELECT name,rtype,ttl,rdata,rdata_wire FROM records "
            "WHERE zone=? AND version_id=? ORDER BY name,rtype,rdata",
            (zone, v))
        for r in cur:
            if not (r["name"] == zone and r["rtype"] == "SOA"):
                yield _rr_wire(r)
        yield _rr_wire(soa)

    def ixfr_rr_stream(self, snap, plan: dict, client_serial):
        """Yield RFC 1995 IXFR RRs by publish boundary (DEL section then ADD
        section per version), or a single current SOA when up to date."""
        from .serial import compare, SerialRelation
        zone, V = plan["zone"], plan["targetVersion"]
        target_soa = snap.execute(
            "SELECT * FROM records WHERE zone=? AND version_id=? AND name=? "
            "AND rtype='SOA'", (zone, V, zone)).fetchone()
        yield _rr_wire(target_soa)  # response always opens with newest SOA
        if client_serial is None or compare(
                client_serial, plan["targetSerial"]) != SerialRelation.GREATER:
            return  # equal (or fallback handled upstream): one SOA only
        v0 = snap.execute(
            "SELECT version_id FROM versions WHERE zone=? AND serial=?",
            (zone, client_serial)).fetchone()["version_id"]
        for vid in range(v0 + 1, V + 1):
            cur = snap.execute(
                "SELECT seq,op,name,rtype,ttl,rdata,rdata_wire FROM changes "
                "WHERE zone=? AND version_id=? ORDER BY seq", (zone, vid))
            for ch in cur:
                yield dnswire.pack_rr(
                    ch["name"], dnswire.TYPES_BY_NAME[ch["rtype"]],
                    dnswire.CLASS_IN, ch["ttl"], ch["rdata_wire"])


class _TransferDenied(Exception):
    def __init__(self, tsig_error, server_time=None):
        super().__init__("transfer denied")
        self.tsig_error = tsig_error
        self.server_time = server_time


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------

class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        logic: DNSLogic = self.server.logic
        try:
            q = dnswire.parse_query(data)
        except dnswire.WireError:
            # Cannot trust the question bytes; send a bare FORMERR header.
            resp = dnswire.build_header(0, dnswire.FLAG_QR | dnswire.RCODE_FORMERR,
                                        0, 0, 0, 0)
            sock.sendto(resp[:512], self.client_address)
            return
        try:
            if q["qtype"] in (dnswire.TYPE_AXFR, dnswire.TYPE_IXFR):
                resp = dnswire.make_simple_response(q["id"], q["raw_question"],
                                                    dnswire.RCODE_NOERROR,
                                                    aa=True, tc=True)
            else:
                rcode, answers = logic.answer_question(q)
                if answers is None:
                    resp = dnswire.make_simple_response(q["id"],
                                                        q["raw_question"], rcode)
                elif answers == b"":
                    resp = dnswire.make_simple_response(q["id"],
                                                        q["raw_question"], rcode)
                else:
                    resp = dnswire.make_simple_response(q["id"],
                                                        q["raw_question"], rcode,
                                                        [answers])
                    if len(resp) > Config.MAX_UDP_PAYLOAD:
                        resp = dnswire.make_simple_response(
                            q["id"], q["raw_question"], rcode, aa=True, tc=True)
        except Exception:
            resp = dnswire.make_simple_response(q["id"], q["raw_question"],
                                                dnswire.RCODE_SERVFAIL)
        try:
            sock.sendto(resp, self.client_address)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

class TCPHandler(socketserver.BaseRequestHandler):
    timeout = Config.XFER_IDLE_TIMEOUT

    def handle(self):
        self.request.settimeout(Config.XFER_IDLE_TIMEOUT)
        try:
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF,
                                    Config.XFER_SNDBUF)
        except OSError:
            pass
        logic: DNSLogic = self.server.logic
        try:
            msg = self._read_message()
            if msg is None:
                return
            try:
                q = dnswire.parse_query(msg)
            except dnswire.WireError:
                bare = dnswire.build_header(
                    0, dnswire.FLAG_QR | dnswire.RCODE_FORMERR, 0, 0, 0, 0)
                self.request.sendall(_frame(bare))
                return
            try:
                if q["qtype"] in (dnswire.TYPE_AXFR, dnswire.TYPE_IXFR):
                    self._handle_transfer(logic, q)
                else:
                    self._handle_simple(logic, q)
            except _TransferDenied as denied:
                self._deny(q, denied)
        except (OSError, socket.timeout):
            pass  # client went away / idle timeout
        except Exception:
            try:
                bare = dnswire.build_header(
                    0, dnswire.FLAG_QR | dnswire.RCODE_SERVFAIL, 0, 0, 0, 0)
                self.request.sendall(_frame(bare))
            except OSError:
                pass

    def _read_message(self) -> bytes | None:
        head = self._recv_exact(2)
        if head is None:
            return None
        (length,) = struct.unpack(">H", head)
        if length < 12 or length > Config.MAX_TCP_MESSAGE:
            return None
        return self._recv_exact(length)

    def _recv_exact(self, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.request.recv(n - len(buf))
            except (ConnectionResetError, socket.timeout):
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _handle_simple(self, logic: DNSLogic, q: dict) -> None:
        rcode, answers = logic.answer_question(q)
        if answers is None:
            resp = dnswire.make_simple_response(q["id"], q["raw_question"], rcode)
        elif answers == b"":
            resp = dnswire.make_simple_response(q["id"], q["raw_question"], rcode)
        else:
            resp = dnswire.make_simple_response(q["id"], q["raw_question"], rcode,
                                                [answers])
        if len(resp) > Config.MAX_TCP_MESSAGE:
            resp = dnswire.make_simple_response(q["id"], q["raw_question"],
                                                dnswire.RCODE_SERVFAIL)
        self.request.sendall(_frame(resp))

    def _deny(self, q: dict, denied: _TransferDenied) -> None:
        # No zone data has been read for output; echo a TSIG error (or plain
        # REFUSED when no TSIG was presented).
        if denied.tsig_error is None or q.get("tsig") is None:
            resp = dnswire.make_simple_response(q["id"], q["raw_question"],
                                                dnswire.RCODE_REFUSED)
        else:
            resp = dnswire.make_error_response(q, dnswire.RCODE_REFUSED,
                                               denied.tsig_error)
        try:
            self.request.sendall(_frame(resp))
        except OSError:
            pass

    def _handle_transfer(self, logic: DNSLogic, q: dict) -> None:
        plan = logic.authorize_transfer(q)
        snap = None
        ref_id = plan["refId"]
        try:
            # Snapshot is taken after the pin commit: pinned versions cannot be
            # cleaned, and this WAL read transaction freezes what we stream.
            snap = logic.db.snapshot_conn()
            client_serial = q.get("client_soa_serial")
            if plan["mode"] == "AXFR":
                qtype = dnswire.TYPE_AXFR
                rr_iter = logic.axfr_rr_stream(snap, plan)
            else:
                qtype = dnswire.TYPE_IXFR
                rr_iter = logic.ixfr_rr_stream(snap, plan, client_serial)
            question = _question_for(plan["zone"], qtype)
            msg_iter = _rr_batches(q["id"], question, rr_iter,
                                   _transfer_budget(), tsig_space=400)
            self._stream_signed_transfer(logic, plan, q, msg_iter)
        finally:
            if snap is not None:
                try:
                    snap.close()
                except Exception:
                    pass
            logic.db.release_transfer(ref_id)

    def _stream_signed_transfer(self, logic, plan, q, msg_iter) -> None:
        """Send messages as they are produced, signing only the first and the
        last (RFC 2845) with the running-MAC chain. A one-message lookahead
        identifies the final message without buffering the whole transfer."""
        when = utcnow()
        key, key_name = plan["secret"], plan["keyName"]
        request_mac = q["tsig"]["mac"]
        first_signed_mac = None
        index = 0

        def send_indexed(i: int, plain: bytes, is_last: bool):
            nonlocal first_signed_mac
            if i == 0 or is_last:
                # First signs chaining from request MAC; last chains from the
                # first response MAC. When first==last, request MAC is used.
                if i == 0:
                    prior = request_mac
                else:
                    prior = first_signed_mac
                signed, mac = dnswire.sign_response(
                    key, plain, key_name, prior, when, 300, q["id"],
                    arcount_before=0)
                if i == 0:
                    first_signed_mac = mac
                out = signed
            else:
                out = plain
            self.request.sendall(_frame(out))
            try:
                logic.db.heartbeat_transfer(plan["refId"])
            except Exception:
                pass

        pending = None
        for plain in msg_iter:
            if pending is not None:
                send_indexed(index, pending, False)
                index += 1
            pending = plain
        # pending is the final message (transfers always yield >=1 message)
        send_indexed(index, pending, True)


def build_dns_servers(db: Database, ready: dict) -> tuple[_ThreadedUDP,
                                                          _ThreadedTCP]:
    logic = DNSLogic(db)

    udp = _ThreadedUDP((Config.DNS_HOST, Config.DNS_PORT), UDPHandler)
    udp.logic = logic
    tcp = _ThreadedTCP((Config.DNS_HOST, Config.DNS_PORT), TCPHandler)
    tcp.logic = logic

    t1 = threading.Thread(target=udp.serve_forever, name="dns-udp", daemon=True)
    t2 = threading.Thread(target=tcp.serve_forever, name="dns-tcp", daemon=True)
    t1.start()
    t2.start()
    ready["udp"] = True
    ready["tcp"] = True
    return udp, tcp
