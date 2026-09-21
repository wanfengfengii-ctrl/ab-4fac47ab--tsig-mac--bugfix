"""End-to-end test on real loopback sockets: HTTP API + UDP/TCP DNS + TSIG
AXFR/IXFR, run in-process against a temp database (no Docker required)."""
import base64
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from app import dnsclient as dc
from app import dnswire as w
from app.api import build_api_server
from app.config import Config
from app.dns_server import build_dns_servers
from app.storage import Database

API_P = 18080
DNS_P = 15353
HOST = "127.0.0.1"


def http(method, path, body=None, want=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{HOST}:{API_P}{path}", data=data,
                                 method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            payload = json.loads(r.read() or b"{}")
            if want is not None:
                assert r.status == want, (r.status, payload)
            return r.status, payload
    except urllib.error.HTTPError as e:
        payload = json.loads(e.read() or b"{}")
        if want is not None:
            assert e.code == want, (e.code, payload)
        return e.code, payload


def soa_ops(serial, **extra):
    ops = [{"action": "replace", "name": "@", "type": "SOA", "ttl": 3600,
            "records": [{"mname": "ns1.e2e.", "rname": "admin.e2e.",
                         "serial": serial, "refresh": 7200, "retry": 3600,
                         "expire": 1209600, "minimum": 3600}]}]
    ops.extend(extra.values())
    return ops


def a_op(name, addr):
    return {"action": "replace", "name": name, "type": "A", "ttl": 300,
            "records": [{"address": addr}]}


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls.tmp.close()
        Config.DB_PATH = cls.tmp.name
        Config.API_PORT = API_P
        Config.DNS_PORT = DNS_P
        Config.API_HOST = HOST
        Config.DNS_HOST = HOST
        Config.INSTANCE_ID = "test"
        Config.MAX_CHANGES_PER_PUBLISH = 5000
        Config.MAX_RECORDS_PER_ZONE = 20000
        cls.db = Database(cls.tmp.name)
        cls.ready = {"udp": False, "tcp": False}
        cls.udp, cls.tcp = build_dns_servers(cls.db, cls.ready)
        cls.httpd = build_api_server(cls.db, cls.ready)
        cls.ht = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.ht.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.udp.shutdown()
        cls.tcp.shutdown()
        os.unlink(cls.tmp.name)

    def setUp(self):
        self.zone = f"z{self._testMethodName}.e2e."

    def _create_zone(self, serial=1, retain=10):
        http("POST", "/v1/zones", {
            "name": self.zone.upper(),  # exercise case-insensitivity
            "serial": serial,
            "soa": {"mname": "ns1.e2e.", "rname": "admin.e2e."},
            "ns": ["ns1.e2e.", "NS1.e2e."],
            "retainVersions": retain}, want=201)

    def _install_key(self, kid="k1", kname="tk.e2e.", retire=None):
        body = {"keyId": kid, "keyName": kname}
        if retire:
            body["retireInSeconds"] = retire
        st, resp = http("POST", f"/v1/zones/{self.zone}/keys", body, want=201)
        return kname, base64.b64decode(resp["key"]["secret"])

    def _transfer(self, key_name, secret, qtype, serial=None):
        auth = dc.soa_authority(self.zone, serial) if serial is not None else b""
        q = dc.build_tsig_query(0x1111, self.zone, qtype, key_name, secret,
                                authority=auth)
        msgs = dc.tcp_transfer(HOST, DNS_P, q)
        self.assertTrue(msgs, "no transfer messages")
        return q, msgs

    # --------------------------------------------------------------- tests
    def test_01_udp_tcp_soa_and_records(self):
        self._create_zone(1)
        http("POST", f"/v1/zones/{self.zone}/publish",
             {"requestId": "r2", "baseSerial": 1, "nextSerial": 2,
              "changes": soa_ops(2, h=a_op("h", "192.0.2.7"))}, want=201)
        resp = dc.udp_query(HOST, DNS_P,
                            dc.build_plain_query(1, self.zone, w.TYPE_SOA))
        m = dc.parse_message(resp)
        self.assertEqual(m["rcode"], 0)
        self.assertTrue(m["aa"])
        self.assertEqual(dc.soa_serial(m["answers"][0]["rdata"]), 2)
        resp = dc.tcp_query(HOST, DNS_P,
                            dc.build_plain_query(2, "h." + self.zone, w.TYPE_A))
        m = dc.parse_message(resp)
        self.assertEqual(m["answers"][0]["rdata"],
                         socket.inet_aton("192.0.2.7"))
        # AXFR over UDP sets TC
        kn, sec = self._install_key()
        q = dc.build_tsig_query(3, self.zone, w.TYPE_AXFR, kn, sec)
        m = dc.parse_message(dc.udp_query(HOST, DNS_P, q))
        self.assertTrue(m["tc"])
        self.assertEqual(m["answers"], [])

    def test_02_unsigned_and_bad_tsig_refused(self):
        self._create_zone(1)
        kn, sec = self._install_key()
        resp = dc.tcp_query(HOST, DNS_P,
                            dc.build_plain_query(1, self.zone, w.TYPE_AXFR))
        self.assertEqual(dc.parse_message(resp)["rcode"], w.RCODE_REFUSED)
        bad = dc.build_tsig_query(2, self.zone, w.TYPE_AXFR, kn, b"0" * 32)
        m = dc.parse_message(dc.tcp_query(HOST, DNS_P, bad))
        self.assertEqual(m["rcode"], w.RCODE_REFUSED)
        self.assertIsNotNone(m["tsig"])
        self.assertEqual(m["tsig"]["error"], w.TSIG_BADSIG)
        self.assertEqual(m["answers"], [])
        ghost = dc.build_tsig_query(3, self.zone, w.TYPE_AXFR, "nope.", b"1"*32)
        m = dc.parse_message(dc.tcp_query(HOST, DNS_P, ghost))
        self.assertEqual(m["tsig"]["error"], w.TSIG_BADKEY)

    def test_03_axfr_signed_and_deterministic(self):
        self._create_zone(1)
        http("POST", f"/v1/zones/{self.zone}/publish",
             {"requestId": "r2", "baseSerial": 1, "nextSerial": 2,
              "changes": soa_ops(2,
                                 h=a_op("h", "192.0.2.8"),
                                 t={"action": "replace", "name": "t",
                                    "type": "TXT", "ttl": 60,
                                    "records": [{"text": "v"}]})}, want=201)
        kn, sec = self._install_key()
        q1, msgs1 = self._transfer(kn, sec, w.TYPE_AXFR)
        q2, msgs2 = self._transfer(kn, sec, w.TYPE_AXFR)
        self.assertEqual(msgs1, msgs2)  # deterministic ordering
        parsed = [dc.parse_message(m) for m in msgs1]
        prior = w.parse_query(q1)["tsig"]["mac"]
        for i, m in enumerate(parsed):
            if i in (0, len(parsed) - 1):
                prior = dc.verify_response_mac(m, sec, prior, kn)
        answers = [a for m in msgs1 for a in dc.parse_message(m)["answers"]]
        self.assertEqual(answers[0]["type"], w.TYPE_SOA)
        self.assertEqual(answers[-1]["type"], w.TYPE_SOA)
        self.assertEqual(dc.soa_serial(answers[0]["rdata"]), 2)
        self.assertEqual(dc.soa_serial(answers[-1]["rdata"]), 2)
        middle = answers[1:-1]
        self.assertEqual(sum(1 for r in middle if r["type"] == w.TYPE_NS), 1)
        self.assertTrue(any(r["type"] == w.TYPE_A for r in middle))
        self.assertTrue(any(r["type"] == w.TYPE_TXT for r in middle))

    def test_03b_multi_message_axfr_signs_first_and_last_only(self):
        # Force a tiny message budget so a small zone spans many TCP messages:
        # exactly the first and last must carry a verifiable TSIG, middles none.
        old_budget = Config.XFER_MESSAGE_BUDGET
        Config.XFER_MESSAGE_BUDGET = 300
        try:
            self._create_zone(1)
            ops = soa_ops(2) + [
                a_op(f"h{i}", f"192.0.2.{i}") for i in range(2, 12)]
            http("POST", f"/v1/zones/{self.zone}/publish",
                 {"requestId": "r", "baseSerial": 1, "nextSerial": 2,
                  "changes": ops}, want=201)
            kn, sec = self._install_key()
            q, msgs = self._transfer(kn, sec, w.TYPE_AXFR)
            self.assertGreater(len(msgs), 2, "expected a multi-message transfer")
            parsed = [dc.parse_message(m) for m in msgs]
            for i, m in enumerate(parsed):
                if i in (0, len(parsed) - 1):
                    self.assertIsNotNone(m["tsig"], f"msg {i} must be signed")
                else:
                    self.assertIsNone(m["tsig"], f"middle msg {i} must be unsigned")
            prior = w.parse_query(q)["tsig"]["mac"]
            for i, m in enumerate(parsed):
                if i in (0, len(parsed) - 1):
                    prior = dc.verify_response_mac(m, sec, prior, kn)
            answers = [a for m in msgs for a in dc.parse_message(m)["answers"]]
            self.assertEqual(dc.soa_serial(answers[0]["rdata"]), 2)
            self.assertEqual(dc.soa_serial(answers[-1]["rdata"]), 2)
        finally:
            Config.XFER_MESSAGE_BUDGET = old_budget

    def test_04_ixfr_chain_and_equality(self):
        self._create_zone(1)
        http("POST", f"/v1/zones/{self.zone}/publish",
             {"requestId": "r2", "baseSerial": 1, "nextSerial": 2,
              "changes": soa_ops(2, h=a_op("h", "192.0.2.20"))}, want=201)
        http("POST", f"/v1/zones/{self.zone}/publish",
             {"requestId": "r3", "baseSerial": 2, "nextSerial": 3,
              "changes": soa_ops(3, h=a_op("h", "192.0.2.21"))}, want=201)
        kn, sec = self._install_key()

        # equal to current -> single current SOA
        _, msgs = self._transfer(kn, sec, w.TYPE_IXFR, serial=3)
        answers = [a for m in msgs for a in dc.parse_message(m)["answers"]]
        self.assertEqual(len(answers), 1)
        self.assertEqual(dc.soa_serial(answers[0]["rdata"]), 3)

        # full history 1 -> 3
        _, msgs = self._transfer(kn, sec, w.TYPE_IXFR, serial=1)
        answers = [a for m in msgs for a in dc.parse_message(m)["answers"]]
        soa_seq = [dc.soa_serial(r["rdata"]) for r in answers
                   if r["type"] == w.TYPE_SOA]
        # newest SOA, then per boundary: deleted old SOA / added new SOA
        self.assertEqual(soa_seq, [3, 1, 2, 2, 3], str(soa_seq))

    def test_05_ixfr_falls_back_after_cleanup(self):
        self._create_zone(1, retain=1)
        for i in range(2, 5):
            http("POST", f"/v1/zones/{self.zone}/publish",
                 {"requestId": f"r{i}", "baseSerial": i - 1, "nextSerial": i,
                  "changes": soa_ops(i, h=a_op("h", f"192.0.2.{i}"))},
                 want=201)
        kn, sec = self._install_key()
        task = self.db.claim_cleanup_task()
        while task is not None:
            self.db.run_cleanup(task)
            task = self.db.claim_cleanup_task()
        _, msgs = self._transfer(kn, sec, w.TYPE_IXFR, serial=1)
        answers = [a for m in msgs for a in dc.parse_message(m)["answers"]]
        # AXFR fallback: bookends both serial 4, whole zone, no boundary SOAs
        soa_seq = [dc.soa_serial(r["rdata"]) for r in answers
                   if r["type"] == w.TYPE_SOA]
        self.assertEqual(soa_seq, [4, 4], str(soa_seq))
        self.assertTrue(any(r["type"] == w.TYPE_A for r in answers[1:-1]))

    def test_06_concurrent_publish_only_one_wins(self):
        self._create_zone(1)
        outcomes = []

        def pub(rid, addr):
            st, resp = http("POST", f"/v1/zones/{self.zone}/publish",
                            {"requestId": rid, "baseSerial": 1, "nextSerial": 2,
                             "changes": soa_ops(2, h=a_op("h", addr))})
            outcomes.append((st, resp))

        threads = [threading.Thread(target=pub, args=(f"r{i}", f"10.0.0.{i}"))
                   for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        committed = [o for o in outcomes if o[0] in (200, 201)]
        conflicts = [o for o in outcomes if o[0] == 409]
        self.assertEqual(len(committed), 1)
        self.assertEqual(len(conflicts), 4)
        self.assertTrue(all(
            o[1]["error"]["code"] == "VERSION_CONFLICT" for o in conflicts))
        st, meta = http("GET", f"/v1/zones/{self.zone}")
        self.assertEqual(meta["currentSerial"], 2)

    def test_07_key_rotation_and_revoke(self):
        self._create_zone(1)
        n1, s1 = self._install_key("old", "old-tk.e2e.", retire=3600)
        n2, s2 = self._install_key("new", "new-tk.e2e.", retire=3600)
        _, msgs = self._transfer(n1, s1, w.TYPE_AXFR)  # RETIRING still works
        self.assertEqual(dc.parse_message(msgs[0])["rcode"], 0)
        _, msgs = self._transfer(n2, s2, w.TYPE_AXFR)  # new ACTIVE works
        self.assertEqual(dc.parse_message(msgs[0])["rcode"], 0)
        http("POST", f"/v1/zones/{self.zone}/keys/old/revoke", {}, want=200)
        resp = dc.tcp_query(HOST, DNS_P,
                            dc.build_tsig_query(9, self.zone, w.TYPE_AXFR,
                                                n1, s1))
        m = dc.parse_message(resp)
        self.assertEqual(m["rcode"], w.RCODE_REFUSED)
        self.assertEqual(m["answers"], [])
        st, listing = http("GET", f"/v1/zones/{self.zone}/keys")
        self.assertNotIn("secret", json.dumps(listing))

    def test_09_disconnect_during_transfer_releases_ref(self):
        # Client aborts mid-transfer: the pin must be released (DONE) and the
        # snapshot read transaction closed, i.e. no leaked in-flight reference.
        self._create_zone(1, retain=1)
        Config.MAX_CHANGES_PER_PUBLISH = 5000
        ops = soa_ops(2) + [
            a_op(f"h{i:04d}", f"192.10.{(i >> 8) & 255}.{i & 255}")
            for i in range(1200)]
        http("POST", f"/v1/zones/{self.zone}/publish",
             {"requestId": "big", "baseSerial": 1, "nextSerial": 2,
              "changes": ops}, want=201)
        kn, sec = self._install_key("k", "drop.e2e.")
        sock = socket.create_connection((HOST, DNS_P), timeout=10)
        q = dc.build_tsig_query(0x8888, self.zone, w.TYPE_AXFR, kn, sec)
        sock.sendall(struct.pack(">H", len(q)) + q)
        # read a tiny bit then abruptly close while the server still streams
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        _recvn(sock, 2)
        _recvn(sock, 100)
        time.sleep(0.3)
        sock.close()
        deadline = time.time() + 5
        open_refs = 1
        while time.time() < deadline:
            open_refs = self.db.conn.execute(
                "SELECT COUNT(*) AS c FROM transfer_refs WHERE state='OPEN'"
            ).fetchone()["c"]
            if open_refs == 0:
                break
            time.sleep(0.1)
        self.assertEqual(open_refs, 0, "aborted transfer must release its pin")
        task = self.db.claim_cleanup_task()
        while task is not None:
            self.db.run_cleanup(task)
            task = self.db.claim_cleanup_task()
        resp = dc.udp_query(HOST, DNS_P,
                            dc.build_plain_query(1, self.zone, w.TYPE_SOA))
        self.assertEqual(dc.parse_message(resp)["rcode"], 0)

    def test_10_state_survives_restart(self):
        # A brand-new Database handle (like a restarted process) over the same
        # durable file must retain the ledger, serial history and key state.
        self._create_zone(1)
        http("POST", f"/v1/zones/{self.zone}/publish",
             {"requestId": "p2", "baseSerial": 1, "nextSerial": 2,
              "changes": soa_ops(2, h=a_op("h", "192.0.2.2"))}, want=201)
        kn, sec = self._install_key("k", "persist.e2e.", retire=3600)

        db2 = Database(self.tmp.name)  # fresh process-style handle
        meta = db2.zone_metadata(self.zone)
        self.assertEqual(meta["currentSerial"], 2)
        row = db2.get_request(self.zone, "p2")
        self.assertEqual(row["status"], "COMMITTED")
        keys = {k["keyName"]: k for k in db2.list_keys(self.zone)}
        self.assertEqual(keys["persist.e2e."]["state"], "ACTIVE")
        keyrow = db2.conn.execute(
            "SELECT secret,gen FROM keys WHERE key_name='persist.e2e.'").fetchone()
        self.assertEqual(keyrow["secret"], sec)
        del db2

        _, msgs = self._transfer(kn, sec, w.TYPE_AXFR)
        answers = [a for m in msgs for a in dc.parse_message(m)["answers"]]
        self.assertEqual(dc.soa_serial(answers[0]["rdata"]), 2)

    def _drain_frames(self, sock, first_len, first_prefix):
        frames = []
        body = first_prefix + _recvn(sock, first_len - len(first_prefix))
        frames.append(body)
        while True:
            head = _recvn(sock, 2)
            if len(head) < 2:
                break
            (ln,) = struct.unpack(">H", head)
            frames.append(_recvn(sock, ln))
        return frames

    def test_08_pinned_transfer_survives_publish_revoke_cleanup(self):
        # A transfer fixes target version + key generation at start. While the
        # client deliberately reads slowly (small receive buffer blocks the
        # server's writes), another publisher advances the zone, the transfer
        # key is revoked, and retention cleanup runs. The in-flight connection
        # must still deliver the full, old-version, correctly signed zone.
        self._create_zone(1, retain=1)
        n_records = 1200
        ops = soa_ops(2) + [
            a_op(f"h{i:04d}", f"192.{(i >> 8) & 255}.{i & 255}.1")
            for i in range(n_records)]
        http("POST", f"/v1/zones/{self.zone}/publish",
             {"requestId": "big", "baseSerial": 1, "nextSerial": 2,
              "changes": ops}, want=201)
        kn, sec = self._install_key("k", "pin-tk.e2e.")

        sock = socket.create_connection((HOST, DNS_P), timeout=15)
        # Tiny receive window + deliberately slow reader so the server blocks
        # mid-transfer (its pin must stay OPEN and its snapshot pinned).
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        q = dc.build_tsig_query(0x7777, self.zone, w.TYPE_AXFR, kn, sec)
        sock.sendall(struct.pack(">H", len(q)) + q)

        # Read only the 2-byte length prefix and a small prefix of the first
        # frame, then stop draining: the server blocks sending this frame.
        prefix_len = struct.unpack(">H", _recvn(sock, 2))[0]
        prefix = _recvn(sock, 200)
        self.assertGreater(prefix_len, 1000)
        time.sleep(0.5)  # let the server fill the window and block

        # --- races while the transfer is in flight ---
        http("POST", f"/v1/zones/{self.zone}/publish",
             {"requestId": "new", "baseSerial": 2, "nextSerial": 3,
              "changes": soa_ops(3)}, want=201)
        _, kresp = http("POST", f"/v1/zones/{self.zone}/keys",
                        {"keyId": "k2", "keyName": "pin2.e2e."}, want=201)
        n2, s2 = "pin2.e2e.", base64.b64decode(kresp["key"]["secret"])
        http("POST", f"/v1/zones/{self.zone}/keys/k/revoke", {}, want=200)
        task = self.db.claim_cleanup_task()
        while task is not None:  # retention would like to prune v0/v1
            self.db.run_cleanup(task)
            task = self.db.claim_cleanup_task()
        pinned = self.db.conn.execute(
            "SELECT COUNT(*) AS c FROM transfer_refs WHERE state='OPEN'"
        ).fetchone()["c"]
        self.assertGreaterEqual(pinned, 1, "in-flight transfer must be pinned")
        versions_pinned = {r["version_id"] for r in self.db.conn.execute(
            "SELECT version_id FROM versions WHERE zone=?", (self.zone,))}
        self.assertIn(1, versions_pinned)  # pinned target version survives

        # Drain the rest of the connection, starting from the partial frame.
        # Re-enlarge the receive window so draining is fast.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        except OSError:
            pass
        frames = self._drain_frames(sock, prefix_len, prefix)
        sock.close()

        answers = [a for f in frames for a in dc.parse_message(f)["answers"]]
        self.assertEqual(dc.soa_serial(answers[0]["rdata"]), 2)
        self.assertEqual(dc.soa_serial(answers[-1]["rdata"]), 2)
        self.assertEqual(sum(1 for r in answers if r["type"] == w.TYPE_A),
                         n_records)
        # TSIG chain on first/last still verifies with the (now revoked) key
        parsed = [dc.parse_message(f) for f in frames]
        prior = w.parse_query(q)["tsig"]["mac"]
        for i, m in enumerate(parsed):
            if i in (0, len(parsed) - 1):
                prior = dc.verify_response_mac(m, sec, prior, kn)

        # new connections observe the new state: revoked key refused,
        # new key serves serial 3
        resp = dc.tcp_query(HOST, DNS_P,
                            dc.build_tsig_query(1, self.zone, w.TYPE_AXFR,
                                                kn, sec))
        self.assertEqual(dc.parse_message(resp)["rcode"], w.RCODE_REFUSED)
        _, msgs = self._transfer(n2, s2, w.TYPE_AXFR)
        answers = [a for m in msgs for a in dc.parse_message(m)["answers"]]
        self.assertEqual(dc.soa_serial(answers[0]["rdata"]), 3)
        self.assertEqual(dc.soa_serial(answers[-1]["rdata"]), 3)


if __name__ == "__main__":
    unittest.main()
