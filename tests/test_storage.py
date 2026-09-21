import json
import os
import tempfile
import unittest

from app.errors import ApiError, ErrorCode
from app.storage import Database


def soa(serial, **extra):
    ops = [{"action": "replace", "name": "@", "type": "SOA", "ttl": 3600,
            "records": [{"mname": "ns1.z.", "rname": "admin.z.",
                         "serial": serial, "refresh": 7200, "retry": 3600,
                         "expire": 1209600, "minimum": 3600}]}]
    ops.extend(extra.values())
    return ops


def a(name, addr, action="replace"):
    return {"action": action, "name": name, "type": "A", "ttl": 300,
            "records": [{"address": addr}]}


class StorageTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        self.db.create_zone(
            "z.", 1,
            {"mname": "ns1.z.", "rname": "admin.z.", "refresh": 7200,
             "retry": 3600, "expire": 1209600, "minimum": 3600},
            ["ns1.z."], 10)

    def tearDown(self):
        del self.db
        os.unlink(self.tmp.name)


class TestPublish(StorageTestBase):
    def test_commit_and_metadata(self):
        r = self.db.publish("z.", "r1", 1, 2, soa(2, h=a("h", "192.0.2.1")),
                            "fp1")
        self.assertEqual(r["serial"], 2)
        meta = self.db.zone_metadata("z.")
        self.assertEqual(meta["currentSerial"], 2)
        self.assertGreaterEqual(meta["recordCount"], 3)

    def test_idempotent_retry(self):
        ops = soa(2, h=a("h", "192.0.2.1"))
        r1 = self.db.publish("z.", "r1", 1, 2, ops, "fp")
        r2 = self.db.publish("z.", "r1", 1, 2, ops, "fp")
        self.assertEqual(r1["versionId"], r2["versionId"])
        self.assertTrue(r2.get("replayed"))

    def test_same_request_id_different_content_conflicts(self):
        self.db.publish("z.", "r1", 1, 2, soa(2, h=a("h", "192.0.2.1")), "fp1")
        with self.assertRaises(ApiError) as ctx:
            self.db.publish("z.", "r1", 1, 2,
                            soa(2, h=a("h", "192.0.2.2")), "fp2")
        self.assertEqual(ctx.exception.code, ErrorCode.IDEMPOTENCY_CONFLICT)

    def test_version_conflict_on_stale_base(self):
        self.db.publish("z.", "r1", 1, 2, soa(2), "fp1")
        with self.assertRaises(ApiError) as ctx:
            self.db.publish("z.", "r2", 1, 3, soa(3), "fp2")
        self.assertEqual(ctx.exception.code, ErrorCode.VERSION_CONFLICT)
        self.assertEqual(ctx.exception.details["currentSerial"], 2)

    def test_undecidable_serial(self):
        with self.assertRaises(ApiError) as ctx:
            self.db.publish("z.", "r1", 1, 1 + 2**31,
                            soa(1 + 2**31), "fp")
        self.assertEqual(ctx.exception.code, ErrorCode.SERIAL_UNDECIDABLE)

    def test_failed_publish_leaves_nothing(self):
        with self.assertRaises(ApiError):
            self.db.publish("z.", "r1", 1, 2,
                            [{"action": "delete", "name": "@",
                              "type": "SOA"}], "fp")
        meta = self.db.zone_metadata("z.")
        self.assertEqual(meta["currentSerial"], 1)
        self.assertEqual(meta["recordCount"], 2)
        # requestId with a malformed-style failure may be reused; but invariant
        # failures are ledgered FAILED and replay the same error.
        with self.assertRaises(ApiError) as ctx:
            self.db.publish("z.", "r1", 1, 2,
                            [{"action": "delete", "name": "@",
                              "type": "SOA"}], "fp")
        self.assertEqual(ctx.exception.code, ErrorCode.ZONE_INVALID)
        self.assertTrue(ctx.exception.details.get("replayed"))

    def test_cname_coexistence(self):
        with self.assertRaises(ApiError) as ctx:
            self.db.publish("z.", "r1", 1, 2, soa(2, **{
                "c": {"action": "replace", "name": "c", "type": "CNAME",
                      "ttl": 300, "records": [{"target": "x.z."}]},
                "a": a("c", "192.0.2.4")}), "fp")
        self.assertEqual(ctx.exception.code, ErrorCode.ZONE_INVALID)

    def test_replace_same_content_is_noop(self):
        ops = soa(2, h=a("h", "192.0.2.1"))
        self.db.publish("z.", "r1", 1, 2, ops, "fp")
        meta = self.db.zone_metadata("z.")
        # republishing identical RRsets at a new serial still valid
        self.db.publish("z.", "r2", 2, 3, soa(3, h=a("h", "192.0.2.1")), "fp2")
        self.assertEqual(self.db.zone_metadata("z.")["currentSerial"], 3)
        self.assertEqual(self.db.zone_metadata("z.")["recordCount"],
                         meta["recordCount"])

    def test_snapshot_and_delta_persisted(self):
        self.db.publish("z.", "r1", 1, 2, soa(2, h=a("h", "192.0.2.1")), "fp")
        snap = self.db.snapshot_conn()
        rows = list(self.db.iter_snapshot(snap, "z.", 1))
        names = {(r["name"], r["rtype"]) for r in rows}
        self.assertIn(("h.z.", "A"), names)
        changes = list(self.db.iter_changes(snap, "z.", 1))
        ops_seen = [c["op"] for c in changes]
        self.assertEqual(ops_seen[0], "DEL")  # old SOA deletion first
        self.assertIn("ADD", ops_seen)
        # boundary ordering: SOA deletion precedes A addition
        self.assertEqual(changes[0]["rtype"], "SOA")
        snap.close()


class TestCleanup(StorageTestBase):
    def test_cleanup_keeps_retained_versions(self):
        self.db.set_retention("z.", 2)
        for i in range(2, 6):
            self.db.publish("z.", f"r{i}", i - 1, i, soa(i), f"fp{i}")
        task = self.db.claim_cleanup_task()
        result = self.db.run_cleanup(task)
        remaining = {r["version_id"] for r in
                     self.db.conn.execute(
                         "SELECT version_id FROM versions WHERE zone='z.'")}
        # current version_id is 4 (serial 5); keep the last 2 => versions 3,4
        self.assertEqual(self.db.zone_metadata("z.")["currentSerial"], 5)
        self.assertNotIn(0, remaining)
        self.assertNotIn(1, remaining)
        self.assertEqual(remaining, {3, 4})
        self.assertGreaterEqual(min(remaining), result["deleteBefore"])

    def test_cleanup_idempotent_after_reclaim(self):
        self.db.set_retention("z.", 1)
        for i in range(2, 5):
            self.db.publish("z.", f"r{i}", i - 1, i, soa(i), f"fp{i}")
        task = self.db.claim_cleanup_task()
        self.db.run_cleanup(task)
        # reclaim/rerun must not fail even with nothing left
        task2 = self.db.claim_cleanup_task()
        if task2 is not None:
            self.db.run_cleanup(task2)

    def test_pin_protects_inflight_versions(self):
        self.db.set_retention("z.", 1)
        for i in range(2, 5):
            self.db.publish("z.", f"r{i}", i - 1, i, soa(i), f"fp{i}")
        self.db.pin_transfer("z.", "test-instance", 4, 1, 1)
        task = self.db.claim_cleanup_task()
        result = self.db.run_cleanup(task)
        remaining = {r["version_id"] for r in
                     self.db.conn.execute(
                         "SELECT version_id FROM versions WHERE zone='z.'")}
        self.assertIn(1, remaining)  # IXFR chain start protected
        self.db.release_transfer(
            self.db.conn.execute(
                "SELECT ref_id FROM transfer_refs").fetchone()["ref_id"])


class TestKeys(StorageTestBase):
    def test_rotation_and_revoke(self):
        k1 = self.db.install_key("z.", "k1", "key1.", None)
        self.assertEqual(k1["state"], "ACTIVE")
        k2 = self.db.install_key("z.", "k2", "key2.", None)
        states = {k["keyName"]: k["state"]
                  for k in self.db.list_keys("z.")}
        self.assertEqual(states["key1."], "RETIRING")
        self.assertEqual(states["key2."], "ACTIVE")
        self.db.revoke_key("z.", "k1")
        states = {k["keyName"]: k["state"]
                  for k in self.db.list_keys("z.")}
        self.assertEqual(states["key1."], "REVOKED")
        # secret never appears in listings
        self.assertNotIn("secret", states)

    def test_listing_has_no_secret(self):
        self.db.install_key("z.", "k1", "key1.", None)
        for k in self.db.list_keys("z."):
            self.assertNotIn("secret", k)


if __name__ == "__main__":
    unittest.main()
