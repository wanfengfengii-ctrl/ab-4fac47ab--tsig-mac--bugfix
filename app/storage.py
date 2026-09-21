"""SQLite-backed durable storage.

Concurrency model
-----------------
Every mutating operation runs in ``BEGIN IMMEDIATE`` so only one writer exists
at a time; two publishers racing on the same baseSerial therefore serialize,
the loser observing the new current version and receiving a deterministic
VERSION_CONFLICT. Per-version data (records/changes) is immutable: a publish
materializes a *full* snapshot plus a delta row set, so any transfer can read
its pinned version even while newer versions appear.

Cross-process transfer pinning is the ``transfer_refs`` table; the cleaner
never removes a version whose snapshot or delta an OPEN ref may still stream
(IXFR pins ``min_version`` = the client's starting version).
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid

from . import canonical as canon
from .errors import ApiError, ErrorCode
from .serial import SerialRelation, compare, is_forward

SCHEMA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "migrations")

# Transfer refs whose heartbeat is older than this are treated as dead, so a
# crashed edge instance cannot pin history forever.
REF_STALE_SECONDS = 300
# Cleanup lease duration; a crashed cleaner's task is reclaimable afterwards.
CLEANUP_LEASE_SECONDS = 30

# Semantic publish outcomes that are stored in the idempotency ledger. Input
# validation failures are NOT recorded, so the same requestId may be retried
# after correcting malformed content.
LEDGERABLE_FAILURES = {
    ErrorCode.VERSION_CONFLICT, ErrorCode.SERIAL_INVALID,
    ErrorCode.SERIAL_UNDECIDABLE, ErrorCode.ZONE_INVALID,
    ErrorCode.CHANGESET_INVALID, ErrorCode.LIMIT_EXCEEDED,
}


def now_ms() -> int:
    return int(time.time() * 1000)


def utcnow() -> int:
    return int(time.time())


class Database:
    def __init__(self, path: str):
        self.path = path
        self._tl = threading.local()
        self._init_schema()

    # ------------------------------------------------------------------ conn
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._tl, "conn", None)
        if c is None:
            c = self._connect()
            self._tl.conn = c
        return c

    def _init_schema(self) -> None:
        c = self._connect()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)")
        # Claim each migration name first (INSERT OR IGNORE) so concurrent
        # first-boot instances never collide; the DDL itself is idempotent.
        applied = {r[0] for r in c.execute("SELECT name FROM schema_migrations")}
        for name in sorted(os.listdir(SCHEMA_DIR)):
            if name.endswith(".sql") and name not in applied:
                with open(os.path.join(SCHEMA_DIR, name)) as f:
                    c.executescript(f.read())
                c.execute("INSERT OR IGNORE INTO schema_migrations(name) "
                          "VALUES (?)", (name,))
        c.close()

    def ping(self) -> bool:
        self.conn.execute("SELECT 1").fetchone()
        return True

    def snapshot_conn(self) -> sqlite3.Connection:
        """Open a dedicated connection with an open read transaction: under
        WAL it holds a stable read snapshot for the whole transfer. The
        serving thread owns and closes it."""
        c = self._connect()
        c.execute("BEGIN")
        return c

    # ----------------------------------------------------------------- zones
    def create_zone(self, zone: str, serial: int, soa: dict, ns_targets: list[str],
                    retain_versions: int) -> dict:
        ts = now_ms()
        soa = dict(soa)
        soa["serial"] = serial
        soa_json, soa_wire = canon.canonical_rdata("SOA", soa, zone)
        rr_rows = [(zone, "SOA", int(soa.get("_ttl", 3600)), soa_json, soa_wire)]
        ns_seen = set()
        for target in ns_targets:  # de-duplicate AFTER canonicalization
            t = canon.canonical_target(target, zone)
            if t in ns_seen:
                continue
            ns_seen.add(t)
            rj, rw = canon.canonical_rdata("NS", {"target": t}, zone)
            rr_rows.append((zone, "NS", 3600, rj, rw))
        conn = self.conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM zones WHERE name=?", (zone,)).fetchone():
                raise ApiError(ErrorCode.ZONE_ALREADY_EXISTS,
                               f"zone {zone} already exists", 409)
            conn.execute(
                "INSERT INTO zones(name,current_serial,current_version,"
                "retain_versions,record_count,rrset_count,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (zone, serial, 0, retain_versions, len(rr_rows), 2, ts, ts))
            conn.execute(
                "INSERT INTO versions(zone,version_id,serial,request_id,created_at)"
                " VALUES(?,?,?,?,?)", (zone, 0, serial, "__create__", ts))
            for name, rtype, ttl, rj, rw in rr_rows:
                conn.execute(
                    "INSERT INTO records(zone,version_id,name,rtype,ttl,rdata,"
                    "rdata_wire) VALUES(?,?,?,?,?,?,?)",
                    (zone, 0, name, rtype, ttl, rj, rw))
            conn.commit()
        except ApiError:
            conn.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            if conn.execute("SELECT 1 FROM zones WHERE name=?",
                            (zone,)).fetchone():
                raise ApiError(ErrorCode.ZONE_ALREADY_EXISTS,
                               f"zone {zone} already exists", 409)
            raise ApiError(ErrorCode.INTERNAL,
                           f"zone creation failed: {exc}", 500)
        return self.zone_metadata(zone)

    def get_zone_row(self, zone: str) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM zones WHERE name=?",
                                (zone,)).fetchone()
        if row is None:
            raise ApiError(ErrorCode.ZONE_NOT_FOUND, f"zone {zone} not found", 404)
        return row

    def find_zone_by_name(self, name: str) -> sqlite3.Row | None:
        """Longest matching enclosing zone for an owner name (qname is
        already lowercase from the wire parser). Matching is done in Python to
        avoid LIKE wildcard collisions with '_'/'%' inside zone labels."""
        name = name.lower()
        best = None
        for z in self.conn.execute("SELECT * FROM zones"):
            zn = z["name"]
            if name == zn or name.endswith("." + zn):
                if best is None or len(zn) > len(best["name"]):
                    best = z
        return best

    def list_zones(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM zones ORDER BY name"))

    def zone_metadata(self, zone: str) -> dict:
        z = self.get_zone_row(zone)
        soa = self.get_soa(zone, z["current_version"])
        soa_json = json.loads(soa["rdata"])
        ns = [json.loads(r["rdata"])["target"] for r in self.conn.execute(
            "SELECT rdata FROM records WHERE zone=? AND version_id=? AND name=? "
            "AND rtype='NS' ORDER BY rdata",
            (zone, z["current_version"], zone))]
        return {"name": z["name"], "currentSerial": z["current_serial"],
                "currentVersionId": z["current_version"],
                "retainVersions": z["retain_versions"],
                "recordCount": z["record_count"],
                "rrsetCount": z["rrset_count"],
                "soa": {k: v for k, v in soa_json.items() if k != "serial"},
                "serial": z["current_serial"], "ns": ns,
                "createdAt": z["created_at"], "updatedAt": z["updated_at"]}

    def set_retention(self, zone: str, retain_versions: int) -> dict:
        self.get_zone_row(zone)
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("UPDATE zones SET retain_versions=?, updated_at=? "
                         "WHERE name=?", (retain_versions, now_ms(), zone))
            conn.execute(
                "INSERT INTO cleanup_tasks(zone,state,attempts,created_at)"
                " VALUES(?, 'PENDING', 0, ?)", (zone, now_ms()))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return {"zone": zone, "retainVersions": retain_versions}

    def get_soa(self, zone: str, version_id: int) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM records WHERE zone=? AND version_id=? AND name=? "
            "AND rtype='SOA'", (zone, version_id, zone)).fetchone()
        if row is None:
            raise ApiError(ErrorCode.INTERNAL, "SOA missing in snapshot")
        return row

    def version_by_serial(self, zone: str, serial: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM versions WHERE zone=? AND serial=?",
            (zone, serial)).fetchone()

    def iter_snapshot(self, conn, zone: str, version_id: int):
        return conn.execute(
            "SELECT name,rtype,ttl,rdata,rdata_wire FROM records "
            "WHERE zone=? AND version_id=? ORDER BY name,rtype,rdata",
            (zone, version_id))

    def iter_changes(self, conn, zone: str, version_id: int):
        return conn.execute(
            "SELECT seq,op,name,rtype,ttl,rdata,rdata_wire FROM changes "
            "WHERE zone=? AND version_id=? ORDER BY seq", (zone, version_id))

    # --------------------------------------------------------------- publish
    def publish(self, zone_name: str, request_id: str, base_serial: int,
                next_serial: int, ops: list[dict], fingerprint: str) -> dict:
        """Atomically apply a changeset.

        Whole-commit-or-whole-failure: all derived rows are inserted inside one
        IMMEDIATE transaction; zone-invariant / limit validation happens before
        any derived row is written. Semantic failures persist a FAILED ledger
        entry (they consume the requestId with its first outcome); malformed
        input consumes nothing.
        """
        from .config import Config
        conn = self.conn
        zone = None
        try:
            conn.execute("BEGIN IMMEDIATE")

            z = conn.execute("SELECT * FROM zones WHERE name=?",
                             (zone_name,)).fetchone()
            if z is None:
                raise ApiError(ErrorCode.ZONE_NOT_FOUND,
                               f"zone {zone_name} not found", 404)
            zone = z["name"]
            cur_version = z["current_version"]
            cur_serial = z["current_serial"]

            ledger = conn.execute(
                "SELECT * FROM publish_requests WHERE zone=? AND request_id=?",
                (zone, request_id)).fetchone()
            if ledger is not None:
                # Replay path: release the IMMEDIATE write lock before
                # returning so the thread-local connection never pins it.
                conn.commit()
                if not secrets.compare_digest(ledger["fingerprint"],
                                              fingerprint):
                    raise ApiError(
                        ErrorCode.IDEMPOTENCY_CONFLICT,
                        f"requestId {request_id!r} was already used with "
                        "different content", 409,
                        {"requestId": request_id,
                         "originalStatus": ledger["status"]})
                return self._ledger_result(ledger)

            # Serial arithmetic per RFC 1982, never plain integer comparison.
            ok, msg = is_forward(base_serial, next_serial)
            if not ok:
                code = (ErrorCode.SERIAL_UNDECIDABLE
                        if "undecidable" in msg else ErrorCode.SERIAL_INVALID)
                raise ApiError(code, msg, 422,
                               {"baseSerial": base_serial,
                                "nextSerial": next_serial})

            rel = compare(cur_serial, base_serial)
            if rel != SerialRelation.EQUAL:
                raise ApiError(
                    ErrorCode.VERSION_CONFLICT,
                    f"baseSerial {base_serial} is not current; current is "
                    f"{cur_serial}", 409,
                    {"currentSerial": cur_serial, "baseSerial": base_serial,
                     "relation": rel,
                     "hint": "rebase onto currentSerial and resubmit with a new "
                             "requestId"})

            rrsets = self._load_rrsets(conn, zone, cur_version)
            changed: set[tuple[str, str]] = set()
            self._apply_ops(zone, ops, rrsets, changed)
            self._validate_zone_invariants(zone, rrsets, next_serial)

            total_records = sum(len(v[1]) for n in rrsets.values() for v in
                                n.values())
            if total_records > Config.MAX_RECORDS_PER_ZONE:
                raise ApiError(
                    ErrorCode.LIMIT_EXCEEDED,
                    f"zone would hold {total_records} records; limit "
                    f"{Config.MAX_RECORDS_PER_ZONE}", 413,
                    {"limit": Config.MAX_RECORDS_PER_ZONE, "count": total_records})

            new_version = cur_version + 1
            ts = now_ms()
            self._materialize(conn, zone, cur_version, new_version, rrsets,
                              changed)

            conn.execute(
                "INSERT INTO versions(zone,version_id,serial,request_id,created_at)"
                " VALUES(?,?,?,?,?)",
                (zone, new_version, next_serial, request_id, ts))
            conn.execute("UPDATE zones SET current_serial=?, current_version=?,"
                         " record_count=?, rrset_count=?, updated_at=? "
                         "WHERE name=?",
                         (next_serial, new_version, total_records,
                          self._count_rrsets(rrsets), ts, zone))
            self._insert_ledger(conn, zone, request_id, fingerprint,
                                "COMMITTED", new_version, next_serial,
                                base_serial, next_serial, ts)
            conn.execute(
                "INSERT INTO cleanup_tasks(zone,state,attempts,created_at)"
                " VALUES(?, 'PENDING', 0, ?)", (zone, ts))
            conn.commit()
            return {"status": "COMMITTED", "zone": zone,
                    "requestId": request_id, "versionId": new_version,
                    "serial": next_serial}
        except ApiError as exc:
            self._fail_or_rollback(conn, zone, request_id, fingerprint,
                                   base_serial, next_serial, exc)
            raise
        except Exception:
            conn.rollback()
            raise

    @staticmethod
    def _load_rrsets(conn, zone, version_id):
        rrsets: dict[str, dict[str, tuple[int, list[tuple[str, bytes]]]]] = {}
        for r in conn.execute(
                "SELECT name,rtype,ttl,rdata,rdata_wire FROM records "
                "WHERE zone=? AND version_id=? ORDER BY rdata",
                (zone, version_id)):
            rrsets.setdefault(r["name"], {}).setdefault(
                r["rtype"], (r["ttl"], []))[1].append(
                    (r["rdata"], r["rdata_wire"]))
        return rrsets

    @staticmethod
    def _apply_ops(zone, ops, rrsets, changed) -> None:
        if not isinstance(ops, list) or not ops:
            raise ApiError(ErrorCode.CHANGESET_INVALID,
                           "changes must be a non-empty list")
        for idx, op in enumerate(ops):
            if not isinstance(op, dict):
                raise ApiError(ErrorCode.VALIDATION_ERROR,
                               f"op {idx} must be an object")
            action = str(op.get("action", "")).lower()
            name = canon.canonical_name(op.get("name", ""), zone)
            rtype = str(op.get("type", "")).upper()
            if rtype not in canon.dnswire.SUPPORTED_TYPES:
                raise ApiError(ErrorCode.VALIDATION_ERROR,
                               f"op {idx}: unsupported type {rtype!r}")
            if action == "delete":
                if name in rrsets and rtype in rrsets[name] and \
                        (name, rtype) not in changed:
                    changed.add((name, rtype))
                    del rrsets[name][rtype]
                    if not rrsets[name]:
                        del rrsets[name]
            elif action == "replace":
                ttl = canon._check_ttl(op.get("ttl", 3600))
                records = op.get("records", [])
                if not isinstance(records, list):
                    raise ApiError(ErrorCode.VALIDATION_ERROR,
                                   f"op {idx}: records must be a list")
                entries: list[tuple[str, bytes]] = []
                seen = set()
                for val in records:
                    rj, rw = canon.canonical_rdata(rtype, val, zone)
                    canon.rr_fits_message(name, rtype, rw)
                    if rj in seen:
                        raise ApiError(ErrorCode.CHANGESET_INVALID,
                                       f"op {idx}: duplicate RDATA in RRset")
                    seen.add(rj)
                    entries.append((rj, rw))
                old = rrsets.get(name, {}).get(rtype)
                if old is None or (ttl, entries) != (old[0], old[1]):
                    changed.add((name, rtype))
                if entries:
                    rrsets[name] = rrsets.get(name, {})
                    rrsets[name][rtype] = (ttl, entries)
                elif name in rrsets and rtype in rrsets[name]:
                    del rrsets[name][rtype]
                    if not rrsets[name]:
                        del rrsets[name]
            else:
                raise ApiError(ErrorCode.VALIDATION_ERROR,
                               f"op {idx}: action must be 'replace'|'delete'")

    @staticmethod
    def _validate_zone_invariants(zone: str, rrsets: dict, next_serial: int
                                  ) -> None:
        apex = rrsets.get(zone, {})
        soa = apex.get("SOA")
        if soa is None or len(soa[1]) != 1:
            raise ApiError(ErrorCode.ZONE_INVALID,
                           "zone apex must have exactly one SOA record", 422)
        soa_json = json.loads(soa[1][0][0])
        if int(soa_json["serial"]) != int(next_serial):
            raise ApiError(ErrorCode.SERIAL_INVALID,
                           f"SOA serial {soa_json['serial']} must equal "
                           f"nextSerial {next_serial}", 422,
                           {"soaSerial": soa_json["serial"],
                            "nextSerial": next_serial})
        if not apex.get("NS", (0, []))[1]:
            raise ApiError(ErrorCode.ZONE_INVALID,
                           "zone apex must have at least one NS record", 422)
        for name, types in rrsets.items():
            if "CNAME" in types and len(types) > 1:
                raise ApiError(
                    ErrorCode.ZONE_INVALID,
                    f"CNAME at {name} cannot coexist with other data "
                    f"({sorted(t for t in types if t != 'CNAME')})", 422,
                    {"name": name})
            if "CNAME" in types and len(types["CNAME"][1]) > 1:
                raise ApiError(ErrorCode.ZONE_INVALID,
                               f"CNAME RRset at {name} must contain one record",
                               422)

    def _materialize(self, conn, zone, old_version, new_version, rrsets,
                     changed) -> None:
        conn.execute(
            "INSERT INTO records(zone,version_id,name,rtype,ttl,rdata,rdata_wire)"
            " SELECT zone,?,name,rtype,ttl,rdata,rdata_wire FROM records "
            "WHERE zone=? AND version_id=?",
            (new_version, zone, old_version))
        for name, rtype in changed:
            conn.execute("DELETE FROM records WHERE zone=? AND version_id=? "
                         "AND name=? AND rtype=?",
                         (zone, new_version, name, rtype))
            if name in rrsets and rtype in rrsets[name]:
                ttl, entries = rrsets[name][rtype]
                for rj, rw in entries:
                    conn.execute(
                        "INSERT INTO records(zone,version_id,name,rtype,ttl,"
                        "rdata,rdata_wire) VALUES(?,?,?,?,?,?,?)",
                        (zone, new_version, name, rtype, ttl, rj, rw))
        old_index: dict[tuple[str, str], list] = {}
        for r in conn.execute(
                "SELECT name,rtype,ttl,rdata,rdata_wire FROM records "
                "WHERE zone=? AND version_id=?", (zone, old_version)):
            old_index.setdefault((r["name"], r["rtype"]), []).append(r)
        seq = 0
        apex_soa_first = lambda k: (
            0 if k[0] == zone and k[1] == "SOA" else 1, k[0], k[1])
        deletes, adds = [], []
        for key in sorted(changed, key=apex_soa_first):
            name, rtype = key
            for r in sorted(old_index.get(key, []),
                            key=lambda x: x["rdata"]):
                deletes.append((name, rtype, r["ttl"], r["rdata"],
                                r["rdata_wire"]))
            if name in rrsets and rtype in rrsets[name]:
                ttl, entries = rrsets[name][rtype]
                for rj, rw in sorted(entries):
                    adds.append((name, rtype, ttl, rj, rw))
        for op, rows in (("DEL", deletes), ("ADD", adds)):
            for name, rtype, ttl, rj, rw in rows:
                seq += 1
                conn.execute(
                    "INSERT INTO changes(zone,version_id,seq,op,name,rtype,ttl,"
                    "rdata,rdata_wire) VALUES(?,?,?,?,?,?,?,?,?)",
                    (zone, new_version, seq, op, name, rtype, ttl, rj, rw))

    @staticmethod
    def _count_rrsets(rrsets) -> int:
        return sum(len(types) for types in rrsets.values())

    @staticmethod
    def _insert_ledger(conn, zone, request_id, fingerprint, status, version_id,
                       serial, base_serial, next_serial, ts,
                       exc: ApiError | None = None) -> None:
        conn.execute(
            "INSERT INTO publish_requests(zone,request_id,fingerprint,status,"
            "version_id,serial,error_code,error_message,error_status,"
            "error_details,base_serial,next_serial,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (zone, request_id, fingerprint, status, version_id, serial,
             exc.code if exc else None, exc.message if exc else None,
             exc.http_status if exc else None,
             json.dumps(exc.details, sort_keys=True) if exc else None,
             base_serial, next_serial, ts))

    def _fail_or_rollback(self, conn, zone, request_id, fingerprint,
                          base_serial, next_serial, exc: ApiError) -> None:
        # Publish rows are only materialized after validation, so rolling back
        # leaves no partial RRset and consumes no serial.
        if zone is not None and exc.code in LEDGERABLE_FAILURES:
            try:
                if not conn.execute(
                        "SELECT 1 FROM publish_requests WHERE zone=? AND "
                        "request_id=?", (zone, request_id)).fetchone():
                    self._insert_ledger(conn, zone, request_id, fingerprint,
                                        "FAILED", None, None, base_serial,
                                        next_serial, now_ms(), exc)
                    conn.commit()
                    return
            except sqlite3.Error:
                pass
        conn.rollback()

    def _ledger_result(self, ledger: sqlite3.Row) -> dict:
        if ledger["status"] == "COMMITTED":
            return {"status": "COMMITTED", "zone": ledger["zone"],
                    "requestId": ledger["request_id"],
                    "versionId": ledger["version_id"], "serial": ledger["serial"],
                    "replayed": True}
        details = json.loads(ledger["error_details"] or "{}")
        raise ApiError(ledger["error_code"],
                       ledger["error_message"] or "request previously failed",
                       ledger["error_status"] or 409,
                       {**details, "replayed": True})

    def get_request(self, zone: str, request_id: str) -> sqlite3.Row:
        self.get_zone_row(zone)
        row = self.conn.execute(
            "SELECT * FROM publish_requests WHERE zone=? AND request_id=?",
            (zone, request_id)).fetchone()
        if row is None:
            raise ApiError(ErrorCode.REQUEST_NOT_FOUND,
                           f"requestId {request_id!r} not found", 404,
                           {"requestId": request_id})
        return row

    # ------------------------------------------------------------------ keys
    def install_key(self, zone: str, key_id: str, key_name: str | None,
                    expires_at: int | None) -> dict:
        self.get_zone_row(zone)
        key_name = key_name or key_id
        secret = secrets.token_bytes(32)
        ts = now_ms()
        if expires_at is None:
            expires_at = ts + 3600 * 1000
        if expires_at <= ts:
            raise ApiError(ErrorCode.KEY_STATE_INVALID,
                           "retireInSeconds / expiresAt must be in the future",
                           422)
        conn = self.conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            gen = conn.execute(
                "SELECT COALESCE(MAX(gen), -1) AS g FROM keys WHERE zone=?",
                (zone,)).fetchone()["g"] + 1
            if conn.execute(
                    "SELECT 1 FROM keys WHERE zone=? AND key_name=? AND state "
                    "!= 'REVOKED'", (zone, key_name)).fetchone():
                raise ApiError(ErrorCode.KEY_STATE_INVALID,
                               f"key name {key_name!r} is already in use by a "
                               "non-revoked key", 409)
            if conn.execute("SELECT 1 FROM keys WHERE zone=? AND key_id=?",
                            (zone, key_id)).fetchone():
                raise ApiError(ErrorCode.KEY_STATE_INVALID,
                               f"key id {key_id!r} already exists", 409)
            # Atomic rotation: old ACTIVE becomes RETIRING with a hard expiry.
            conn.execute(
                "UPDATE keys SET state='RETIRING', expires_at=? "
                "WHERE zone=? AND state='ACTIVE'", (expires_at, zone))
            conn.execute(
                "INSERT INTO keys(zone,key_id,gen,key_name,secret,state,"
                "created_at,expires_at,revoked_at)"
                " VALUES(?,?,?,?,?, 'ACTIVE', ?, NULL, NULL)",
                (zone, key_id, gen, key_name, secret, ts))
            conn.commit()
        except ApiError:
            conn.rollback()
            raise
        except sqlite3.IntegrityError:
            conn.rollback()
            raise ApiError(ErrorCode.KEY_STATE_INVALID,
                           f"key id {key_id!r} already exists", 409)
        return {"keyId": key_id, "keyName": key_name, "generation": gen,
                "state": "ACTIVE",
                "secret": base64.b64encode(secret).decode("ascii"),
                "createdAt": ts, "algorithm": "hmac-sha256"}

    def list_keys(self, zone: str) -> list[dict]:
        self.get_zone_row(zone)
        out = []
        for r in self.conn.execute(
                "SELECT key_id,key_name,gen,state,created_at,expires_at,"
                "revoked_at FROM keys WHERE zone=? ORDER BY gen", (zone,)):
            out.append({"keyId": r["key_id"], "keyName": r["key_name"],
                        "generation": r["gen"], "state": r["state"],
                        "createdAt": r["created_at"],
                        "expiresAt": r["expires_at"],
                        "revokedAt": r["revoked_at"]})
        return out

    def revoke_key(self, zone: str, key_id: str) -> dict:
        self.get_zone_row(zone)
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT * FROM keys WHERE zone=? AND key_id=?",
                               (zone, key_id)).fetchone()
            if row is None:
                raise ApiError(ErrorCode.KEY_NOT_FOUND,
                               f"key {key_id} not found", 404)
            if row["state"] == "REVOKED":
                raise ApiError(ErrorCode.KEY_STATE_INVALID,
                               "key already REVOKED", 409)
            ts = now_ms()
            conn.execute("UPDATE keys SET state='REVOKED', revoked_at=?, "
                         "expires_at=NULL WHERE zone=? AND key_id=?",
                         (ts, zone, key_id))
            conn.commit()
        except ApiError:
            conn.rollback()
            raise
        return {"keyId": key_id, "state": "REVOKED", "revokedAt": ts}

    # ---------------------------------------------------------- transfers
    def pin_transfer(self, zone: str, instance_id: str, target_version: int,
                     min_version: int, key_gen: int) -> str:
        ref_id = str(uuid.uuid4())
        ts = now_ms()
        self.conn.execute(
            "INSERT INTO transfer_refs(ref_id,zone,instance_id,version_id,"
            "min_version,key_gen,started_at,last_seen,state)"
            " VALUES(?,?,?,?,?,?,?,?, 'OPEN')",
            (ref_id, zone, instance_id, target_version, min_version, key_gen,
             ts, ts))
        return ref_id

    def heartbeat_transfer(self, ref_id: str) -> None:
        self.conn.execute("UPDATE transfer_refs SET last_seen=? WHERE ref_id=?",
                          (now_ms(), ref_id))

    def release_transfer(self, ref_id: str) -> None:
        try:
            self.conn.execute(
                "UPDATE transfer_refs SET state='DONE', last_seen=? WHERE "
                "ref_id=?", (now_ms(), ref_id))
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------ cleanup
    def enqueue_cleanup(self, zone: str) -> None:
        self.conn.execute(
            "INSERT INTO cleanup_tasks(zone,state,attempts,created_at)"
            " VALUES(?, 'PENDING', 0, ?)", (zone, now_ms()))

    def claim_cleanup_task(self) -> sqlite3.Row | None:
        """Atomically claim a PENDING task or reclaim an expired lease. The
        claim is its own committed transaction, so termination at any later
        point leaves a reclaimable RUNNING row."""
        conn = self.conn
        token = uuid.uuid4().hex
        now = utcnow()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM cleanup_tasks WHERE state='PENDING' ORDER BY "
                "task_id LIMIT 1").fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT * FROM cleanup_tasks WHERE state='RUNNING' AND "
                    "lease_expires < ? ORDER BY task_id LIMIT 1",
                    (now,)).fetchone()
            if row is None:
                conn.commit()
                return None
            conn.execute(
                "UPDATE cleanup_tasks SET state='RUNNING', token=?, leased_at=?,"
                " lease_expires=?, attempts=attempts+1, last_error=NULL "
                "WHERE task_id=?",
                (token, now, now + CLEANUP_LEASE_SECONDS, row["task_id"]))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return conn.execute("SELECT * FROM cleanup_tasks WHERE token=?",
                            (token,)).fetchone()

    def run_cleanup(self, task: sqlite3.Row) -> dict:
        """Idempotent retention enforcement.

        Only immutable prefix versions strictly older than both the retention
        horizon and every live transfer pin are deleted; repeating this after a
        crash simply re-evaluates the same predicate against remaining rows.
        """
        conn = self.conn
        zone = task["zone"]
        conn.execute("BEGIN IMMEDIATE")
        try:
            z = conn.execute("SELECT * FROM zones WHERE name=?", (zone,)).fetchone()
            if z is None:
                conn.execute("UPDATE cleanup_tasks SET state='DONE', finished_at=?"
                             " WHERE task_id=?", (now_ms(), task["task_id"]))
                conn.commit()
                return {"zone": zone, "deletedVersions": []}
            keep = max(1, int(z["retain_versions"]))
            delete_before = z["current_version"] - keep + 1
            alive_after = now_ms() - REF_STALE_SECONDS * 1000
            # Reap dead pin rows: completed transfers and OPEN pins whose
            # heartbeat is long dead (the serving thread is gone). They no
            # longer protect anything and must not accumulate forever.
            conn.execute(
                "DELETE FROM transfer_refs WHERE zone=? AND ("
                "state='DONE' OR (state='OPEN' AND last_seen<?))",
                (zone, alive_after))
            # Protect everything the newest open pin's IXFR chain may need:
            # MIN(version_id) for AXFR target, MIN(min_version) for IXFR start.
            pin = conn.execute(
                "SELECT COALESCE(MIN(MIN(version_id, min_version)), 999999999) "
                "AS m FROM transfer_refs WHERE zone=? AND state='OPEN' AND "
                "last_seen>?", (zone, alive_after)).fetchone()
            delete_before = min(delete_before, pin["m"])

            candidates = [r["version_id"] for r in conn.execute(
                "SELECT version_id FROM versions WHERE zone=? AND version_id < ? "
                "ORDER BY version_id", (zone, delete_before))]
            for vid in candidates:
                conn.execute("DELETE FROM records WHERE zone=? AND version_id=?",
                             (zone, vid))
                conn.execute("DELETE FROM changes WHERE zone=? AND version_id=?",
                             (zone, vid))
                conn.execute("DELETE FROM versions WHERE zone=? AND version_id=?",
                             (zone, vid))
            conn.execute("UPDATE cleanup_tasks SET state='DONE', finished_at=? "
                         "WHERE task_id=?", (now_ms(), task["task_id"]))
            conn.commit()
            return {"zone": zone, "deletedVersions": candidates,
                    "deleteBefore": delete_before, "pinnedHorizon": pin["m"]}
        except Exception as exc:
            conn.rollback()
            try:
                conn.execute("UPDATE cleanup_tasks SET last_error=? WHERE task_id=?",
                             (str(exc)[:500], task["task_id"]))
            except sqlite3.Error:
                pass
            raise
