"""Versioned HTTP JSON management API (v1).

All endpoints return JSON; every error has a stable machine code under
``error.code``. The API is stateless apart from the shared Database, so any
instance can serve any request (including idempotent retries).
"""
from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, unquote

from . import canonical as canon
from .config import Config
from .errors import ApiError, ErrorCode
from .serial import valid_u32
from .storage import Database


def canonical_fingerprint(base_serial: int, next_serial: int,
                          ops: list[dict], zone: str) -> str:
    """Stable hash of the semantically meaningful request content.

    Owner names/RDATA are canonicalized, so retries that differ only in case or
    presentation whitespace hash identically; any content change hashes
    differently (stable IDEMPOTENCY_CONFLICT)."""
    norm_ops = []
    for idx, op in enumerate(ops):
        if not isinstance(op, dict):
            raise ApiError(ErrorCode.VALIDATION_ERROR,
                           f"op {idx} must be an object")
        action = str(op.get("action", "")).lower()
        name = canon.canonical_name(op.get("name", ""), zone)
        rtype = str(op.get("type", "")).upper()
        entry = {"action": action, "name": name, "type": rtype}
        if action == "replace":
            entry["ttl"] = canon._check_ttl(op.get("ttl", 3600))
            records = op.get("records", [])
            if not isinstance(records, list):
                raise ApiError(ErrorCode.VALIDATION_ERROR,
                               f"op {idx}: records must be a list")
            entry["records"] = []
            for val in records:
                rj, _ = canon.canonical_rdata(rtype, val, zone)
                entry["records"].append(json.loads(rj))
        norm_ops.append(entry)
    norm_ops.sort(key=lambda o: (o["name"], o["type"], o["action"]))
    payload = json.dumps(
        {"baseSerial": base_serial, "nextSerial": next_serial,
         "ops": norm_ops}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "EdgeDNS/1.0"
    db: Database = None           # injected via server instance
    dns_ready: dict = None        # injected shared state

    # Silence the default noisy logger; structured logging lives in server.py
    def log_message(self, fmt, *args):  # noqa: D401
        pass

    # ------------------------------------------------------------ helpers
    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body, sort_keys=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_error(self, exc: ApiError) -> None:
        self._send_json(exc.http_status, exc.to_dict())

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError(ErrorCode.VALIDATION_ERROR, "bad Content-Length")
        if length <= 0:
            raise ApiError(ErrorCode.MALFORMED_JSON, "request body required")
        if length > 4 * 1024 * 1024:
            raise ApiError(ErrorCode.LIMIT_EXCEEDED, "request body too large",
                           413)
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(ErrorCode.MALFORMED_JSON, "body is not valid JSON")
        if not isinstance(body, dict):
            raise ApiError(ErrorCode.MALFORMED_JSON,
                           "request body must be a JSON object")
        return body

    # --------------------------------------------------------------- GET
    def do_GET(self) -> None:
        try:
            path = urlsplit(self.path).path
            if path == "/healthz":
                return self._health()
            if path == "/v1/zones":
                zones = [self.db.zone_metadata(z["name"])
                         for z in self.db.list_zones()]
                return self._send_json(200, {"zones": zones})
            parts = [unquote(p) for p in path.strip("/").split("/")]
            if len(parts) == 3 and parts[:2] == ["v1", "zones"]:
                return self._send_json(
                    200, self.db.zone_metadata(
                        canon.canonical_zone_arg(parts[2])))
            if len(parts) == 5 and parts[:2] == ["v1", "zones"] \
                    and parts[3] == "requests":
                row = self.db.get_request(
                    canon.canonical_zone_arg(parts[2]), parts[4])
                return self._send_json(200, self._request_view(row))
            if len(parts) == 4 and parts[:2] == ["v1", "zones"] \
                    and parts[3] == "keys":
                return self._send_json(
                    200, {"keys": self.db.list_keys(
                        canon.canonical_zone_arg(parts[2]))})
            raise ApiError(ErrorCode.NOT_FOUND, "no such endpoint", 404)
        except ApiError as exc:
            self._send_error(exc)
        except Exception:
            self._send_error(ApiError(ErrorCode.INTERNAL, "internal error", 500))

    # -------------------------------------------------------------- POST
    def do_POST(self) -> None:
        try:
            path = urlsplit(self.path).path.strip("/")
            parts = [unquote(p) for p in path.split("/")]
            body = self._read_json()
            if parts == ["v1", "zones"]:
                return self._create_zone(body)
            if len(parts) == 4 and parts[:2] == ["v1", "zones"] \
                    and parts[3] == "publish":
                return self._publish(parts[2], body)
            if len(parts) == 4 and parts[:2] == ["v1", "zones"] \
                    and parts[3] == "keys":
                return self._install_key(parts[2], body)
            if len(parts) == 6 and parts[:2] == ["v1", "zones"] \
                    and parts[3] == "keys" and parts[5] == "revoke":
                return self._send_json(
                    200, self.db.revoke_key(
                        canon.canonical_zone_arg(parts[2]), parts[4]))
            raise ApiError(ErrorCode.NOT_FOUND, "no such endpoint", 404)
        except ApiError as exc:
            self._send_error(exc)
        except Exception:
            self._send_error(ApiError(ErrorCode.INTERNAL, "internal error", 500))

    # --------------------------------------------------------------- PUT
    def do_PUT(self) -> None:
        try:
            path = urlsplit(self.path).path.strip("/")
            parts = [unquote(p) for p in path.split("/")]
            body = self._read_json()
            if len(parts) == 4 and parts[:2] == ["v1", "zones"] \
                    and parts[3] == "retention":
                return self._set_retention(parts[2], body)
            raise ApiError(ErrorCode.NOT_FOUND, "no such endpoint", 404)
        except ApiError as exc:
            self._send_error(exc)
        except Exception:
            self._send_error(ApiError(ErrorCode.INTERNAL, "internal error", 500))

    def do_DELETE(self) -> None:
        self._send_error(ApiError(ErrorCode.METHOD_NOT_ALLOWED,
                                  "method not allowed", 405))

    # ------------------------------------------------------------- routes
    def _health(self) -> None:
        checks = {"api": "ok", "persistence": "down", "dnsUdp": "down",
                  "dnsTcp": "down"}
        try:
            self.db.ping()
            checks["persistence"] = "ok"
        except Exception:
            pass
        if self.dns_ready is not None:
            checks["dnsUdp"] = "ok" if self.dns_ready.get("udp") else "down"
            checks["dnsTcp"] = "ok" if self.dns_ready.get("tcp") else "down"
        ok = all(v == "ok" for v in checks.values())
        self._send_json(200 if ok else 503,
                        {"status": "ok" if ok else "degraded", "checks": checks})

    def _create_zone(self, body: dict) -> None:
        name = canon.canonical_zone(str(body.get("name", "")))
        serial = valid_u32(body.get("serial"))
        if serial is None:
            raise ApiError(ErrorCode.SERIAL_INVALID,
                           "serial must be 0..4294967295", 422)
        soa = body.get("soa")
        if not isinstance(soa, dict):
            raise ApiError(ErrorCode.VALIDATION_ERROR, "soa object required")
        for field in ("mname", "rname"):
            if not isinstance(soa.get(field), str):
                raise ApiError(ErrorCode.VALIDATION_ERROR,
                               f"soa.{field} required")
        for field, default in (("refresh", 7200), ("retry", 3600),
                               ("expire", 1209600), ("minimum", 3600)):
            soa.setdefault(field, default)
        ns = body.get("ns")
        if not isinstance(ns, list) or not ns:
            raise ApiError(ErrorCode.VALIDATION_ERROR,
                           "ns must be a non-empty list of name servers")
        if len(ns) > Config.MAX_CHANGES_PER_PUBLISH:
            raise ApiError(ErrorCode.LIMIT_EXCEEDED, "too many NS records", 413)
        retain = int(body.get("retainVersions", 10))
        if not isinstance(retain, int) or retain < 1 or retain > 100000:
            raise ApiError(ErrorCode.VALIDATION_ERROR,
                           "retainVersions must be 1..100000", 422)
        meta = self.db.create_zone(name, serial, soa, [str(n) for n in ns],
                                   retain)
        self._send_json(201, {"zone": meta})

    def _publish(self, zone_name: str, body: dict) -> None:
        zone = canon.canonical_zone_arg(zone_name)
        request_id = body.get("requestId")
        if not isinstance(request_id, str) or not request_id.strip() \
                or len(request_id) > 200:
            raise ApiError(ErrorCode.VALIDATION_ERROR,
                           "requestId must be a non-empty string (<=200 chars)")
        base_serial = valid_u32(body.get("baseSerial"))
        next_serial = valid_u32(body.get("nextSerial"))
        if base_serial is None or next_serial is None:
            raise ApiError(ErrorCode.SERIAL_INVALID,
                           "baseSerial/nextSerial must be 0..4294967295", 422)
        ops = body.get("changes", body.get("ops"))
        if ops is None:
            raise ApiError(ErrorCode.VALIDATION_ERROR, "changes required")
        if not isinstance(ops, list) or not ops:
            raise ApiError(ErrorCode.CHANGESET_INVALID,
                           "changes must be a non-empty list")
        if len(ops) > Config.MAX_CHANGES_PER_PUBLISH:
            raise ApiError(ErrorCode.LIMIT_EXCEEDED,
                           f"at most {Config.MAX_CHANGES_PER_PUBLISH} changes "
                           "per publish", 413,
                           {"limit": Config.MAX_CHANGES_PER_PUBLISH,
                            "count": len(ops)})
        # Canonicalize before opening the write transaction (fail fast and
        # reject over-limit input before any persistence attempt).
        fingerprint = canonical_fingerprint(base_serial, next_serial, ops, zone)
        result = self.db.publish(zone, request_id.strip(), base_serial,
                                 next_serial, ops, fingerprint)
        self._send_json(200 if result.get("replayed") else 201, {"result": result})

    def _set_retention(self, zone: str, body: dict) -> None:
        zone = canon.canonical_zone_arg(zone)
        retain = body.get("retainVersions")
        if not isinstance(retain, int) or isinstance(retain, bool) \
                or retain < 1 or retain > 100000:
            raise ApiError(ErrorCode.VALIDATION_ERROR,
                           "retainVersions must be an integer 1..100000", 422)
        self._send_json(200, {"retention": self.db.set_retention(zone, retain)})

    def _install_key(self, zone: str, body: dict) -> None:
        zone = canon.canonical_zone_arg(zone)
        key_id = str(body.get("keyId") or "").strip()
        if not key_id or len(key_id) > 200:
            raise ApiError(ErrorCode.VALIDATION_ERROR,
                           "keyId must be a non-empty string (<=200 chars)")
        key_name = body.get("keyName")
        if key_name is not None:
            key_name = str(key_name).strip().lower()
            if not key_name or len(key_name) > 255:
                raise ApiError(ErrorCode.VALIDATION_ERROR, "bad keyName")
        expires_at = None
        if body.get("retireInSeconds") is not None:
            secs = body["retireInSeconds"]
            if not isinstance(secs, int) or isinstance(secs, bool) or secs < 1:
                raise ApiError(ErrorCode.VALIDATION_ERROR,
                               "retireInSeconds must be a positive integer")
            from .storage import now_ms
            expires_at = now_ms() + secs * 1000
        result = self.db.install_key(zone, key_id, key_name, expires_at)
        # The plaintext secret is returned exactly once, at installation.
        self._send_json(201, {"key": result})

    @staticmethod
    def _request_view(row) -> dict:
        out = {"zone": row["zone"], "requestId": row["request_id"],
               "status": row["status"], "versionId": row["version_id"],
               "serial": row["serial"], "baseSerial": row["base_serial"],
               "nextSerial": row["next_serial"], "createdAt": row["created_at"]}
        if row["status"] == "FAILED":
            out["error"] = {"code": row["error_code"],
                            "message": row["error_message"]}
        return out


def build_api_server(db: Database, dns_ready: dict) -> ThreadingHTTPServer:
    handler = ApiHandler
    handler.db = db
    handler.dns_ready = dns_ready
    httpd = ThreadingHTTPServer((Config.API_HOST, Config.API_PORT), handler)
    httpd.daemon_threads = True
    return httpd
