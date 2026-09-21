"""Process entry points.

Roles (single image, selected by SERVICE_ROLE):
  edge     -- HTTP management API + UDP/TCP DNS endpoints
  cleaner  -- independent history-retention worker
"""
from __future__ import annotations

import signal
import sys
import threading
import time

from .config import Config
from .storage import Database


def run_edge() -> int:
    from .api import build_api_server
    from .dns_server import build_dns_servers

    db = Database(Config.DB_PATH)
    dns_ready = {"udp": False, "tcp": False}
    udp, tcp = build_dns_servers(db, dns_ready)
    httpd = build_api_server(db, dns_ready)
    api_thread = threading.Thread(target=httpd.serve_forever, name="http-api",
                                  daemon=True)
    api_thread.start()
    print(f"[edge {Config.INSTANCE_ID}] http on :{Config.API_PORT} "
          f"dns udp/tcp on :{Config.DNS_PORT} db={Config.DB_PATH}", flush=True)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        while not stop.wait(1):
            pass
    finally:
        httpd.shutdown()
        udp.shutdown()
        tcp.shutdown()
    return 0


def run_cleaner() -> int:
    from .cleaner import CleanupWorker

    db = Database(Config.DB_PATH)
    worker = CleanupWorker(db, interval=float(
        __import__("os").environ.get("CLEAN_INTERVAL", "2")))
    print("[cleaner] history retention worker started", flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        worker.run(stop)
    finally:
        stop.set()
    return 0


ROLES = {"edge": run_edge, "cleaner": run_cleaner}


def main() -> int:
    role = __import__("os").environ.get("SERVICE_ROLE", "edge")
    if role not in ROLES:
        print(f"unknown SERVICE_ROLE={role!r}; want one of {sorted(ROLES)}",
              file=sys.stderr)
        return 2
    return ROLES[role]()


if __name__ == "__main__":
    raise SystemExit(main())
