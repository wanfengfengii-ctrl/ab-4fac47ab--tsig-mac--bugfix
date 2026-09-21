"""Independent history cleanup worker.

Lease protocol (see storage.claim_cleanup_task / run_cleanup):
  1. Claiming a task is a committed IMMEDIATE transaction that marks the row
     RUNNING with a token and an expiry. Crashes after claim, mid-delete, or
     before commit simply leave a RUNNING row that another worker reclaims once
     the lease expires; deletes are idempotent because the retention predicate
     is re-evaluated against only the rows that still exist.
  2. A post-claim crash also loses nothing: zones enqueue a fresh task on every
     publish and on retention-policy changes.
"""
from __future__ import annotations

import threading
import time

from .storage import Database


class CleanupWorker:
    def __init__(self, db: Database, interval: float = 2.0):
        self.db = db
        self.interval = interval

    def run_once(self) -> bool:
        task = self.db.claim_cleanup_task()
        if task is None:
            return False
        result = self.db.run_cleanup(task)
        if result["deletedVersions"]:
            print(f"[cleaner] zone={result['zone']} deleted versions "
                  f"{result['deletedVersions']} (horizon={result['deleteBefore']})",
                  flush=True)
        return True

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                while not stop.is_set() and self.run_once():
                    pass
            except Exception as exc:  # worker must survive DB hiccups
                print(f"[cleaner] error: {exc!r}", flush=True)
            stop.wait(self.interval)
