"""Persistent replay-protection and idempotency deduplication state stores for AgentWire.

Supports surviving server restarts and sharing replay/idempotency state across multiple
concurrent `AgentWireRpcServer` instances via SQLite in WAL mode (zero external dependencies).
Implement the [`StateStore`] protocol to plug in Redis, PostgreSQL, or etcd in distributed deployments.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class StateStore(Protocol):
    """Pluggable persistence interface for cross-restart & multi-instance replay + idempotency."""

    def record_nonce_if_new(
        self, source_agent: str, nonce: int, expires_at_ms: int
    ) -> bool:
        """Atomically record `(source_agent, nonce)` if unseen; return `False` on replay."""
        ...

    def get_idempotent_response(
        self, source_agent: str, idempotency_key: str
    ) -> bytes | None:
        """Return cached binary response frame if `(source_agent, idempotency_key)` already completed."""
        ...

    def save_idempotent_response(
        self,
        source_agent: str,
        idempotency_key: str,
        response_bytes: bytes,
        expires_at_ms: int,
    ) -> None:
        """Persist the binary response frame for an idempotently completed request."""
        ...

    def close(self) -> None:
        ...


class SqliteStateStore:
    """Thread-safe, multi-process-safe SQLite (WAL mode) replay & idempotency store.

    - Survives server restarts when pointed at a persistent file path.
    - Safe across multiple concurrent `AgentWireRpcServer` instances sharing the same DB file
      thanks to `PRAGMA journal_mode=WAL`, `busy_timeout`, and `BEGIN IMMEDIATE` atomic writes.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if str(db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            isolation_level=None,  # Explicit transaction control
            check_same_thread=False,
        )
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA busy_timeout=5000;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_nonces (
                    source_agent TEXT NOT NULL,
                    nonce INTEGER NOT NULL,
                    expires_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (source_agent, nonce)
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_cache (
                    source_agent TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    response_bytes BLOB NOT NULL,
                    expires_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (source_agent, idempotency_key)
                );
                """
            )
            cur.close()

    def record_nonce_if_new(
        self, source_agent: str, nonce: int, expires_at_ms: int
    ) -> bool:
        """Atomically insert `(source_agent, nonce)`. Returns `True` if fresh, `False` if replayed."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE;")
                cur.execute(
                    """
                    INSERT OR IGNORE INTO seen_nonces (source_agent, nonce, expires_at_ms)
                    VALUES (?, ?, ?);
                    """,
                    (source_agent, int(nonce), int(expires_at_ms)),
                )
                inserted = cur.rowcount == 1
                cur.execute("COMMIT;")
                return inserted
            except Exception:
                cur.execute("ROLLBACK;")
                raise
            finally:
                cur.close()

    def get_idempotent_response(
        self, source_agent: str, idempotency_key: str
    ) -> bytes | None:
        now_ms = int(time.time() * 1000)
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute(
                    """
                    SELECT response_bytes, expires_at_ms
                    FROM idempotency_cache
                    WHERE source_agent = ? AND idempotency_key = ?;
                    """,
                    (source_agent, idempotency_key),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                raw_bytes, exp = row
                if exp > 0 and exp < now_ms:
                    return None
                return bytes(raw_bytes)
            finally:
                cur.close()

    def save_idempotent_response(
        self,
        source_agent: str,
        idempotency_key: str,
        response_bytes: bytes,
        expires_at_ms: int,
    ) -> None:
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE;")
                cur.execute(
                    """
                    INSERT OR REPLACE INTO idempotency_cache
                        (source_agent, idempotency_key, response_bytes, expires_at_ms)
                    VALUES (?, ?, ?, ?);
                    """,
                    (
                        source_agent,
                        idempotency_key,
                        sqlite3.Binary(response_bytes),
                        int(expires_at_ms),
                    ),
                )
                cur.execute("COMMIT;")
            except Exception:
                cur.execute("ROLLBACK;")
                raise
            finally:
                cur.close()

    def purge_expired(self, now_ms: int | None = None) -> int:
        cutoff = now_ms if now_ms is not None else int(time.time() * 1000)
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE;")
                cur.execute("DELETE FROM seen_nonces WHERE expires_at_ms > 0 AND expires_at_ms < ?;", (cutoff,))
                removed = cur.rowcount
                cur.execute("DELETE FROM idempotency_cache WHERE expires_at_ms > 0 AND expires_at_ms < ?;", (cutoff,))
                removed += cur.rowcount
                cur.execute("COMMIT;")
                return removed
            except Exception:
                cur.execute("ROLLBACK;")
                raise
            finally:
                cur.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
