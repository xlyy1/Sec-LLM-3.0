"""Small PyMySQL connection pool.

The API used to open a MySQL connection per request. This pool keeps a bounded
set of warm connections, pings them on checkout and discards broken ones.
"""
from __future__ import annotations

import queue
import threading
from typing import Optional

import pymysql

from config import settings


class PooledConnection:
    """Proxy that returns the underlying connection to the pool on close()."""

    def __init__(self, pool: "ConnectionPool", conn: pymysql.connections.Connection):
        self._pool = pool
        self._conn = conn
        self._released = False

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self) -> None:
        if self._released:
            return
        self._released = True
        self._pool.release(self._conn)


class ConnectionPool:
    def __init__(self, size: int = 10, timeout: float = 5.0):
        self.size = max(int(size), 1)
        self.timeout = timeout
        self._idle: "queue.LifoQueue[pymysql.connections.Connection]" = queue.LifoQueue(
            maxsize=self.size
        )
        self._created = 0
        self._lock = threading.Lock()

    def _new(self) -> pymysql.connections.Connection:
        return pymysql.connect(
            host=settings.MYSQL_HOST,
            user=settings.MYSQL_USER,
            password=settings.MYSQL_PASSWORD,
            database=settings.MYSQL_DB,
            port=settings.MYSQL_PORT,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )

    def acquire(self) -> PooledConnection:
        conn: Optional[pymysql.connections.Connection] = None
        try:
            conn = self._idle.get_nowait()
        except queue.Empty:
            with self._lock:
                if self._created < self.size:
                    self._created += 1
                    conn = self._new()
        if conn is None:
            conn = self._idle.get(timeout=self.timeout)
        try:
            conn.ping(reconnect=True)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            conn = self._new()
        return PooledConnection(self, conn)

    def release(self, conn: pymysql.connections.Connection) -> None:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            self._idle.put_nowait(conn)
        except queue.Full:
            try:
                conn.close()
            except Exception:
                pass
            with self._lock:
                self._created = max(self._created - 1, 0)

    def close_all(self) -> None:
        while True:
            try:
                conn = self._idle.get_nowait()
            except queue.Empty:
                break
            try:
                conn.close()
            except Exception:
                pass
        with self._lock:
            self._created = 0


_pool: Optional[ConnectionPool] = None
_pool_lock = threading.Lock()


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ConnectionPool(
                    size=getattr(settings, "DB_POOL_SIZE", 10),
                    timeout=getattr(settings, "DB_POOL_TIMEOUT_SECONDS", 5.0),
                )
    return _pool


def get_connection() -> PooledConnection:
    return get_pool().acquire()
