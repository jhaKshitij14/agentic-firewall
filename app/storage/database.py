"""SQLite storage: users, sessions, audit_logs, tool_fingerprints.

One connection guarded by a lock (SQLite is fast enough for this scope, and the lock makes
it safe to share between FastAPI's event loop, worker threads, and tests).
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    api_key_hash  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    session_hash  TEXT PRIMARY KEY,            -- SHA-256 of the session id; raw id is never stored
    user_id       TEXT NOT NULL REFERENCES users(user_id),
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    user_id       TEXT,
    session_ref   TEXT,
    role          TEXT,
    tool          TEXT,
    risk          TEXT,
    decision      TEXT NOT NULL,
    stage         TEXT NOT NULL,
    reason        TEXT NOT NULL,
    latency_ms    REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tool_fingerprints (
    tool_name     TEXT PRIMARY KEY,
    fingerprint   TEXT NOT NULL,
    approved_at   REAL NOT NULL,
    approved_by   TEXT
);
"""


class Database:
    def __init__(self, path: str = ":memory:") -> None:
        if path != ":memory:":
            Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # -- helpers ---------------------------------------------------------------------------
    def _write(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _query(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- users / sessions ------------------------------------------------------------------
    def add_user(self, user_id: str, role: str, api_key_hash: str) -> None:
        try:
            self._write(
                "INSERT INTO users (user_id, role, api_key_hash) VALUES (?, ?, ?)",
                (user_id, role, api_key_hash),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"user {user_id!r} already exists") from exc

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM users WHERE user_id = ?", (user_id,))
        return rows[0] if rows else None

    def create_session(
        self, session_hash: str, user_id: str, created_at: float, expires_at: float
    ) -> None:
        self._write(
            "INSERT INTO sessions (session_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (session_hash, user_id, created_at, expires_at),
        )

    def get_session(self, session_hash: str) -> dict[str, Any] | None:
        rows = self._query(
            "SELECT s.session_hash, s.user_id, s.created_at, s.expires_at, s.revoked, u.role "
            "FROM sessions s JOIN users u ON u.user_id = s.user_id WHERE s.session_hash = ?",
            (session_hash,),
        )
        return rows[0] if rows else None

    def revoke_session(self, session_hash: str) -> bool:
        return self._write(
            "UPDATE sessions SET revoked = 1 WHERE session_hash = ?", (session_hash,)
        ).rowcount > 0

    # -- audit -----------------------------------------------------------------------------
    def add_audit(
        self,
        *,
        ts: float,
        user_id: str | None,
        session_ref: str | None,
        role: str | None,
        tool: str | None,
        risk: str | None,
        decision: str,
        stage: str,
        reason: str,
        latency_ms: float,
    ) -> int:
        cur = self._write(
            "INSERT INTO audit_logs (ts, user_id, session_ref, role, tool, risk, decision, stage, "
            "reason, latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, user_id, session_ref, role, tool, risk, decision, stage, reason, latency_ms),
        )
        return int(cur.lastrowid or 0)

    def recent_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (int(limit),))

    # -- tool fingerprints -----------------------------------------------------------------
    def get_fingerprint(self, tool_name: str) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM tool_fingerprints WHERE tool_name = ?", (tool_name,))
        return rows[0] if rows else None

    def upsert_fingerprint(
        self, tool_name: str, fingerprint: str, approved_at: float, approved_by: str | None
    ) -> None:
        self._write(
            "INSERT INTO tool_fingerprints (tool_name, fingerprint, approved_at, approved_by) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(tool_name) DO UPDATE SET "
            "fingerprint = excluded.fingerprint, approved_at = excluded.approved_at, "
            "approved_by = excluded.approved_by",
            (tool_name, fingerprint, approved_at, approved_by),
        )

    def list_fingerprints(self) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM tool_fingerprints ORDER BY tool_name")
