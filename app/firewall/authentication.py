"""Session identity: who is making this request?

Flow: register_user (operator) -> login(user_id, api_key) -> session_id -> every request carries it.
The role is looked up server-side from the users table. The client never supplies its own role.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from typing import Callable

from app.models.requests import UserSession
from app.storage.database import Database

USER_ID_RE = re.compile(r"[A-Za-z0-9_.@\-]{1,64}")
MIN_API_KEY_LEN = 16
_MAX_SESSION_ID_LEN = 256


class AuthError(Exception):
    """Authentication failed. The message is safe to show to the caller."""


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


# Compared against when the user doesn't exist, so "no such user" and "wrong key" take the same path.
_DUMMY_HASH = _sha256("dummy-credential-used-for-constant-time-comparison")


class Authenticator:
    def __init__(
        self,
        db: Database,
        *,
        clock: Callable[[], float] = time.time,
        session_ttl_seconds: int = 3600,
    ) -> None:
        self._db = db
        self._clock = clock
        self._ttl = session_ttl_seconds

    def register_user(self, user_id: str, role: str, api_key: str) -> None:
        if not USER_ID_RE.fullmatch(user_id):
            raise ValueError("user_id must be 1-64 chars of letters, digits, _ . @ -")
        if len(api_key) < MIN_API_KEY_LEN:
            raise ValueError(f"api_key must be at least {MIN_API_KEY_LEN} characters")
        if not role:
            raise ValueError("role must not be empty")
        # API keys are high-entropy random strings, so a plain SHA-256 is appropriate here.
        # (If you ever store human-chosen passwords, use scrypt/argon2 instead.)
        self._db.add_user(user_id, role, _sha256(api_key))

    def login(self, user_id: str, api_key: str) -> tuple[str, UserSession]:
        row = None
        if isinstance(user_id, str) and USER_ID_RE.fullmatch(user_id):
            row = self._db.get_user(user_id)
        supplied = _sha256(api_key if isinstance(api_key, str) else "")
        expected = row["api_key_hash"] if row else _DUMMY_HASH
        matches = hmac.compare_digest(supplied, expected)
        if row is None or not matches:
            raise AuthError("invalid credentials")

        session_id = secrets.token_urlsafe(32)
        now = self._clock()
        session_hash = _sha256(session_id)
        self._db.create_session(session_hash, row["user_id"], now, now + self._ttl)
        return session_id, UserSession(
            user_id=row["user_id"],
            role=row["role"],
            session_ref=session_hash[:12],
            created_at=now,
            expires_at=now + self._ttl,
        )

    def validate(self, session_id: str) -> UserSession:
        if not isinstance(session_id, str) or not session_id:
            raise AuthError("missing session")
        if len(session_id) > _MAX_SESSION_ID_LEN:
            raise AuthError("invalid session")
        session_hash = _sha256(session_id)
        row = self._db.get_session(session_hash)
        if row is None:
            raise AuthError("invalid session")
        if row["revoked"]:
            raise AuthError("session revoked")
        if self._clock() >= row["expires_at"]:
            raise AuthError("session expired")
        return UserSession(
            user_id=row["user_id"],
            role=row["role"],  # current role from the users table, not a copy taken at login
            session_ref=session_hash[:12],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def revoke(self, session_id: str) -> bool:
        return self._db.revoke_session(_sha256(session_id))
