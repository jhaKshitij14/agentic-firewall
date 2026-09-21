"""Tool integrity: pin each approved tool definition by SHA-256 and block on any change.

Threats covered:
  * rug pull: server swaps in a new (malicious) description/schema after you approved the tool
  * tool poisoning: hidden instructions inside a description/schema
  * unapproved tools: anything never approved is not callable

Everything the server declares about the tool is hashed (name, description, input schema,
annotations, extra fields), serialised canonically so key order never matters.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Callable

from app.models.requests import ToolDefinition
from app.storage.database import Database

OK = "ok"
CHANGED = "changed"
UNAPPROVED = "unapproved"


def canonical_bytes(defn: ToolDefinition) -> bytes:
    payload = {
        "name": defn.name,
        "description": defn.description,
        "input_schema": defn.input_schema,
        "annotations": defn.annotations,
        "extras": defn.extras,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def fingerprint(defn: ToolDefinition) -> str:
    return hashlib.sha256(canonical_bytes(defn)).hexdigest()


@dataclass(frozen=True)
class IntegrityResult:
    status: str  # ok | changed | unapproved
    fingerprint: str

    @property
    def ok(self) -> bool:
        return self.status == OK

    @property
    def reason(self) -> str:
        if self.status == CHANGED:
            return "tool definition changed since it was approved"
        if self.status == UNAPPROVED:
            return "tool has not been approved"
        return "tool definition matches approved fingerprint"


class IntegrityChecker:
    def __init__(self, db: Database, *, clock: Callable[[], float] = time.time) -> None:
        self._db = db
        self._clock = clock

    def approve(self, defn: ToolDefinition, approved_by: str | None = None) -> str:
        fp = fingerprint(defn)
        self._db.upsert_fingerprint(defn.name, fp, self._clock(), approved_by)
        return fp

    def approved_fingerprint(self, tool_name: str) -> str | None:
        row = self._db.get_fingerprint(tool_name)
        return row["fingerprint"] if row else None

    def verify(self, defn: ToolDefinition) -> IntegrityResult:
        current = fingerprint(defn)
        stored = self.approved_fingerprint(defn.name)
        if stored is None:
            return IntegrityResult(UNAPPROVED, current)
        if not hmac.compare_digest(stored, current):
            return IntegrityResult(CHANGED, current)
        return IntegrityResult(OK, current)
