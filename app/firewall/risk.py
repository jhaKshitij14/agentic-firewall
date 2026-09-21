"""Rule-based tool risk classification. No ML, no LLM.

    read-only       -> LOW
    writes data     -> MEDIUM
    deletes/spends  -> HIGH
    runs code/shell -> CRITICAL

The tool *name* is split into words (snake_case, kebab-case, camelCase) and matched against
verb lists. The most dangerous match wins. Unknown verbs default to MEDIUM (unknown != safe).
Explicit policy overrides always win.

Caveat: this classifies what a tool *claims* to be. A tool named `get_x` that actually deletes
data is caught by the allowlist + fingerprinting, not by this module.
"""
from __future__ import annotations

import re
from typing import Mapping

from app.models.policies import RiskLevel

_CRITICAL_WORDS = frozenset(
    {"shell", "bash", "sudo", "eval", "exec", "cmd", "powershell", "subprocess", "terminal"}
)
_LAUNCH_VERBS = frozenset({"execute", "run", "invoke", "launch"})
_CODE_OBJECTS = frozenset({"command", "commands", "cmd", "script", "code", "program", "binary", "process"})
_HIGH_WORDS = frozenset(
    {
        "delete", "remove", "drop", "truncate", "destroy", "erase", "wipe", "purge", "kill",
        "terminate", "revoke", "format", "reset", "shutdown", "execute", "trade", "buy", "sell",
        "transfer", "withdraw", "pay", "payment", "grant",
    }
)
_MEDIUM_WORDS = frozenset(
    {
        "write", "create", "update", "set", "save", "send", "post", "put", "add", "edit", "modify",
        "upload", "insert", "append", "move", "rename", "copy", "install", "deploy", "run",
        "submit", "email", "publish", "patch", "invoke",
    }
)
_LOW_WORDS = frozenset(
    {
        "get", "read", "search", "list", "fetch", "query", "describe", "show", "find", "lookup",
        "view", "check", "count", "stat", "status", "summarize", "info",
    }
)

_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")


def _words(name: str) -> set[str]:
    spaced = _CAMEL_RE.sub(r"\1_\2", name)
    return {w.lower() for w in _SPLIT_RE.split(spaced) if w}


class RiskClassifier:
    def __init__(self, overrides: Mapping[str, RiskLevel] | None = None) -> None:
        self._overrides = dict(overrides or {})

    def classify(self, tool_name: str) -> RiskLevel:
        if tool_name in self._overrides:
            return self._overrides[tool_name]
        words = _words(tool_name)
        if words & _CRITICAL_WORDS or (words & _LAUNCH_VERBS and words & _CODE_OBJECTS):
            return RiskLevel.CRITICAL
        if words & _HIGH_WORDS:
            return RiskLevel.HIGH
        if words & _MEDIUM_WORDS:
            return RiskLevel.MEDIUM
        if words & _LOW_WORDS:
            return RiskLevel.LOW
        return RiskLevel.MEDIUM
