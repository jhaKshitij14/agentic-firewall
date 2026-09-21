"""Deterministic input/output/description scanner. Regex rules only: no ML, no LLM.

Directions:
    input        agent -> tool   (tool-call arguments)
    output       tool  -> agent  (tool responses)
    description  tool metadata   (checked when a tool is approved)

Text is normalised before matching (NFKC, zero-width characters stripped, whitespace collapsed)
so trivial obfuscation like fullwidth letters or "ig<zero-width space>nore" does not slip past.

The scanner never stores or returns matched text, only rule name + location, so findings
can be logged without leaking the secret that triggered them.

What this is NOT: a semantic prompt-injection detector. A paraphrased attack that avoids these
patterns will pass. See README "Known limitations". That is why authorization, fingerprinting and
rate limits, which do not depend on reading intent, are the primary controls.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Mapping

INPUT = "input"
OUTPUT = "output"
DESCRIPTION = "description"
_ALL = frozenset({INPUT, OUTPUT, DESCRIPTION})
_INPUT_ONLY = frozenset({INPUT})
_INPUT_AND_DESC = frozenset({INPUT, DESCRIPTION})
_DESC_AND_OUTPUT = frozenset({DESCRIPTION, OUTPUT})


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    pattern: re.Pattern[str]
    directions: frozenset[str] = _ALL


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


_SECRET_WORDS = r"(?:secrets?|passwords?|credentials?|tokens?|api\s*keys?|private\s*keys?|ssh\s*keys?)"

RULES: tuple[Rule, ...] = (
    # ---- prompt injection / tool poisoning -------------------------------------------------
    Rule(
        "ignore_instructions",
        "prompt_injection",
        _r(
            r"\b(?:ignore|disregard|forget|override|bypass)\s+"
            r"(?:(?:all|any|the|your|my|these|those|of)\s+)*"
            r"(?:(?:previous|prior|above|earlier|preceding|system|safety|original|initial|other)\s+)*"
            r"(?:instructions?|prompts?|rules?|guidelines?|directions?|polic(?:y|ies)|constraints?|restrictions?)\b"
        ),
    ),
    Rule(
        "reveal_system_prompt",
        "prompt_injection",
        _r(
            r"\b(?:reveal|show|print|output|repeat|leak|display|disclose)\b[^.]{0,30}"
            r"\b(?:system\s+prompt|hidden\s+(?:instructions?|prompt)|initial\s+(?:instructions?|prompt))\b"
        ),
    ),
    Rule(
        "role_override",
        "prompt_injection",
        _r(
            r"\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|evil|dan\b|free\s+of|no\s+longer\s+bound)"
            r"|\bnew\s+instructions?\s*:"
            r"|\bfrom\s+now\s+on,?\s+you\s+(?:must|will|should|are|shall)\b"
            r"|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|dan)\b"
        ),
    ),
    Rule(
        "hidden_directive_tag",
        "prompt_injection",
        _r(r"<\s*/?\s*(?:important|system|instructions?|admin|secret|override)\s*>"),
    ),
    Rule(
        "chat_template_token",
        "prompt_injection",
        _r(r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>|\[/?INST\]"),
    ),
    Rule(
        "conceal_from_user",
        "prompt_injection",
        _r(
            r"\b(?:do\s+not|don['\u2019]?t|never)\s+(?:tell|inform|mention|reveal|show|notify|alert)\b"
            r"[^.]{0,30}\b(?:user|human|operator)\b"
        ),
    ),
    Rule(
        "pre_use_directive",
        "prompt_injection",
        _r(
            r"\bbefore\s+(?:using|calling|invoking|running)\s+(?:this|the)\s+tool\b[^.]{0,100}"
            r"\b(?:read|send|include|pass|open|access|attach|append)\b"
        ),
        _DESC_AND_OUTPUT,
    ),
    # ---- exfiltration ----------------------------------------------------------------------
    Rule(
        "send_secret_to",
        "exfiltration",
        _r(
            r"\b(?:send|post|upload|exfiltrat\w*|forward|transmit|leak|email)\b[^.]{0,40}\b"
            + _SECRET_WORDS
            + r"\b[^.]{0,40}\b(?:to|at|via)\b"
        ),
    ),
    Rule("exfiltrate_word", "exfiltration", _r(r"\bexfiltrat(?:e|es|ed|ing|ion)\b"), _INPUT_AND_DESC),
    # ---- secret access (sensitive files/paths) ---------------------------------------------
    Rule(
        "sensitive_path",
        "secret_access",
        _r(
            r"(?<![\w])(?:\.env(?:\.[\w-]+)?|\.ssh|\.aws|\.gnupg|\.kube|\.netrc|\.npmrc|\.pypirc|\.git-credentials)(?![\w-])"
            r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)"
            r"|/etc/(?:passwd|shadow|sudoers)\b"
            r"|/proc/self/environ\b"
            r"|\bcredentials\.json\b"
            r"|\bsecrets?\.(?:ya?ml|json)\b"
        ),
    ),
    # ---- secret material (keys/tokens in the payload itself) -------------------------------
    Rule("aws_access_key", "secret_material", _r(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule(
        "private_key_block",
        "secret_material",
        _r(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    ),
    Rule(
        "service_token",
        "secret_material",
        _r(
            r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"
            r"|\bgithub_pat_[A-Za-z0-9_]{22,}\b"
            r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
            r"|\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"
            r"|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
        ),
    ),
    Rule(
        "credential_assignment",
        "secret_material",
        _r(
            r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)\b"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{12,}"
        ),
    ),
    # ---- command injection / path traversal (arguments only) -------------------------------
    Rule(
        "shell_chaining",
        "command_injection",
        _r(
            r"(?:;|&&|\|\||\|)\s*(?:rm|curl|wget|nc|ncat|netcat|bash|sh|zsh|powershell|cmd|chmod|chown|dd|mkfs|sudo|scp)\b"
        ),
        _INPUT_ONLY,
    ),
    Rule(
        "command_substitution",
        "command_injection",
        _r(
            r"\$\(\s*(?:rm|curl|wget|nc|bash|sh|cat|ls|id|whoami|env|printenv|echo|uname)\b[^)]{0,200}\)"
            r"|`\s*(?:rm|curl|wget|nc|bash|sh|cat|ls|id|whoami|env|printenv|echo|uname)\b[^`]{0,200}`"
        ),
        _INPUT_ONLY,
    ),
    Rule("destructive_rm", "command_injection", _r(r"\brm\s+-[a-z]*[rf][a-z]*\b"), _INPUT_ONLY),
    Rule(
        "download_and_execute",
        "command_injection",
        _r(r"\b(?:curl|wget)\b[^|;&]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
        _INPUT_ONLY,
    ),
    Rule(
        "reverse_shell",
        "command_injection",
        _r(r"/dev/tcp/|\bbash\s+-i\b|\b(?:nc|ncat|netcat)\b[^|;&]{0,40}\s-[a-z]*e\b"),
        _INPUT_ONLY,
    ),
    Rule("path_traversal", "path_traversal", _r(r"\.\.[/\\]"), _INPUT_ONLY),
)

# Characters that are suspicious on their own (invisible text, bidi overrides, Unicode tag block
# used for "ASCII smuggling"). ZWJ/ZWNJ/LRM/RLM are NOT flagged (legit in emoji, Indic and RTL
# scripts) but are stripped before matching so they can't be used to split keywords.
_FLAG_RE = re.compile(r"[\u200b\u2060-\u2064\u202a-\u202e\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
_STRIP_RE = re.compile(r"[\u200b-\u200f\u2060-\u2064\u202a-\u202e\u2066-\u2069\ufeff\u00ad\U000e0000-\U000e007f]")
_WS_RE = re.compile(r"\s+")

_RULES_BY_DIRECTION: dict[str, tuple[Rule, ...]] = {
    d: tuple(r for r in RULES if d in r.directions) for d in (INPUT, OUTPUT, DESCRIPTION)
}


@dataclass(frozen=True)
class Finding:
    rule: str
    category: str
    location: str  # e.g. arguments.query or arguments.items[2]; never the matched text


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.findings)

    @property
    def categories(self) -> set[str]:
        return {f.category for f in self.findings}

    def summary(self, limit: int = 5) -> str:
        shown = [f"{f.category}/{f.rule} at {f.location}" for f in self.findings[:limit]]
        extra = len(self.findings) - limit
        if extra > 0:
            shown.append(f"and {extra} more")
        return "; ".join(shown)


class _State:
    def __init__(self, budget: int) -> None:
        self.budget = budget
        self.findings: list[Finding] = []
        self.stop = False


class Scanner:
    def __init__(self, max_chars: int = 1_000_000, max_depth: int = 20) -> None:
        self._max_chars = max_chars
        self._max_depth = max_depth

    # -- single string ---------------------------------------------------------------------
    def scan_text(self, text: str, direction: str, location: str = "text") -> list[Finding]:
        if direction not in _RULES_BY_DIRECTION:
            raise ValueError(f"unknown scan direction {direction!r}")
        findings: list[Finding] = []
        if _FLAG_RE.search(text):
            findings.append(Finding("hidden_characters", "obfuscation", location))
        norm = unicodedata.normalize("NFKC", text)
        norm = _STRIP_RE.sub("", norm)
        norm = _WS_RE.sub(" ", norm)
        for rule in _RULES_BY_DIRECTION[direction]:
            if rule.pattern.search(norm):
                findings.append(Finding(rule.name, rule.category, location))
        return findings

    # -- arbitrary JSON-like value ---------------------------------------------------------
    def scan_value(self, value: Any, direction: str, root: str = "value") -> ScanResult:
        if direction not in _RULES_BY_DIRECTION:
            raise ValueError(f"unknown scan direction {direction!r}")
        state = _State(self._max_chars)
        self._walk(value, direction, root, 0, state)
        return ScanResult(state.findings)

    def _walk(self, value: Any, direction: str, loc: str, depth: int, st: _State) -> None:
        if st.stop:
            return
        if depth > self._max_depth:
            st.findings.append(Finding("excessive_nesting", "resource_abuse", loc))
            st.stop = True
            return
        if value is None or isinstance(value, (bool, int, float)):
            return
        if isinstance(value, Mapping):
            for key, item in value.items():
                key_s = key if isinstance(key, str) else str(key)
                self._scan_string(key_s, direction, f"{loc}.<key>", st)
                if st.stop:
                    return
                self._walk(item, direction, f"{loc}.{key_s[:40]}", depth + 1, st)
                if st.stop:
                    return
        elif isinstance(value, (list, tuple)):
            for i, item in enumerate(value):
                self._walk(item, direction, f"{loc}[{i}]", depth + 1, st)
                if st.stop:
                    return
        else:
            self._scan_string(value if isinstance(value, str) else str(value), direction, loc, st)

    def _scan_string(self, text: str, direction: str, loc: str, st: _State) -> None:
        st.budget -= len(text) + 1
        if st.budget < 0:
            st.findings.append(Finding("oversized_payload", "resource_abuse", loc))
            st.stop = True
            return
        st.findings.extend(self.scan_text(text, direction, loc))
