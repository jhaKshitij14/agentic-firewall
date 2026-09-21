"""Red-team attack suite. Each module exposes ATTACKS: list[Attack]."""
from attacks import (
    privilege_escalation,
    prompt_injection,
    rate_limit,
    secret_exfiltration,
    tool_poisoning,
    unauthorized_tool,
)
from attacks.harness import Attack

ALL_ATTACKS: list[Attack] = [
    *unauthorized_tool.ATTACKS,
    *privilege_escalation.ATTACKS,
    *tool_poisoning.ATTACKS,
    *prompt_injection.ATTACKS,
    *secret_exfiltration.ATTACKS,
    *rate_limit.ATTACKS,
]
