"""
Explanation-only policy for AI output.

AIOutputValidator removes shell syntax and paths. This policy adds what makes
text an *instruction to Sentinel or the reader's system* rather than an
explanation: directives to run something, invoke a tool or function, change the
defense state, authorise or trigger a response, turn on live actions, disable a
safety control, follow a URL, or hidden characters. A match rejects the whole
answer (fail closed); describing what Sentinel already did ("the quarantine was
simulated") does not match.

The rules are deliberately conservative, so an occasional legitimate sentence
may be rejected. The cost is a fallback explanation, never an unsafe one.
"""

from __future__ import annotations

import re
import unicodedata

_RULES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        (
            "run_directive",
            r"\b(run|execute|exec|launch|invoke|call|type|paste|enter)\s+"
            r"(this|these|the\s+following|following|a|an|the)?\s*"
            r"(command|commands|script|scripts|tool|tools|function|program|code|payload)\b",
        ),
        ("tool_call", r"\b(tool_calls?|function_call|functions\.|tools\.)"),
        (
            "state_change",
            r"\b(set|change|switch|raise|lower|force|escalate|move|reset)\s+"
            r"(sentinel'?s?\s+)?(the\s+)?(defen[cs]e\s+)?(state|posture|threat\s+score|score)\s+"
            r"(to|into)\b",
        ),
        (
            "authorize_action",
            r"\b(authori[sz]e|approve|trigger|perform|carry\s+out|initiate)\s+(the\s+|a\s+|an\s+)?"
            r"(live\s+)?(action|response|quarantine|block|blocking|isolation|containment)\b",
        ),
        ("live_actions", r"\blive[_\s]+actions?\s*(=|to\s+true|on\b)|\benable\s+live\b"),
        (
            "disable_control",
            r"\b(disable|bypass|turn\s+off|skip|override)\s+(the\s+)?"
            r"(response\s*guard|guard|validator|safety|filter|security\s+control)",
        ),
        ("url", r"\b(https?|ftp|file)://|\bwww\.[a-z0-9-]+\.[a-z]{2,}"),
        ("privileged_command", r"\b(sudo|chmod|chown|taskkill|iptables|netsh|nft|regedit)\b"),
        ("role_marker", r"(^|\s)(system|assistant|developer)\s*:\s"),
        ("embedded_json", r"\{\s*\"[a-z_]+\"\s*:"),
    )
)


def first_violation(text: str) -> str | None:
    """Name of the first rule the text breaks, or None if it is explanatory."""
    for char in text:
        category = unicodedata.category(char)
        # Control (other than newline/tab), format (bidi overrides, zero-width), surrogates.
        if category.startswith("C") and char not in "\n\t":
            return "hidden_character"
    for name, pattern in _RULES:
        if pattern.search(text):
            return name
    return None
