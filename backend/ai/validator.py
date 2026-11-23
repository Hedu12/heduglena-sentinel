"""
AI output safety validator.

Applies length cap, shell command scan, and path scan to every AI response
before it is stored or displayed. See AS-03 and SR-02.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Shell command patterns — any match triggers redaction. See AS-03 step 2.
_SHELL_PATTERN = re.compile(
    r"(rm\s+-[rf]+|del\s+/[fqs]|wget\s+http|curl\s+http"
    r"|bash\s+-[ci]|sh\s+-[ci]|powershell[\s.]+"
    r"|python\s+-[cm]|pip\s+install|\$\(.*?\)|`[^`]+`"
    r"|;\s*(rm|del|wget|curl|bash|sh)"
    r"|&&\s*(rm|del|wget|curl))",
    re.IGNORECASE | re.DOTALL,
)

# Absolute path patterns — See AS-03 step 3.
_PATH_PATTERN = re.compile(
    r"(/[a-z]+/[a-z][a-z0-9/_.-]+"
    r"|[A-Z]:\\[A-Za-z\\]+"
    r"|~/[a-z][a-z0-9/_.-]*)",
    re.IGNORECASE,
)

REDACTION_PLACEHOLDER = "[REDACTED BY SAFETY FILTER]"


def validate(
    text: str,
    max_chars: int,
    incident_id: str = "unknown",
) -> str:
    """
    Validate and sanitize AI output.

    Steps (in order):
        1. Truncate to max_chars.
        2. Scan and redact shell command patterns.
        3. Scan and redact absolute path patterns.
        4. Log a WARNING if any redaction occurred.

    Returns the sanitized string.
    """
    # Step 1: Length cap
    result = text[:max_chars]

    redacted = False

    # Step 2: Shell commands
    def _redact_shell(m: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        logger.warning(
            "AI output redaction: shell pattern matched",
            extra={
                "incident_id": incident_id,
                "pattern": "shell",
                "match": m.group(0)[:80],
                "offset": m.start(),
            },
        )
        return REDACTION_PLACEHOLDER

    result = _SHELL_PATTERN.sub(_redact_shell, result)

    # Step 3: File paths
    def _redact_path(m: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        logger.warning(
            "AI output redaction: path pattern matched",
            extra={
                "incident_id": incident_id,
                "pattern": "path",
                "match": m.group(0)[:80],
                "offset": m.start(),
            },
        )
        return REDACTION_PLACEHOLDER

    result = _PATH_PATTERN.sub(_redact_path, result)

    return result
