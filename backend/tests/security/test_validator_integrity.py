"""
AIOutputValidator is a security boundary, not code to refactor.

This test pins the exact bytes of ai/validator.py. It fails on ANY change,
including formatting. Update PINNED_SHA256 only after an explicit human
security review of the change, in the same commit.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

VALIDATOR = Path(__file__).resolve().parents[2] / "ai" / "validator.py"
PINNED_SHA256 = "BC4A601CC1C700C4A754A0EAD7A07ADE300221DDDE1C1377E356FDE9EC0EA0E5"


def test_ai_output_validator_is_unchanged() -> None:
    actual = hashlib.sha256(VALIDATOR.read_bytes()).hexdigest().upper()
    assert actual == PINNED_SHA256, (
        "ai/validator.py changed. AIOutputValidator is a security boundary: revert the change, "
        "or get an explicit human security review before updating PINNED_SHA256."
    )
